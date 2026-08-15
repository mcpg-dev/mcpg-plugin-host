//! Plugin health prober — the first writer of `PluginState::Degraded`.
//!
//! Background task that walks the registry on a tick, sends each
//! eligible plugin a synthetic probe call, and flips plugin state
//! between `Active` and `Degraded` based on a consecutive-failure
//! streak.
//!
//! ## Contract
//!
//! - Probes are no-op calls (tool name `__healthcheck`, empty
//!   arguments, anonymous identity). A plugin whose decision logic
//!   depends on the request contents will almost always rubber-stamp
//!   the probe as `Allow` (or `Unchanged` for transforms, or `None`
//!   for identity resolvers) — that's fine; the probe is checking
//!   **liveness**, not **policy**.
//! - Failure is narrow: only panic-sentinel returns + timeouts count.
//!   A plugin that denies tool calls is still healthy.
//! - The prober never flips **out of** `Degraded` on the first probe —
//!   recovery is a single-success transition but still requires a live
//!   probe to have succeeded; it won't spontaneously reset.
//! - Disabled + terminal-state plugins are skipped. The prober will
//!   not resurrect them.
//!
//! ## Metric
//!
//! Each probe emits
//! `mcpg_plugin_health{plugin_id, result=pass|fail|timeout|skipped|unsupported|notfound}`
//! — wired into the Grafana dashboard.
//!
//! ## Why not part of the chain-evaluation path
//!
//! The chain path is hot and per-request. Health probing is periodic
//! and per-plugin. Keeping them separate means the prober is the only
//! writer of `Degraded`; the chain just reads and serves accordingly.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::registry::{PluginRegistry, ProbeOutcome};

/// Operator knobs for the health prober.
#[derive(Debug, Clone)]
pub struct HealthProbeConfig {
    /// How long to wait between probe cycles across the registry.
    /// Each cycle probes every eligible plugin once. Default: 30s.
    pub interval: Duration,
    /// Per-probe deadline. A plugin whose FFI call exceeds this is
    /// recorded as `ProbeOutcome::Timeout` (a failure). Default: 5s.
    pub probe_timeout: Duration,
    /// Consecutive failures required before flipping `Active` →
    /// `Degraded`. Default: 3 — enough to rule out single-probe
    /// flakes without waiting minutes to mark a genuinely-broken
    /// plugin degraded.
    pub failure_threshold: u32,
}

impl Default for HealthProbeConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            probe_timeout: Duration::from_secs(5),
            failure_threshold: 3,
        }
    }
}

impl HealthProbeConfig {
    /// Validate the config. Hard requirements: non-zero `interval`,
    /// non-zero `probe_timeout`, `failure_threshold ≥ 1`, and
    /// `probe_timeout < interval`. Any violation returns a descriptive
    /// error; the caller decides whether to refuse startup or warn.
    pub fn validate(&self) -> Result<(), String> {
        if self.interval.is_zero() {
            return Err("health_probe.interval must be > 0".into());
        }
        if self.probe_timeout.is_zero() {
            return Err("health_probe.probe_timeout must be > 0".into());
        }
        if self.failure_threshold == 0 {
            return Err("health_probe.failure_threshold must be >= 1".into());
        }
        if self.probe_timeout >= self.interval {
            return Err(format!(
                "health_probe.probe_timeout ({:?}) must be < interval ({:?})",
                self.probe_timeout, self.interval,
            ));
        }
        Ok(())
    }
}

/// Handle to a running prober. Drop or call [`Self::stop`] to signal
/// shutdown; the task exits before its next tick.
pub struct HealthProberHandle {
    stop: Arc<AtomicBool>,
    wake: Arc<Notify>,
    join: Option<JoinHandle<()>>,
}

impl HealthProberHandle {
    /// Signal the prober to stop and wait for its task to finish.
    /// Safe to call multiple times; only the first call awaits.
    pub async fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        self.wake.notify_waiters();
        if let Some(h) = self.join.take() {
            let _ = h.await;
        }
    }

    /// Force the next probe cycle immediately (primarily for tests).
    pub fn nudge(&self) {
        self.wake.notify_waiters();
    }
}

impl Drop for HealthProberHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.wake.notify_waiters();
        // The task has an `Arc` on `stop` + `wake`; it will observe
        // the flag on its next wakeup. We don't await here because
        // Drop can't be async; operators who want a clean wait call
        // `stop().await` explicitly.
    }
}

/// Spawn the health prober as a background tokio task.
///
/// The task lives on the current multi-threaded runtime; probes are
/// serialised across plugins (one-at-a-time, not fanned out) so a
/// slow plugin can't back-pressure a fast plugin's probe schedule.
pub fn spawn(registry: Arc<PluginRegistry>, config: HealthProbeConfig) -> HealthProberHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let wake = Arc::new(Notify::new());
    let stop_for_task = Arc::clone(&stop);
    let wake_for_task = Arc::clone(&wake);

    let join = tokio::spawn(async move {
        run_prober(registry, config, stop_for_task, wake_for_task).await;
    });

    HealthProberHandle {
        stop,
        wake,
        join: Some(join),
    }
}

async fn run_prober(
    registry: Arc<PluginRegistry>,
    config: HealthProbeConfig,
    stop: Arc<AtomicBool>,
    wake: Arc<Notify>,
) {
    info!(
        interval_ms = config.interval.as_millis() as u64,
        probe_timeout_ms = config.probe_timeout.as_millis() as u64,
        failure_threshold = config.failure_threshold,
        "plugin health prober started",
    );

    let mut streaks: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();

    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }

        let plugin_ids = registry.registered_plugin_ids();
        debug!(plugin_count = plugin_ids.len(), "health probe cycle");

        for id in &plugin_ids {
            if stop.load(Ordering::Acquire) {
                break;
            }
            let outcome = registry.probe_plugin(id, config.probe_timeout).await;
            metrics::counter!(
                "mcpg_plugin_health",
                "plugin_id" => id.clone(),
                "result" => outcome.metric_label(),
            )
            .increment(1);

            if outcome.is_failure() {
                let streak = streaks.entry(id.clone()).or_insert(0);
                *streak += 1;
                warn!(
                    plugin_id = %id,
                    outcome = ?outcome,
                    streak = *streak,
                    threshold = config.failure_threshold,
                    "plugin health probe failed",
                );
                if *streak >= config.failure_threshold {
                    match registry.mark_degraded(id) {
                        Ok(()) => {}
                        Err(e) => debug!(plugin_id = %id, error = %e, "mark_degraded no-op"),
                    }
                }
            } else if matches!(outcome, ProbeOutcome::Pass) {
                // Successful probe — reset streak, recover if needed.
                if streaks.remove(id).is_some() {
                    debug!(plugin_id = %id, "failure streak cleared");
                }
                match registry.mark_active(id) {
                    Ok(()) => {}
                    Err(e) => debug!(plugin_id = %id, error = %e, "mark_active no-op"),
                }
            } else {
                // Skipped / Unsupported / NotFound — leave streak as-is
                // (don't increment, don't reset). A plugin that's
                // temporarily Disabled shouldn't lose its failure
                // history; a plugin that came back as NotFound was
                // probably unloaded, and its streak entry will age out
                // when a future cycle reports Pass (or never probe it
                // again).
            }
        }

        // Sleep until the next cycle OR a wake-nudge OR a stop signal.
        tokio::select! {
            _ = tokio::time::sleep(config.interval) => {}
            _ = wake.notified() => {}
        }
    }

    info!("plugin health prober stopped");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::{
        GateDecision, PluginClass, PluginContext, PluginManifest, PluginTier, ToolGatePlugin,
        async_trait,
    };
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU32;

    /// A tool-gate plugin whose `evaluate_pre_dispatch` returns a
    /// pre-set outcome sequence. Lets tests script "panic, panic,
    /// panic, then recover" behaviour without writing a real plugin.
    struct ScriptedPlugin {
        manifest: PluginManifest,
        /// Sequence of outcomes this plugin will return on successive
        /// probe calls. When exhausted, loops on the last value.
        script: Mutex<Vec<ScriptedOutcome>>,
        calls: AtomicU32,
    }

    #[derive(Debug, Clone)]
    enum ScriptedOutcome {
        Allow,
        PanicDeny,
    }

    impl ScriptedPlugin {
        fn new(id: &str, script: Vec<ScriptedOutcome>) -> Self {
            Self {
                manifest: PluginManifest {
                    id: id.into(),
                    version: "0.0.0".into(),
                    name: id.into(),
                    plugin_class: PluginClass::ToolGate,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: vec![],
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                script: Mutex::new(script),
                calls: AtomicU32::new(0),
            }
        }

        fn call_count(&self) -> u32 {
            self.calls.load(Ordering::Acquire)
        }
    }

    #[async_trait]
    impl ToolGatePlugin for ScriptedPlugin {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }

        async fn evaluate_pre_dispatch(
            &self,
            _ctx: &PluginContext,
            _args: &serde_json::Value,
            _meta: Option<&serde_json::Value>,
            _cfg: &serde_json::Value,
        ) -> GateDecision {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let mut s = self.script.lock().unwrap();
            let outcome = if s.is_empty() {
                ScriptedOutcome::Allow
            } else if s.len() == 1 {
                s[0].clone()
            } else {
                s.remove(0)
            };
            match outcome {
                ScriptedOutcome::Allow => GateDecision::allow(),
                ScriptedOutcome::PanicDeny => GateDecision::Deny {
                    http_status: 500,
                    code: mcpg_plugin_protocol::abi::PANIC_DENY_CODE,
                    message: "panic sentinel".into(),
                    error_data: None,
                },
            }
        }
    }

    fn build_registry_with(plugin: ScriptedPlugin) -> Arc<PluginRegistry> {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(Box::new(plugin), PluginTier::Native, serde_json::json!({}))
            .expect("register");
        Arc::new(reg)
    }

    #[tokio::test]
    async fn healthy_plugin_stays_active() {
        let plugin = ScriptedPlugin::new("dev.test.healthy", vec![ScriptedOutcome::Allow]);
        let registry = build_registry_with(plugin);

        assert_eq!(
            registry.lifecycle_state("dev.test.healthy"),
            Some(crate::lifecycle::PluginState::Active)
        );

        // Direct probe — bypass the tick loop.
        let outcome = registry
            .probe_plugin("dev.test.healthy", Duration::from_secs(1))
            .await;
        assert_eq!(outcome, ProbeOutcome::Pass);
        assert_eq!(
            registry.lifecycle_state("dev.test.healthy"),
            Some(crate::lifecycle::PluginState::Active)
        );
    }

    #[tokio::test]
    async fn panicking_plugin_flips_to_degraded_after_threshold() {
        let plugin = ScriptedPlugin::new("dev.test.crasher", vec![ScriptedOutcome::PanicDeny; 10]);
        let registry = build_registry_with(plugin);

        let failure_threshold = 3;
        let config = HealthProbeConfig {
            interval: Duration::from_millis(20),
            probe_timeout: Duration::from_millis(10),
            failure_threshold,
        };
        let handle = spawn(Arc::clone(&registry), config);

        // Wait for enough cycles to cross the threshold. Each cycle
        // is ~20ms; 3 failures = 3 cycles; give it generous headroom.
        for _ in 0..50 {
            if registry.lifecycle_state("dev.test.crasher")
                == Some(crate::lifecycle::PluginState::Degraded)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        assert_eq!(
            registry.lifecycle_state("dev.test.crasher"),
            Some(crate::lifecycle::PluginState::Degraded),
            "expected Degraded after {failure_threshold} failed probes",
        );

        handle.stop().await;
    }

    #[tokio::test]
    async fn degraded_plugin_recovers_on_first_success() {
        // Script: two panics (insufficient to flip on their own under
        // threshold=3), then Allow forever. Threshold=2 so the plugin
        // does go Degraded briefly, then recovers.
        let script = vec![
            ScriptedOutcome::PanicDeny,
            ScriptedOutcome::PanicDeny,
            ScriptedOutcome::Allow,
        ];
        let plugin = ScriptedPlugin::new("dev.test.recovery", script);
        let registry = build_registry_with(plugin);

        let config = HealthProbeConfig {
            interval: Duration::from_millis(15),
            probe_timeout: Duration::from_millis(10),
            failure_threshold: 2,
        };
        let handle = spawn(Arc::clone(&registry), config);

        // First: wait for Degraded.
        let mut saw_degraded = false;
        for _ in 0..80 {
            if registry.lifecycle_state("dev.test.recovery")
                == Some(crate::lifecycle::PluginState::Degraded)
            {
                saw_degraded = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        assert!(saw_degraded, "plugin should have gone Degraded");

        // Then: wait for recovery back to Active.
        let mut saw_active_again = false;
        for _ in 0..80 {
            if registry.lifecycle_state("dev.test.recovery")
                == Some(crate::lifecycle::PluginState::Active)
            {
                saw_active_again = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        assert!(
            saw_active_again,
            "plugin should have recovered to Active after a passing probe",
        );

        handle.stop().await;
    }

    #[tokio::test]
    async fn unknown_plugin_id_returns_not_found() {
        let plugin = ScriptedPlugin::new("dev.test.only", vec![ScriptedOutcome::Allow]);
        let registry = build_registry_with(plugin);
        let outcome = registry
            .probe_plugin("dev.test.missing", Duration::from_secs(1))
            .await;
        assert_eq!(outcome, ProbeOutcome::NotFound);
    }

    #[tokio::test]
    async fn disabled_plugin_is_skipped_not_probed() {
        let plugin = ScriptedPlugin::new("dev.test.disabled", vec![ScriptedOutcome::Allow]);
        let registry = build_registry_with(plugin);
        registry.disable("dev.test.disabled").unwrap();

        let outcome = registry
            .probe_plugin("dev.test.disabled", Duration::from_secs(1))
            .await;
        match outcome {
            ProbeOutcome::Skipped { state } => {
                assert_eq!(state, crate::lifecycle::PluginState::Disabled);
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    #[test]
    fn config_validate_catches_zero_interval() {
        let cfg = HealthProbeConfig {
            interval: Duration::ZERO,
            ..HealthProbeConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_catches_zero_probe_timeout() {
        let cfg = HealthProbeConfig {
            probe_timeout: Duration::ZERO,
            ..HealthProbeConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_catches_zero_threshold() {
        let cfg = HealthProbeConfig {
            failure_threshold: 0,
            ..HealthProbeConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_catches_probe_timeout_exceeding_interval() {
        let cfg = HealthProbeConfig {
            interval: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(2),
            ..HealthProbeConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn default_config_validates() {
        assert!(HealthProbeConfig::default().validate().is_ok());
    }

    #[test]
    fn probe_outcome_is_failure_only_on_real_failures() {
        assert!(!ProbeOutcome::Pass.is_failure());
        assert!(ProbeOutcome::Panicked.is_failure());
        assert!(ProbeOutcome::Timeout.is_failure());
        assert!(
            !ProbeOutcome::Skipped {
                state: crate::lifecycle::PluginState::Disabled
            }
            .is_failure()
        );
        assert!(!ProbeOutcome::Unsupported.is_failure());
        assert!(!ProbeOutcome::NotFound.is_failure());
    }

    #[test]
    fn probe_outcome_metric_labels_are_stable() {
        // The Grafana dashboard queries by these labels; stabilise
        // them against refactoring.
        assert_eq!(ProbeOutcome::Pass.metric_label(), "pass");
        assert_eq!(ProbeOutcome::Panicked.metric_label(), "fail");
        assert_eq!(ProbeOutcome::Timeout.metric_label(), "timeout");
        assert_eq!(
            ProbeOutcome::Skipped {
                state: crate::lifecycle::PluginState::Disabled
            }
            .metric_label(),
            "skipped"
        );
        assert_eq!(ProbeOutcome::Unsupported.metric_label(), "unsupported");
        assert_eq!(ProbeOutcome::NotFound.metric_label(), "notfound");
    }

    /// Smoke test — verify the test scaffolding reaches the plugin
    /// at all, independent of the prober loop.
    #[tokio::test]
    async fn scripted_plugin_wired_correctly() {
        let plugin = ScriptedPlugin::new(
            "dev.test.wiring",
            vec![ScriptedOutcome::Allow, ScriptedOutcome::PanicDeny],
        );
        let plugin_ref = std::sync::Arc::new(plugin);
        // Register via a different registry-construction shape so we
        // can still query call count on the original Arc.
        let mut reg = PluginRegistry::new();
        let call_count_handle = Arc::clone(&plugin_ref);
        // Register — we can't Box::new an Arc directly. So we wrap:
        // register_tool_gate takes Box<dyn ToolGatePlugin>.
        //
        // This is the only test in this module that needs
        // out-of-registry access to the plugin state; it's fine to
        // use a small shim for it.
        struct Shim(Arc<ScriptedPlugin>);
        #[async_trait]
        impl ToolGatePlugin for Shim {
            fn manifest(&self) -> &PluginManifest {
                self.0.manifest()
            }
            async fn evaluate_pre_dispatch(
                &self,
                ctx: &PluginContext,
                args: &serde_json::Value,
                meta: Option<&serde_json::Value>,
                cfg: &serde_json::Value,
            ) -> GateDecision {
                self.0.evaluate_pre_dispatch(ctx, args, meta, cfg).await
            }
        }
        reg.register_tool_gate(
            Box::new(Shim(Arc::clone(&plugin_ref))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        let reg = Arc::new(reg);

        let _ = reg
            .probe_plugin("dev.test.wiring", Duration::from_secs(1))
            .await;
        let _ = reg
            .probe_plugin("dev.test.wiring", Duration::from_secs(1))
            .await;
        assert_eq!(call_count_handle.call_count(), 2);
    }
}
