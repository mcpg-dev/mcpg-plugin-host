//! Gateway-side secret-rotation watch loop.
//!
//! For every unique `scheme://...` URI that
//! [`crate::secret_resolver`] expanded during config load, this
//! module spawns a background task that pulls
//! [`mcpg_plugin_protocol::secret::SecretRotation`] events off the
//! provider's `watch(secret_ref)` stream, debounces bursts, and
//! calls a fan-out callback the gateway wires into
//! `GatewayBackendHost::secret_rotation_broadcaster().notify(...)`.
//!
//! ## Why debouncing
//!
//! Vault's `sys/events/subscribe` (KV v2) delivers an event per
//! `kv-v2/data-write`; rotators that bump a secret in a tight loop
//! would produce a stampede that evicts every backend pool sharing
//! the URI for each event. A small (50–100ms) coalescing window
//! turns the burst into one fan-out per secret, capped at the
//! latest version.
//!
//! ## Lifecycle
//!
//! [`SecretWatcherSet`] owns one `JoinHandle` per watched URI plus
//! a [`tokio_util::sync::CancellationToken`]. Dropping the set
//! cancels every task. The gateway calls
//! [`SecretWatcherSet::cancel`] explicitly on `reload_config` so
//! the new set's watchers can replace the old ones cleanly.
//!
//! ## Failure handling
//!
//! Each watch loop survives transient provider failures by simply
//! ending the stream — the provider trait says `watch` returns a
//! stream that may complete; restarts are the operator's
//! responsibility (config reload re-spawns). A future enhancement
//! would re-subscribe with backoff on stream-end.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::StreamExt;
use mcpg_plugin_protocol::secret::parse_secret_ref;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::PluginRegistry;

/// Default coalescing window. Vault rotators that rewrite a secret
/// in tight succession (operator-triggered re-key, lease renewal
/// cascade) collapse to one fan-out within this window.
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(75);

/// Callback fired once per debounced rotation. Receives the URI
/// (`secret_ref`) and the provider-reported version reduced to a
/// `u64` (parsed where possible, `0` otherwise — see
/// [`parse_version`]). Returns the number of subscribers the
/// gateway notified, used for audit.
pub type RotationFanOut = Arc<dyn Fn(&str, u64) -> usize + Send + Sync>;

/// Set of live watch tasks, one per unique resolved `secret_ref`.
/// Cheap to hold across hot-reload boundaries — old set is
/// `cancel()`ed before the new set's tasks come up.
pub struct SecretWatcherSet {
    cancel: CancellationToken,
    handles: Mutex<Vec<JoinHandle<()>>>,
    watched: BTreeSet<String>,
}

impl std::fmt::Debug for SecretWatcherSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretWatcherSet")
            .field("watched", &self.watched.len())
            .field("cancelled", &self.cancel.is_cancelled())
            .finish()
    }
}

impl SecretWatcherSet {
    /// Spawn one watch task per unique URI in `secret_refs`. URIs
    /// whose scheme is not bound (or whose provider returns an
    /// error from `watch`) are silently skipped — the watch path
    /// is best-effort and config-reload-driven, not part of the
    /// hot dispatch path.
    ///
    /// `fan_out` is called once per debounced rotation event. The
    /// caller is expected to hand a closure that calls
    /// `GatewayBackendHost::secret_rotation_broadcaster().notify(...)`.
    pub async fn spawn(
        registry: Arc<PluginRegistry>,
        secret_refs: BTreeSet<String>,
        fan_out: RotationFanOut,
        debounce: Duration,
    ) -> Self {
        let cancel = CancellationToken::new();
        let mut handles: Vec<JoinHandle<()>> = Vec::new();
        let mut watched: BTreeSet<String> = BTreeSet::new();
        for secret_ref in secret_refs {
            let Some((scheme, _)) = parse_secret_ref(&secret_ref) else {
                continue;
            };
            let Some(provider) = registry.secret_provider_for_scheme(scheme) else {
                debug!(
                    target: "mcpg::secret_watcher",
                    secret_ref = %secret_ref,
                    "scheme has no bound provider, skipping watch"
                );
                continue;
            };
            let stream = match provider.watch(&secret_ref).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        target: "mcpg::secret_watcher",
                        secret_ref = %secret_ref,
                        error = %e,
                        "secret provider watch failed; rotation events will not fan out for this URI"
                    );
                    continue;
                }
            };
            watched.insert(secret_ref.clone());
            let cancel_for_task = cancel.clone();
            let fan_out_for_task = Arc::clone(&fan_out);
            let secret_ref_for_task = secret_ref.clone();
            let handle = tokio::spawn(async move {
                run_watch_loop(
                    secret_ref_for_task,
                    stream,
                    fan_out_for_task,
                    debounce,
                    cancel_for_task,
                )
                .await;
            });
            handles.push(handle);
        }
        info!(
            target: "mcpg::secret_watcher",
            watched_count = watched.len(),
            debounce_ms = debounce.as_millis() as u64,
            "spawned secret-rotation watch tasks"
        );
        Self {
            cancel,
            handles: Mutex::new(handles),
            watched,
        }
    }

    /// Cancel every watch task in the set. Safe to call more than
    /// once. Awaits the tasks' join handles so the caller can rely
    /// on no in-flight rotation callbacks after this returns.
    pub async fn cancel(&self) {
        self.cancel.cancel();
        let mut handles = self.handles.lock().await;
        for h in handles.drain(..) {
            // Errors here mean the task panicked; surface as a
            // warning but don't propagate — gateway shutdown
            // should not block on misbehaving plugins.
            if let Err(e) = h.await
                && !e.is_cancelled()
            {
                warn!(
                    target: "mcpg::secret_watcher",
                    error = %e,
                    "secret-rotation watch task panicked or was aborted"
                );
            }
        }
    }

    /// URIs currently being watched. Stable + dedup'd. Useful for
    /// the boot audit log + tests.
    pub fn watched(&self) -> &BTreeSet<String> {
        &self.watched
    }
}

impl Drop for SecretWatcherSet {
    fn drop(&mut self) {
        // Best-effort cancellation; tasks observe and exit.
        // Awaiting handles requires async context, so cancel-only
        // is the synchronous fallback. Production callers prefer
        // the explicit `cancel().await` path.
        self.cancel.cancel();
    }
}

/// Per-URI watch loop with debounce. Awaits the provider's
/// rotation stream + the cancel token; on each event, records the
/// "latest version" and arms a debounce timer; on the timer firing,
/// invokes the fan-out callback once.
async fn run_watch_loop(
    secret_ref: String,
    mut stream: mcpg_plugin_protocol::secret::BoxSecretRotationStream,
    fan_out: RotationFanOut,
    debounce: Duration,
    cancel: CancellationToken,
) {
    // `latest` carries (version, observed_at) for events seen but
    // not yet fanned out. `next_fire` is the deadline at which the
    // accumulated event will be emitted.
    let mut latest: Option<u64> = None;
    let mut next_fire: Option<Instant> = None;
    loop {
        // Either:
        // - cancel requested → exit;
        // - stream produces an event → coalesce;
        // - debounce timer fires → fan-out.
        let next_fire_dur = next_fire.map(|d| d.saturating_duration_since(Instant::now()));
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                debug!(
                    target: "mcpg::secret_watcher",
                    secret_ref = %secret_ref,
                    "watch loop cancelled"
                );
                return;
            }
            // Debounce timer arm — only sleeps when we have a
            // pending event.
            () = async {
                match next_fire_dur {
                    Some(d) => tokio::time::sleep(d).await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(version) = latest.take() {
                    let started = Instant::now();
                    let subscriber_count = (fan_out)(&secret_ref, version);
                    let duration_ms = started.elapsed().as_millis() as u64;
                    info!(
                        target: "mcpg::secret_watcher",
                        event = "gateway.secret.rotation_observed",
                        secret_ref = %secret_ref,
                        version = version,
                        subscriber_count = subscriber_count,
                        duration_ms = duration_ms,
                        "secret rotation observed; fan-out complete"
                    );
                    metrics::counter!(
                        "mcpg_secret_rotation_observed_total",
                        "secret_ref" => secret_ref.clone(),
                    )
                    .increment(1);
                }
                next_fire = None;
            }
            event = stream.next() => {
                match event {
                    Some(rotation) => {
                        let version = parse_version(&rotation.new_value.version);
                        // Always overwrite latest so we end up
                        // emitting the freshest version observed
                        // within the debounce window.
                        latest = Some(version);
                        if next_fire.is_none() {
                            next_fire = Some(Instant::now() + debounce);
                        }
                    }
                    None => {
                        // Stream ended — provider closed the
                        // subscription. Best-effort: emit any
                        // pending event then exit. Operators
                        // restart the watcher via reload_config.
                        if let Some(version) = latest.take() {
                            let _ = (fan_out)(&secret_ref, version);
                        }
                        debug!(
                            target: "mcpg::secret_watcher",
                            secret_ref = %secret_ref,
                            "rotation stream ended; watch loop exiting"
                        );
                        return;
                    }
                }
            }
        }
    }
}

/// Best-effort version parse: prefer the provider-reported `u64`
/// integer (Vault KV-v2 `metadata.version` is "1", "2", ...; AWS
/// SM `VersionId` is a UUID — caller passes `0` instead). Hosts
/// use the version for de-dup; rotation behaviour is correct even
/// when every event reports `0`.
fn parse_version(version: &Option<String>) -> u64 {
    match version.as_deref() {
        Some(s) => s.parse::<u64>().unwrap_or(0),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use mcpg_plugin_protocol::secret::{
        BoxSecretRotationStream, SecretError, SecretProvider, SecretRotation, SecretValue,
    };
    use mcpg_plugin_protocol::{PluginClass, PluginManifest, PluginTier};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn manifest(id: &str) -> PluginManifest {
        PluginManifest {
            id: id.into(),
            version: "0.1.0".into(),
            name: "fixed".into(),
            plugin_class: PluginClass::SecretProvider,
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
        }
    }

    /// Fake provider that drives a tokio mpsc through `watch` so
    /// the test can inject rotation events on demand.
    struct FakeProvider {
        manifest: PluginManifest,
        scheme: String,
        rx: tokio::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<SecretRotation>>>,
    }

    #[mcpg_plugin_protocol::async_trait]
    impl SecretProvider for FakeProvider {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn supported_schemes(&self) -> Vec<String> {
            vec![self.scheme.clone()]
        }
        async fn get(&self, _r: &str) -> Result<SecretValue, SecretError> {
            Ok(SecretValue::new(Bytes::from_static(b"v")))
        }
        async fn watch(&self, _r: &str) -> Result<BoxSecretRotationStream, SecretError> {
            // One-shot: hand the receiver out the first time, then
            // refuse subsequent calls with NotFound (test only
            // calls watch once per URI per test).
            let mut slot = self.rx.lock().await;
            let rx = slot.take().ok_or(SecretError::Backend {
                reason: "watch already taken".into(),
            })?;
            let stream =
                futures::stream::unfold(
                    rx,
                    |mut rx| async move { rx.recv().await.map(|ev| (ev, rx)) },
                );
            Ok(Box::pin(stream))
        }
    }

    fn registry_with_fake(
        scheme: &str,
    ) -> (
        Arc<PluginRegistry>,
        tokio::sync::mpsc::UnboundedSender<SecretRotation>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let provider = Arc::new(FakeProvider {
            manifest: manifest("dev.test.fake"),
            scheme: scheme.to_owned(),
            rx: tokio::sync::Mutex::new(Some(rx)),
        });
        let mut reg = PluginRegistry::new();
        reg.register_secret_provider(provider, PluginTier::Native)
            .unwrap();
        reg.bind_secret_scheme(scheme, "dev.test.fake").unwrap();
        (Arc::new(reg), tx)
    }

    fn rotation(version: &str) -> SecretRotation {
        SecretRotation {
            new_value: SecretValue {
                bytes: Bytes::from_static(b"v"),
                version: Some(version.to_owned()),
                expires_at: None,
                metadata: Default::default(),
            },
            reason: "test".into(),
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn debounce_collapses_burst_to_single_fan_out() {
        let (reg, tx) = registry_with_fake("vaulttest");
        let counter = Arc::new(AtomicUsize::new(0));
        let last_version = Arc::new(std::sync::Mutex::new(0u64));
        let cnt_for_cb = Arc::clone(&counter);
        let lv_for_cb = Arc::clone(&last_version);
        let fan_out: RotationFanOut = Arc::new(move |_secret_ref, version| {
            cnt_for_cb.fetch_add(1, Ordering::SeqCst);
            *lv_for_cb.lock().unwrap() = version;
            7 // pretend 7 subscribers
        });
        let mut refs = BTreeSet::new();
        refs.insert("vaulttest://kv/db#password".to_owned());
        let set = SecretWatcherSet::spawn(reg, refs, fan_out, Duration::from_millis(50)).await;
        // Burst 5 events within the debounce window.
        for v in ["1", "2", "3", "4", "5"] {
            tx.send(rotation(v)).unwrap();
        }
        // Yield + advance past the debounce window.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(80)).await;
        // Let the spawned task actually run + emit.
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "burst collapses to one fan-out"
        );
        assert_eq!(
            *last_version.lock().unwrap(),
            5,
            "fan-out uses the latest version"
        );
        set.cancel().await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn cancel_stops_watch_loop() {
        let (reg, _tx) = registry_with_fake("vaulttest2");
        let counter = Arc::new(AtomicUsize::new(0));
        let cnt_for_cb = Arc::clone(&counter);
        let fan_out: RotationFanOut = Arc::new(move |_, _| {
            cnt_for_cb.fetch_add(1, Ordering::SeqCst);
            0
        });
        let mut refs = BTreeSet::new();
        refs.insert("vaulttest2://kv/x".to_owned());
        let set = SecretWatcherSet::spawn(reg, refs, fan_out, Duration::from_millis(20)).await;
        set.cancel().await;
        // No events were sent; counter stays at 0 + cancel returns.
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn parse_version_handles_numeric_and_non_numeric() {
        assert_eq!(parse_version(&Some("42".into())), 42);
        assert_eq!(parse_version(&Some("not-a-number".into())), 0);
        assert_eq!(parse_version(&None), 0);
    }
}
