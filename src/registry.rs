//! Plugin registry — manages loaded plugins and evaluates plugin chains.
//!
//! The registry holds ordered chains of plugins for each plugin class.
//! At request time, the gateway calls into the registry which iterates the
//! chain and returns the combined decision.
//!
//! ## Zero-cost when empty
//!
//! All chain evaluation methods bail out immediately when no plugins are
//! registered, adding zero overhead to the non-plugin request path.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use mcpg_plugin_protocol::{
    BackendPlugin, GateDecision, IdentityProviderPlugin, IdentityResolution, PluginContext,
    PluginDescriptor, PluginManifest, PluginTier, ToolGatePlugin, TransformPlugin, TransformResult,
    WatchStrategyPlugin,
};
use tokio::time::timeout;
use tracing::{Instrument, info, warn};

use crate::descriptor::validate_descriptor;
use crate::lifecycle::{AtomicPluginState, PluginState};

/// Default per-plugin budget for `shutdown()` during drain. A
/// misbehaving plugin (e.g., a webhook sink whose flush is blocked
/// on a hung remote) must not be able to stall gateway teardown
/// past this budget; we log a warning and move on.
pub const DEFAULT_PLUGIN_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Loaded plugin wrapper
// ---------------------------------------------------------------------------

/// A loaded plugin instance with metadata. The `enforce` flag controls shadow mode:
/// when false, Deny/Challenge decisions are logged but overridden to Allow, letting
/// operators evaluate a new plugin in production without affecting traffic.
struct LoadedPlugin<T: ?Sized> {
    /// Operator-chosen alias for this entry — unique across the
    /// entire registry. Used as the registry key, audit attribution
    /// label, observability target. The alias model lets
    /// one cdylib ship under multiple aliases (multi-instance). Most
    /// register_* call sites set `alias = manifest.id` for the
    /// simple single-instance case; the boot loop's
    /// `register_*_with_alias` variants accept the operator-supplied
    /// alias for true multi-instance support.
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    config: serde_json::Value,
    /// When false, the plugin runs in shadow mode: evaluate and log, but
    /// override Deny/Challenge → Allow. Defaults to true (enforce).
    enforce: bool,
    /// Current lifecycle state, mutable at runtime via admin-plane
    /// disable / enable / degrade operations. Stored in an atomic
    /// cell so chain-evaluation code can read it without taking a
    /// lock on the registry — the request-path performance
    /// invariant (immutable chains, zero locking) is preserved
    /// even as the registry tracks operator-driven state changes.
    state: AtomicPluginState,
    /// Wall-clock time the plugin was registered. Surfaced by admin
    /// detail endpoints so operators can correlate a plugin's uptime
    /// with observed behaviour (incidents, config reloads, etc.).
    registered_at: std::time::SystemTime,
    /// Per-plugin in-flight call counter. Incremented by
    /// `InflightGuard::acquire` at the top of each chain-eval
    /// invocation and decremented on guard drop. Admin drain uses
    /// this to wait for outstanding work to finish.
    inflight: Arc<InflightTracker>,
    instance: Box<T>,
}

/// Public info about a loaded plugin (for admin/inspection endpoints).
#[derive(Debug, Clone, serde::Serialize)]
pub struct LoadedPluginInfo {
    pub id: String,
    pub version: String,
    pub name: String,
    pub plugin_class: String,
    pub tier: String,
    pub protocol_version: String,
    /// Lifecycle state (see [`PluginState`]). Current writers:
    /// registration (→ `active`), the admin `disable` / `enable` /
    /// `:drain` endpoints, and the health prober (`active` ↔
    /// `degraded`).
    pub state: String,
}

/// Read-only view of one registered `http_route` entity, for host
/// dispatch-table construction + admin listing. Borrows from the
/// registry; doesn't own the route specs.
#[derive(Debug)]
pub struct HttpRouteEntry<'a> {
    pub plugin_id: &'a str,
    pub entity_name: &'a str,
    pub state: PluginState,
    pub routes: &'a [mcpg_plugin_protocol::http_route::RouteSpec],
}

/// One `(method, path, plugin_id, entity_name)` tuple emitted by
/// [`PluginRegistry::http_route_override_entries`] — every row the
/// gateway's axum router builder needs to mount top-level for
/// override-mode plugins.
#[derive(Debug, Clone, Copy)]
pub struct HttpRouteOverrideEntry<'a> {
    pub plugin_id: &'a str,
    pub entity_name: &'a str,
    pub method: &'a str,
    pub path: &'a str,
}

/// Reserved top-level path prefixes that override-mode plugins MUST
/// NOT claim. Mirrors the gateway's built-in endpoints + the
/// namespaced-mount root. Matched on either full-path equality (for
/// `/` or `/mcp`) or prefix match (for `/plugins/`, `/.well-known/`
/// etc.).
///
/// Centralised here so the registry can reject at registration time
/// AND the axum router builder can re-check at mount time — two
/// layers of defence against a collision sneaking through.
pub const RESERVED_OVERRIDE_PATH_PREFIXES: &[&str] = &[
    "/mcp",
    "/healthz",
    "/ready",
    "/runtime",
    "/metrics",
    "/plugins/",
    "/webhooks/",
    "/.well-known/",
];

/// Whether `path` hits the reserved override set. Equality for the
/// bare-root path (`"/"`), prefix match for the rest.
pub(crate) fn is_reserved_override_path(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    RESERVED_OVERRIDE_PATH_PREFIXES
        .iter()
        .any(|prefix| path == prefix.trim_end_matches('/') || path.starts_with(prefix))
}

/// Full per-plugin detail payload returned by
/// [`PluginRegistry::plugin_detail`]. Richer than
/// [`LoadedPluginInfo`] — carries the manifest, operator config,
/// enforce / shadow flag, registered_at timestamp, and live
/// in-flight count so admin surfaces can render a single-plugin
/// detail page without multiple round trips.
///
/// The `config` field is the operator config verbatim; admin handlers
/// are expected to redact sensitive values before serialising to the
/// network. The registry keeps the raw value because its consumers
/// (audit pipelines, debug logs) sometimes need the unredacted form.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LoadedPluginDetail {
    pub id: String,
    pub version: String,
    pub name: String,
    pub plugin_class: String,
    pub tier: String,
    pub protocol_version: String,
    pub required_capabilities: Vec<String>,
    pub state: String,
    /// Wall-clock time the plugin was registered, as seconds since
    /// the Unix epoch. Admin surfaces typically render this as an
    /// absolute timestamp + uptime.
    pub registered_at_unix_secs: u64,
    /// Current in-flight chain-eval count (always `None` for
    /// binding / watch-strategy plugins — those don't track per-call
    /// inflight state at the registry level).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inflight: Option<usize>,
    /// Whether decisions are applied (`true`) or shadow-logged only
    /// (`false`). `None` for keyed plugins — enforce is a tool-gate
    /// concept.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforce: Option<bool>,
    /// Operator config the plugin was registered with, unredacted.
    /// Callers MUST redact before returning to untrusted surfaces.
    pub config: serde_json::Value,
}

/// Summary of a [`PluginRegistry::shutdown_all`] invocation. Useful
/// for operators (via admin surfaces) and tests that need to assert
/// a plugin drained within budget.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ShutdownReport {
    /// Number of plugins that completed `shutdown()` within the
    /// per-plugin timeout.
    pub clean: usize,
    /// Plugin ids that exceeded the per-plugin timeout and were
    /// abandoned.
    pub timed_out: Vec<String>,
    /// Wall-clock duration of the entire drain sequence.
    #[serde(with = "duration_ms")]
    pub total_elapsed: Duration,
}

impl ShutdownReport {
    /// Whether every plugin drained within budget.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.timed_out.is_empty()
    }
}

mod duration_ms {
    use std::time::Duration;

    pub fn serialize<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_millis() as u64)
    }
}

// ---------------------------------------------------------------------------
// In-flight tracking for graceful drain
// ---------------------------------------------------------------------------

/// Per-plugin counter of in-flight chain-eval calls. Admin drain uses
/// this to wait for outstanding requests to finish before flipping
/// the plugin to `Disabled`.
///
/// Ordering:
///
/// - `fetch_add` on call entry uses `AcqRel` so the counter bump is
///   visible to any thread that subsequently reads `count`.
/// - `fetch_sub` on exit uses `AcqRel`; on `prev == 1` we call
///   `notify_waiters()` so a concurrent `DrainToken::wait` wakes up.
///
/// The counter lives inside an `Arc` so the `DrainToken` handed out by
/// `mark_draining` can outlive the `&self` borrow of the registry.
pub(crate) struct InflightTracker {
    count: std::sync::atomic::AtomicUsize,
    notify: tokio::sync::Notify,
}

impl InflightTracker {
    pub(crate) fn new() -> Self {
        Self {
            count: std::sync::atomic::AtomicUsize::new(0),
            notify: tokio::sync::Notify::new(),
        }
    }

    #[inline]
    fn load(&self) -> usize {
        self.count.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// RAII guard held across a single plugin invocation. Increments the
/// in-flight counter on construction, decrements + wakes drain
/// waiters on drop. Drop runs on any exit path (including panic
/// unwinding), so the counter can't leak.
pub(crate) struct InflightGuard<'a> {
    tracker: &'a InflightTracker,
}

impl<'a> InflightGuard<'a> {
    pub(crate) fn acquire(tracker: &'a InflightTracker) -> Self {
        tracker
            .count
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Self { tracker }
    }
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        let prev = self
            .tracker
            .count
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        if prev == 1 {
            // Counter just hit zero — wake any drain waiters.
            self.tracker.notify.notify_waiters();
        }
    }
}

/// Handle returned by [`PluginRegistry::mark_draining`]. Call
/// [`Self::wait`] to block until either in-flight calls drain or a
/// caller-specified timeout elapses.
#[derive(Debug)]
pub struct DrainToken {
    plugin_id: String,
    tracker: Arc<InflightTracker>,
}

impl std::fmt::Debug for InflightTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InflightTracker")
            .field("count", &self.load())
            .finish()
    }
}

impl DrainToken {
    /// Plugin id this token was issued for.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// Current in-flight-call count for the plugin.
    #[must_use]
    pub fn inflight(&self) -> usize {
        self.tracker.load()
    }

    /// Wait for the plugin's in-flight count to reach zero, bounded
    /// by `timeout`. On timeout, returns `TimedOut` with the last
    /// observed count.
    pub async fn wait(self, timeout: Duration) -> DrainOutcome {
        let start = Instant::now();
        loop {
            let current = self.tracker.load();
            if current == 0 {
                return DrainOutcome::Completed;
            }
            let remaining = match timeout.checked_sub(start.elapsed()) {
                Some(r) if !r.is_zero() => r,
                _ => {
                    return DrainOutcome::TimedOut { inflight: current };
                }
            };
            // Park on the notifier; a decrement-to-zero wakes us.
            // Spurious wakeups are fine — the loop re-checks.
            match tokio::time::timeout(remaining, self.tracker.notify.notified()).await {
                Ok(()) => continue,
                Err(_) => {
                    return DrainOutcome::TimedOut {
                        inflight: self.tracker.load(),
                    };
                }
            }
        }
    }
}

/// Result of [`DrainToken::wait`]. `Completed` ↔ every in-flight call
/// returned within the budget; `TimedOut` ↔ at least one call was
/// still running when the budget elapsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrainOutcome {
    /// All in-flight calls returned before the timeout.
    Completed,
    /// Timeout elapsed with work still in flight. `inflight` is the
    /// counter's value at the moment the timer fired — an operator
    /// can retry with a longer budget or force-disable the plugin.
    TimedOut { inflight: usize },
}

// ---------------------------------------------------------------------------
// Health probe outcomes
// ---------------------------------------------------------------------------

/// Outcome of a single [`PluginRegistry::probe_plugin`] call. The
/// health prober aggregates these into a consecutive-failure streak
/// and flips plugins between `Active` and `Degraded` accordingly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The plugin responded within the probe's deadline with a
    /// non-panic decision. A regular `Deny` from a tool-gate plugin
    /// counts as Pass — the plugin is alive; it's just saying no.
    Pass,
    /// The plugin panicked inside its FFI boundary, surfaced via one
    /// of the panic-sentinel return values (Deny with
    /// `PANIC_DENY_CODE`, `TransformResult::Error` carrying
    /// `PANIC_TRANSFORM_MSG`, or `IdentityResolution::Invalid` with
    /// `PANIC_IDENTITY_MSG`).
    Panicked,
    /// The FFI call did not complete inside the probe's deadline.
    Timeout,
    /// The plugin is registered but currently in a state where the
    /// prober won't exercise it (Disabled, terminal, etc.). Not a
    /// failure signal.
    Skipped { state: PluginState },
    /// The plugin kind has no no-arg probe shape. Today: binding +
    /// watch_strategy. Reported for clarity; not counted toward the
    /// consecutive-failure streak.
    Unsupported,
    /// No plugin with the given id is registered. Usually indicates a
    /// race between enumeration and probe (plugin was unloaded).
    NotFound,
}

impl ProbeOutcome {
    /// Whether the outcome should increment the consecutive-failure
    /// counter. Pass / Skipped / Unsupported / NotFound do not.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        matches!(self, ProbeOutcome::Panicked | ProbeOutcome::Timeout)
    }

    /// Metric label — matches the `result` dimension on
    /// `mcpg_plugin_health{plugin_id,result=pass|fail|timeout|skipped|unsupported|notfound}`.
    #[must_use]
    pub fn metric_label(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Panicked => "fail",
            Self::Timeout => "timeout",
            Self::Skipped { .. } => "skipped",
            Self::Unsupported => "unsupported",
            Self::NotFound => "notfound",
        }
    }
}

fn synthesise_probe_context(plugin_id: &str) -> PluginContext {
    PluginContext {
        request_id: format!("mcpg.healthcheck.{plugin_id}"),
        session_id: None,
        tool_name: "__healthcheck".to_owned(),
        surface: "tool".to_owned(),
        transport: "internal".to_owned(),
        identity: mcpg_plugin_protocol::PluginIdentity {
            kind: "anonymous".to_owned(),
            trust_level: "unauthenticated".to_owned(),
            subject_id: None,
            auth_provider: None,
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: std::collections::BTreeMap::new(),
        },
    }
}

fn classify_gate_decision(d: &GateDecision) -> ProbeOutcome {
    match d {
        GateDecision::Deny { code, .. } if *code == mcpg_plugin_protocol::abi::PANIC_DENY_CODE => {
            ProbeOutcome::Panicked
        }
        _ => ProbeOutcome::Pass,
    }
}

fn classify_transform_result(r: &TransformResult) -> ProbeOutcome {
    match r {
        TransformResult::Error { message }
            if message.contains(mcpg_plugin_protocol::abi::PANIC_TRANSFORM_MSG) =>
        {
            ProbeOutcome::Panicked
        }
        _ => ProbeOutcome::Pass,
    }
}

fn classify_identity_resolution(r: &IdentityResolution) -> ProbeOutcome {
    match r {
        IdentityResolution::Invalid { reason }
            if reason.contains(mcpg_plugin_protocol::abi::PANIC_IDENTITY_MSG) =>
        {
            ProbeOutcome::Panicked
        }
        _ => ProbeOutcome::Pass,
    }
}

// ---------------------------------------------------------------------------
// Plugin Registry
// ---------------------------------------------------------------------------

/// The central plugin registry that holds all loaded plugin instances.
///
/// Thread-safe: the registry is built at startup and is immutable during
/// request processing. It lives inside an `Arc` on the `GatewayRuntime`.
pub struct PluginRegistry {
    tool_gate_chain: Vec<LoadedPlugin<dyn ToolGatePlugin>>,
    transform_chain: Vec<LoadedPlugin<dyn TransformPlugin>>,
    identity_chain: Vec<LoadedPlugin<dyn IdentityProviderPlugin>>,
    /// Backend plugins indexed by their `kind()` ("nats", "kafka", …).
    /// Each kind maps to at most one plugin — registration rejects duplicates.
    backends: HashMap<String, LoadedBackendPlugin>,
    /// `content_store` factory plugins indexed by their `kind()`
    /// ("in_process", "file_system", "s3", …). One plugin per kind. The
    /// gateway's storage-registry builder looks these up by the operator's
    /// `storage.providers: [{kind: ...}]` and calls `build_profile`.
    content_stores: HashMap<String, LoadedContentStorePlugin>,
    /// Watch-strategy plugins indexed by their `kind()` ("nats_topic",
    /// "kafka_topic", …). One plugin per kind.
    watch_strategies: HashMap<String, LoadedWatchPlugin>,
    /// HTTP-route plugins keyed by `(plugin_id, entity_name)` —
    /// each plugin may expose multiple routes under one entity, and
    /// each plugin can register multiple entities. Keyed (rather
    /// than chained) so dispatch is O(1) on the HTTP hot path.
    http_routes: Vec<LoadedHttpRoutePlugin>,
    /// Audit sinks registered for fan-out (spec §9.12). Every
    /// registered sink receives every `emit_audit_event` call;
    /// order matches registration order so operators can read a
    /// deterministic fan-out order in logs. Collision on
    /// `plugin_id` is refused — duplicate sinks would double-count
    /// events in downstream compliance stores.
    audit_sinks: Vec<LoadedAuditSinkPlugin>,
    /// Store plugins (spec §9.8), registered by plugin_id. Each
    /// plugin advertises which roles it can serve; operators bind
    /// specific roles to specific plugins via
    /// [`Self::bind_store_role`]. Collision on plugin_id is
    /// refused; role bindings live in `store_bindings`.
    stores: Vec<LoadedStorePlugin>,
    /// Per-role dispatch table. Populated by `bind_store_role`
    /// after the plugins register (so the operator can wire any
    /// registered plugin to any of its supported roles). Reads on
    /// the gateway's hot path go through this map.
    store_bindings: BTreeMap<
        mcpg_plugin_protocol::store::StoreRole,
        Arc<dyn mcpg_plugin_protocol::store::Store>,
    >,
    /// Cache plugins (spec §9.9), registered by plugin id. Each
    /// advertises `supported_namespaces()`; operators bind
    /// specific namespaces to specific plugins via
    /// [`Self::bind_cache_namespace`]. Same two-step design as
    /// stores — one plugin may serve several namespaces.
    caches: Vec<LoadedCachePlugin>,
    /// Per-namespace dispatch table. Reads on the hot path.
    cache_bindings: BTreeMap<String, Arc<dyn mcpg_plugin_protocol::cache::Cache>>,
    /// Telemetry sinks registered for fan-out (spec §9.10). Every
    /// registered sink receives every span / metric / log event
    /// the gateway's telemetry pipeline produces. Collision on
    /// `plugin_id` is refused.
    telemetry_sinks: Vec<LoadedTelemetrySinkPlugin>,
    /// Log sinks registered for fan-out (spec §9.11). Every
    /// registered sink receives every `emit` call. Collision on
    /// `plugin_id` is refused.
    log_sinks: Vec<LoadedLogSinkPlugin>,
    /// Metrics sinks registered for fan-out. Every
    /// registered sink receives every metric `emit`. Operators
    /// gate which sinks fire via the
    /// `observability.metrics.sinks[].kind` allow-list at the
    /// gateway boot path; unfiltered emit is also exposed for
    /// direct admin / test callers. Collision on `plugin_id` is
    /// refused.
    metrics_sinks: Vec<LoadedMetricsSinkPlugin>,
    /// Secret-provider plugins (spec §9.15), registered by
    /// plugin id. Each advertises its supported URI schemes;
    /// operator binds specific schemes to specific plugins via
    /// [`Self::bind_secret_scheme`]. Two-step design mirrors
    /// store / cache.
    secret_providers: Vec<LoadedSecretProviderPlugin>,
    /// Per-scheme dispatch table. Reads on the hot path go
    /// through this map (secret resolution is invoked at boot +
    /// on rotation watches; not a per-request hot path).
    secret_scheme_bindings: BTreeMap<String, Arc<dyn mcpg_plugin_protocol::secret::SecretProvider>>,
    /// Config-provider plugins (spec §9.16), registered by
    /// plugin id. Each advertises its supported URI schemes;
    /// operator binds specific schemes via
    /// [`Self::bind_config_scheme`]. Shape mirrors
    /// `secret_providers` — two-step register-then-bind with
    /// per-scheme dispatch.
    config_providers: Vec<LoadedConfigProviderPlugin>,
    /// Per-scheme dispatch table for config lookups. Read on the
    /// reconciliation path (snapshot + delta watch), not per
    /// request.
    config_scheme_bindings: BTreeMap<String, Arc<dyn mcpg_plugin_protocol::config::ConfigProvider>>,
    /// Transport plugins (spec §9.6). Keyed by transport name
    /// — one plugin per name (like `binding` is keyed by kind).
    /// No separate bind step: the plugin self-declares its name
    /// at registration. Operators enable transports via
    /// `server.transports[]` at the app layer.
    transports: Vec<LoadedTransportPlugin>,
    /// Policy engines (spec §9.14). Keyed by the self-declared
    /// engine name; one plugin per name. Multiple engines can
    /// coexist — consumers reference one by name in their config.
    policy_engines: Vec<LoadedPolicyEnginePlugin>,
    /// Cluster coordinator (spec §9.13). Singleton — exactly one
    /// per gateway. Stored as an Option because the gateway can
    /// legitimately start with no coordinator (single-node mode
    /// uses the default built-in, which the app layer registers
    /// unconditionally; other coordinators replace it via the
    /// top-level `cluster: { kind: <plugin_id> }` block).
    cluster_backend: Option<LoadedClusterBackendPlugin>,
    /// Catalog providers (spec §9.17). Chain — operators
    /// bind one or more in `plugins[]` order; the gateway
    /// walks the chain on every `tools/list` request to filter +
    /// enrich tool descriptors.
    catalog_chain: Vec<LoadedPlugin<dyn mcpg_plugin_protocol::catalog::CatalogProvider>>,
    /// Credential issuers (spec §9.18). Keyed by
    /// `manifest.id`. Operators reference issuers via
    /// `cred://<plugin_id>/<target>` URIs in binding configs;
    /// the gateway resolves them per-request.
    credential_issuers: BTreeMap<String, LoadedCredentialIssuerPlugin>,
    /// Approval notifiers (spec §9.19). Keyed by
    /// `manifest.id`. The gateway dispatches `NotificationRequest`s
    /// here when a `tool_gate` returns `PendingApproval`. Either
    /// fan-out (when the gate's `target_notifiers` is empty) or
    /// targeted (matched by manifest id).
    approval_notifiers: BTreeMap<String, LoadedApprovalNotifierPlugin>,
    /// When `true`, the registry emits `mcpg.tool.call.allowed`
    /// after the pre-dispatch tool_gate chain accepts. Default
    /// `true` — most operators want every tool call on record for
    /// SOC2 / HIPAA. High-volume deploys can disable via the
    /// `audit.emit_tool_call_allowed` operator config.
    audit_emit_tool_call_allowed: bool,
    /// When `true`, the registry emits `mcpg.tool.call.completed`
    /// after the post-dispatch tool_gate chain accepts. Default
    /// `true`. Operators that don't care about per-call latency
    /// in the audit stream can disable via
    /// `audit.emit_tool_call_completed`.
    audit_emit_tool_call_completed: bool,
    /// Operator-granted typed capabilities, keyed by the plugin's
    /// registration alias. Recorded for cdylib plugins (the
    /// only ones that call back into the host via `HostServices`) so the
    /// host-services bridge can enforce `SecretsRead`/`ConfigRead`/
    /// `CredentialIssue` PER CALL — not just once at boot. Empty entry /
    /// absent alias ⇒ no grant ⇒ the callback is refused (fail-closed).
    granted_caps: HashMap<String, Vec<mcpg_plugin_protocol::capability::Capability>>,
    /// Per-cdylib-alias config-origin `cred://` issuer allowlist. Derived
    /// at boot from each plugin entry's OWN operator-authored config (the
    /// set of `cred://<issuer>/…` authorities it statically references), so
    /// the `resolve_credentials` host-FFI slot can enforce that a plugin
    /// resolves only credentials its config authorizes — a compromised
    /// cdylib cannot hand the host an arbitrary `cred://other-issuer/secret`
    /// and exfiltrate it. Absent alias / issuer not in the set ⇒ refused
    /// (fail-closed); mirrors the [`Self::granted_caps`] discipline.
    cred_resolve_allowlist: HashMap<String, std::collections::HashSet<String>>,
    /// Per-cdylib-alias config-origin `cred://` **target** allowlist — the
    /// set of full `<issuer>/<target>` refs (rendered by
    /// [`crate::credential_resolver::cred_ref_key`]) the entry's OWN config
    /// names. Where [`Self::cred_resolve_allowlist`] gates the *issuer*, this
    /// gates the exact *target*, so a plugin can't resolve an arbitrary
    /// target on an issuer it merely references. Absent alias / ref not in the
    /// set ⇒ refused (fail-closed).
    cred_resolve_ref_allowlist: HashMap<String, std::collections::HashSet<String>>,
    /// Per-cdylib-alias config-origin secret/config **resource** allowlist —
    /// the set of concrete `scheme://resource` URIs (anchor-stripped, via
    /// [`crate::secret_resolver::resource_allowlist_key`]) the entry's OWN
    /// config references. Gates the `resolve_secret` / `config_snapshot`
    /// host-FFI slots so a plugin holding `SecretsRead{env}` /
    /// `ConfigRead{…}` can only read the specific resources its config names —
    /// not every var/file/key on the scheme. Absent alias / resource not in
    /// the set ⇒ refused (fail-closed); mirrors the [`Self::granted_caps`]
    /// discipline.
    resource_resolve_allowlist: HashMap<String, std::collections::HashSet<String>>,
}

/// A loaded `credential_issuer` entity.
///
/// `alias` is the registry-level identifier (J.1.4): it equals
/// `manifest.id` for single-entity plugins; for multi-instance
/// (multiple issuers from one cdylib via `declare_plugin!`) it is
/// `format!("{plugin_id}:{inner_name}")`. The host's
/// `check_duplicate_alias` keys on this so two issuers from the same
/// source coexist without colliding.
struct LoadedCredentialIssuerPlugin {
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    state: AtomicPluginState,
    instance: Arc<dyn mcpg_plugin_protocol::credential::CredentialIssuer>,
}

/// A loaded `approval_notifier` entity (spec §9.19).
///
/// `alias` is the registry-level identifier (J.1.4): it equals
/// `manifest.id` for single-entity plugins; for multi-instance
/// (multiple notifiers from one cdylib via `declare_plugin!`) it is
/// `format!("{plugin_id}:{inner_name}")`. The host's
/// `check_duplicate_alias` keys on this so two notifiers from the
/// same source coexist without colliding.
struct LoadedApprovalNotifierPlugin {
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    state: AtomicPluginState,
    instance: Arc<dyn mcpg_plugin_protocol::approval_notifier::ApprovalNotifier>,
}

/// A loaded `backend` entity. Stored in a HashMap keyed by
/// `plugin.kind()` — at most one backend per kind today.
///
/// `alias` is the registry-level identifier (J.1.4): it equals
/// `manifest.id` for single-entity plugins; for multi-instance
/// (multiple backends from one cdylib via `declare_plugin!`) it is
/// `format!("{plugin_id}:{inner_name}")`. The host's
/// `check_duplicate_alias` keys on this so two backends from the
/// same source coexist in alias-space — note however that the
/// kind-keyed HashMap still enforces one-backend-per-kind, so
/// distinct aliases sharing the same kind() will collide there.
struct LoadedBackendPlugin {
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    state: AtomicPluginState,
    instance: Arc<dyn BackendPlugin>,
}

/// A loaded `content_store` factory entity. Stored in a HashMap keyed by
/// `plugin.kind()` — at most one content_store plugin per kind today
/// (mirrors `LoadedBackendPlugin`). `alias` follows the J.1.4 convention
/// (`manifest.id`, or `"{plugin_id}:{inner_name}"` for multi-entity
/// cdylibs).
struct LoadedContentStorePlugin {
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    state: AtomicPluginState,
    instance: Arc<dyn mcpg_plugin_protocol::content_store::ContentStorePlugin>,
}

/// A loaded `watch_strategy` entity. Stored in a HashMap keyed by
/// `plugin.kind()` — at most one watch-strategy per kind today.
///
/// `alias` is the registry-level identifier (J.1.4): it equals
/// `manifest.id` for single-entity plugins; for multi-instance
/// (multiple watch strategies from one cdylib via `declare_plugin!`)
/// it is `format!("{plugin_id}:{inner_name}")`. The host's
/// `check_duplicate_alias` keys on this so two strategies from the
/// same source coexist in alias-space — note however that the
/// kind-keyed HashMap still enforces one-strategy-per-kind, so
/// distinct aliases sharing the same kind() will collide there.
struct LoadedWatchPlugin {
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    state: AtomicPluginState,
    instance: Arc<dyn WatchStrategyPlugin>,
}

/// A loaded `http_route` entity. Unlike the keyed
/// binding/watch-strategy plugins, HTTP-route entities are identified
/// by `(plugin_id, entity_name)` because one plugin may expose
/// multiple entities (e.g. a webhook plugin with both
/// `/receive/stripe` and `/receive/github` routes grouped under
/// different entity names).
///
/// `alias` is the registry-level identifier (J.1.4): it defaults to
/// `entity_name` (already required non-empty) for single-instance
/// registrations; multi-instance callers pass an explicit
/// `format!("{plugin_id}:{inner_name}")` to keep uniqueness in
/// alias-space. The host's `check_duplicate_alias` keys on this so
/// two route entities from the same source coexist without
/// colliding.
struct LoadedHttpRoutePlugin {
    alias: String,
    manifest: PluginManifest,
    /// Per-plugin entity name. Part of the mount path:
    /// `/plugins/{manifest.id}/{entity_name}/...`.
    entity_name: String,
    tier: PluginTier,
    state: AtomicPluginState,
    /// Snapshot of `HttpRoute::routes()` taken at registration time.
    /// The trait allows dynamic routing, but most implementations
    /// return a static Vec — snapshotting lets the host build its
    /// dispatch table once and avoid the repeated `routes()` call on
    /// every request.
    routes: Vec<mcpg_plugin_protocol::http_route::RouteSpec>,
    /// Operator overrides for this entity — carried alongside the
    /// plugin handle so the axum dispatcher can apply them without
    /// a second round trip to the config. `None` means "use every
    /// default the plugin declared".
    overrides: HttpRouteOverrides,
    instance: Arc<dyn mcpg_plugin_protocol::http_route::HttpRoute>,
}

/// A loaded `audit_sink` entity. Unlike chain plugins, sinks have
/// no per-call decision — each `emit_audit_event` invocation fans
/// out to every registered sink and awaits each receipt.
///
/// `alias` is the registry-level identifier (J.1.4): it equals
/// `manifest.id` for single-entity plugins; for multi-instance
/// (multiple sinks from one cdylib via `declare_plugin!`) it is
/// `format!("{plugin_id}:{inner_name}")`. The host's
/// `check_duplicate_alias` keys on this so two sinks from the same
/// source coexist without colliding.
struct LoadedAuditSinkPlugin {
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    state: AtomicPluginState,
    instance: Arc<dyn mcpg_plugin_protocol::audit::AuditSink>,
}

/// A loaded `store` entity (spec §9.8). The plugin advertises its
/// `supported_roles()` at registration; the gateway binds specific
/// roles to this plugin via [`PluginRegistry::bind_store_role`].
/// One plugin id may serve several roles.
///
/// `alias` is the registry-level identifier (J.1.4): it equals
/// `manifest.id` for single-entity plugins; for multi-instance
/// (multiple stores from one cdylib via `declare_plugin!`) it is
/// `format!("{plugin_id}:{inner_name}")`. The host's
/// `check_duplicate_alias` keys on this so two stores from the same
/// source coexist without colliding.
struct LoadedStorePlugin {
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    state: AtomicPluginState,
    /// Snapshot of `supported_roles()` taken at registration time,
    /// so the binding path doesn't call back into the plugin under
    /// the registry's &mut self lock.
    supported_roles: Vec<mcpg_plugin_protocol::store::StoreRole>,
    instance: Arc<dyn mcpg_plugin_protocol::store::Store>,
}

/// A loaded `cache` entity (spec §9.9). Same two-step register-
/// then-bind flow as Store. `serves_any` captures the
/// generic-KV-backend pattern where one plugin is willing to be
/// bound to any operator-named namespace.
///
/// `alias` is the registry-level identifier (J.1.4): it equals
/// `manifest.id` for single-entity plugins; for multi-instance
/// (multiple caches from one cdylib via `declare_plugin!`) it is
/// `format!("{plugin_id}:{inner_name}")`. The host's
/// `check_duplicate_alias` keys on this so two caches from the same
/// source coexist without colliding.
struct LoadedCachePlugin {
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    state: AtomicPluginState,
    supported_namespaces: Vec<String>,
    serves_any: bool,
    instance: Arc<dyn mcpg_plugin_protocol::cache::Cache>,
}

/// A loaded `telemetry_sink` entity (spec §9.10). Fan-out
/// dispatch — one registration, every event fans to every sink.
///
/// `alias` is the registry-level identifier (J.1.4): it equals
/// `manifest.id` for single-entity plugins; for multi-instance
/// (multiple sinks from one cdylib via `declare_plugin!`) it is
/// `format!("{plugin_id}:{inner_name}")`. The host's
/// `check_duplicate_alias` keys on this so two sinks from the same
/// source coexist without colliding.
struct LoadedTelemetrySinkPlugin {
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    state: AtomicPluginState,
    instance: Arc<dyn mcpg_plugin_protocol::telemetry::TelemetrySink>,
}

/// A loaded `log_sink` entity (spec §9.11). Fan-out dispatch.
///
/// `alias` is the registry-level identifier (J.1.4): it equals
/// `manifest.id` for single-entity plugins; for multi-instance
/// (multiple sinks from one cdylib via `declare_plugin!`) it is
/// `format!("{plugin_id}:{inner_name}")`. The host's
/// `check_duplicate_alias` keys on this so two sinks from the same
/// source coexist without colliding.
struct LoadedLogSinkPlugin {
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    state: AtomicPluginState,
    instance: Arc<dyn mcpg_plugin_protocol::logs::LogSink>,
}

/// A loaded `metrics_sink` entity. Fan-out dispatch
/// — every registered sink receives every emit; operators gate
/// the bridge fan-out via the `observability.metrics.sinks[].kind`
/// allow-list while direct admin / test paths use the unfiltered
/// emit method.
///
/// `alias` is the registry-level identifier (J.1.4): it equals
/// `manifest.id` for single-entity plugins; for multi-instance
/// (multiple sinks from one cdylib via `declare_plugin!`) it is
/// `format!("{plugin_id}:{inner_name}")`. The host's
/// `check_duplicate_alias` keys on this so two sinks from the same
/// source coexist without colliding.
struct LoadedMetricsSinkPlugin {
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    state: AtomicPluginState,
    instance: Arc<dyn mcpg_plugin_protocol::metrics::MetricsSink>,
}

/// A loaded `secret_provider` entity (spec §9.15). Same two-step
/// register-then-bind flow as store / cache — the plugin
/// advertises schemes, operator binds each scheme to a chosen
/// plugin.
///
/// `alias` is the registry-level identifier (J.1.4): it equals
/// `manifest.id` for single-entity plugins; for multi-instance
/// (multiple secret_providers from one cdylib via `declare_plugin!`)
/// it is `format!("{plugin_id}:{inner_name}")`. The host's
/// `check_duplicate_alias` keys on this so two providers from the
/// same source coexist without colliding.
struct LoadedSecretProviderPlugin {
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    state: AtomicPluginState,
    supported_schemes: Vec<String>,
    instance: Arc<dyn mcpg_plugin_protocol::secret::SecretProvider>,
}

/// A loaded `config_provider` entity (spec §9.16). Same two-step
/// register-then-bind flow as `secret_provider`.
///
/// `alias` is the registry-level identifier (J.1.4): it equals
/// `manifest.id` for single-entity plugins; for multi-instance
/// (multiple config_providers from one cdylib via `declare_plugin!`)
/// it is `format!("{plugin_id}:{inner_name}")`. The host's
/// `check_duplicate_alias` keys on this so two config_providers from
/// the same source coexist without colliding.
struct LoadedConfigProviderPlugin {
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    state: AtomicPluginState,
    supported_schemes: Vec<String>,
    instance: Arc<dyn mcpg_plugin_protocol::config::ConfigProvider>,
}

/// A loaded `transport` entity (spec §9.6). Keyed by the
/// self-declared transport name (`http-v1`, `stdio-v1`, ...);
/// one plugin per name. No bind step — the plugin's name IS its
/// binding.
///
/// `alias` is the registry-level identifier (J.1.4): it equals
/// `manifest.id` for single-entity plugins; for multi-instance
/// (multiple transports from one cdylib via `declare_plugin!`) it is
/// `format!("{plugin_id}:{inner_name}")`. The host's
/// `check_duplicate_alias` keys on this so two transports from the
/// same source coexist in alias-space — note that the
/// transport_name-keyed lookup still enforces one transport per
/// name() regardless of alias.
struct LoadedTransportPlugin {
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    state: AtomicPluginState,
    /// Snapshot of `Transport::name()` taken at register time.
    /// Keeps lookup off the plugin's hot path.
    transport_name: String,
    instance: Arc<dyn mcpg_plugin_protocol::transport::Transport>,
}

/// A loaded `policy_engine` entity (spec §9.14). Keyed by the
/// self-declared engine name (`opa`, `cedar`, `yaml-rules`, ...).
///
/// `alias` is the registry-level identifier (J.1.4): it equals
/// `manifest.id` for single-entity plugins; for multi-instance
/// (multiple policy_engines from one cdylib via `declare_plugin!`)
/// it is `format!("{plugin_id}:{inner_name}")`. The host's
/// `check_duplicate_alias` keys on this so two policy_engines from
/// the same source coexist without colliding. The `engine_name`
/// dispatch key is separate — it's the operator-facing
/// name() the engine self-declares.
struct LoadedPolicyEnginePlugin {
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    state: AtomicPluginState,
    /// Snapshot of `PolicyEngine::name()` taken at register time.
    engine_name: String,
    instance: Arc<dyn mcpg_plugin_protocol::policy::PolicyEngine>,
}

/// A loaded `cluster_backend` entity (spec §9.13). Singleton.
///
/// `ffi_ref` is populated when the coordinator is a native cdylib
/// (the only tier that ships coordinators today — Consul, etcd,
/// NATS JetStream); the host hands a copy of it to consumer
/// plugins (identity, policy_engine) so they can opt into
/// cluster-coordinated state through their `make` slot's v20
/// `cluster` argument. `None` when the coordinator is, e.g., a
/// pure-Rust test double registered through
/// `register_cluster_backend` directly without a vtable
/// behind it; consumers in that mode see `RNone` at make time
/// and behave as if no coordinator were configured.
///
/// `alias` is the registry-level identifier (J.1.4). The
/// coordinator is a singleton, so multi-instance does not apply —
/// `alias` always equals `manifest.id` in practice. The field
/// exists for API consistency with the other kinds and so the
/// host's `check_duplicate_alias` still catches collisions against
/// other entities sharing the same id.
struct LoadedClusterBackendPlugin {
    alias: String,
    manifest: PluginManifest,
    tier: PluginTier,
    state: AtomicPluginState,
    instance: Arc<dyn mcpg_cluster_api::ClusterBackend>,
    ffi_ref: Option<mcpg_plugin_protocol::abi::ClusterClientRef>,
}

/// Per-sink result returned by [`PluginRegistry::emit_audit_event`].
/// One entry per registered sink. `result` carries the sink's
/// receipt on success or its error kind on failure; a mixture is
/// expected — fan-out continues across individual failures.
#[derive(Debug)]
pub struct AuditEmitResult {
    /// `plugin_id` of the sink that produced this entry.
    pub sink_id: String,
    /// `Ok(receipt)` on success, `Err(audit_error)` on failure.
    pub result:
        Result<mcpg_plugin_protocol::audit::AuditReceipt, mcpg_plugin_protocol::audit::AuditError>,
}

/// What should happen when one or more registered audit sinks
/// return an error from `emit`. Parallels
/// `apps/gateway/src/config/mod.rs::AuditOnFailure` — the gateway
/// config's shape — but kept here in plugin-host so the
/// enforcement helper doesn't pull in gateway config types.
/// Conversion at the app layer is trivial.
///
/// Spec §9.12 requires `fail_closed` for SOC2-clean deployments:
/// "no action happens without a durable audit trail". `fail_open`
/// is dev / CI only — a compliance auditor will not accept it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEmitPolicy {
    /// Any sink failure blocks the caller's action. The action's
    /// surface (admin HTTP handler, gateway startup, future
    /// tool-call dispatch) is responsible for converting this
    /// into a 5xx response / startup halt / request refusal.
    FailClosed,
    /// Sink failures are logged + counted (`mcpg_audit_sink_
    /// failures_total`) but the action proceeds. Dev / CI only.
    FailOpen,
}

/// Returned from [`PluginRegistry::emit_audit_event_enforced`]
/// when the configured policy is `FailClosed` and at least one
/// sink failed. Carries every per-sink result so the caller can
/// log the failed-sink ids + the underlying errors before
/// shaping a response.
///
/// Does NOT `impl std::error::Error` because Rust errors are
/// owned + Send + Sync, and we want the caller to choose how to
/// serialise the failure (admin returns JSON, startup logs +
/// aborts). `Display` is enough for the logging path.
#[derive(Debug)]
pub struct AuditEnforcementFailure {
    /// Every sink's per-attempt result. Callers filter to the
    /// `Err` entries for the "what failed" report.
    pub results: Vec<AuditEmitResult>,
}

impl AuditEnforcementFailure {
    /// Iterator over only the failed sinks. Useful for logging
    /// "audit sinks that failed: X, Y, Z" without forcing
    /// callers to re-filter.
    pub fn failed_sinks(
        &self,
    ) -> impl Iterator<Item = (&str, &mcpg_plugin_protocol::audit::AuditError)> {
        self.results.iter().filter_map(|r| match &r.result {
            Err(e) => Some((r.sink_id.as_str(), e)),
            Ok(_) => None,
        })
    }
}

impl std::fmt::Display for AuditEnforcementFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "audit fail_closed tripped: ")?;
        let mut first = true;
        for (sink, err) in self.failed_sinks() {
            if !first {
                write!(f, "; ")?;
            }
            first = false;
            write!(f, "{sink}: {err}")?;
        }
        if first {
            // Should not happen — constructed only when at least
            // one sink failed — but be defensive.
            write!(f, "<no failed sinks reported>")?;
        }
        Ok(())
    }
}

/// Per-entity operator overrides applied by the axum dispatcher.
/// Mirrors the loadbearing fields of
/// `apps/gateway/src/config/mod.rs::PluginHttpRouteConfig` but keeps
/// the registry crate independent of the gateway config types.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpRouteOverrides {
    /// When set, overrides `RouteSpec.max_body_bytes` for every
    /// spec the entity declares.
    pub max_body_bytes: Option<u64>,
    /// When set, overrides `RouteSpec.requires_identity` for every
    /// spec the entity declares.
    pub requires_identity: Option<bool>,
    /// When `true`, the plugin's `RouteSpec.path` values mount at
    /// their declared top-level paths instead of under the
    /// namespaced `/plugins/{id}/{entity}/` prefix. Registration
    /// refuses override mode if the plugin's manifest does not
    /// declare `http_route_serve` — operator can't
    /// silently promote a plugin past what it asked for.
    pub allow_path_override: bool,
}

impl std::fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginRegistry")
            .field("tool_gate_count", &self.tool_gate_chain.len())
            .field("transform_count", &self.transform_chain.len())
            .field("identity_count", &self.identity_chain.len())
            .field("backend_kinds", &self.backends.keys().collect::<Vec<_>>())
            .field(
                "watch_kinds",
                &self.watch_strategies.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRegistry {
    /// Create an empty registry (zero plugins loaded).
    pub fn new() -> Self {
        Self {
            tool_gate_chain: Vec::new(),
            transform_chain: Vec::new(),
            identity_chain: Vec::new(),
            backends: HashMap::new(),
            content_stores: HashMap::new(),
            watch_strategies: HashMap::new(),
            http_routes: Vec::new(),
            audit_sinks: Vec::new(),
            stores: Vec::new(),
            store_bindings: BTreeMap::new(),
            caches: Vec::new(),
            cache_bindings: BTreeMap::new(),
            telemetry_sinks: Vec::new(),
            log_sinks: Vec::new(),
            metrics_sinks: Vec::new(),
            secret_providers: Vec::new(),
            secret_scheme_bindings: BTreeMap::new(),
            config_providers: Vec::new(),
            config_scheme_bindings: BTreeMap::new(),
            transports: Vec::new(),
            policy_engines: Vec::new(),
            cluster_backend: None,
            catalog_chain: Vec::new(),
            credential_issuers: BTreeMap::new(),
            approval_notifiers: BTreeMap::new(),
            audit_emit_tool_call_allowed: true,
            audit_emit_tool_call_completed: true,
            granted_caps: HashMap::new(),
            cred_resolve_allowlist: HashMap::new(),
            cred_resolve_ref_allowlist: HashMap::new(),
            resource_resolve_allowlist: HashMap::new(),
        }
    }

    /// Configure whether the registry emits `mcpg.tool.call.allowed`
    /// + `mcpg.tool.call.completed` audit events. The gateway
    ///   surfaces these as `audit.emit_tool_call_allowed` +
    ///   `audit.emit_tool_call_completed` operator config knobs.
    pub fn set_tool_call_audit_emission(&mut self, emit_allowed: bool, emit_completed: bool) {
        self.audit_emit_tool_call_allowed = emit_allowed;
        self.audit_emit_tool_call_completed = emit_completed;
    }

    // -----------------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------------

    /// Register a tool-gate plugin.
    ///
    /// Validates the manifest before accepting. Returns an error if the plugin
    /// declares an incompatible API version or a duplicate alias.
    pub fn register_tool_gate(
        &mut self,
        plugin: Box<dyn ToolGatePlugin>,
        tier: PluginTier,
        config: serde_json::Value,
    ) -> Result<()> {
        self.register_tool_gate_with_enforce(plugin, tier, config, true)
    }

    /// Register a tool-gate plugin with explicit enforce flag.
    pub fn register_tool_gate_with_enforce(
        &mut self,
        plugin: Box<dyn ToolGatePlugin>,
        tier: PluginTier,
        config: serde_json::Value,
        enforce: bool,
    ) -> Result<()> {
        self.register_tool_gate_with_alias(None, plugin, tier, config, enforce)
    }

    /// Variant that accepts the operator alias
    /// explicitly, enabling multi-instance registrations where one
    /// cdylib ships under multiple aliases. `alias = None` falls
    /// back to `manifest.id` (the single-instance default).
    pub fn register_tool_gate_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Box<dyn ToolGatePlugin>,
        tier: PluginTier,
        config: serde_json::Value,
        enforce: bool,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            enforce = enforce,
            "registered tool-gate plugin"
        );
        self.tool_gate_chain.push(LoadedPlugin {
            alias,
            manifest,
            tier,
            config,
            enforce,
            state: AtomicPluginState::new(PluginState::Active),
            registered_at: std::time::SystemTime::now(),
            inflight: Arc::new(InflightTracker::new()),
            instance: plugin,
        });
        Ok(())
    }

    /// Register a transform plugin.
    pub fn register_transform(
        &mut self,
        plugin: Box<dyn TransformPlugin>,
        tier: PluginTier,
        config: serde_json::Value,
    ) -> Result<()> {
        self.register_transform_with_alias(None, plugin, tier, config)
    }

    /// Alias-aware variant. See
    /// [`Self::register_tool_gate_with_alias`].
    pub fn register_transform_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Box<dyn TransformPlugin>,
        tier: PluginTier,
        config: serde_json::Value,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            "registered transform plugin"
        );
        self.transform_chain.push(LoadedPlugin {
            alias,
            manifest,
            tier,
            config,
            enforce: true,
            state: AtomicPluginState::new(PluginState::Active),
            registered_at: std::time::SystemTime::now(),
            inflight: Arc::new(InflightTracker::new()),
            instance: plugin,
        });
        Ok(())
    }

    /// Register an identity plugin.
    pub fn register_identity(
        &mut self,
        plugin: Box<dyn IdentityProviderPlugin>,
        tier: PluginTier,
        config: serde_json::Value,
    ) -> Result<()> {
        self.register_identity_with_alias(None, plugin, tier, config)
    }

    /// Alias-aware variant. See
    /// [`Self::register_tool_gate_with_alias`].
    pub fn register_identity_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Box<dyn IdentityProviderPlugin>,
        tier: PluginTier,
        config: serde_json::Value,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            "registered identity plugin"
        );
        // Wrap in the metering decorator so every identity plugin
        // (this one + the OIDC sibling + the gateway-internal JWT
        // adapter) emits `mcpg_identity_*` metrics. Mirrors the
        // pattern used by every other entity kind's metered
        // wrapper.
        let metered = crate::identity_metering::MeteredIdentityProvider::wrap(plugin);
        self.identity_chain.push(LoadedPlugin {
            alias,
            manifest,
            tier,
            config,
            enforce: true,
            state: AtomicPluginState::new(PluginState::Active),
            registered_at: std::time::SystemTime::now(),
            inflight: Arc::new(InflightTracker::new()),
            instance: metered,
        });
        Ok(())
    }

    /// Register a backend plugin. The plugin is stored under its `kind()`;
    /// only one backend plugin per kind is allowed.
    pub fn register_backend(
        &mut self,
        plugin: Arc<dyn BackendPlugin>,
        tier: PluginTier,
    ) -> Result<()> {
        self.register_backend_with_alias(None, plugin, tier)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id` (legacy single-instance behaviour); pass
    /// `Some(format!("{plugin_id}:{inner_name}"))` to register multiple
    /// backends from one plugin source. Uniqueness is enforced via
    /// `check_duplicate_alias` against the whole registry. The
    /// kind-keyed HashMap still admits at most one backend per
    /// `plugin.kind()` regardless of alias.
    pub fn register_backend_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Arc<dyn BackendPlugin>,
        tier: PluginTier,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        let kind = plugin.kind().to_owned();
        if kind.is_empty() {
            anyhow::bail!("backend plugin '{}' has empty kind", manifest.id);
        }
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        if self.backends.contains_key(&kind) {
            anyhow::bail!(
                "backend plugin kind '{}' already registered (new plugin id: '{}')",
                kind,
                manifest.id,
            );
        }
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            kind = %kind,
            tier = %tier,
            "registered backend plugin"
        );
        self.backends.insert(
            kind,
            LoadedBackendPlugin {
                alias,
                manifest,
                tier,
                state: AtomicPluginState::new(PluginState::Active),
                instance: plugin,
            },
        );
        Ok(())
    }

    /// Register a `content_store` factory plugin. Stored under its
    /// `kind()` ("in_process", "file_system", "s3", …); at most one per
    /// kind. The gateway's storage-registry builder looks these up by the
    /// operator's `storage.providers: [{kind: ...}]` and calls
    /// `build_profile`.
    pub fn register_content_store(
        &mut self,
        plugin: Arc<dyn mcpg_plugin_protocol::content_store::ContentStorePlugin>,
        tier: PluginTier,
    ) -> Result<()> {
        self.register_content_store_with_alias(None, plugin, tier)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id`; pass `Some(format!("{plugin_id}:{inner_name}"))` to
    /// register multiple content_store factories from one plugin source.
    /// Uniqueness is enforced via `check_duplicate_alias`; the kind-keyed
    /// HashMap still admits at most one plugin per `plugin.kind()`.
    pub fn register_content_store_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Arc<dyn mcpg_plugin_protocol::content_store::ContentStorePlugin>,
        tier: PluginTier,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        let kind = plugin.kind().to_owned();
        if kind.is_empty() {
            anyhow::bail!("content_store plugin '{}' has empty kind", manifest.id);
        }
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        if self.content_stores.contains_key(&kind) {
            anyhow::bail!(
                "content_store plugin kind '{}' already registered (new plugin id: '{}')",
                kind,
                manifest.id,
            );
        }
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            kind = %kind,
            tier = %tier,
            "registered content_store plugin"
        );
        self.content_stores.insert(
            kind,
            LoadedContentStorePlugin {
                alias,
                manifest,
                tier,
                state: AtomicPluginState::new(PluginState::Active),
                instance: plugin,
            },
        );
        Ok(())
    }

    /// Look up a `content_store` factory plugin by kind.
    pub fn content_store_plugin(
        &self,
        kind: &str,
    ) -> Option<Arc<dyn mcpg_plugin_protocol::content_store::ContentStorePlugin>> {
        self.content_stores
            .get(kind)
            .filter(|p| p.state.serves_traffic())
            .map(|p| p.instance.clone())
    }

    /// All registered `content_store` factory plugins as `(kind, plugin)`
    /// pairs. The gateway's storage-registry builder merges these
    /// cdylib-loaded factories with the static built-ins before walking
    /// `storage.providers`.
    pub fn content_store_plugins(
        &self,
    ) -> Vec<(
        String,
        Arc<dyn mcpg_plugin_protocol::content_store::ContentStorePlugin>,
    )> {
        self.content_stores
            .iter()
            .filter(|(_, p)| p.state.serves_traffic())
            .map(|(kind, p)| (kind.clone(), p.instance.clone()))
            .collect()
    }

    /// All registered content_store kinds (for diagnostics and startup logs).
    pub fn content_store_kinds(&self) -> Vec<String> {
        self.content_stores.keys().cloned().collect()
    }

    /// Register a watch-strategy plugin. Stored under its `kind()`;
    /// only one per kind is allowed.
    pub fn register_watch_strategy(
        &mut self,
        plugin: Arc<dyn WatchStrategyPlugin>,
        tier: PluginTier,
    ) -> Result<()> {
        self.register_watch_strategy_with_alias(None, plugin, tier)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id` (legacy single-instance behaviour); pass
    /// `Some(format!("{plugin_id}:{inner_name}"))` to register multiple
    /// watch strategies from one plugin source. Uniqueness is enforced
    /// via `check_duplicate_alias` against the whole registry. The
    /// kind-keyed HashMap still admits at most one strategy per
    /// `plugin.kind()` regardless of alias.
    pub fn register_watch_strategy_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Arc<dyn WatchStrategyPlugin>,
        tier: PluginTier,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        let kind = plugin.kind().to_owned();
        if kind.is_empty() {
            anyhow::bail!("watch-strategy plugin '{}' has empty kind", manifest.id);
        }
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        if self.watch_strategies.contains_key(&kind) {
            anyhow::bail!(
                "watch-strategy kind '{}' already registered (new plugin id: '{}')",
                kind,
                manifest.id,
            );
        }
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            kind = %kind,
            tier = %tier,
            "registered watch-strategy plugin"
        );
        self.watch_strategies.insert(
            kind,
            LoadedWatchPlugin {
                alias,
                manifest,
                tier,
                state: AtomicPluginState::new(PluginState::Active),
                instance: plugin,
            },
        );
        Ok(())
    }

    /// Register an `http_route` entity.
    ///
    /// A single plugin id MAY register multiple entities (distinct
    /// `entity_name` per entity); collisions on `(plugin_id,
    /// entity_name)` are refused. Each entity declares one or more
    /// route specs; the host builds a dispatch table over all
    /// registered entities' specs at startup.
    ///
    /// Per spec §9.7, routes mount at
    /// `/plugins/{plugin_id}/{entity_name}/{spec.path}` in the
    /// default namespaced mode. Override mode (claiming a bare path
    /// like `/health`) is not supported; there is no operator
    /// config plumbing for it.
    pub fn register_http_route(
        &mut self,
        entity_name: impl Into<String>,
        plugin: Arc<dyn mcpg_plugin_protocol::http_route::HttpRoute>,
        tier: PluginTier,
    ) -> Result<()> {
        // No-override registration: namespaced mount, so no capability
        // is required and none is threaded.
        self.register_http_route_with_overrides(
            entity_name,
            plugin,
            tier,
            HttpRouteOverrides::default(),
            &[],
        )
    }

    /// Variant of [`Self::register_http_route`] that attaches
    /// operator-provided overrides. Callers that source overrides
    /// from `plugins[*].http_route` in `apps/gateway`
    /// translate each field to [`HttpRouteOverrides`] before
    /// registering; other callers use the default-override entry
    /// point.
    pub fn register_http_route_with_overrides(
        &mut self,
        entity_name: impl Into<String>,
        plugin: Arc<dyn mcpg_plugin_protocol::http_route::HttpRoute>,
        tier: PluginTier,
        overrides: HttpRouteOverrides,
        declared_capabilities: &[mcpg_plugin_protocol::capability::Capability],
    ) -> Result<()> {
        self.register_http_route_with_alias_and_overrides(
            None,
            entity_name,
            plugin,
            tier,
            overrides,
            declared_capabilities,
        )
    }

    /// J.1.4 — alias-aware variant of
    /// [`Self::register_http_route_with_overrides`]. `alias = None`
    /// defaults the registry-level identifier to `entity_name` (which
    /// is already required non-empty); pass
    /// `Some(format!("{plugin_id}:{inner_name}"))` to register multiple
    /// http_route entities from one plugin source under distinct
    /// aliases. Uniqueness is enforced via `check_duplicate_alias`
    /// against the whole registry, in addition to the existing
    /// `(plugin_id, entity_name)` collision check.
    pub fn register_http_route_with_alias_and_overrides(
        &mut self,
        alias: Option<String>,
        entity_name: impl Into<String>,
        plugin: Arc<dyn mcpg_plugin_protocol::http_route::HttpRoute>,
        tier: PluginTier,
        overrides: HttpRouteOverrides,
        declared_capabilities: &[mcpg_plugin_protocol::capability::Capability],
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let entity_name = entity_name.into();
        if entity_name.is_empty() {
            anyhow::bail!(
                "http_route plugin '{}' registered with empty entity_name",
                manifest.id
            );
        }
        let alias = alias.unwrap_or_else(|| entity_name.clone());
        // Only a duplicate (plugin_id, entity_name) pair collides —
        // the same plugin id with different entity names is the
        // multi-entity case from spec §3.1 + §4.3 and is explicitly
        // supported here.
        if self
            .http_routes
            .iter()
            .any(|p| p.manifest.id == manifest.id && p.entity_name == entity_name)
        {
            anyhow::bail!(
                "http_route entity already registered: plugin_id='{}' entity_name='{}'",
                manifest.id,
                entity_name,
            );
        }
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        let routes = plugin.routes();
        if routes.is_empty() {
            anyhow::bail!(
                "http_route plugin '{}' entity '{}' declared no routes",
                manifest.id,
                entity_name
            );
        }
        // Override-mode guardrails. Operator asking for override
        // mode on a plugin that didn't declare the capability is
        // a privilege escalation — the plugin's author never
        // consented to the top-level mount.
        //
        // The gate keys on the AUTHORITATIVE typed capability set
        // (`declared_capabilities`, threaded from the plugin's FFI
        // `PluginRegistration.capabilities` / descriptor) — NOT the
        // manifest's `required_capabilities: Vec<String>`, which is
        // display-only and can drift from the
        // typed set. Override mode requires the plugin declared the
        // typed `Capability::HttpRouteServe`. (A plugin that hasn't
        // been swept simply won't carry it; operators wanting override
        // mode must rebuild the plugin against this protocol version.)
        if overrides.allow_path_override
            && !declared_capabilities.iter().any(|c| {
                matches!(
                    c,
                    mcpg_plugin_protocol::capability::Capability::HttpRouteServe
                )
            })
        {
            anyhow::bail!(
                "http_route plugin '{}' entity '{}' has \
                 allow_path_override: true in operator config but does not \
                 declare the typed `HttpRouteServe` capability — \
                 refuse to promote",
                manifest.id,
                entity_name,
            );
        }
        // Override-mode specs MUST start with `/` — they're
        // absolute paths from the gateway root, not relative to a
        // mount. Also refuse any override path that hits the
        // reserved set (gateway's own endpoints).
        if overrides.allow_path_override {
            for spec in &routes {
                if !spec.path.starts_with('/') {
                    anyhow::bail!(
                        "http_route plugin '{}' entity '{}' override-mode path \
                         '{}' must start with '/'",
                        manifest.id,
                        entity_name,
                        spec.path,
                    );
                }
                if is_reserved_override_path(&spec.path) {
                    anyhow::bail!(
                        "http_route plugin '{}' entity '{}' override-mode path \
                         '{}' collides with a reserved gateway path",
                        manifest.id,
                        entity_name,
                        spec.path,
                    );
                }
            }
        }
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            entity_name = %entity_name,
            route_count = routes.len(),
            tier = %tier,
            max_body_bytes_override = ?overrides.max_body_bytes,
            requires_identity_override = ?overrides.requires_identity,
            allow_path_override = %overrides.allow_path_override,
            "registered http_route plugin"
        );
        self.http_routes.push(LoadedHttpRoutePlugin {
            alias,
            manifest,
            entity_name,
            tier,
            state: AtomicPluginState::new(PluginState::Active),
            routes,
            overrides,
            instance: plugin,
        });
        Ok(())
    }

    /// Operator overrides for an `http_route` entity, if any.
    /// Returns `None` for unregistered `(plugin_id, entity_name)`
    /// pairs; returns a handle to the stored overrides for
    /// registered entities (which may themselves be all-defaults).
    pub fn http_route_overrides(
        &self,
        plugin_id: &str,
        entity_name: &str,
    ) -> Option<&HttpRouteOverrides> {
        self.http_routes
            .iter()
            .find(|p| p.manifest.id == plugin_id && p.entity_name == entity_name)
            .map(|p| &p.overrides)
    }

    /// Look up an `http_route` entity by `(plugin_id, entity_name)`
    /// and return the plugin handle if it's serving traffic.
    /// `None` for unregistered pairs OR for registered entities in
    /// non-serving states (Disabled, Draining, Failed).
    pub fn http_route(
        &self,
        plugin_id: &str,
        entity_name: &str,
    ) -> Option<Arc<dyn mcpg_plugin_protocol::http_route::HttpRoute>> {
        self.http_routes
            .iter()
            .find(|p| p.manifest.id == plugin_id && p.entity_name == entity_name)
            .filter(|p| p.state.serves_traffic())
            .map(|p| Arc::clone(&p.instance))
    }

    /// Every registered `http_route` entity with its declared routes,
    /// for dispatch table construction + admin listing.
    ///
    /// The host builds a `method + path → entity` dispatch structure
    /// from this on startup; refreshing it is not currently supported
    /// (the `http_routes` vec is append-only during the gateway's
    /// lifetime; operator `:disable` flips state but the entry stays).
    pub fn http_route_entries(&self) -> Vec<HttpRouteEntry<'_>> {
        self.http_routes
            .iter()
            .map(|p| HttpRouteEntry {
                plugin_id: p.manifest.id.as_str(),
                entity_name: p.entity_name.as_str(),
                state: p.state.load(),
                routes: &p.routes,
            })
            .collect()
    }

    /// Every `(method, path, plugin_id, entity_name)` tuple the
    /// override-mode dispatcher needs to wire into its axum router.
    ///
    /// Only includes entities whose operator config set
    /// `allow_path_override: true` AND whose plugin manifest
    /// declared `http_route_serve`; that combined
    /// condition is already enforced at registration time, so
    /// every entry returned here is safe to mount at the top
    /// level.
    ///
    /// Callers (the gateway's axum router builder) MUST detect
    /// cross-plugin collisions themselves: two override entries
    /// with the same `(method, path)` pair is a configuration
    /// error that the router should refuse loudly at build time.
    /// This method does not dedup.
    pub fn http_route_override_entries(&self) -> Vec<HttpRouteOverrideEntry<'_>> {
        let mut out = Vec::new();
        for p in &self.http_routes {
            if !p.overrides.allow_path_override {
                continue;
            }
            for spec in &p.routes {
                out.push(HttpRouteOverrideEntry {
                    plugin_id: p.manifest.id.as_str(),
                    entity_name: p.entity_name.as_str(),
                    method: spec.method.as_str(),
                    path: spec.path.as_str(),
                });
            }
        }
        out
    }

    /// Look up a backend plugin by kind ("nats", "kafka", …).
    pub fn backend(&self, kind: &str) -> Option<Arc<dyn BackendPlugin>> {
        self.backends
            .get(kind)
            .filter(|p| p.state.serves_traffic())
            .map(|p| p.instance.clone())
    }

    /// Look up a single transform plugin by its alias/id, bypassing the
    /// global pre/post chain. Used by the pipeline `plugin_transform` step
    /// to invoke one named transform on the step input. Borrows
    /// the registry (the chain stores `Box`, not `Arc`).
    pub fn transform_by_id(&self, id: &str) -> Option<&dyn TransformPlugin> {
        self.transform_chain
            .iter()
            .find(|p| p.alias == id && p.state.serves_traffic())
            .map(|p| p.instance.as_ref())
    }

    /// Look up a watch-strategy plugin by kind ("nats_topic", "kafka_topic", …).
    pub fn watch_strategy(&self, kind: &str) -> Option<Arc<dyn WatchStrategyPlugin>> {
        self.watch_strategies
            .get(kind)
            .filter(|p| p.state.serves_traffic())
            .map(|p| p.instance.clone())
    }

    /// All registered backend kinds (for diagnostics and startup logs).
    pub fn backend_kinds(&self) -> Vec<String> {
        self.backends.keys().cloned().collect()
    }

    /// The host-services bridge alias (the `entry.id` the per-call
    /// allowlists are keyed under) for the backend plugin registered
    /// under `kind`, or `None` if no backend serves that kind. Used by
    /// the binding register pass to extend a backend's config-origin
    /// `cred://`/resource allowlist with the refs in its per-binding
    /// spec.
    pub fn backend_alias(&self, kind: &str) -> Option<&str> {
        self.backends.get(kind).map(|p| p.alias.as_str())
    }

    /// The manifest-declared [`BackendProfile`] for the backend plugin
    /// registered under `kind`, cloned out of the stored manifest. The
    /// generic dispatch path reads this back by kind to drive the residual
    /// per-kind facts (health probe, type label, dynamic-list capability,
    /// pipeline eligibility, transport-only field policy). `None` when no
    /// backend serves that kind OR the plugin declared no profile —
    /// callers treat `None` as "fall back to the behaviour-neutral
    /// defaults", which reproduces today's hardcoded behaviour.
    pub fn backend_profile(
        &self,
        kind: &str,
    ) -> Option<mcpg_plugin_protocol::manifest::BackendProfile> {
        self.backends
            .get(kind)
            .and_then(|p| p.manifest.backend_profile.clone())
    }

    /// All registered watch-strategy kinds.
    pub fn watch_strategy_kinds(&self) -> Vec<String> {
        self.watch_strategies.keys().cloned().collect()
    }

    /// Register an `audit_sink` entity for fan-out. Per spec §9.12,
    /// every registered sink receives every audit event. Collision
    /// on `plugin_id` is refused so a misconfigured operator can't
    /// accidentally double-count events.
    pub fn register_audit_sink(
        &mut self,
        plugin: Arc<dyn mcpg_plugin_protocol::audit::AuditSink>,
        tier: PluginTier,
    ) -> Result<()> {
        self.register_audit_sink_with_alias(None, plugin, tier)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id` (legacy single-instance behaviour); pass
    /// `Some(format!("{plugin_id}:{inner_name}"))` to register multiple
    /// audit_sinks from one plugin source. Uniqueness is enforced via
    /// `check_duplicate_alias` against the whole registry.
    pub fn register_audit_sink_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Arc<dyn mcpg_plugin_protocol::audit::AuditSink>,
        tier: PluginTier,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            "registered audit_sink plugin"
        );
        self.audit_sinks.push(LoadedAuditSinkPlugin {
            alias,
            manifest,
            tier,
            state: AtomicPluginState::new(PluginState::Active),
            instance: plugin,
        });
        Ok(())
    }

    /// Every registered audit sink's plugin id, in registration
    /// order. Used by admin surfaces + the startup-required-sink
    /// check.
    pub fn audit_sink_ids(&self) -> Vec<String> {
        self.audit_sinks
            .iter()
            .map(|p| p.manifest.id.clone())
            .collect()
    }

    /// Whether any audit sink is currently serving traffic. The
    /// `governance.audit.required: true` startup check consults this;
    /// operators can register a sink but disable it post-boot.
    pub fn has_serving_audit_sink(&self) -> bool {
        self.audit_sinks.iter().any(|p| p.state.serves_traffic())
    }

    /// Emit `event` to every registered sink that is currently
    /// serving traffic. Fan-out is sequential in registration order;
    /// one slow sink blocks the others but bounded-latency is the
    /// operator's responsibility per spec §9.12.
    ///
    /// Returns one [`AuditEmitResult`] per sink. Disabled / draining
    /// / failed sinks are skipped and do NOT appear in the result
    /// vector — consumers that want full coverage including
    /// skipped sinks call [`Self::audit_sink_ids`] and diff.
    ///
    /// Emit metrics are recorded per-sink regardless of outcome:
    /// `mcpg_audit_events_emitted_total{sink_id, outcome}` on
    /// success, `mcpg_audit_sink_failures_total{sink_id, kind}` on
    /// failure, plus `mcpg_audit_sink_latency_seconds{sink_id}`
    /// sampled for every attempt.
    pub async fn emit_audit_event(
        &self,
        event: &mcpg_plugin_protocol::audit::AuditEvent,
    ) -> Vec<AuditEmitResult> {
        let mut out = Vec::with_capacity(self.audit_sinks.len());
        for sink in &self.audit_sinks {
            if !sink.state.serves_traffic() {
                continue;
            }
            let sink_id = sink.manifest.id.clone();
            let start = Instant::now();
            let result = sink.instance.emit(event).await;
            let elapsed = start.elapsed();
            match &result {
                Ok(_) => {
                    metrics::counter!(
                        "mcpg_audit_events_emitted_total",
                        "sink_id" => sink_id.clone(),
                        "outcome" => event.outcome.to_string(),
                    )
                    .increment(1);
                }
                Err(e) => {
                    metrics::counter!(
                        "mcpg_audit_sink_failures_total",
                        "sink_id" => sink_id.clone(),
                        "kind" => e.kind_label(),
                    )
                    .increment(1);
                    warn!(
                        plugin_id = %sink_id,
                        error = %e,
                        "audit sink emit failed"
                    );
                }
            }
            metrics::histogram!(
                "mcpg_audit_sink_latency_seconds",
                "sink_id" => sink_id.clone(),
            )
            .record(elapsed.as_secs_f64());
            out.push(AuditEmitResult { sink_id, result });
        }
        out
    }

    /// Emit + enforce the operator's on-failure policy. Wraps
    /// [`Self::emit_audit_event`] with policy-aware return
    /// handling. Callers that care about SOC2 compliance call
    /// THIS instead of the raw emit — admin endpoints, gateway
    /// startup, tool-call audit emission.
    ///
    /// Behaviour:
    ///   - `FailOpen` always returns `Ok(results)`; failed sinks
    ///     are observable via `results.iter().any(Err)`.
    ///   - `FailClosed` returns `Ok(results)` only when every
    ///     sink succeeded; returns `Err(AuditEnforcementFailure)`
    ///     the moment any sink fails.
    ///
    /// The zero-sink case (no sinks registered — the
    /// `required: true` + zero-sinks combination is already
    /// refused at startup) returns `Ok(vec![])` regardless of
    /// policy: no sinks means no failures.
    pub async fn emit_audit_event_enforced(
        &self,
        event: &mcpg_plugin_protocol::audit::AuditEvent,
        policy: AuditEmitPolicy,
    ) -> Result<Vec<AuditEmitResult>, AuditEnforcementFailure> {
        let results = self.emit_audit_event(event).await;
        let any_failed = results.iter().any(|r| r.result.is_err());
        match policy {
            AuditEmitPolicy::FailOpen => Ok(results),
            AuditEmitPolicy::FailClosed if any_failed => Err(AuditEnforcementFailure { results }),
            AuditEmitPolicy::FailClosed => Ok(results),
        }
    }

    /// Flush every registered audit sink. Called at gateway
    /// shutdown (from `shutdown_all`) and optionally by admin on
    /// demand. Per-sink failures are logged but do not short-circuit
    /// the iteration.
    pub async fn flush_audit_sinks(&self, timeout_ms: u64) {
        for sink in &self.audit_sinks {
            if !sink.state.serves_traffic() {
                continue;
            }
            if let Err(e) = sink.instance.flush(timeout_ms).await {
                warn!(
                    plugin_id = %sink.manifest.id,
                    error = %e,
                    "audit sink flush failed"
                );
            }
        }
    }

    /// Register a `store` plugin (spec §9.8). The plugin joins the
    /// `stores` list; role binding is a separate step via
    /// [`Self::bind_store_role`] so operator config decides which
    /// plugin serves each role.
    ///
    /// Collision on plugin_id is refused — two plugins sharing an
    /// id would confuse the registrar's descriptor cross-check.
    pub fn register_store(
        &mut self,
        plugin: Arc<dyn mcpg_plugin_protocol::store::Store>,
        tier: PluginTier,
    ) -> Result<()> {
        self.register_store_with_alias(None, plugin, tier)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id` (legacy single-instance behaviour); pass
    /// `Some(format!("{plugin_id}:{inner_name}"))` to register multiple
    /// stores from one plugin source. Uniqueness is enforced via
    /// `check_duplicate_alias` against the whole registry.
    pub fn register_store_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Arc<dyn mcpg_plugin_protocol::store::Store>,
        tier: PluginTier,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        let supported_roles = plugin.supported_roles();
        if supported_roles.is_empty() {
            anyhow::bail!(
                "store plugin '{}' declared supported_roles() = [] — \
                 registration is vacuous; the plugin is unreachable",
                manifest.id
            );
        }
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            supported_roles = ?supported_roles.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "registered store plugin"
        );
        self.stores.push(LoadedStorePlugin {
            alias,
            manifest,
            tier,
            state: AtomicPluginState::new(PluginState::Active),
            supported_roles,
            instance: plugin,
        });
        Ok(())
    }

    /// Bind `role` to the registered store plugin with `plugin_id`.
    /// Refuses when the plugin isn't registered, doesn't advertise
    /// the role, or is in a non-serving state. Replaces any prior
    /// binding silently — operators can re-point a role at a
    /// different plugin.
    pub fn bind_store_role(
        &mut self,
        role: mcpg_plugin_protocol::store::StoreRole,
        plugin_id: &str,
    ) -> Result<()> {
        let Some(plugin) = self.stores.iter().find(|p| p.manifest.id == plugin_id) else {
            anyhow::bail!("store binding failed: plugin_id '{plugin_id}' is not registered");
        };
        if !plugin.state.serves_traffic() {
            anyhow::bail!(
                "store binding failed: plugin_id '{plugin_id}' is not serving traffic \
                 (state = {})",
                plugin.state.load()
            );
        }
        if !plugin.supported_roles.contains(&role) {
            anyhow::bail!(
                "store binding failed: plugin_id '{plugin_id}' does not support role \
                 '{}'; supported roles: {:?}",
                role,
                plugin
                    .supported_roles
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            );
        }
        info!(
            plugin_id = %plugin_id,
            role = %role,
            "bound store role"
        );
        // Wrap in the metering decorator so every op on the
        // binding surface emits `mcpg_store_ops_total` /
        // `mcpg_store_op_latency_seconds` / `mcpg_store_errors_
        // total` transparently. Callers on the hot path see only
        // `Arc<dyn Store>`.
        let metered = crate::store_metering::MeteredStore::wrap(Arc::clone(&plugin.instance));
        self.store_bindings.insert(role, metered);
        Ok(())
    }

    /// Look up the store plugin bound to `role`, or `None` if no
    /// plugin is bound. Callers on the hot path go through this
    /// instead of iterating `stores`.
    pub fn store_for_role(
        &self,
        role: &mcpg_plugin_protocol::store::StoreRole,
    ) -> Option<Arc<dyn mcpg_plugin_protocol::store::Store>> {
        self.store_bindings.get(role).cloned()
    }

    /// Every role currently bound to a store plugin. Order is by
    /// role Display (alphabetical under `BTreeMap`).
    pub fn bound_store_roles(&self) -> Vec<(mcpg_plugin_protocol::store::StoreRole, String)> {
        self.store_bindings
            .iter()
            .map(|(role, plugin)| (role.clone(), plugin.manifest().id.clone()))
            .collect()
    }

    /// Ids of every registered store plugin, in registration order.
    pub fn store_plugin_ids(&self) -> Vec<String> {
        self.stores.iter().map(|p| p.manifest.id.clone()).collect()
    }

    /// Look up a store plugin by its manifest id. Used by the
    /// gateway's per-capability `kind: <plugin-id>` override path,
    /// where the operator names a specific
    /// plugin to back a configuration's KV state. Returns the
    /// raw `Store` (not metered — capability adapters wrap their
    /// own metrics layer if needed).
    pub fn store_by_id(
        &self,
        plugin_id: &str,
    ) -> Option<Arc<dyn mcpg_plugin_protocol::store::Store>> {
        self.stores
            .iter()
            .find(|p| p.manifest.id == plugin_id)
            .map(|p| Arc::clone(&p.instance))
    }

    /// Register a `cache` plugin (spec §9.9). Two-step dispatch —
    /// the plugin joins the `caches` list; per-namespace binding
    /// is a separate step via [`Self::bind_cache_namespace`].
    /// Collision on plugin_id is refused.
    pub fn register_cache(
        &mut self,
        plugin: Arc<dyn mcpg_plugin_protocol::cache::Cache>,
        tier: PluginTier,
    ) -> Result<()> {
        self.register_cache_with_alias(None, plugin, tier)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id` (legacy single-instance behaviour); pass
    /// `Some(format!("{plugin_id}:{inner_name}"))` to register multiple
    /// caches from one plugin source. Uniqueness is enforced via
    /// `check_duplicate_alias` against the whole registry.
    pub fn register_cache_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Arc<dyn mcpg_plugin_protocol::cache::Cache>,
        tier: PluginTier,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        let supported_namespaces = plugin.supported_namespaces();
        let serves_any = plugin.serves_any_namespace();
        if supported_namespaces.is_empty() && !serves_any {
            anyhow::bail!(
                "cache plugin '{}' declared no supported_namespaces() AND \
                 serves_any_namespace() = false — the plugin is unreachable",
                manifest.id
            );
        }
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            supported_namespaces = ?supported_namespaces,
            serves_any = serves_any,
            "registered cache plugin"
        );
        self.caches.push(LoadedCachePlugin {
            alias,
            manifest,
            tier,
            state: AtomicPluginState::new(PluginState::Active),
            supported_namespaces,
            serves_any,
            instance: plugin,
        });
        Ok(())
    }

    /// Bind `namespace` to the registered cache plugin with
    /// `plugin_id`. Refuses when the plugin isn't registered,
    /// doesn't advertise the namespace (or `serves_any_namespace()
    /// = true`), or is in a non-serving state. Replaces any prior
    /// binding silently.
    pub fn bind_cache_namespace(
        &mut self,
        namespace: impl Into<String>,
        plugin_id: &str,
    ) -> Result<()> {
        let namespace = namespace.into();
        let Some(plugin) = self.caches.iter().find(|p| p.manifest.id == plugin_id) else {
            anyhow::bail!("cache binding failed: plugin_id '{plugin_id}' is not registered");
        };
        if !plugin.state.serves_traffic() {
            anyhow::bail!(
                "cache binding failed: plugin_id '{plugin_id}' is not serving \
                 traffic (state = {})",
                plugin.state.load()
            );
        }
        if !plugin.serves_any && !plugin.supported_namespaces.contains(&namespace) {
            anyhow::bail!(
                "cache binding failed: plugin_id '{plugin_id}' does not support \
                 namespace '{namespace}'; supported: {:?}",
                plugin.supported_namespaces
            );
        }
        info!(
            plugin_id = %plugin_id,
            namespace = %namespace,
            "bound cache namespace"
        );
        // Wrap in the metering decorator so every op on the
        // binding surface emits `mcpg_cache_ops_total` /
        // `mcpg_cache_op_latency_seconds` /
        // `mcpg_cache_errors_total` transparently. Namespace label
        // is baked in at wrap time — the caller already knows it.
        let metered = crate::cache_metering::MeteredCache::wrap(
            namespace.clone(),
            Arc::clone(&plugin.instance),
        );
        self.cache_bindings.insert(namespace, metered);
        Ok(())
    }

    /// Look up the cache plugin bound to `namespace`, or `None` if
    /// no plugin is bound.
    pub fn cache_for_namespace(
        &self,
        namespace: &str,
    ) -> Option<Arc<dyn mcpg_plugin_protocol::cache::Cache>> {
        self.cache_bindings.get(namespace).cloned()
    }

    /// Every namespace → plugin_id binding currently active.
    pub fn bound_cache_namespaces(&self) -> Vec<(String, String)> {
        self.cache_bindings
            .iter()
            .map(|(ns, plugin)| (ns.clone(), plugin.manifest().id.clone()))
            .collect()
    }

    /// Ids of every registered cache plugin, in registration order.
    pub fn cache_plugin_ids(&self) -> Vec<String> {
        self.caches.iter().map(|p| p.manifest.id.clone()).collect()
    }

    /// Register a `telemetry_sink` plugin (spec §9.10). Fan-out —
    /// every registered sink receives every event emitted. Refuses
    /// duplicate plugin ids so a misconfigured operator can't
    /// double-send metrics to a downstream backend.
    pub fn register_telemetry_sink(
        &mut self,
        plugin: Arc<dyn mcpg_plugin_protocol::telemetry::TelemetrySink>,
        tier: PluginTier,
    ) -> Result<()> {
        self.register_telemetry_sink_with_alias(None, plugin, tier)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id` (legacy single-instance behaviour); pass
    /// `Some(format!("{plugin_id}:{inner_name}"))` to register multiple
    /// telemetry_sinks from one plugin source. Uniqueness is enforced
    /// via `check_duplicate_alias` against the whole registry.
    pub fn register_telemetry_sink_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Arc<dyn mcpg_plugin_protocol::telemetry::TelemetrySink>,
        tier: PluginTier,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            "registered telemetry_sink plugin"
        );
        self.telemetry_sinks.push(LoadedTelemetrySinkPlugin {
            alias,
            manifest,
            tier,
            state: AtomicPluginState::new(PluginState::Active),
            instance: plugin,
        });
        Ok(())
    }

    /// Every registered telemetry-sink's plugin id, in registration
    /// order. Used by admin surfaces + operator-config sanity logs.
    pub fn telemetry_sink_ids(&self) -> Vec<String> {
        self.telemetry_sinks
            .iter()
            .map(|p| p.manifest.id.clone())
            .collect()
    }

    /// Fan `span` out to every telemetry sink that is currently
    /// serving traffic. Sequential in registration order; one slow
    /// sink blocks the others but telemetry is not hot-path-
    /// critical (§9.10 "sinks MUST NOT block the request path" is
    /// enforced by the caller's own queue, not by this method).
    pub async fn emit_telemetry_span_started(
        &self,
        span: &mcpg_plugin_protocol::telemetry::SpanStart,
    ) {
        for sink in &self.telemetry_sinks {
            if !sink.state.serves_traffic() {
                continue;
            }
            let start = Instant::now();
            sink.instance.span_started(span.clone()).await;
            record_telemetry_dispatch(&sink.manifest.id, "span_started", start.elapsed());
        }
    }

    /// Fan `span` out to telemetry sinks whose `manifest.id` appears
    /// in `allowed_plugin_ids`. Mirrors [`Self::emit_telemetry_span_started`]
    /// but lets operators gate fan-out via
    /// `observability.traces.sinks[].kind`. The telemetry bridge
    /// uses this variant; direct admin / test paths use the
    /// unfiltered version.
    pub async fn emit_telemetry_span_started_filtered(
        &self,
        span: &mcpg_plugin_protocol::telemetry::SpanStart,
        allowed_plugin_ids: &std::collections::HashSet<String>,
    ) {
        for sink in &self.telemetry_sinks {
            if !sink.state.serves_traffic() {
                continue;
            }
            if !allowed_plugin_ids.contains(&sink.manifest.id) {
                continue;
            }
            let start = Instant::now();
            sink.instance.span_started(span.clone()).await;
            record_telemetry_dispatch(&sink.manifest.id, "span_started", start.elapsed());
        }
    }

    /// Fan `span` out to every telemetry sink that is currently
    /// serving traffic.
    pub async fn emit_telemetry_span_ended(&self, span: &mcpg_plugin_protocol::telemetry::SpanEnd) {
        for sink in &self.telemetry_sinks {
            if !sink.state.serves_traffic() {
                continue;
            }
            let start = Instant::now();
            sink.instance.span_ended(span.clone()).await;
            record_telemetry_dispatch(&sink.manifest.id, "span_ended", start.elapsed());
        }
    }

    /// Filtered counterpart of [`Self::emit_telemetry_span_ended`].
    pub async fn emit_telemetry_span_ended_filtered(
        &self,
        span: &mcpg_plugin_protocol::telemetry::SpanEnd,
        allowed_plugin_ids: &std::collections::HashSet<String>,
    ) {
        for sink in &self.telemetry_sinks {
            if !sink.state.serves_traffic() {
                continue;
            }
            if !allowed_plugin_ids.contains(&sink.manifest.id) {
                continue;
            }
            let start = Instant::now();
            sink.instance.span_ended(span.clone()).await;
            record_telemetry_dispatch(&sink.manifest.id, "span_ended", start.elapsed());
        }
    }

    /// Fan `metric` out to every telemetry sink that is currently
    /// serving traffic.
    pub async fn emit_telemetry_metric(
        &self,
        metric: &mcpg_plugin_protocol::telemetry::MetricPoint,
    ) {
        for sink in &self.telemetry_sinks {
            if !sink.state.serves_traffic() {
                continue;
            }
            let start = Instant::now();
            sink.instance.metric_recorded(metric.clone()).await;
            record_telemetry_dispatch(&sink.manifest.id, "metric_recorded", start.elapsed());
        }
    }

    /// Filtered counterpart of [`Self::emit_telemetry_metric`].
    pub async fn emit_telemetry_metric_filtered(
        &self,
        metric: &mcpg_plugin_protocol::telemetry::MetricPoint,
        allowed_plugin_ids: &std::collections::HashSet<String>,
    ) {
        for sink in &self.telemetry_sinks {
            if !sink.state.serves_traffic() {
                continue;
            }
            if !allowed_plugin_ids.contains(&sink.manifest.id) {
                continue;
            }
            let start = Instant::now();
            sink.instance.metric_recorded(metric.clone()).await;
            record_telemetry_dispatch(&sink.manifest.id, "metric_recorded", start.elapsed());
        }
    }

    /// Flush every telemetry sink. Called at gateway shutdown +
    /// on admin demand. Per-sink failures are logged but don't
    /// short-circuit iteration.
    pub async fn flush_telemetry_sinks(&self, timeout: std::time::Duration) {
        for sink in &self.telemetry_sinks {
            if !sink.state.serves_traffic() {
                continue;
            }
            if let Err(e) = sink.instance.flush(timeout).await {
                metrics::counter!(
                    "mcpg_telemetry_sink_failures_total",
                    "sink_id" => sink.manifest.id.clone(),
                    "kind" => e.kind_label(),
                )
                .increment(1);
                warn!(
                    plugin_id = %sink.manifest.id,
                    error = %e,
                    "telemetry sink flush failed"
                );
            }
        }
    }

    /// Register a `log_sink` plugin (spec §9.11). Fan-out — every
    /// registered sink receives every `emit` call. Refuses
    /// duplicate plugin ids.
    pub fn register_log_sink(
        &mut self,
        plugin: Arc<dyn mcpg_plugin_protocol::logs::LogSink>,
        tier: PluginTier,
    ) -> Result<()> {
        self.register_log_sink_with_alias(None, plugin, tier)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id` (legacy single-instance behaviour); pass
    /// `Some(format!("{plugin_id}:{inner_name}"))` to register multiple
    /// log_sinks from one plugin source. Uniqueness is enforced via
    /// `check_duplicate_alias` against the whole registry.
    pub fn register_log_sink_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Arc<dyn mcpg_plugin_protocol::logs::LogSink>,
        tier: PluginTier,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            "registered log_sink plugin"
        );
        self.log_sinks.push(LoadedLogSinkPlugin {
            alias,
            manifest,
            tier,
            state: AtomicPluginState::new(PluginState::Active),
            instance: plugin,
        });
        Ok(())
    }

    /// Every registered log-sink's plugin id, in registration order.
    pub fn log_sink_ids(&self) -> Vec<String> {
        self.log_sinks
            .iter()
            .map(|p| p.manifest.id.clone())
            .collect()
    }

    /// Fan `record` out to every log sink that is currently
    /// serving traffic. Sequential — log sinks are expected to
    /// return immediately after queueing, so serial fanout doesn't
    /// cost anything in practice.
    pub async fn emit_log_record(&self, record: &mcpg_plugin_protocol::logs::LogRecord) {
        for sink in &self.log_sinks {
            if !sink.state.serves_traffic() {
                continue;
            }
            let start = Instant::now();
            sink.instance.emit(record).await;
            record_log_dispatch(&sink.manifest.id, start.elapsed());
        }
    }

    /// Fan `record` out to log sinks whose `manifest.id` appears in
    /// `allowed_plugin_ids`. Mirrors [`Self::emit_log_record`] but
    /// lets operators gate fan-out via
    /// `observability.logs.sinks[].kind`. The log bridge uses
    /// this variant; direct admin / test paths use the unfiltered
    /// version.
    pub async fn emit_log_record_filtered(
        &self,
        record: &mcpg_plugin_protocol::logs::LogRecord,
        allowed_plugin_ids: &std::collections::HashSet<String>,
    ) {
        for sink in &self.log_sinks {
            if !sink.state.serves_traffic() {
                continue;
            }
            if !allowed_plugin_ids.contains(&sink.manifest.id) {
                continue;
            }
            let start = Instant::now();
            sink.instance.emit(record).await;
            record_log_dispatch(&sink.manifest.id, start.elapsed());
        }
    }

    /// Flush every log sink. Called at gateway shutdown.
    pub async fn flush_log_sinks(&self, timeout: std::time::Duration) {
        for sink in &self.log_sinks {
            if !sink.state.serves_traffic() {
                continue;
            }
            if let Err(e) = sink.instance.flush(timeout).await {
                metrics::counter!(
                    "mcpg_log_sink_failures_total",
                    "sink_id" => sink.manifest.id.clone(),
                    "kind" => e.kind_label(),
                )
                .increment(1);
                warn!(
                    plugin_id = %sink.manifest.id,
                    error = %e,
                    "log sink flush failed"
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // metrics_sink
    // -----------------------------------------------------------------

    /// Register a `metrics_sink` plugin. Fan-out — every registered
    /// sink receives every `emit_metric_event` call. Refuses
    /// duplicate plugin ids.
    pub fn register_metrics_sink(
        &mut self,
        plugin: Arc<dyn mcpg_plugin_protocol::metrics::MetricsSink>,
        tier: PluginTier,
    ) -> Result<()> {
        self.register_metrics_sink_with_alias(None, plugin, tier)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id` (legacy single-instance behaviour); pass
    /// `Some(format!("{plugin_id}:{inner_name}"))` to register multiple
    /// metrics_sinks from one plugin source. Uniqueness is enforced
    /// via `check_duplicate_alias` against the whole registry.
    pub fn register_metrics_sink_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Arc<dyn mcpg_plugin_protocol::metrics::MetricsSink>,
        tier: PluginTier,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            "registered metrics_sink plugin"
        );
        self.metrics_sinks.push(LoadedMetricsSinkPlugin {
            alias,
            manifest,
            tier,
            state: AtomicPluginState::new(PluginState::Active),
            instance: plugin,
        });
        Ok(())
    }

    /// Every registered metrics-sink's plugin id, in registration order.
    pub fn metrics_sink_ids(&self) -> Vec<String> {
        self.metrics_sinks
            .iter()
            .map(|p| p.manifest.id.clone())
            .collect()
    }

    /// Fan `metric` out to every metrics sink that is currently
    /// serving traffic. Sequential — sinks are expected to return
    /// immediately after queueing.
    pub async fn emit_metric_event(&self, metric: &mcpg_plugin_protocol::metrics::MetricPoint) {
        for sink in &self.metrics_sinks {
            if !sink.state.serves_traffic() {
                continue;
            }
            let start = Instant::now();
            sink.instance.emit(metric).await;
            record_metrics_dispatch(&sink.manifest.id, start.elapsed());
        }
    }

    /// Fan `metric` out to metrics sinks whose `manifest.id`
    /// appears in `allowed_plugin_ids`. Mirrors
    /// [`Self::emit_metric_event`] but lets operators gate fan-out
    /// via `observability.metrics.sinks[].kind`. The metrics
    /// bridge uses this variant; direct admin / test paths use the
    /// unfiltered version.
    pub async fn emit_metric_event_filtered(
        &self,
        metric: &mcpg_plugin_protocol::metrics::MetricPoint,
        allowed_plugin_ids: &std::collections::HashSet<String>,
    ) {
        for sink in &self.metrics_sinks {
            if !sink.state.serves_traffic() {
                continue;
            }
            if !allowed_plugin_ids.contains(&sink.manifest.id) {
                continue;
            }
            let start = Instant::now();
            sink.instance.emit(metric).await;
            record_metrics_dispatch(&sink.manifest.id, start.elapsed());
        }
    }

    /// Pull a textual snapshot from one metrics-sink plugin by id.
    /// Backs the gateway's `/metrics` route — the
    /// route looks up the plugin id matching the operator's
    /// `observability.metrics.sinks[].kind` and renders directly
    /// from the plugin's accumulator (Prometheus exposition for the
    /// canonical Prometheus plugin). Returns `None` when no plugin
    /// of that id is registered, the plugin is currently not
    /// serving traffic, or the plugin is push-only (default trait
    /// impl returns `None`).
    pub async fn metrics_sink_render_text_exposition(&self, plugin_id: &str) -> Option<String> {
        let sink = self
            .metrics_sinks
            .iter()
            .find(|s| s.manifest.id == plugin_id)?;
        if !sink.state.serves_traffic() {
            return None;
        }
        sink.instance.render_text_exposition().await
    }

    /// Flush every metrics sink. Called at gateway shutdown +
    /// on admin demand. Per-sink failures are logged but don't
    /// short-circuit iteration.
    pub async fn flush_metrics_sinks(&self, timeout: std::time::Duration) {
        for sink in &self.metrics_sinks {
            if !sink.state.serves_traffic() {
                continue;
            }
            if let Err(e) = sink.instance.flush(timeout).await {
                metrics::counter!(
                    "mcpg_metrics_sink_failures_total",
                    "sink_id" => sink.manifest.id.clone(),
                    "kind" => e.kind_label(),
                )
                .increment(1);
                warn!(
                    plugin_id = %sink.manifest.id,
                    error = %e,
                    "metrics sink flush failed"
                );
            }
        }
    }

    /// Register a `secret_provider` plugin (spec §9.15). Two-step
    /// dispatch — the plugin joins the `secret_providers` list,
    /// per-scheme binding is a separate step via
    /// [`Self::bind_secret_scheme`]. Collision on plugin id is
    /// refused.
    pub fn register_secret_provider(
        &mut self,
        plugin: Arc<dyn mcpg_plugin_protocol::secret::SecretProvider>,
        tier: PluginTier,
    ) -> Result<()> {
        self.register_secret_provider_with_alias(None, plugin, tier)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id` (legacy single-instance behaviour); pass
    /// `Some(format!("{plugin_id}:{inner_name}"))` to register multiple
    /// secret_providers from one plugin source. Uniqueness is enforced
    /// via `check_duplicate_alias` against the whole registry, in
    /// addition to the existing per-plugin-id collision check.
    pub fn register_secret_provider_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Arc<dyn mcpg_plugin_protocol::secret::SecretProvider>,
        tier: PluginTier,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        if self
            .secret_providers
            .iter()
            .any(|p| p.manifest.id == manifest.id)
        {
            anyhow::bail!(
                "secret_provider plugin '{}' is already registered",
                manifest.id
            );
        }
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        let supported_schemes = plugin.supported_schemes();
        if supported_schemes.is_empty() {
            anyhow::bail!(
                "secret_provider plugin '{}' declared no supported_schemes() \
                 — the plugin is unreachable",
                manifest.id
            );
        }
        cross_check_provides_schemes(
            "secret_provider",
            &manifest.id,
            &manifest.provides_schemes,
            &supported_schemes,
        )?;
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            supported_schemes = ?supported_schemes,
            "registered secret_provider plugin"
        );
        self.secret_providers.push(LoadedSecretProviderPlugin {
            alias,
            manifest,
            tier,
            state: AtomicPluginState::new(PluginState::Active),
            supported_schemes,
            instance: plugin,
        });
        Ok(())
    }

    /// Bind `scheme` to the registered secret-provider plugin
    /// with `plugin_id`. Refuses unknown plugin / non-serving
    /// state / unsupported-scheme mismatch. Replaces any prior
    /// binding silently — operator re-pointing is a feature.
    pub fn bind_secret_scheme(&mut self, scheme: impl Into<String>, plugin_id: &str) -> Result<()> {
        let scheme = scheme.into();
        // Reserved-scheme invariant enforced at the binding chokepoint: env://
        // and file:// may only be served by the gateway's built-in resolvers,
        // regardless of which path reaches this bind.
        reject_reserved_scheme("secret_provider", &scheme, plugin_id)?;
        let Some(plugin) = self
            .secret_providers
            .iter()
            .find(|p| p.manifest.id == plugin_id)
        else {
            anyhow::bail!(
                "secret_provider binding failed: plugin_id '{plugin_id}' \
                 is not registered"
            );
        };
        if !plugin.state.serves_traffic() {
            anyhow::bail!(
                "secret_provider binding failed: plugin_id '{plugin_id}' \
                 is not serving traffic (state = {})",
                plugin.state.load()
            );
        }
        if !plugin.supported_schemes.contains(&scheme) {
            anyhow::bail!(
                "secret_provider binding failed: plugin_id '{plugin_id}' \
                 does not support scheme '{scheme}'; supported: {:?}",
                plugin.supported_schemes
            );
        }
        info!(
            plugin_id = %plugin_id,
            scheme = %scheme,
            "bound secret scheme"
        );
        // Wrap in the metering decorator — callers on the lookup
        // path see a transparent `Arc<dyn SecretProvider>`.
        let metered = crate::secret_metering::MeteredSecretProvider::wrap(
            scheme.clone(),
            Arc::clone(&plugin.instance),
        );
        self.secret_scheme_bindings.insert(scheme, metered);
        Ok(())
    }

    /// Look up the secret-provider plugin bound to `scheme`.
    /// `None` if no provider is bound.
    pub fn secret_provider_for_scheme(
        &self,
        scheme: &str,
    ) -> Option<Arc<dyn mcpg_plugin_protocol::secret::SecretProvider>> {
        self.secret_scheme_bindings.get(scheme).cloned()
    }

    /// Every `(scheme, plugin_id)` currently bound.
    pub fn bound_secret_schemes(&self) -> Vec<(String, String)> {
        self.secret_scheme_bindings
            .iter()
            .map(|(s, p)| (s.clone(), p.manifest().id.clone()))
            .collect()
    }

    /// Ids of every registered secret-provider plugin.
    pub fn secret_provider_ids(&self) -> Vec<String> {
        self.secret_providers
            .iter()
            .map(|p| p.manifest.id.clone())
            .collect()
    }

    /// Auto-bind every scheme advertised by every registered
    /// secret-provider plugin to its owning plugin.
    ///
    /// The current model replaces the old `plugin_bindings.secrets` map
    /// with point-of-use scheme ownership: a plugin's
    /// [`SecretProvider::supported_schemes`] is the source of
    /// truth, the registry's binding map is just a dispatch cache.
    /// This method walks every registered provider once and binds
    /// each `(scheme, plugin_id)` pair via
    /// [`Self::bind_secret_scheme`].
    ///
    /// Refuses boot if two plugins both claim the same scheme —
    /// the operator must pick one or rename. Skips schemes that
    /// are already bound (e.g. built-in `env://` from the gateway
    /// pre-binding step) so callers can wire built-ins first and
    /// auto-bind third-party plugins second.
    pub fn auto_bind_secret_provider_schemes(&mut self) -> Result<()> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        for plugin in &self.secret_providers {
            for scheme in &plugin.supported_schemes {
                pairs.push((scheme.clone(), plugin.manifest.id.clone()));
            }
        }
        let mut claimants: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for (scheme, plugin_id) in &pairs {
            claimants
                .entry(scheme.clone())
                .or_default()
                .push(plugin_id.clone());
        }
        for (scheme, plugins) in &claimants {
            if plugins.len() > 1 {
                anyhow::bail!(
                    "secret_provider scheme conflict: '{scheme}' is claimed \
                     by multiple plugins: {plugins:?} — pick one or rename"
                );
            }
        }
        for (scheme, plugin_id) in pairs {
            if self.secret_scheme_bindings.contains_key(&scheme) {
                continue;
            }
            self.bind_secret_scheme(scheme, &plugin_id)?;
        }
        Ok(())
    }

    /// Resolve a secret reference URI through the bound provider.
    /// Convenience helper — dispatches `scheme` → provider then
    /// calls `get(secret_ref)`. Consumers that resolve many refs
    /// at once (operator-config expansion path) grab the provider
    /// once via [`Self::secret_provider_for_scheme`] and batch.
    pub async fn resolve_secret(
        &self,
        secret_ref: &str,
    ) -> Result<mcpg_plugin_protocol::secret::SecretValue, mcpg_plugin_protocol::secret::SecretError>
    {
        let (scheme, _) =
            mcpg_plugin_protocol::secret::parse_secret_ref(secret_ref).ok_or_else(|| {
                mcpg_plugin_protocol::secret::SecretError::InvalidReference {
                    message: format!("not a valid scheme://path URI: '{secret_ref}'"),
                }
            })?;
        let provider = self.secret_provider_for_scheme(scheme).ok_or_else(|| {
            mcpg_plugin_protocol::secret::SecretError::UnsupportedScheme {
                scheme: scheme.to_owned(),
            }
        })?;
        provider.get(secret_ref).await
    }

    /// Register a `config_provider` plugin (spec §9.16). Two-step
    /// dispatch — the plugin joins the `config_providers` list,
    /// per-scheme binding is a separate step via
    /// [`Self::bind_config_scheme`]. Collision on plugin id is
    /// refused; a plugin that advertises no schemes is unreachable
    /// and refused too.
    pub fn register_config_provider(
        &mut self,
        plugin: Arc<dyn mcpg_plugin_protocol::config::ConfigProvider>,
        tier: PluginTier,
    ) -> Result<()> {
        self.register_config_provider_with_alias(None, plugin, tier)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id` (legacy single-instance behaviour); pass
    /// `Some(format!("{plugin_id}:{inner_name}"))` to register multiple
    /// config_providers from one plugin source. Uniqueness is enforced
    /// via `check_duplicate_alias` against the whole registry.
    pub fn register_config_provider_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Arc<dyn mcpg_plugin_protocol::config::ConfigProvider>,
        tier: PluginTier,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        let supported_schemes = plugin.supported_schemes();
        if supported_schemes.is_empty() {
            anyhow::bail!(
                "config_provider plugin '{}' declared no supported_schemes() \
                 — the plugin is unreachable",
                manifest.id
            );
        }
        cross_check_provides_schemes(
            "config_provider",
            &manifest.id,
            &manifest.provides_schemes,
            &supported_schemes,
        )?;
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            supported_schemes = ?supported_schemes,
            "registered config_provider plugin"
        );
        self.config_providers.push(LoadedConfigProviderPlugin {
            alias,
            manifest,
            tier,
            state: AtomicPluginState::new(PluginState::Active),
            supported_schemes,
            instance: plugin,
        });
        Ok(())
    }

    /// Bind `scheme` to the registered config-provider plugin
    /// with `plugin_id`. Same validation rules as
    /// [`Self::bind_secret_scheme`] — unknown plugin / non-serving
    /// / unsupported-scheme all refused; re-binding replaces
    /// silently (operator re-pointing is a feature).
    pub fn bind_config_scheme(&mut self, scheme: impl Into<String>, plugin_id: &str) -> Result<()> {
        let scheme = scheme.into();
        // Reserved-scheme invariant enforced at the binding chokepoint: env://
        // and file:// may only be served by the gateway's built-in resolvers,
        // regardless of which path reaches this bind.
        reject_reserved_scheme("config_provider", &scheme, plugin_id)?;
        let Some(plugin) = self
            .config_providers
            .iter()
            .find(|p| p.manifest.id == plugin_id)
        else {
            anyhow::bail!(
                "config_provider binding failed: plugin_id '{plugin_id}' \
                 is not registered"
            );
        };
        if !plugin.state.serves_traffic() {
            anyhow::bail!(
                "config_provider binding failed: plugin_id '{plugin_id}' \
                 is not serving traffic (state = {})",
                plugin.state.load()
            );
        }
        if !plugin.supported_schemes.contains(&scheme) {
            anyhow::bail!(
                "config_provider binding failed: plugin_id '{plugin_id}' \
                 does not support scheme '{scheme}'; supported: {:?}",
                plugin.supported_schemes
            );
        }
        info!(
            plugin_id = %plugin_id,
            scheme = %scheme,
            "bound config scheme"
        );
        // Transparent metrics decorator — the lookup path sees
        // `Arc<dyn ConfigProvider>`. Scheme is baked in at wrap
        // time so every metric emission carries the right label
        // without an extra parse.
        let metered = crate::config_metering::MeteredConfigProvider::wrap(
            scheme.clone(),
            Arc::clone(&plugin.instance),
        );
        self.config_scheme_bindings.insert(scheme, metered);
        Ok(())
    }

    /// Look up the config-provider plugin bound to `scheme`.
    /// `None` if no provider is bound.
    pub fn config_provider_for_scheme(
        &self,
        scheme: &str,
    ) -> Option<Arc<dyn mcpg_plugin_protocol::config::ConfigProvider>> {
        self.config_scheme_bindings.get(scheme).cloned()
    }

    /// Every `(scheme, plugin_id)` currently bound.
    pub fn bound_config_schemes(&self) -> Vec<(String, String)> {
        self.config_scheme_bindings
            .iter()
            .map(|(s, p)| (s.clone(), p.manifest().id.clone()))
            .collect()
    }

    /// Record the operator-granted typed capabilities for a plugin alias
    /// (per-call enforcement). Called once per cdylib entry at
    /// load time — those are the only plugins that call back into the host
    /// via [`crate::host_services::HostServices`], and the alias here is the
    /// same one the host bridge carries into each callback.
    pub fn record_granted_capabilities(
        &mut self,
        alias: String,
        caps: Vec<mcpg_plugin_protocol::capability::Capability>,
    ) {
        self.granted_caps.insert(alias, caps);
    }

    /// The operator-granted typed capabilities for `alias`. Empty slice when
    /// the alias is unknown or was granted nothing — callers treat that as
    /// "no grant" and refuse the host-service call (fail-closed).
    pub fn granted_capabilities_for_alias(
        &self,
        alias: &str,
    ) -> &[mcpg_plugin_protocol::capability::Capability] {
        self.granted_caps
            .get(alias)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Record the config-origin `cred://` issuer allowlist for a cdylib
    /// alias — the set of issuer plugin-ids the entry's own config
    /// references. Called once per cdylib entry at load time, alongside
    /// [`Self::record_granted_capabilities`].
    pub fn record_cred_resolve_allowlist(
        &mut self,
        alias: String,
        issuers: std::collections::HashSet<String>,
    ) {
        self.cred_resolve_allowlist.insert(alias, issuers);
    }

    /// Merge additional config-origin `cred://` issuers into an alias's
    /// existing allowlist (rather than replacing it). Used to fold the
    /// `cred://` issuers a backend's per-binding spec references into the
    /// allowlist already recorded from `plugins[].config` — a binding's
    /// `cred://` refs are as config-origin as the plugin entry's own, so
    /// they must be allowed too (fail-closed otherwise).
    pub fn extend_cred_resolve_allowlist(
        &mut self,
        alias: &str,
        issuers: std::collections::HashSet<String>,
    ) {
        self.cred_resolve_allowlist
            .entry(alias.to_owned())
            .or_default()
            .extend(issuers);
    }

    /// Whether `alias` is permitted to resolve `cred://<issuer>/…` — true
    /// only when the issuer appears in the alias's recorded config-origin
    /// allowlist. Unknown alias / unlisted issuer ⇒ false (fail-closed).
    #[must_use]
    pub fn cred_resolve_issuer_allowed(&self, alias: &str, issuer: &str) -> bool {
        self.cred_resolve_allowlist
            .get(alias)
            .is_some_and(|set| set.contains(issuer))
    }

    /// Record the config-origin `cred://` **target** allowlist for a cdylib
    /// alias — the set of full `<issuer>/<target>` ref keys the entry's own
    /// config references (from
    /// [`crate::credential_resolver::collect_cred_refs`]). Recorded at boot
    /// alongside [`Self::record_cred_resolve_allowlist`].
    pub fn record_cred_resolve_ref_allowlist(
        &mut self,
        alias: String,
        refs: std::collections::HashSet<String>,
    ) {
        self.cred_resolve_ref_allowlist.insert(alias, refs);
    }

    /// Merge additional config-origin `cred://` target refs into an
    /// alias's existing ref allowlist. Companion to
    /// [`Self::extend_cred_resolve_allowlist`] for the per-binding-spec
    /// `cred://` refs (the tighter `<issuer>/<target>` keys).
    pub fn extend_cred_resolve_ref_allowlist(
        &mut self,
        alias: &str,
        refs: std::collections::HashSet<String>,
    ) {
        self.cred_resolve_ref_allowlist
            .entry(alias.to_owned())
            .or_default()
            .extend(refs);
    }

    /// Whether `alias` may resolve the exact `cred://<issuer>/<target>` —
    /// true only when the `(issuer, target)` pair appears in the alias's
    /// recorded config-origin ref allowlist. Unknown alias / unlisted target
    /// ⇒ false (fail-closed). Tighter than
    /// [`Self::cred_resolve_issuer_allowed`]: the issuer being referenced is
    /// not enough — the specific target must be too.
    #[must_use]
    pub fn cred_resolve_ref_allowed(&self, alias: &str, issuer: &str, target: &str) -> bool {
        self.cred_resolve_ref_key_allowed(
            alias,
            &crate::credential_resolver::cred_ref_key(issuer, target),
        )
    }

    /// Like [`Self::cred_resolve_ref_allowed`] but takes a pre-rendered
    /// `<issuer>/<target>` key (the shape
    /// [`crate::credential_resolver::collect_cred_refs`] yields), so the
    /// host-FFI gate can check each ref it walked out of a config value
    /// without re-splitting it.
    #[must_use]
    pub fn cred_resolve_ref_key_allowed(&self, alias: &str, key: &str) -> bool {
        self.cred_resolve_ref_allowlist
            .get(alias)
            .is_some_and(|set| set.contains(key))
    }

    /// Record the config-origin secret/config **resource** allowlist for a
    /// cdylib alias — the set of anchor-stripped `scheme://resource` URIs the
    /// entry's own config references (from
    /// [`crate::secret_resolver::collect_resource_refs`]). Recorded at boot
    /// from the PRE-resolution config (secret refs are substituted in place
    /// during boot, so a post-resolution walk would find nothing).
    pub fn record_resource_resolve_allowlist(
        &mut self,
        alias: String,
        resources: std::collections::HashSet<String>,
    ) {
        self.resource_resolve_allowlist.insert(alias, resources);
    }

    /// Merge additional config-origin `scheme://resource` refs into an
    /// alias's existing resource allowlist. Companion to
    /// [`Self::extend_cred_resolve_allowlist`] for the secret/config
    /// resource URIs a backend's per-binding spec references.
    pub fn extend_resource_resolve_allowlist(
        &mut self,
        alias: &str,
        resources: std::collections::HashSet<String>,
    ) {
        self.resource_resolve_allowlist
            .entry(alias.to_owned())
            .or_default()
            .extend(resources);
    }

    /// Whether `alias` may resolve the secret/config `uri` through the
    /// `resolve_secret` / `config_snapshot` host-FFI slot. Layered on TOP of
    /// the scheme-level `SecretsRead`/`ConfigRead` capability gate: the cap
    /// authorizes the scheme, this authorizes the concrete resource.
    ///
    /// Allowed iff EITHER the full URI (`#anchor` included) appears verbatim
    /// in the alias's config-origin allowlist — a per-field grant — OR the
    /// alias was granted the WHOLE resource (a bare `scheme://path`, no
    /// anchor, in its config), which covers any `#field` on that path. The
    /// anchor is significant on the way in: a plugin that referenced only
    /// `vault://kv/app#github` cannot widen to `#stripe` (a sibling secret),
    /// but one that referenced the bare `vault://kv/app` can read any field of
    /// it. Unknown alias / non-URI / unlisted resource ⇒ false (fail-closed).
    #[must_use]
    pub fn resource_resolve_allowed(&self, alias: &str, uri: &str) -> bool {
        let Some(set) = self.resource_resolve_allowlist.get(alias) else {
            return false;
        };
        let Some(full) = crate::secret_resolver::resource_allowlist_key(uri) else {
            return false;
        };
        // Exact (per-field or whole-resource) grant.
        if set.contains(&full) {
            return true;
        }
        // A whole-resource grant (bare `scheme://path`) covers a `#field`
        // request on that path — but NOT the reverse (a field grant never
        // widens to the bare path or sibling fields).
        match crate::secret_resolver::resource_allowlist_base_key(uri) {
            Some(base) if base != full => set.contains(&base),
            _ => false,
        }
    }

    /// Host-derivation of the manifest's capability projection: overwrite
    /// the stored entity's `manifest.required_capabilities` with the
    /// authoritative typed set (the cdylib's FFI decls / the descriptor).
    /// The boot loop calls this once per registered entity so the manifest
    /// projection surfaced by `loaded_plugins` / `plugin_detail` reflects
    /// what's actually enforced, rather than the empty list a plugin's
    /// `manifest()` now ships. Keyed by the registration `alias` (the same
    /// key `check_duplicate_alias` enforces unique), so the lookup hits at
    /// most one entry; a no-op miss is harmless.
    pub fn set_manifest_caps(
        &mut self,
        alias: &str,
        caps: &[mcpg_plugin_protocol::capability::Capability],
    ) {
        macro_rules! try_seq {
            ($seq:expr) => {
                if let Some(p) = $seq.iter_mut().find(|p| p.alias == alias) {
                    p.manifest.required_capabilities = caps.to_vec();
                    return;
                }
            };
        }
        macro_rules! try_map {
            ($map:expr) => {
                if let Some(p) = $map.values_mut().find(|p| p.alias == alias) {
                    p.manifest.required_capabilities = caps.to_vec();
                    return;
                }
            };
        }
        try_seq!(self.tool_gate_chain);
        try_seq!(self.transform_chain);
        try_seq!(self.identity_chain);
        try_seq!(self.catalog_chain);
        try_seq!(self.http_routes);
        try_seq!(self.audit_sinks);
        try_seq!(self.stores);
        try_seq!(self.caches);
        try_seq!(self.telemetry_sinks);
        try_seq!(self.log_sinks);
        try_seq!(self.metrics_sinks);
        try_seq!(self.secret_providers);
        try_seq!(self.config_providers);
        try_seq!(self.transports);
        try_seq!(self.policy_engines);
        try_map!(self.backends);
        try_map!(self.content_stores);
        try_map!(self.watch_strategies);
        try_map!(self.credential_issuers);
        try_map!(self.approval_notifiers);
        if let Some(p) = self.cluster_backend.as_mut()
            && p.alias == alias
        {
            p.manifest.required_capabilities = caps.to_vec();
        }
    }

    /// Ids of every registered config-provider plugin.
    pub fn config_provider_ids(&self) -> Vec<String> {
        self.config_providers
            .iter()
            .map(|p| p.manifest.id.clone())
            .collect()
    }

    /// Auto-bind every scheme advertised by every registered
    /// config-provider plugin to its owning plugin. Mirror of
    /// [`Self::auto_bind_secret_provider_schemes`] for config
    /// schemes — same conflict rules, same skip-already-bound
    /// behavior so built-in `file://` can be pre-bound by the
    /// gateway before the auto-bind sweep.
    pub fn auto_bind_config_provider_schemes(&mut self) -> Result<()> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        for plugin in &self.config_providers {
            for scheme in &plugin.supported_schemes {
                pairs.push((scheme.clone(), plugin.manifest.id.clone()));
            }
        }
        let mut claimants: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for (scheme, plugin_id) in &pairs {
            claimants
                .entry(scheme.clone())
                .or_default()
                .push(plugin_id.clone());
        }
        for (scheme, plugins) in &claimants {
            if plugins.len() > 1 {
                anyhow::bail!(
                    "config_provider scheme conflict: '{scheme}' is claimed \
                     by multiple plugins: {plugins:?} — pick one or rename"
                );
            }
        }
        for (scheme, plugin_id) in pairs {
            if self.config_scheme_bindings.contains_key(&scheme) {
                continue;
            }
            self.bind_config_scheme(scheme, &plugin_id)?;
        }
        Ok(())
    }

    /// Snapshot a config reference through the bound provider.
    /// Convenience helper — dispatches `scheme` → provider then
    /// calls `snapshot(reference)`.
    pub async fn snapshot_config(
        &self,
        reference: &str,
    ) -> Result<
        mcpg_plugin_protocol::config::ConfigSnapshot,
        mcpg_plugin_protocol::config::ConfigError,
    > {
        let (scheme, _) =
            mcpg_plugin_protocol::config::parse_config_ref(reference).ok_or_else(|| {
                mcpg_plugin_protocol::config::ConfigError::InvalidReference {
                    message: format!("not a valid scheme://path URI: '{reference}'"),
                }
            })?;
        let provider = self.config_provider_for_scheme(scheme).ok_or_else(|| {
            mcpg_plugin_protocol::config::ConfigError::UnsupportedScheme {
                scheme: scheme.to_owned(),
            }
        })?;
        provider.snapshot(reference).await
    }

    /// Register a `transport` plugin (spec §9.6). The plugin's
    /// self-declared `name()` doubles as the dispatch key —
    /// collision on plugin id OR on transport name is refused.
    /// Unlike secret / config, there is no separate bind step:
    /// the plugin's name IS the binding.
    pub fn register_transport(
        &mut self,
        plugin: Arc<dyn mcpg_plugin_protocol::transport::Transport>,
        tier: PluginTier,
    ) -> Result<()> {
        self.register_transport_with_alias(None, plugin, tier)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id` (legacy single-instance behaviour); pass
    /// `Some(format!("{plugin_id}:{inner_name}"))` to register multiple
    /// transports from one plugin source. Uniqueness is enforced via
    /// `check_duplicate_alias` against the whole registry, in addition
    /// to the existing per-plugin-id and per-transport-name collision
    /// checks.
    pub fn register_transport_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Arc<dyn mcpg_plugin_protocol::transport::Transport>,
        tier: PluginTier,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        if self.transports.iter().any(|p| p.manifest.id == manifest.id) {
            anyhow::bail!("transport plugin '{}' is already registered", manifest.id);
        }
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        let transport_name = plugin.name().to_owned();
        if transport_name.is_empty() {
            anyhow::bail!(
                "transport plugin '{}' declared an empty name() — \
                 transports self-declare their dispatch key",
                manifest.id
            );
        }
        if let Some(existing) = self
            .transports
            .iter()
            .find(|p| p.transport_name == transport_name)
        {
            anyhow::bail!(
                "transport name '{transport_name}' is already served by \
                 plugin '{}'; cannot register '{}'",
                existing.manifest.id,
                manifest.id
            );
        }
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            transport_name = %transport_name,
            "registered transport plugin"
        );
        // Wrap in the metering decorator — callers on the lookup
        // path see a transparent `Arc<dyn Transport>`. Plugin_id
        // + transport_name labels are baked in at wrap time.
        let metered = crate::transport_metering::MeteredTransport::wrap(plugin);
        self.transports.push(LoadedTransportPlugin {
            alias,
            manifest,
            tier,
            state: AtomicPluginState::new(PluginState::Active),
            transport_name,
            instance: metered,
        });
        Ok(())
    }

    /// Look up the transport plugin registered under `name`.
    /// `None` if no transport is registered. Callers start the
    /// transport themselves by calling `start` on the returned
    /// Arc with their dispatcher + listener config.
    pub fn transport_by_name(
        &self,
        name: &str,
    ) -> Option<Arc<dyn mcpg_plugin_protocol::transport::Transport>> {
        self.transports
            .iter()
            .find(|p| p.transport_name == name)
            .map(|p| Arc::clone(&p.instance))
    }

    /// Every transport name that has a registered plugin. Sorted
    /// to keep the admin output deterministic.
    pub fn transport_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .transports
            .iter()
            .map(|p| p.transport_name.clone())
            .collect();
        names.sort();
        names
    }

    /// Ids of every registered transport plugin.
    pub fn transport_plugin_ids(&self) -> Vec<String> {
        self.transports
            .iter()
            .map(|p| p.manifest.id.clone())
            .collect()
    }

    /// Look up a transport plugin by its manifest id. Used by the
    /// gateway's `gateway.server.transports[]` startup loop,
    /// where the operator names a specific plugin
    /// to start as an additional listener. The lookup is by
    /// plugin id, not by `Transport::name()` — those can differ
    /// (the name is the dispatch key, the id is the install
    /// identity).
    pub fn transport_by_id(
        &self,
        plugin_id: &str,
    ) -> Option<Arc<dyn mcpg_plugin_protocol::transport::Transport>> {
        self.transports
            .iter()
            .find(|p| p.manifest.id == plugin_id)
            .map(|p| Arc::clone(&p.instance))
    }

    /// Register a `policy_engine` plugin (spec §9.14). The
    /// plugin's self-declared `name()` doubles as the dispatch key
    /// — collision on plugin id OR on engine name is refused.
    /// Same shape as `register_transport`.
    pub fn register_policy_engine(
        &mut self,
        plugin: Arc<dyn mcpg_plugin_protocol::policy::PolicyEngine>,
        tier: PluginTier,
    ) -> Result<()> {
        self.register_policy_engine_with_alias(None, plugin, tier)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id` (legacy single-instance behaviour); pass
    /// `Some(format!("{plugin_id}:{inner_name}"))` to register multiple
    /// policy_engines from one plugin source. Uniqueness is enforced
    /// via `check_duplicate_alias` against the whole registry. The
    /// `engine_name` dispatch key is independent and still validated
    /// for emptiness + collision.
    pub fn register_policy_engine_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Arc<dyn mcpg_plugin_protocol::policy::PolicyEngine>,
        tier: PluginTier,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        let engine_name = plugin.name().to_owned();
        if engine_name.is_empty() {
            anyhow::bail!(
                "policy_engine plugin '{}' declared an empty name() — \
                 engines self-declare their dispatch key",
                manifest.id
            );
        }
        if let Some(existing) = self
            .policy_engines
            .iter()
            .find(|p| p.engine_name == engine_name)
        {
            anyhow::bail!(
                "policy_engine name '{engine_name}' is already served by \
                 plugin '{}'; cannot register '{}'",
                existing.manifest.id,
                manifest.id
            );
        }
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            engine_name = %engine_name,
            "registered policy_engine plugin"
        );
        // Wrap in the metering decorator so every `evaluate` call
        // emits metrics automatically.
        let metered = crate::policy_metering::MeteredPolicyEngine::wrap(plugin);
        self.policy_engines.push(LoadedPolicyEnginePlugin {
            alias,
            manifest,
            tier,
            state: AtomicPluginState::new(PluginState::Active),
            engine_name,
            instance: metered,
        });
        Ok(())
    }

    /// Look up the policy engine registered under `name`.
    /// `None` if no engine is registered.
    pub fn policy_engine_by_name(
        &self,
        name: &str,
    ) -> Option<Arc<dyn mcpg_plugin_protocol::policy::PolicyEngine>> {
        self.policy_engines
            .iter()
            .find(|p| p.engine_name == name)
            .map(|p| Arc::clone(&p.instance))
    }

    /// Every engine name that has a registered plugin, sorted.
    pub fn policy_engine_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .policy_engines
            .iter()
            .map(|p| p.engine_name.clone())
            .collect();
        names.sort();
        names
    }

    /// Ids of every registered policy-engine plugin.
    pub fn policy_engine_plugin_ids(&self) -> Vec<String> {
        self.policy_engines
            .iter()
            .map(|p| p.manifest.id.clone())
            .collect()
    }

    /// Evaluate a decision through the named engine. Convenience
    /// helper — dispatches `engine_name` → plugin then calls
    /// `evaluate(decision_point, input, context)`. Returns
    /// `PolicyEffect::NotApplicable` (with an empty policy_version)
    /// when the named engine isn't registered; callers that need
    /// stricter failure semantics look up the engine explicitly
    /// via `policy_engine_by_name`.
    pub async fn evaluate_policy(
        &self,
        engine_name: &str,
        decision_point: &str,
        input: &serde_json::Value,
        context: &mcpg_plugin_protocol::PluginContext,
    ) -> mcpg_plugin_protocol::policy::PolicyDecision {
        let Some(engine) = self.policy_engine_by_name(engine_name) else {
            return mcpg_plugin_protocol::policy::PolicyDecision::not_applicable(String::new());
        };
        engine.evaluate(decision_point, input, context).await
    }

    /// Evaluate the registered policy_engine chain against a
    /// plugin's manifest at the `plugin.lifecycle.register`
    /// decision point. Operators wire policies that gate plugin
    /// loading by tag / id / class — typical rules:
    ///
    /// - "deny `tags: [experimental]` in prod"
    /// - "only allow `tags: [vendor:internal]` plugins"
    /// - "block plugin_class=binding when missing
    ///   `tags: [security-reviewed]`"
    ///
    /// Returns the chain outcome. The caller (typically the
    /// gateway boot path that loads `plugins[]`) refuses
    /// to register the plugin on `Deny`. Empty chain (no policy
    /// engines registered yet, or operator hasn't bound any) →
    /// `NotApplicable`, treated as Allow by the caller.
    ///
    /// The actor is `system_identity()` since plugin loading is
    /// gateway-side; the policy_engine sees `request_id =
    /// "plugin-load-<plugin_id>"` + `surface = "plugin_lifecycle"`.
    pub async fn evaluate_plugin_registration_policy(
        &self,
        manifest: &mcpg_plugin_protocol::PluginManifest,
    ) -> PolicyChainOutcome {
        let engines = self.policy_engine_names();
        if engines.is_empty() {
            return PolicyChainOutcome::NotApplicable;
        }
        let manifest_json = match serde_json::to_value(manifest) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    plugin_id = %manifest.id,
                    error = %err,
                    "registration policy: manifest serialization failed; skipping chain"
                );
                return PolicyChainOutcome::NotApplicable;
            }
        };
        let context = mcpg_plugin_protocol::PluginContext {
            request_id: format!("plugin-load-{}", manifest.id),
            session_id: None,
            tool_name: manifest.id.clone(),
            surface: "plugin_lifecycle".to_owned(),
            identity: crate::audit_events::system_identity(),
            transport: "internal".to_owned(),
        };
        self.evaluate_policy_chain(
            &engines,
            "plugin.lifecycle.register",
            &manifest_json,
            &context,
        )
        .await
    }

    /// Evaluate a chain of operator-bound policy engines. Each
    /// engine is consulted in order at the same `decision_point`
    /// against the same `input` + `context`; aggregation rules:
    ///
    /// - **First `Deny` short-circuits** with the engine's reason.
    ///   The returned `PolicyChainOutcome::Deny` carries the
    ///   denying engine's name + the policy_version so audit can
    ///   record exactly which policy refused the call.
    /// - **`Allow` advances the chain** but is "sticky" — once any
    ///   engine has explicitly allowed, a subsequent
    ///   `NotApplicable` doesn't downgrade the result.
    /// - **All `NotApplicable`** with no `Allow` returns
    ///   `NotApplicable` so callers can decide whether to treat
    ///   "no policy spoke" as Allow (default) or Deny (strict).
    /// - Unknown engine names (operator typo) emit a warn log +
    ///   are silently skipped; the chain doesn't fail-closed on
    ///   misconfiguration since the trust-level pre-dispatch gate
    ///   still runs after this.
    pub async fn evaluate_policy_chain(
        &self,
        engines: &[String],
        decision_point: &str,
        input: &serde_json::Value,
        context: &mcpg_plugin_protocol::PluginContext,
    ) -> PolicyChainOutcome {
        if engines.is_empty() {
            return PolicyChainOutcome::NotApplicable;
        }
        let mut allowed_by: Option<(String, String)> = None;
        for engine_name in engines {
            let Some(engine) = self.policy_engine_by_name(engine_name) else {
                warn!(
                    engine_name = %engine_name,
                    "policy chain: unknown engine name; skipping"
                );
                continue;
            };
            let decision = engine.evaluate(decision_point, input, context).await;
            metrics::counter!(
                "mcpg_policy_chain_decisions_total",
                "engine" => engine_name.clone(),
                "decision_point" => decision_point.to_owned(),
                "effect" => policy_effect_label(&decision.effect),
            )
            .increment(1);
            match decision.effect {
                mcpg_plugin_protocol::policy::PolicyEffect::Deny => {
                    return PolicyChainOutcome::Deny {
                        engine: engine_name.clone(),
                        reason: decision
                            .reason
                            .unwrap_or_else(|| format!("policy {engine_name} denied")),
                        policy_version: decision.policy_version,
                    };
                }
                mcpg_plugin_protocol::policy::PolicyEffect::Allow => {
                    if allowed_by.is_none() {
                        allowed_by = Some((engine_name.clone(), decision.policy_version));
                    }
                }
                mcpg_plugin_protocol::policy::PolicyEffect::NotApplicable => {
                    // Continue.
                }
            }
        }
        match allowed_by {
            Some((engine, policy_version)) => PolicyChainOutcome::Allow {
                engine,
                policy_version,
            },
            None => PolicyChainOutcome::NotApplicable,
        }
    }

    /// Register the cluster coordinator (spec §9.13). Singleton —
    /// a second registration refuses. Operators who want to swap
    /// coordinators restart the gateway; runtime replacement is
    /// intentionally disallowed because fencing-token semantics
    /// depend on a single coordinator lifetime.
    pub fn register_cluster_backend(
        &mut self,
        plugin: Arc<dyn mcpg_cluster_api::ClusterBackend>,
        tier: PluginTier,
    ) -> Result<()> {
        self.register_cluster_backend_with_ffi(plugin, tier, None)
    }

    /// v20-aware variant that also stores the coordinator's raw
    /// FFI ref (handle + vtable copy) so consumer plugins
    /// (identity / policy_engine) can opt into cluster-coordinated
    /// state through their `make` slot's `cluster` argument. Pass
    /// `None` for `ffi_ref` when the coordinator was constructed
    /// without a backing vtable (Rust-side test doubles, future
    /// in-process coordinators).
    pub fn register_cluster_backend_with_ffi(
        &mut self,
        plugin: Arc<dyn mcpg_cluster_api::ClusterBackend>,
        tier: PluginTier,
        ffi_ref: Option<mcpg_plugin_protocol::abi::ClusterClientRef>,
    ) -> Result<()> {
        self.register_cluster_backend_with_alias(None, plugin, tier, ffi_ref)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id` (legacy single-instance behaviour). The
    /// cluster_backend is a singleton, so a second registration
    /// refuses regardless of alias — multi-instance does not apply.
    /// The alias is recorded for API consistency with other kinds and
    /// participates in the cross-kind `check_duplicate_alias` check.
    pub fn register_cluster_backend_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Arc<dyn mcpg_cluster_api::ClusterBackend>,
        tier: PluginTier,
        ffi_ref: Option<mcpg_plugin_protocol::abi::ClusterClientRef>,
    ) -> Result<()> {
        if let Some(existing) = &self.cluster_backend {
            anyhow::bail!(
                "cluster_backend already registered: '{}' cannot be \
                 replaced by '{}' at runtime",
                existing.manifest.id,
                plugin.manifest().id,
            );
        }
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            ffi_ref = ffi_ref.is_some(),
            "registered cluster_backend plugin"
        );
        let metered = crate::cluster_metering::MeteredClusterBackend::wrap(plugin);
        self.cluster_backend = Some(LoadedClusterBackendPlugin {
            alias,
            manifest,
            tier,
            state: AtomicPluginState::new(PluginState::Active),
            instance: metered,
            ffi_ref,
        });
        Ok(())
    }

    /// FFI ref of the registered cluster coordinator, if any. Used
    /// by the gateway when constructing identity / policy_engine
    /// plugin adapters: the ref is handed to the plugin's `make`
    /// slot so the plugin can opt into cluster-coordinated state
    /// through `mcpg_plugin_sdk::ClusterClient`. Returns `None`
    /// when no coordinator is registered or when the coordinator
    /// was registered without an FFI ref (e.g., test doubles).
    pub fn cluster_backend_ffi_ref(&self) -> Option<mcpg_plugin_protocol::abi::ClusterClientRef> {
        self.cluster_backend.as_ref().and_then(|p| p.ffi_ref)
    }

    /// The currently-registered cluster coordinator, if any.
    /// Callers hold the returned Arc across calls; the registry
    /// is not a hot-path for cluster ops (lookups happen at boot
    /// + on cluster state changes).
    pub fn cluster_backend(&self) -> Option<Arc<dyn mcpg_cluster_api::ClusterBackend>> {
        self.cluster_backend
            .as_ref()
            .map(|p| Arc::clone(&p.instance))
    }

    /// Whether a cluster coordinator is registered.
    pub fn has_cluster_backend(&self) -> bool {
        self.cluster_backend.is_some()
    }

    /// Id of the registered cluster coordinator plugin, if any.
    pub fn cluster_backend_plugin_id(&self) -> Option<String> {
        self.cluster_backend.as_ref().map(|p| p.manifest.id.clone())
    }

    /// Register a `catalog_provider` plugin. Chain — order
    /// matters; operators bind providers in `plugins[]` order
    /// and the gateway walks the chain on every `tools/list`
    /// request. The first provider in the chain is most
    /// authoritative for first-write-wins scalar fields; later
    /// providers union into `tags` and fill gaps.
    pub fn register_catalog_provider(
        &mut self,
        plugin: Box<dyn mcpg_plugin_protocol::catalog::CatalogProvider>,
        tier: PluginTier,
        config: serde_json::Value,
    ) -> Result<()> {
        self.register_catalog_provider_with_alias(None, plugin, tier, config)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id` (legacy single-instance behaviour); pass
    /// `Some(format!("{plugin_id}:{inner_name}"))` to register multiple
    /// catalog_providers from one plugin source. Uniqueness is
    /// enforced via `check_duplicate_alias` against the whole registry.
    pub fn register_catalog_provider_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Box<dyn mcpg_plugin_protocol::catalog::CatalogProvider>,
        tier: PluginTier,
        config: serde_json::Value,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            chain_position = self.catalog_chain.len(),
            "registered catalog_provider plugin"
        );
        // Wrap in the metering decorator so every chain pass emits
        // `mcpg_catalog_*` metrics (op latency, op total,
        // tools_filtered_total).
        let metered = crate::catalog_metering::MeteredCatalogProvider::wrap(plugin);
        self.catalog_chain.push(LoadedPlugin {
            alias,
            manifest,
            tier,
            config,
            enforce: true,
            state: AtomicPluginState::new(PluginState::Active),
            registered_at: std::time::SystemTime::now(),
            inflight: Arc::new(InflightTracker::new()),
            instance: metered,
        });
        Ok(())
    }

    /// Returns the catalog chain in registration order. Empty when
    /// no catalog providers are bound — the gateway treats that as
    /// "no enrichment, raw tool list flows through unchanged."
    pub fn catalog_chain(&self) -> Vec<&dyn mcpg_plugin_protocol::catalog::CatalogProvider> {
        self.catalog_chain
            .iter()
            .filter(|p| p.state.load() == PluginState::Active)
            .map(|p| p.instance.as_ref())
            .collect()
    }

    /// Ids of every registered catalog_provider plugin (regardless
    /// of state).
    pub fn catalog_provider_plugin_ids(&self) -> Vec<String> {
        self.catalog_chain
            .iter()
            .map(|p| p.manifest.id.clone())
            .collect()
    }

    /// Register a `credential_issuer` plugin. Keyed by
    /// `manifest.id`. Operators reference the issuer via
    /// `cred://<plugin_id>/<target>` in their binding configs.
    pub fn register_credential_issuer(
        &mut self,
        plugin: Arc<dyn mcpg_plugin_protocol::credential::CredentialIssuer>,
        tier: PluginTier,
    ) -> Result<()> {
        self.register_credential_issuer_with_alias(None, plugin, tier)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id` (legacy single-instance behaviour); pass
    /// `Some(format!("{plugin_id}:{inner_name}"))` to register multiple
    /// credential_issuers from one plugin source. Uniqueness is
    /// enforced via `check_duplicate_alias` against the whole registry,
    /// in addition to the per-kind HashMap-key uniqueness on
    /// `manifest.id`.
    pub fn register_credential_issuer_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Arc<dyn mcpg_plugin_protocol::credential::CredentialIssuer>,
        tier: PluginTier,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        if self.credential_issuers.contains_key(&manifest.id) {
            anyhow::bail!(
                "credential_issuer plugin '{}' is already registered",
                manifest.id
            );
        }
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            "registered credential_issuer plugin"
        );
        // Wrap in metering decorator for per-request observability.
        let metered = crate::credential_metering::MeteredCredentialIssuer::wrap(plugin);
        self.credential_issuers.insert(
            manifest.id.clone(),
            LoadedCredentialIssuerPlugin {
                alias,
                manifest,
                tier,
                state: AtomicPluginState::new(PluginState::Active),
                instance: metered,
            },
        );
        Ok(())
    }

    /// Look up the credential_issuer registered under
    /// `plugin_id`. `None` if no issuer with that id is registered
    /// or the issuer is not in `Active` state.
    pub fn credential_issuer(
        &self,
        plugin_id: &str,
    ) -> Option<Arc<dyn mcpg_plugin_protocol::credential::CredentialIssuer>> {
        self.credential_issuers
            .get(plugin_id)
            .filter(|p| p.state.load() == PluginState::Active)
            .map(|p| Arc::clone(&p.instance))
    }

    /// Ids of every registered credential_issuer plugin.
    pub fn credential_issuer_plugin_ids(&self) -> Vec<String> {
        self.credential_issuers.keys().cloned().collect()
    }

    /// Register an `approval_notifier` plugin (spec §9.19).
    /// Keyed by `manifest.id`. Operators bind notifiers in
    /// `plugins[]`; tool_gate plugins reference them by
    /// manifest id via `GateDecision::PendingApproval.target_notifiers`.
    pub fn register_approval_notifier(
        &mut self,
        plugin: Arc<dyn mcpg_plugin_protocol::approval_notifier::ApprovalNotifier>,
        tier: PluginTier,
    ) -> Result<()> {
        self.register_approval_notifier_with_alias(None, plugin, tier)
    }

    /// J.1.4 — alias-aware variant. `alias = None` keys the entity by
    /// `manifest.id` (legacy single-instance behaviour); pass
    /// `Some(format!("{plugin_id}:{inner_name}"))` to register multiple
    /// approval_notifiers from one plugin source. Uniqueness is
    /// enforced via `check_duplicate_alias` against the whole registry,
    /// in addition to the per-kind HashMap-key uniqueness on
    /// `manifest.id`.
    pub fn register_approval_notifier_with_alias(
        &mut self,
        alias: Option<String>,
        plugin: Arc<dyn mcpg_plugin_protocol::approval_notifier::ApprovalNotifier>,
        tier: PluginTier,
    ) -> Result<()> {
        let manifest = plugin.manifest().clone();
        let alias = alias.unwrap_or_else(|| manifest.id.clone());
        if self.approval_notifiers.contains_key(&manifest.id) {
            anyhow::bail!(
                "approval_notifier plugin '{}' is already registered",
                manifest.id
            );
        }
        self.validate_manifest(&manifest)?;
        self.check_duplicate_alias(&alias)?;
        info!(
            plugin_alias = %alias,
            plugin_id = %manifest.id,
            plugin_version = %manifest.version,
            plugin_name = %manifest.name,
            tier = %tier,
            "registered approval_notifier plugin"
        );
        let metered = crate::approval_notifier_metering::MeteredApprovalNotifier::wrap(plugin);
        self.approval_notifiers.insert(
            manifest.id.clone(),
            LoadedApprovalNotifierPlugin {
                alias,
                manifest,
                tier,
                state: AtomicPluginState::new(PluginState::Active),
                instance: metered,
            },
        );
        Ok(())
    }

    /// Look up an approval_notifier by `plugin_id`. `None` if no
    /// matching notifier is registered or the notifier is not in
    /// `Active` state.
    pub fn approval_notifier(
        &self,
        plugin_id: &str,
    ) -> Option<Arc<dyn mcpg_plugin_protocol::approval_notifier::ApprovalNotifier>> {
        self.approval_notifiers
            .get(plugin_id)
            .filter(|p| p.state.load() == PluginState::Active)
            .map(|p| Arc::clone(&p.instance))
    }

    /// Ids of every registered approval_notifier plugin in
    /// registration (BTreeMap) order. Used by the approval-state
    /// machine to fan out a `PendingApproval` whose
    /// `target_notifiers` is empty.
    pub fn approval_notifier_plugin_ids(&self) -> Vec<String> {
        self.approval_notifiers.keys().cloned().collect()
    }

    /// Resolve `target_notifiers` from a `PendingApproval`
    /// to concrete handles. Empty `targets` means "fan out to every
    /// active notifier". Unknown ids are silently dropped — the
    /// gateway logs the mismatch but keeps going so a single
    /// missing plugin doesn't block every approval. Notifier order
    /// follows the input list when targeted; BTreeMap iteration
    /// order when fanned out.
    pub fn resolve_approval_notifiers(
        &self,
        targets: &[String],
    ) -> Vec<Arc<dyn mcpg_plugin_protocol::approval_notifier::ApprovalNotifier>> {
        if targets.is_empty() {
            return self
                .approval_notifiers
                .values()
                .filter(|p| p.state.load() == PluginState::Active)
                .map(|p| Arc::clone(&p.instance))
                .collect();
        }
        let mut out = Vec::with_capacity(targets.len());
        for id in targets {
            if let Some(p) = self.approval_notifier(id) {
                out.push(p);
            }
        }
        out
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /// Drain every loaded plugin's background state. Called
    /// from the app `serve` path on shutdown. Each plugin's
    /// `shutdown()` is awaited sequentially — with a per-plugin
    /// timeout — so ordering is deterministic and a single
    /// misbehaving plugin cannot stall the gateway's teardown past
    /// the configured budget. The default trait impl is a no-op so
    /// plugins that allocate no background state require no change.
    ///
    /// Uses [`DEFAULT_PLUGIN_SHUTDOWN_TIMEOUT`]. Callers that need a
    /// different budget can use [`Self::shutdown_all_with_timeout`].
    ///
    /// Returns a [`ShutdownReport`] so operators (and tests) can
    /// observe whether any plugins exceeded the deadline.
    pub async fn shutdown_all(&self) -> ShutdownReport {
        self.shutdown_all_with_timeout(DEFAULT_PLUGIN_SHUTDOWN_TIMEOUT)
            .await
    }

    /// [`Self::shutdown_all`] with an explicit per-plugin timeout.
    ///
    /// A plugin that fails to complete `shutdown()` within
    /// `per_plugin_timeout` is abandoned: a warning is logged, the
    /// report records its id, and drain moves on. The registry does
    /// not attempt to cancel the in-flight future (the plugin's
    /// tokio task is dropped when the registry is dropped), so
    /// plugins SHOULD treat `shutdown()` as best-effort.
    pub async fn shutdown_all_with_timeout(&self, per_plugin_timeout: Duration) -> ShutdownReport {
        let mut report = ShutdownReport::default();
        let started = Instant::now();

        for entry in &self.tool_gate_chain {
            drain_one(
                entry.instance.manifest().id.clone(),
                "tool_gate",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in self.backends.values() {
            drain_one(
                entry.manifest.id.clone(),
                "binding",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in self.watch_strategies.values() {
            drain_one(
                entry.manifest.id.clone(),
                "watch_strategy",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in self.approval_notifiers.values() {
            drain_one(
                entry.manifest.id.clone(),
                "approval_notifier",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        // Every remaining stateful class. Previously only the four chains
        // above were drained, so transform/identity/catalog chains, all sink
        // classes, stores, caches, secret/config providers, transports, policy
        // engines, http_routes, credential issuers, and the cluster backend
        // leaked their plugin-owned background state on shutdown/reload. Each
        // trait carries a defaulted no-op `shutdown()`, so this is safe for
        // plugins with no background state and drives the FFI shutdown slot for
        // those that override it.
        for entry in &self.transform_chain {
            drain_one(
                entry.manifest.id.clone(),
                "transform",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in &self.identity_chain {
            drain_one(
                entry.manifest.id.clone(),
                "identity",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in &self.catalog_chain {
            drain_one(
                entry.manifest.id.clone(),
                "catalog",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in &self.http_routes {
            drain_one(
                entry.manifest.id.clone(),
                "http_route",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in &self.audit_sinks {
            drain_one(
                entry.manifest.id.clone(),
                "audit_sink",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in &self.stores {
            drain_one(
                entry.manifest.id.clone(),
                "store",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in &self.caches {
            drain_one(
                entry.manifest.id.clone(),
                "cache",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in &self.telemetry_sinks {
            drain_one(
                entry.manifest.id.clone(),
                "telemetry_sink",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in &self.log_sinks {
            drain_one(
                entry.manifest.id.clone(),
                "log_sink",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in &self.metrics_sinks {
            drain_one(
                entry.manifest.id.clone(),
                "metrics_sink",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in &self.secret_providers {
            drain_one(
                entry.manifest.id.clone(),
                "secret_provider",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in &self.config_providers {
            drain_one(
                entry.manifest.id.clone(),
                "config_provider",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in &self.transports {
            drain_one(
                entry.manifest.id.clone(),
                "transport",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in &self.policy_engines {
            drain_one(
                entry.manifest.id.clone(),
                "policy_engine",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        for entry in self.credential_issuers.values() {
            drain_one(
                entry.manifest.id.clone(),
                "credential_issuer",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }
        if let Some(entry) = &self.cluster_backend {
            drain_one(
                entry.manifest.id.clone(),
                "cluster_backend",
                entry.instance.shutdown(),
                per_plugin_timeout,
                &mut report,
            )
            .await;
        }

        report.total_elapsed = started.elapsed();
        info!(
            clean = report.clean,
            timed_out = report.timed_out.len(),
            elapsed_ms = report.total_elapsed.as_millis() as u64,
            "plugin drain complete"
        );
        report
    }

    pub fn has_tool_gate_plugins(&self) -> bool {
        !self.tool_gate_chain.is_empty()
    }

    /// Returns true if any transform plugins are registered.
    pub fn has_transform_plugins(&self) -> bool {
        !self.transform_chain.is_empty()
    }

    /// Returns true if any identity plugins are registered.
    pub fn has_identity_plugins(&self) -> bool {
        !self.identity_chain.is_empty()
    }

    /// Ids of the registered identity providers, in chain order. Callers use
    /// this to check that a configured identity kind actually has a plugin
    /// behind it — an identity provider that silently is not there would let
    /// requests through unauthenticated.
    pub fn identity_plugin_ids(&self) -> Vec<String> {
        self.identity_chain
            .iter()
            .map(|p| p.manifest.id.clone())
            .collect()
    }

    /// Total number of loaded plugins across all classes.
    pub fn total_count(&self) -> usize {
        self.tool_gate_chain.len()
            + self.transform_chain.len()
            + self.identity_chain.len()
            + self.backends.len()
            + self.content_stores.len()
            + self.watch_strategies.len()
            + self.http_routes.len()
            + self.audit_sinks.len()
            + self.stores.len()
            + self.caches.len()
            + self.telemetry_sinks.len()
            + self.log_sinks.len()
            + self.metrics_sinks.len()
            + self.secret_providers.len()
            + self.config_providers.len()
            + self.transports.len()
            + self.policy_engines.len()
            + usize::from(self.cluster_backend.is_some())
            + self.catalog_chain.len()
            + self.credential_issuers.len()
            + self.approval_notifiers.len()
    }

    /// Returns info about all loaded plugins (for admin endpoints).
    pub fn loaded_plugins(&self) -> Vec<LoadedPluginInfo> {
        let mut out = Vec::new();
        for p in &self.tool_gate_chain {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: p.manifest.plugin_class.to_string(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for p in &self.transform_chain {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: p.manifest.plugin_class.to_string(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for p in &self.identity_chain {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: p.manifest.plugin_class.to_string(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for (kind, p) in &self.backends {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("binding:{}", kind),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for (kind, p) in &self.content_stores {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("content_store:{}", kind),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for (kind, p) in &self.watch_strategies {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("watch_strategy:{}", kind),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for p in &self.http_routes {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("http_route:{}", p.entity_name),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for p in &self.audit_sinks {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: "audit_sink".to_owned(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for p in &self.stores {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                // Class string embeds the supported-roles list so
                // admin listings disambiguate "this plugin serves
                // session" from "this plugin serves replay".
                plugin_class: format!(
                    "store:{}",
                    p.supported_roles
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for p in &self.caches {
            let ns_label = if p.serves_any {
                "*".to_owned()
            } else {
                p.supported_namespaces.join(",")
            };
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("cache:{ns_label}"),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for p in &self.telemetry_sinks {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: "telemetry_sink".to_owned(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for p in &self.log_sinks {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: "log_sink".to_owned(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for p in &self.metrics_sinks {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: "metrics_sink".to_owned(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for p in &self.secret_providers {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("secret_provider:{}", p.supported_schemes.join(",")),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for p in &self.config_providers {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("config_provider:{}", p.supported_schemes.join(",")),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for p in &self.transports {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("transport:{}", p.transport_name),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for p in &self.policy_engines {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("policy_engine:{}", p.engine_name),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        if let Some(p) = &self.cluster_backend {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: "cluster".to_owned(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for p in &self.catalog_chain {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: p.manifest.plugin_class.to_string(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for p in self.credential_issuers.values() {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: p.manifest.plugin_class.to_string(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        for p in self.approval_notifiers.values() {
            out.push(LoadedPluginInfo {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: p.manifest.plugin_class.to_string(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                state: p.state.load().to_string(),
            });
        }
        out
    }

    /// Return the current lifecycle state of the plugin with the
    /// given id, or `None` if no such plugin is registered.
    ///
    /// Admin surfaces call this to display the per-plugin state
    /// without having to walk [`Self::loaded_plugins`] themselves.
    pub fn lifecycle_state(&self, plugin_id: &str) -> Option<PluginState> {
        self.find_state_cell(plugin_id).map(|s| s.load())
    }

    /// Full per-plugin detail, or `None` if `plugin_id` is not
    /// registered.
    ///
    /// Backing store for `GET /admin/v1/plugins/:id`. Caller redacts
    /// the `config` field before serialising.
    pub fn plugin_detail(&self, plugin_id: &str) -> Option<LoadedPluginDetail> {
        let unix_secs = |t: std::time::SystemTime| -> u64 {
            t.duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        };

        if let Some(p) = self
            .tool_gate_chain
            .iter()
            .find(|p| p.manifest.id == plugin_id)
        {
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: p.manifest.plugin_class.to_string(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: unix_secs(p.registered_at),
                inflight: Some(p.inflight.load()),
                enforce: Some(p.enforce),
                config: p.config.clone(),
            });
        }
        if let Some(p) = self
            .transform_chain
            .iter()
            .find(|p| p.manifest.id == plugin_id)
        {
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: p.manifest.plugin_class.to_string(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: unix_secs(p.registered_at),
                inflight: Some(p.inflight.load()),
                enforce: None,
                config: p.config.clone(),
            });
        }
        if let Some(p) = self
            .identity_chain
            .iter()
            .find(|p| p.manifest.id == plugin_id)
        {
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: p.manifest.plugin_class.to_string(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: unix_secs(p.registered_at),
                inflight: Some(p.inflight.load()),
                enforce: None,
                config: p.config.clone(),
            });
        }
        // Binding + watch-strategy plugins have no per-plugin config
        // on the registry (they share operator-supplied per-profile
        // specs), no enforce flag, and no chain-level inflight
        // counter.
        if let Some((kind, p)) = self
            .backends
            .iter()
            .find(|(_, p)| p.manifest.id == plugin_id)
        {
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("binding:{kind}"),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: 0,
                inflight: None,
                enforce: None,
                config: serde_json::Value::Null,
            });
        }
        if let Some((kind, p)) = self
            .watch_strategies
            .iter()
            .find(|(_, p)| p.manifest.id == plugin_id)
        {
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("watch_strategy:{kind}"),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: 0,
                inflight: None,
                enforce: None,
                config: serde_json::Value::Null,
            });
        }
        // HTTP-route entities — one detail per (plugin_id,
        // entity_name) pair; the class string embeds the entity name
        // so admin listings disambiguate multiple entities from the
        // same plugin id.
        if let Some(p) = self.http_routes.iter().find(|p| p.manifest.id == plugin_id) {
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("http_route:{}", p.entity_name),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: 0,
                inflight: None,
                enforce: None,
                config: serde_json::Value::Null,
            });
        }
        if let Some(p) = self.audit_sinks.iter().find(|p| p.manifest.id == plugin_id) {
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: "audit_sink".to_owned(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: 0,
                inflight: None,
                enforce: None,
                config: serde_json::Value::Null,
            });
        }
        if let Some(p) = self.stores.iter().find(|p| p.manifest.id == plugin_id) {
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!(
                    "store:{}",
                    p.supported_roles
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: 0,
                inflight: None,
                enforce: None,
                config: serde_json::Value::Null,
            });
        }
        if let Some(p) = self.caches.iter().find(|p| p.manifest.id == plugin_id) {
            let ns_label = if p.serves_any {
                "*".to_owned()
            } else {
                p.supported_namespaces.join(",")
            };
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("cache:{ns_label}"),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: 0,
                inflight: None,
                enforce: None,
                config: serde_json::Value::Null,
            });
        }
        if let Some(p) = self
            .telemetry_sinks
            .iter()
            .find(|p| p.manifest.id == plugin_id)
        {
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: "telemetry_sink".to_owned(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: 0,
                inflight: None,
                enforce: None,
                config: serde_json::Value::Null,
            });
        }
        if let Some(p) = self
            .metrics_sinks
            .iter()
            .find(|p| p.manifest.id == plugin_id)
        {
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: "metrics_sink".to_owned(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: 0,
                inflight: None,
                enforce: None,
                config: serde_json::Value::Null,
            });
        }
        if let Some(p) = self.log_sinks.iter().find(|p| p.manifest.id == plugin_id) {
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: "log_sink".to_owned(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: 0,
                inflight: None,
                enforce: None,
                config: serde_json::Value::Null,
            });
        }
        if let Some(p) = self
            .secret_providers
            .iter()
            .find(|p| p.manifest.id == plugin_id)
        {
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("secret_provider:{}", p.supported_schemes.join(",")),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: 0,
                inflight: None,
                enforce: None,
                config: serde_json::Value::Null,
            });
        }
        if let Some(p) = self
            .config_providers
            .iter()
            .find(|p| p.manifest.id == plugin_id)
        {
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("config_provider:{}", p.supported_schemes.join(",")),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: 0,
                inflight: None,
                enforce: None,
                config: serde_json::Value::Null,
            });
        }
        if let Some(p) = self.transports.iter().find(|p| p.manifest.id == plugin_id) {
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("transport:{}", p.transport_name),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: 0,
                inflight: None,
                enforce: None,
                config: serde_json::Value::Null,
            });
        }
        if let Some(p) = self
            .policy_engines
            .iter()
            .find(|p| p.manifest.id == plugin_id)
        {
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: format!("policy_engine:{}", p.engine_name),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: 0,
                inflight: None,
                enforce: None,
                config: serde_json::Value::Null,
            });
        }
        if let Some(p) = self
            .cluster_backend
            .as_ref()
            .filter(|p| p.manifest.id == plugin_id)
        {
            return Some(LoadedPluginDetail {
                id: p.manifest.id.clone(),
                version: p.manifest.version.clone(),
                name: p.manifest.name.clone(),
                plugin_class: "cluster".to_owned(),
                tier: p.tier.to_string(),
                protocol_version: p.manifest.protocol_version.clone(),
                required_capabilities: p
                    .manifest
                    .required_capabilities
                    .iter()
                    .map(|c| c.kind().to_owned())
                    .collect(),
                state: p.state.load().to_string(),
                registered_at_unix_secs: 0,
                inflight: None,
                enforce: None,
                config: serde_json::Value::Null,
            });
        }
        None
    }

    /// Locate a registered plugin's state cell by id.
    fn find_state_cell(&self, plugin_id: &str) -> Option<&AtomicPluginState> {
        self.tool_gate_chain
            .iter()
            .find(|p| p.manifest.id == plugin_id)
            .map(|p| &p.state)
            .or_else(|| {
                self.transform_chain
                    .iter()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.identity_chain
                    .iter()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.backends
                    .values()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.watch_strategies
                    .values()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                // A single plugin id may host multiple http_route
                // entities; `find` returns the first. All entries
                // share the same plugin's lifecycle so any state cell
                // reflects the plugin's state. For per-entity state
                // inspection, callers use `http_route_entries()`.
                self.http_routes
                    .iter()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.audit_sinks
                    .iter()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.stores
                    .iter()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.caches
                    .iter()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.telemetry_sinks
                    .iter()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.log_sinks
                    .iter()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.metrics_sinks
                    .iter()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.secret_providers
                    .iter()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.config_providers
                    .iter()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.transports
                    .iter()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.policy_engines
                    .iter()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.cluster_backend
                    .as_ref()
                    .filter(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.catalog_chain
                    .iter()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.credential_issuers
                    .values()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
            .or_else(|| {
                self.approval_notifiers
                    .values()
                    .find(|p| p.manifest.id == plugin_id)
                    .map(|p| &p.state)
            })
    }

    /// Operator action: mark a registered plugin as disabled.
    ///
    /// Disabled plugins remain loaded (their resources are not
    /// freed) but are skipped during chain evaluation. The state
    /// flip is lock-free — live requests in flight observe the
    /// change at their next chain iteration. Returns an error if
    /// no plugin with the given id is registered or the current
    /// state does not permit the transition to `Disabled`.
    pub fn disable(&self, plugin_id: &str) -> Result<()> {
        let Some(cell) = self.find_state_cell(plugin_id) else {
            anyhow::bail!("plugin '{plugin_id}' is not registered");
        };
        let current = cell.load();
        if !crate::lifecycle::transition_allowed(current, PluginState::Disabled) {
            anyhow::bail!("plugin '{plugin_id}' cannot transition from {current} to disabled");
        }
        cell.store(PluginState::Disabled);
        info!(plugin_id = %plugin_id, previous_state = %current, "plugin disabled");
        Ok(())
    }

    /// Operator action: re-enable a previously disabled plugin.
    ///
    /// Transitions through `Enabled` → `Initialized` → `Active`
    /// atomically; the intermediate states are not observable to
    /// readers (the atomic store is a single write). This is by
    /// design — there is no per-plugin `init()` hook today, so the
    /// states collapse for first-party plugins. When an init hook
    /// is added in a future phase this method splits into a
    /// multi-step progression.
    pub fn enable(&self, plugin_id: &str) -> Result<()> {
        let Some(cell) = self.find_state_cell(plugin_id) else {
            anyhow::bail!("plugin '{plugin_id}' is not registered");
        };
        let current = cell.load();
        if current != PluginState::Disabled {
            anyhow::bail!("plugin '{plugin_id}' is not disabled (current state: {current})");
        }
        cell.store(PluginState::Active);
        info!(plugin_id = %plugin_id, "plugin re-enabled");
        Ok(())
    }

    /// Admin hook: flip a plugin into `Draining`. New chain-eval
    /// calls see `serves_traffic() == false` and skip the plugin
    /// immediately. In-flight calls continue to run and decrement
    /// the in-flight counter on exit.
    ///
    /// Returns a [`DrainToken`] whose [`DrainToken::wait`] blocks
    /// until every in-flight call returns or the caller-supplied
    /// timeout elapses. The caller is responsible for deciding what
    /// to do after the wait — typically a clean [`Self::mark_disabled_after_drain`]
    /// on `Completed`, leaving `Draining` (for operator follow-up)
    /// or a forced `mark_disabled_after_drain` on `TimedOut`.
    ///
    /// Idempotent: if the plugin is already `Draining`, returns a new
    /// token for the same tracker. Refuses to transition from any
    /// state that isn't `Active`, `Degraded`, or `Draining` — e.g.,
    /// `Disabled` plugins don't need draining, and terminal-state
    /// plugins are past the point of useful drain.
    ///
    /// Drain is only wired for the chain plugin classes (tool_gate,
    /// transform, identity_provider). Binding + watch-strategy
    /// plugins have no per-request in-flight counter at the
    /// registry level; operators disable those via the existing
    /// `disable` path.
    pub fn mark_draining(&self, plugin_id: &str) -> Result<DrainToken> {
        let Some(entry) = self.find_chain_plugin_inflight(plugin_id) else {
            anyhow::bail!(
                "plugin '{plugin_id}' is not a chain plugin (binding / watch \
                 plugins don't support drain; use :disable)"
            );
        };
        let (state, tracker) = entry;
        let current = state.load();
        match current {
            PluginState::Active | PluginState::Degraded => {
                state.store(PluginState::Draining);
                info!(
                    plugin_id = %plugin_id,
                    previous_state = %current,
                    inflight = tracker.load(),
                    "plugin drain initiated",
                );
            }
            PluginState::Draining => {
                info!(
                    plugin_id = %plugin_id,
                    inflight = tracker.load(),
                    "plugin already draining; re-issuing token",
                );
            }
            other => {
                anyhow::bail!("plugin '{plugin_id}' cannot transition from {other} to draining");
            }
        }
        Ok(DrainToken {
            plugin_id: plugin_id.to_owned(),
            tracker,
        })
    }

    /// After a successful / timed-out drain, flip the plugin to
    /// `Disabled`. Accepts `Draining` as the only source state (the
    /// caller is expected to have gone through `mark_draining` first).
    ///
    /// If the plugin is already `Disabled`, returns `Ok` idempotently.
    pub fn mark_disabled_after_drain(&self, plugin_id: &str) -> Result<()> {
        let Some(cell) = self.find_state_cell(plugin_id) else {
            anyhow::bail!("plugin '{plugin_id}' is not registered");
        };
        let current = cell.load();
        match current {
            PluginState::Draining => {
                cell.store(PluginState::Disabled);
                info!(
                    plugin_id = %plugin_id,
                    "plugin drain finalised — state is now Disabled",
                );
                Ok(())
            }
            PluginState::Disabled => Ok(()),
            other => {
                anyhow::bail!(
                    "plugin '{plugin_id}' cannot finalise drain from {other}; \
                     expected Draining"
                )
            }
        }
    }

    /// Locate the `(state, inflight)` pair for a chain plugin by id.
    /// Returns `None` for binding / watch-strategy plugins (keyed
    /// maps don't carry an `InflightTracker`) and for unregistered
    /// ids.
    fn find_chain_plugin_inflight(
        &self,
        plugin_id: &str,
    ) -> Option<(&AtomicPluginState, Arc<InflightTracker>)> {
        if let Some(p) = self
            .tool_gate_chain
            .iter()
            .find(|p| p.manifest.id == plugin_id)
        {
            return Some((&p.state, Arc::clone(&p.inflight)));
        }
        if let Some(p) = self
            .transform_chain
            .iter()
            .find(|p| p.manifest.id == plugin_id)
        {
            return Some((&p.state, Arc::clone(&p.inflight)));
        }
        if let Some(p) = self
            .identity_chain
            .iter()
            .find(|p| p.manifest.id == plugin_id)
        {
            return Some((&p.state, Arc::clone(&p.inflight)));
        }
        None
    }

    /// Health-prober hook: flip a plugin from `Active` to `Degraded`.
    ///
    /// A degraded plugin still serves traffic (its state still satisfies
    /// `serves_traffic()`); the flag is purely observational. Operators
    /// and admin endpoints use it to distinguish "plugin is fine" from
    /// "plugin is flapping, probably needs an owner page."
    ///
    /// Idempotent: if the plugin is already `Degraded`, returns `Ok`.
    /// Refuses to transition out of any other state (Disabled plugins
    /// are not probed in the first place; terminal states would be
    /// misleading to mark Degraded — they are already dead).
    pub fn mark_degraded(&self, plugin_id: &str) -> Result<()> {
        let Some(cell) = self.find_state_cell(plugin_id) else {
            anyhow::bail!("plugin '{plugin_id}' is not registered");
        };
        let current = cell.load();
        match current {
            PluginState::Active => {
                cell.store(PluginState::Degraded);
                warn!(
                    plugin_id = %plugin_id,
                    "plugin marked Degraded by health prober",
                );
                Ok(())
            }
            PluginState::Degraded => Ok(()),
            other => {
                anyhow::bail!("plugin '{plugin_id}' cannot transition from {other} to degraded")
            }
        }
    }

    /// Health-prober hook: flip a plugin from `Degraded` back to
    /// `Active` after a successful probe.
    ///
    /// Idempotent: if the plugin is already `Active`, returns `Ok`.
    /// Refuses from any other state (the prober should not resurrect
    /// Disabled or terminal plugins).
    pub fn mark_active(&self, plugin_id: &str) -> Result<()> {
        let Some(cell) = self.find_state_cell(plugin_id) else {
            anyhow::bail!("plugin '{plugin_id}' is not registered");
        };
        let current = cell.load();
        match current {
            PluginState::Degraded => {
                cell.store(PluginState::Active);
                info!(
                    plugin_id = %plugin_id,
                    "plugin recovered — state flipped back to Active",
                );
                Ok(())
            }
            PluginState::Active => Ok(()),
            other => {
                anyhow::bail!("plugin '{plugin_id}' cannot transition from {other} to active")
            }
        }
    }

    /// Drive a single health probe against a registered plugin.
    ///
    /// Dispatches based on the plugin's class:
    ///
    /// - `tool_gate` → `evaluate_pre_dispatch` with a synthetic
    ///   anonymous context + empty arguments. `ProbeOutcome::Pass` if
    ///   the decision is anything except a panic-sentinel Deny
    ///   (`code == PANIC_DENY_CODE`). Normal Deny = healthy plugin
    ///   doing its job.
    /// - `transform` → `transform_arguments`. Pass unless the result
    ///   is `Error { message }` containing the panic sentinel.
    /// - `identity_provider` → `resolve_identity`. Pass unless the
    ///   result is `Invalid { reason }` containing the panic sentinel.
    /// - `binding` / `watch_strategy` → `Unsupported` (no
    ///   meaningful no-arg probe; these are event-driven).
    /// - Disabled plugins → `Skipped`.
    /// - Unregistered plugin id → `ProbeOutcome::NotFound`.
    ///
    /// `probe_timeout` bounds each FFI call; a timeout is recorded as
    /// `ProbeOutcome::Timeout`.
    pub async fn probe_plugin(&self, plugin_id: &str, probe_timeout: Duration) -> ProbeOutcome {
        // Canonical synthetic context used across every probe. Any
        // plugin whose decision depends on these fields specifically
        // will probably just rubber-stamp the call as Allow — which
        // is fine; the probe is checking liveness, not policy.
        let ctx = synthesise_probe_context(plugin_id);
        let args = serde_json::json!({});
        let cfg = serde_json::json!({});

        if let Some(p) = self
            .tool_gate_chain
            .iter()
            .find(|p| p.manifest.id == plugin_id)
        {
            if !p.state.load().serves_traffic() {
                return ProbeOutcome::Skipped {
                    state: p.state.load(),
                };
            }
            let fut = p.instance.evaluate_pre_dispatch(&ctx, &args, None, &cfg);
            return match timeout(probe_timeout, fut).await {
                Err(_) => ProbeOutcome::Timeout,
                Ok(decision) => classify_gate_decision(&decision),
            };
        }

        if let Some(p) = self
            .transform_chain
            .iter()
            .find(|p| p.manifest.id == plugin_id)
        {
            if !p.state.load().serves_traffic() {
                return ProbeOutcome::Skipped {
                    state: p.state.load(),
                };
            }
            let fut = p.instance.transform_arguments(&ctx, &args, &cfg);
            return match timeout(probe_timeout, fut).await {
                Err(_) => ProbeOutcome::Timeout,
                Ok(result) => classify_transform_result(&result),
            };
        }

        if let Some(p) = self
            .identity_chain
            .iter()
            .find(|p| p.manifest.id == plugin_id)
        {
            if !p.state.load().serves_traffic() {
                return ProbeOutcome::Skipped {
                    state: p.state.load(),
                };
            }
            let metadata = mcpg_plugin_protocol::types::RequestMetadata::default();
            let fut = p.instance.resolve_identity(&[], &metadata, &cfg);
            return match timeout(probe_timeout, fut).await {
                Err(_) => ProbeOutcome::Timeout,
                Ok(resolution) => classify_identity_resolution(&resolution),
            };
        }

        if self.backends.values().any(|p| p.manifest.id == plugin_id)
            || self
                .content_stores
                .values()
                .any(|p| p.manifest.id == plugin_id)
            || self
                .watch_strategies
                .values()
                .any(|p| p.manifest.id == plugin_id)
        {
            return ProbeOutcome::Unsupported;
        }

        ProbeOutcome::NotFound
    }

    /// Plugin ids currently registered, in deterministic order across
    /// classes (tool_gate → transform → identity → binding → watch
    /// → http_route). Used by the health prober to iterate without
    /// holding chain references across await points.
    ///
    /// http_route plugins that expose multiple entities surface once
    /// per (plugin_id, entity_name) pair — each entity is a
    /// separately-state'd registration, and the health prober's
    /// ProbeOutcome::Unsupported path already covers the no-no-op-
    /// probe case for non-chain kinds.
    pub fn registered_plugin_ids(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        out.extend(self.tool_gate_chain.iter().map(|p| p.manifest.id.clone()));
        out.extend(self.transform_chain.iter().map(|p| p.manifest.id.clone()));
        out.extend(self.identity_chain.iter().map(|p| p.manifest.id.clone()));
        out.extend(self.backends.values().map(|p| p.manifest.id.clone()));
        out.extend(self.content_stores.values().map(|p| p.manifest.id.clone()));
        out.extend(
            self.watch_strategies
                .values()
                .map(|p| p.manifest.id.clone()),
        );
        out.extend(self.http_routes.iter().map(|p| p.manifest.id.clone()));
        out.extend(self.audit_sinks.iter().map(|p| p.manifest.id.clone()));
        out.extend(self.stores.iter().map(|p| p.manifest.id.clone()));
        out.extend(self.caches.iter().map(|p| p.manifest.id.clone()));
        out.extend(self.telemetry_sinks.iter().map(|p| p.manifest.id.clone()));
        out.extend(self.log_sinks.iter().map(|p| p.manifest.id.clone()));
        out.extend(self.metrics_sinks.iter().map(|p| p.manifest.id.clone()));
        out.extend(self.secret_providers.iter().map(|p| p.manifest.id.clone()));
        out.extend(self.config_providers.iter().map(|p| p.manifest.id.clone()));
        out.extend(self.transports.iter().map(|p| p.manifest.id.clone()));
        out.extend(self.policy_engines.iter().map(|p| p.manifest.id.clone()));
        out.extend(self.catalog_chain.iter().map(|p| p.manifest.id.clone()));
        out.extend(
            self.credential_issuers
                .values()
                .map(|p| p.manifest.id.clone()),
        );
        out.extend(
            self.approval_notifiers
                .values()
                .map(|p| p.manifest.id.clone()),
        );
        if let Some(p) = &self.cluster_backend {
            out.push(p.manifest.id.clone());
        }
        out
    }

    /// Cross-check a [`PluginDescriptor`] against an already-
    /// registered plugin's runtime manifest.
    ///
    /// Returns `Ok(())` if the descriptor and manifest agree on
    /// identity / class / protocol / capabilities, or a structured
    /// error otherwise. Intended to be called at startup when a
    /// plugin ships a `plugin.yaml` alongside its code so packaging
    /// drift is caught before the gateway begins serving traffic.
    ///
    /// The plugin id in the descriptor must already be registered;
    /// unregistered ids return an error.
    pub fn validate_registered_descriptor(&self, descriptor: &PluginDescriptor) -> Result<()> {
        let manifest = self.find_manifest(&descriptor.id).ok_or_else(|| {
            anyhow::anyhow!(
                "descriptor refers to unregistered plugin id: {}",
                descriptor.id
            )
        })?;
        validate_descriptor(descriptor, manifest)
            .map_err(|e| anyhow::anyhow!("descriptor / manifest mismatch: {e}"))
    }

    fn find_manifest(&self, id: &str) -> Option<&PluginManifest> {
        self.iter_manifests().find(|m| m.id == id)
    }

    /// Iterate over every registered plugin's manifest across all
    /// entity-kind chains. Backs the gateway's
    /// observability bridges, which build a `module_path_prefix →
    /// plugin_id` map after registration to attribute events back
    /// to their source plugin. Public so the gateway boot path
    /// can call it; internal callers (`find_manifest`) reuse it.
    pub fn iter_manifests(&self) -> impl Iterator<Item = &PluginManifest> {
        self.tool_gate_chain
            .iter()
            .map(|p| &p.manifest)
            .chain(self.transform_chain.iter().map(|p| &p.manifest))
            .chain(self.identity_chain.iter().map(|p| &p.manifest))
            .chain(self.backends.values().map(|p| &p.manifest))
            .chain(self.content_stores.values().map(|p| &p.manifest))
            .chain(self.watch_strategies.values().map(|p| &p.manifest))
            // http_route plugins can host multiple entities under one
            // id; iteration may yield the same manifest more than
            // once. Callers building a HashMap deduplicate by id.
            .chain(self.http_routes.iter().map(|p| &p.manifest))
            .chain(self.audit_sinks.iter().map(|p| &p.manifest))
            .chain(self.stores.iter().map(|p| &p.manifest))
            .chain(self.caches.iter().map(|p| &p.manifest))
            .chain(self.telemetry_sinks.iter().map(|p| &p.manifest))
            .chain(self.log_sinks.iter().map(|p| &p.manifest))
            .chain(self.metrics_sinks.iter().map(|p| &p.manifest))
            .chain(self.secret_providers.iter().map(|p| &p.manifest))
            .chain(self.config_providers.iter().map(|p| &p.manifest))
            .chain(self.transports.iter().map(|p| &p.manifest))
            .chain(self.policy_engines.iter().map(|p| &p.manifest))
            .chain(self.cluster_backend.iter().map(|p| &p.manifest))
            .chain(self.catalog_chain.iter().map(|p| &p.manifest))
            .chain(self.credential_issuers.values().map(|p| &p.manifest))
            .chain(self.approval_notifiers.values().map(|p| &p.manifest))
    }

    /// Return manifests for all loaded tool-gate plugins.
    pub fn tool_gate_manifests(&self) -> Vec<&PluginManifest> {
        self.tool_gate_chain.iter().map(|p| &p.manifest).collect()
    }

    // -----------------------------------------------------------------------
    // Chain evaluation — Tool Gates
    // -----------------------------------------------------------------------

    /// Evaluate the pre-dispatch tool-gate chain.
    ///
    /// Iterates plugins in registration order. The first non-Allow decision
    /// (Deny or Challenge) short-circuits the chain.
    pub async fn evaluate_tool_gates_pre(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        meta: Option<&serde_json::Value>,
    ) -> GateDecision {
        if self.tool_gate_chain.is_empty() {
            // No chain → emit the success event so empty-chain
            // deploys still get tool-call audit coverage.
            if self.audit_emit_tool_call_allowed {
                let event = crate::audit_events::tool_gate_allowed_event(ctx, 0, &[]);
                let _ = self.emit_audit_event(&event).await;
            }
            return GateDecision::allow();
        }

        let mut merged_metadata: Option<serde_json::Value> = None;
        let mut evaluated: usize = 0;
        // GateDecision::Allow can carry per-plugin mutations the protocol
        // advertises as functional. Thread them through the
        // chain instead of dropping them:
        // - `modified_arguments` rewrites the tool arguments for every
        //   subsequent gate AND for the backend (the dispatch site applies the
        //   returned value). `current_args` carries the running rewrite.
        // - `modified_result` is a pre-dispatch short-circuit (e.g. the
        //   response-cache plugin returning a cached result) — the dispatch
        //   site skips the backend when it's set.
        let mut current_args = arguments.clone();
        let mut args_modified = false;
        let mut chain_modified_result: Option<serde_json::Value> = None;
        // Accumulate per-plugin audit entries so the
        // tool.call.allowed event carries the full chain trace.
        let mut chain: Vec<crate::audit_events::ChainEntry> = Vec::new();

        for loaded in &self.tool_gate_chain {
            if !loaded.state.serves_traffic() {
                continue;
            }
            // In-flight counter for graceful drain. Guard drops on
            // any exit path after the await, wakes drain waiters
            // when the counter reaches zero.
            let _inflight = InflightGuard::acquire(&loaded.inflight);
            let start = Instant::now();
            let decision = loaded
                .instance
                .evaluate_pre_dispatch(ctx, &current_args, meta, &loaded.config)
                .await;
            let elapsed_ms = start.elapsed().as_millis();

            metrics::counter!(
                "mcpg_plugin_evaluations_total",
                "plugin_id" => loaded.manifest.id.clone(),
                "phase" => "pre_dispatch",
                "decision" => decision_label(&decision),
            )
            .increment(1);
            chain.push(crate::audit_events::ChainEntry {
                plugin_id: loaded.manifest.id.clone(),
                phase: "pre_dispatch",
                decision: decision_label(&decision),
                latency_ms: elapsed_ms as u64,
            });

            if elapsed_ms > 50 {
                warn!(
                    plugin_id = %loaded.manifest.id,
                    elapsed_ms = %elapsed_ms,
                    "slow plugin evaluation"
                );
            }

            match decision {
                GateDecision::Allow {
                    metadata,
                    modified_arguments,
                    modified_result,
                } => {
                    evaluated += 1;
                    // Carry per-plugin mutations forward (see the chain setup
                    // above). A later gate evaluates against the rewritten args;
                    // a pre-dispatch modified_result short-circuits the backend.
                    if let Some(args) = modified_arguments {
                        current_args = args;
                        args_modified = true;
                    }
                    if let Some(res) = modified_result {
                        chain_modified_result = Some(res);
                    }
                    // Payment plugins specifically
                    // need a PCI-DSS-shaped audit event (`mcpg.payment.charged`)
                    // alongside the generic tool-gate audit. Detect by
                    // plugin id prefix; non-payment plugins fall through
                    // unchanged.
                    if loaded.manifest.id.starts_with("dev.mcpg.payment.") {
                        let event = crate::audit_events::payment_outcome_event(
                            ctx,
                            &loaded.manifest.id,
                            true,
                            metadata.as_ref(),
                            None,
                        );
                        let _ = self.emit_audit_event(&event).await;
                    }
                    // Collect metadata from allow decisions (e.g. payment receipts)
                    if let Some(plugin_meta) = metadata {
                        merged_metadata = Some(match merged_metadata {
                            Some(existing) => merge_json_objects(existing, plugin_meta),
                            None => plugin_meta,
                        });
                    }
                    continue;
                }
                // Short-circuit — pause the chain and
                // surface the PendingApproval to the gateway's
                // approval state machine. The gateway intercepts
                // before any further chain evaluation runs.
                GateDecision::PendingApproval { .. } => {
                    info!(
                        plugin_id = %loaded.manifest.id,
                        tool_name = %ctx.tool_name,
                        elapsed_ms = %elapsed_ms,
                        "tool-gate plugin requested human approval"
                    );
                    return decision;
                }
                GateDecision::Deny { .. } | GateDecision::Challenge { .. } => {
                    if !loaded.enforce {
                        // Shadow mode: log the decision but override to Allow
                        info!(
                            plugin_id = %loaded.manifest.id,
                            tool_name = %ctx.tool_name,
                            shadow = true,
                            decision = decision_label(&decision),
                            elapsed_ms = %elapsed_ms,
                            "shadow evaluation: would deny/challenge but allowing"
                        );
                        metrics::counter!(
                            "mcpg_shadow_evaluations_total",
                            "plugin_id" => loaded.manifest.id.clone(),
                            "decision" => decision_label(&decision),
                        )
                        .increment(1);
                        continue;
                    }
                    info!(
                        plugin_id = %loaded.manifest.id,
                        tool_name = %ctx.tool_name,
                        decision = decision_label(&decision),
                        elapsed_ms = %elapsed_ms,
                        "tool-gate plugin short-circuited"
                    );
                    // Fan the short-circuit out to every audit
                    // sink — `mcpg.tool.call.denied` +
                    // `mcpg.tool.call.challenged` are both
                    // compliance-relevant (SOC2 / HIPAA auditors
                    // want every access refusal on record).
                    let (action, outcome) = match &decision {
                        GateDecision::Deny { .. } => (
                            "mcpg.tool.call.denied",
                            mcpg_plugin_protocol::audit::AuditOutcome::Denied,
                        ),
                        GateDecision::Challenge { .. } => (
                            "mcpg.tool.call.challenged",
                            mcpg_plugin_protocol::audit::AuditOutcome::Partial,
                        ),
                        _ => unreachable!(),
                    };
                    let event = crate::audit_events::tool_gate_event(
                        ctx,
                        &loaded.manifest.id,
                        action,
                        outcome,
                        decision_details(&decision),
                    );
                    let _ = self.emit_audit_event(&event).await;
                    // Record a payment-specific failure
                    // per PCI-DSS 10.2.2. Distinct from the
                    // generic tool.call.denied above so auditor
                    // queries on `action LIKE 'mcpg.payment.%'`
                    // capture all payment activity.
                    if loaded.manifest.id.starts_with("dev.mcpg.payment.") {
                        let deny_reason = match &decision {
                            GateDecision::Deny { message, .. }
                            | GateDecision::Challenge { message, .. } => Some(message.as_str()),
                            _ => None,
                        };
                        let payment_event = crate::audit_events::payment_outcome_event(
                            ctx,
                            &loaded.manifest.id,
                            false,
                            None,
                            deny_reason,
                        );
                        let _ = self.emit_audit_event(&payment_event).await;
                    }
                    return decision;
                }
            }
        }

        // All plugins allowed — emit the success audit event
        // (gated on operator config; default ON for compliance
        // posture) and return the merged metadata.
        if self.audit_emit_tool_call_allowed {
            let event = crate::audit_events::tool_gate_allowed_event(ctx, evaluated, &chain);
            let _ = self.emit_audit_event(&event).await;
        }
        GateDecision::Allow {
            modified_arguments: if args_modified {
                Some(current_args)
            } else {
                None
            },
            modified_result: chain_modified_result,
            metadata: merged_metadata,
        }
    }

    /// Evaluate the post-dispatch tool-gate chain.
    pub async fn evaluate_tool_gates_post(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        result: &serde_json::Value,
        execution_duration_ms: u64,
    ) -> GateDecision {
        if self.tool_gate_chain.is_empty() {
            if self.audit_emit_tool_call_completed {
                let event = crate::audit_events::tool_gate_completed_event(
                    ctx,
                    0,
                    execution_duration_ms,
                    &[],
                );
                let _ = self.emit_audit_event(&event).await;
            }
            return GateDecision::allow();
        }

        let mut evaluated: usize = 0;
        // A post-dispatch gate may rewrite the tool result via
        // Allow.modified_result (e.g. guardrails/masking redacting output).
        // Thread it: each gate sees the running rewrite, and the accumulated
        // result is returned for the dispatch site to send to the client.
        let mut current_result = result.clone();
        let mut result_modified = false;
        // Accumulate post-dispatch chain entries for the audit trace.
        let mut chain: Vec<crate::audit_events::ChainEntry> = Vec::new();

        for loaded in &self.tool_gate_chain {
            if !loaded.state.serves_traffic() {
                continue;
            }
            // In-flight counter for graceful drain. Guard drops on
            // any exit path after the await, wakes drain waiters
            // when the counter reaches zero.
            let _inflight = InflightGuard::acquire(&loaded.inflight);
            let start = Instant::now();
            let decision = loaded
                .instance
                .evaluate_post_dispatch(
                    ctx,
                    arguments,
                    &current_result,
                    execution_duration_ms,
                    &loaded.config,
                )
                .await;
            let elapsed_ms = start.elapsed().as_millis();

            metrics::counter!(
                "mcpg_plugin_evaluations_total",
                "plugin_id" => loaded.manifest.id.clone(),
                "phase" => "post_dispatch",
                "decision" => decision_label(&decision),
            )
            .increment(1);
            chain.push(crate::audit_events::ChainEntry {
                plugin_id: loaded.manifest.id.clone(),
                phase: "post_dispatch",
                decision: decision_label(&decision),
                latency_ms: elapsed_ms as u64,
            });

            match &decision {
                GateDecision::Allow {
                    modified_result, ..
                } => {
                    evaluated += 1;
                    // A post gate may rewrite the result; carry it to the next
                    // gate and to the terminal return.
                    if let Some(r) = modified_result {
                        current_result = r.clone();
                        result_modified = true;
                    }
                    continue;
                }
                GateDecision::PendingApproval { .. } => {
                    // Post-dispatch PendingApproval is a plugin
                    // bug — by post-dispatch the tool already
                    // ran. Log + treat as Deny so the result
                    // doesn't leak to the caller.
                    warn!(
                        plugin_id = %loaded.manifest.id,
                        tool_name = %ctx.tool_name,
                        "post-dispatch tool_gate returned PendingApproval — \
                         not a valid post-dispatch decision; treating as deny"
                    );
                    return GateDecision::Deny {
                        http_status: 500,
                        code: -33000,
                        message: format!(
                            "post-dispatch plugin '{}' returned an invalid \
                             PendingApproval decision",
                            loaded.manifest.id
                        ),
                        error_data: None,
                    };
                }
                GateDecision::Deny { .. } | GateDecision::Challenge { .. } => {
                    if !loaded.enforce {
                        // Shadow mode: log the decision but override to Allow.
                        info!(
                            plugin_id = %loaded.manifest.id,
                            tool_name = %ctx.tool_name,
                            shadow = true,
                            decision = decision_label(&decision),
                            elapsed_ms = %elapsed_ms,
                            "shadow post-dispatch: would deny/challenge but allowing"
                        );
                        metrics::counter!(
                            "mcpg_shadow_evaluations_total",
                            "plugin_id" => loaded.manifest.id.clone(),
                            "decision" => decision_label(&decision),
                        )
                        .increment(1);
                        continue;
                    }
                    info!(
                        plugin_id = %loaded.manifest.id,
                        tool_name = %ctx.tool_name,
                        decision = decision_label(&decision),
                        elapsed_ms = %elapsed_ms,
                        "post-dispatch plugin short-circuited"
                    );
                    return decision;
                }
            }
        }

        // Whole post-dispatch chain accepted — emit the completion
        // event for compliance + observability.
        if self.audit_emit_tool_call_completed {
            let event = crate::audit_events::tool_gate_completed_event(
                ctx,
                evaluated,
                execution_duration_ms,
                &chain,
            );
            let _ = self.emit_audit_event(&event).await;
        }
        GateDecision::Allow {
            modified_arguments: None,
            modified_result: if result_modified {
                Some(current_result)
            } else {
                None
            },
            metadata: None,
        }
    }

    // -----------------------------------------------------------------------
    // Chain evaluation — Transforms
    // -----------------------------------------------------------------------

    /// Apply pre-dispatch transforms to arguments.
    ///
    /// Transforms are applied in order; each transform receives the output
    /// of the previous one. An error from any transform logs a warning and
    /// returns the last-good value.
    pub async fn apply_transforms_pre(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
    ) -> serde_json::Value {
        if self.transform_chain.is_empty() {
            return arguments.clone();
        }

        let mut current = arguments.clone();
        for loaded in &self.transform_chain {
            if !loaded.state.serves_traffic() {
                continue;
            }
            // In-flight counter for graceful drain. Guard drops on
            // any exit path after the await, wakes drain waiters
            // when the counter reaches zero.
            let _inflight = InflightGuard::acquire(&loaded.inflight);
            // Wrap each transform plugin call in a
            // plugin-scoped span so traces (and the outcome counter
            // / latency histogram) attribute back to the plugin id
            // for per-plugin observability override. WASM transform
            // plugins (e.g. transform-masking) emit nothing
            // themselves; this host-side wrapper is the canonical
            // emit point for their triad.
            let span = tracing::info_span!(
                "transform_apply_pre",
                plugin_id = %loaded.manifest.id,
                tool = %ctx.tool_name,
            );
            let started = std::time::Instant::now();
            let result = loaded
                .instance
                .transform_arguments(ctx, &current, &loaded.config)
                .instrument(span)
                .await;
            let elapsed = started.elapsed();
            let outcome = match &result {
                TransformResult::Unchanged => "unchanged",
                TransformResult::Modified { .. } => "modified",
                TransformResult::Error { .. } => "error",
            };
            metrics::counter!(
                "mcpg_transform_applies_total",
                "plugin_id" => loaded.manifest.id.to_string(),
                "phase" => "pre",
                "outcome" => outcome,
            )
            .increment(1);
            metrics::histogram!(
                "mcpg_transform_apply_ms",
                "plugin_id" => loaded.manifest.id.to_string(),
                "phase" => "pre",
            )
            .record(elapsed.as_millis() as f64);
            match result {
                TransformResult::Unchanged => {}
                TransformResult::Modified { value } => {
                    // Record what changed on the audit lane (hash-only,
                    // no plaintext). The transform
                    // plugin id attributes the rewrite for replay.
                    let event = crate::audit_events::transform_applied_event(
                        ctx,
                        &loaded.manifest.id,
                        "pre",
                        &current,
                        &value,
                    );
                    let _ = self.emit_audit_event(&event).await;
                    current = value;
                }
                TransformResult::Error { message } => {
                    warn!(
                        plugin_id = %loaded.manifest.id,
                        error = %message,
                        "transform plugin error in pre-dispatch"
                    );
                }
            }
        }
        current
    }

    /// Apply post-dispatch transforms to results.
    pub async fn apply_transforms_post(
        &self,
        ctx: &PluginContext,
        result: &serde_json::Value,
    ) -> serde_json::Value {
        if self.transform_chain.is_empty() {
            return result.clone();
        }

        let mut current = result.clone();
        for loaded in &self.transform_chain {
            if !loaded.state.serves_traffic() {
                continue;
            }
            // In-flight counter for graceful drain. Guard drops on
            // any exit path after the await, wakes drain waiters
            // when the counter reaches zero.
            let _inflight = InflightGuard::acquire(&loaded.inflight);
            let span = tracing::info_span!(
                "transform_apply_post",
                plugin_id = %loaded.manifest.id,
                tool = %ctx.tool_name,
            );
            let started = std::time::Instant::now();
            let outcome_value = loaded
                .instance
                .transform_result(ctx, &current, &loaded.config)
                .instrument(span)
                .await;
            let elapsed = started.elapsed();
            let outcome = match &outcome_value {
                TransformResult::Unchanged => "unchanged",
                TransformResult::Modified { .. } => "modified",
                TransformResult::Error { .. } => "error",
            };
            metrics::counter!(
                "mcpg_transform_applies_total",
                "plugin_id" => loaded.manifest.id.to_string(),
                "phase" => "post",
                "outcome" => outcome,
            )
            .increment(1);
            metrics::histogram!(
                "mcpg_transform_apply_ms",
                "plugin_id" => loaded.manifest.id.to_string(),
                "phase" => "post",
            )
            .record(elapsed.as_millis() as f64);
            match outcome_value {
                TransformResult::Unchanged => {}
                TransformResult::Modified { value } => {
                    // Audit the rewrite — see the pre-dispatch sibling.
                    let event = crate::audit_events::transform_applied_event(
                        ctx,
                        &loaded.manifest.id,
                        "post",
                        &current,
                        &value,
                    );
                    let _ = self.emit_audit_event(&event).await;
                    current = value;
                }
                TransformResult::Error { message } => {
                    warn!(
                        plugin_id = %loaded.manifest.id,
                        error = %message,
                        "transform plugin error in post-dispatch"
                    );
                }
            }
        }
        current
    }

    // -----------------------------------------------------------------------
    // Chain evaluation — Identity
    // -----------------------------------------------------------------------

    /// Attempt identity resolution via the identity plugin chain.
    ///
    /// The first plugin to return `Resolved` wins, and `None` falls through
    /// to the next plugin. An `Invalid` **stops** the chain: a credential a
    /// plugin explicitly rejected must not be re-adjudicated by a laxer one,
    /// and must not be indistinguishable from presenting no credential at
    /// all. This mirrors the transport-level cascade, where a bearer that
    /// claims an issuer never falls through to another verifier.
    pub async fn resolve_identity(
        &self,
        headers: &[(String, String)],
        metadata: &mcpg_plugin_protocol::types::RequestMetadata,
    ) -> ChainIdentityOutcome {
        for loaded in &self.identity_chain {
            if !loaded.state.serves_traffic() {
                continue;
            }
            // In-flight counter for graceful drain. Guard drops on
            // any exit path after the await, wakes drain waiters
            // when the counter reaches zero.
            let _inflight = InflightGuard::acquire(&loaded.inflight);
            match loaded
                .instance
                .resolve_identity(headers, metadata, &loaded.config)
                .await
            {
                IdentityResolution::Resolved { identity } => {
                    info!(
                        plugin_id = %loaded.manifest.id,
                        subject_id = ?identity.subject_id,
                        "identity resolved by plugin"
                    );
                    return ChainIdentityOutcome::Resolved(identity);
                }
                IdentityResolution::None => continue,
                IdentityResolution::Invalid { reason } => {
                    warn!(
                        plugin_id = %loaded.manifest.id,
                        reason = %reason,
                        "identity plugin rejected token"
                    );
                    return ChainIdentityOutcome::Rejected {
                        plugin_id: loaded.manifest.id.clone(),
                        reason,
                    };
                }
            }
        }
        ChainIdentityOutcome::NoCredential
    }

    // -----------------------------------------------------------------------
    // Validation helpers
    // -----------------------------------------------------------------------

    fn validate_manifest(&self, manifest: &PluginManifest) -> Result<()> {
        if manifest.id.is_empty() {
            anyhow::bail!("plugin manifest has empty id");
        }
        if manifest.version.is_empty() {
            anyhow::bail!("plugin '{}' has empty version", manifest.id);
        }
        // Accept any 1.x protocol version (additive changes only).
        // A major bump (2.0+) will require explicit host upgrade.
        if !manifest.protocol_version.starts_with("1.") {
            anyhow::bail!(
                "plugin '{}' declares protocol_version {:?} but host only supports 1.x",
                manifest.id,
                manifest.protocol_version,
            );
        }
        // WARN when the reported protocol_version is older
        // than the host's current PROTOCOL_VERSION. Plugins compiled
        // against an older minor version still load (additive ABI),
        // but operators should know which plugins lag — a stale plugin
        // misses post-bump fields with their default values rather than
        // the operator-supplied ones.
        //
        // DORMANT DURING THE FREEZE: a cdylib's `manifest.protocol_version`
        // is the SDK constant it compiled against (see `make_manifest!`), so
        // this WARN only fires once the protocol version unfreezes AND a
        // plugin built against an older SDK loads on a newer host. While the
        // version is pinned at "1.0" everywhere, manifest == host constant
        // and this branch never trips — by design, not a bug.
        if manifest.protocol_version != mcpg_plugin_protocol::PROTOCOL_VERSION {
            warn!(
                plugin_id = %manifest.id,
                plugin_version = %manifest.version,
                reported_protocol_version = %manifest.protocol_version,
                host_protocol_version = mcpg_plugin_protocol::PROTOCOL_VERSION,
                "plugin reports stale protocol_version (compiled against older host); rebuild against current SDK to pick up post-bump fields"
            );
        }
        // WARN when a non-builtin plugin is missing
        // `module_path_prefix`. Builtins (`dev.mcpg.builtin.*`) skip the
        // warning because the gateway maps their tracing events to the
        // `core` pseudo-id by design; everyone else needs the prefix or
        // operators can't aim per-plugin observability overrides at
        // them and audit grep on plugin-specific log lines is harder.
        if manifest.module_path_prefix.is_empty() && !manifest.id.starts_with("dev.mcpg.builtin.") {
            warn!(
                plugin_id = %manifest.id,
                plugin_version = %manifest.version,
                "plugin manifest is missing `module_path_prefix`; per-plugin observability overrides will not work and tracing events from this plugin attribute to `core` instead of its plugin id"
            );
        }
        Ok(())
    }

    /// Check that no other registered plugin in the chain/kind-keyed
    /// registries already uses this alias. The check keys
    /// on the operator-supplied alias via `LoadedPlugin.alias` so
    /// multi-instance configs (two entries pointing at the same
    /// artifact under distinct aliases) succeed.
    ///
    /// J.1.4 — every non-chain registry slot now carries an `alias`
    /// field (defaults to `manifest.id`), so duplicate-detection
    /// reads the alias uniformly across chains, kind-keyed maps,
    /// and Vec-of-plugin slots.
    fn check_duplicate_alias(&self, alias: &str) -> Result<()> {
        let exists = self.tool_gate_chain.iter().any(|p| p.alias == alias)
            || self.transform_chain.iter().any(|p| p.alias == alias)
            || self.identity_chain.iter().any(|p| p.alias == alias)
            || self.catalog_chain.iter().any(|p| p.alias == alias)
            || self.backends.values().any(|p| p.alias == alias)
            || self.content_stores.values().any(|p| p.alias == alias)
            || self.watch_strategies.values().any(|p| p.alias == alias)
            || self.http_routes.iter().any(|p| p.alias == alias)
            || self.audit_sinks.iter().any(|p| p.alias == alias)
            || self.stores.iter().any(|p| p.alias == alias)
            || self.caches.iter().any(|p| p.alias == alias)
            || self.telemetry_sinks.iter().any(|p| p.alias == alias)
            || self.log_sinks.iter().any(|p| p.alias == alias)
            || self.metrics_sinks.iter().any(|p| p.alias == alias)
            || self.secret_providers.iter().any(|p| p.alias == alias)
            || self.config_providers.iter().any(|p| p.alias == alias)
            || self.transports.iter().any(|p| p.alias == alias)
            || self.policy_engines.iter().any(|p| p.alias == alias)
            || self.credential_issuers.values().any(|p| p.alias == alias)
            || self.approval_notifiers.values().any(|p| p.alias == alias)
            || self
                .cluster_backend
                .as_ref()
                .is_some_and(|p| p.alias == alias);
        if exists {
            // Wording deliberately includes both "duplicate" and "already
            // registered" so the existing per-kind duplicate-id rejection
            // tests continue to pass after the per-kind in-place checks
            // were collapsed into this single alias-level check.
            anyhow::bail!("duplicate plugin: alias '{}' is already registered", alias);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Reject a non-builtin plugin that tries to serve a reserved scheme
/// (`env://`, `file://`).
///
/// Those schemes route to the gateway's built-in inline secret/config
/// resolvers; letting a third-party plugin bind them would let it shadow
/// secret + config resolution gateway-wide (a config-origin / credential-exfil
/// vector). Built-in providers (`dev.mcpg.builtin.*`) are the legitimate owners
/// and are exempt. Enforced on the auto-bind path — the production route by
/// which a registered plugin's `supported_schemes()` become live bindings.
fn reject_reserved_scheme(class: &str, scheme: &str, plugin_id: &str) -> Result<()> {
    if crate::uri_routing::RESERVED_SCHEMES.contains(&scheme)
        && !plugin_id.starts_with("dev.mcpg.builtin.")
    {
        anyhow::bail!(
            "{class} plugin '{plugin_id}' claims reserved scheme '{scheme}://' — \
             env:// and file:// are reserved for the gateway's built-in resolvers \
             and cannot be served by a plugin"
        );
    }
    Ok(())
}

/// Cross-check a secret/config provider's static `provides_schemes`
/// declaration against its runtime `supported_schemes()` at registration,
/// fail-closed (the secret/config analogue of the cluster `provides`
/// cross-check).
///
/// `supported_schemes()` (FFI-carried) is the authoritative live routing
/// surface; `provides_schemes` is the static descriptor/manifest mirror
/// surfaced to catalogs and `mcpg-config`. When a provider declares
/// `provides_schemes`, it MUST match the scheme set it actually serves —
/// otherwise the catalog advertises a routing claim the runtime won't
/// honour. An empty `provides_schemes` opts out (the field is optional;
/// `supported_schemes()` stays authoritative).
fn cross_check_provides_schemes(
    class: &str,
    plugin_id: &str,
    provides_schemes: &[String],
    supported_schemes: &[String],
) -> Result<()> {
    if provides_schemes.is_empty() {
        return Ok(());
    }
    let declared: std::collections::BTreeSet<&str> =
        provides_schemes.iter().map(String::as_str).collect();
    let actual: std::collections::BTreeSet<&str> =
        supported_schemes.iter().map(String::as_str).collect();
    if declared != actual {
        anyhow::bail!(
            "{class} plugin '{plugin_id}' scheme drift: manifest \
             provides_schemes={provides_schemes:?} but \
             supported_schemes()={supported_schemes:?} — the static declaration \
             must match the scheme set the plugin actually serves"
        );
    }
    Ok(())
}

/// Emit the per-dispatch counter + latency histogram for a
/// telemetry sink. Op is one of `"span_started"`, `"span_ended"`,
/// `"metric_recorded"`. Failure metrics land from the `flush`
/// path (`emit_*` methods are infallible on the trait).
fn record_telemetry_dispatch(sink_id: &str, op: &'static str, elapsed: std::time::Duration) {
    metrics::counter!(
        "mcpg_telemetry_sink_events_total",
        "sink_id" => sink_id.to_owned(),
        "op" => op,
    )
    .increment(1);
    metrics::histogram!(
        "mcpg_telemetry_sink_dispatch_latency_seconds",
        "sink_id" => sink_id.to_owned(),
        "op" => op,
    )
    .record(elapsed.as_secs_f64());
}

/// Emit the per-dispatch counter + latency histogram for a log
/// sink. Logs have a single op (`emit`) so no `op` label here —
/// `sink_id` is the only variable dimension.
fn record_log_dispatch(sink_id: &str, elapsed: std::time::Duration) {
    metrics::counter!(
        "mcpg_log_sink_records_total",
        "sink_id" => sink_id.to_owned(),
    )
    .increment(1);
    metrics::histogram!(
        "mcpg_log_sink_dispatch_latency_seconds",
        "sink_id" => sink_id.to_owned(),
    )
    .record(elapsed.as_secs_f64());
}

/// Emit the per-dispatch counter + latency histogram for a metrics
/// sink. Symmetric to [`record_log_dispatch`] — the trait has a
/// single `emit` op so `sink_id` is the only variable dimension.
fn record_metrics_dispatch(sink_id: &str, elapsed: std::time::Duration) {
    metrics::counter!(
        "mcpg_metrics_sink_records_total",
        "sink_id" => sink_id.to_owned(),
    )
    .increment(1);
    metrics::histogram!(
        "mcpg_metrics_sink_dispatch_latency_seconds",
        "sink_id" => sink_id.to_owned(),
    )
    .record(elapsed.as_secs_f64());
}

/// Return value of `PluginRegistry::evaluate_policy_chain`. Used
/// by the gateway runtime to short-circuit a tool call on a Deny
/// or to record the deciding engine + policy_version on Allow.
#[derive(Debug, Clone)]
pub enum PolicyChainOutcome {
    /// At least one engine returned `Allow`; no engine denied.
    /// `engine` is the FIRST engine that allowed (chain order);
    /// downstream `NotApplicable` doesn't downgrade the result.
    Allow {
        engine: String,
        policy_version: String,
    },
    /// Some engine returned `Deny`. Chain short-circuits at the
    /// first deny.
    Deny {
        engine: String,
        reason: String,
        policy_version: String,
    },
    /// All engines returned `NotApplicable` (or the chain was
    /// empty / all engines were unknown). Caller decides whether
    /// to treat this as Allow (default) or as Deny (strict).
    NotApplicable,
}

fn policy_effect_label(e: &mcpg_plugin_protocol::policy::PolicyEffect) -> &'static str {
    match e {
        mcpg_plugin_protocol::policy::PolicyEffect::Allow => "allow",
        mcpg_plugin_protocol::policy::PolicyEffect::Deny => "deny",
        mcpg_plugin_protocol::policy::PolicyEffect::NotApplicable => "not_applicable",
    }
}

fn decision_label(d: &GateDecision) -> &'static str {
    match d {
        GateDecision::Allow { .. } => "allow",
        GateDecision::Deny { .. } => "deny",
        GateDecision::Challenge { .. } => "challenge",
        GateDecision::PendingApproval { .. } => "pending_approval",
    }
}

/// Condense a `GateDecision` into the structured detail blob every
/// audit event attaches. Keeps the blob stable across trait
/// evolution: if new decision variants land, callers keep working.
fn decision_details(d: &GateDecision) -> serde_json::Value {
    match d {
        GateDecision::Allow { .. } => serde_json::json!({ "decision": "allow" }),
        GateDecision::Deny {
            http_status,
            code,
            message,
            ..
        } => serde_json::json!({
            "decision": "deny",
            "http_status": http_status,
            "code": code,
            "message": message,
        }),
        GateDecision::Challenge {
            http_status,
            code,
            message,
            ..
        } => serde_json::json!({
            "decision": "challenge",
            "http_status": http_status,
            "code": code,
            "message": message,
        }),
        GateDecision::PendingApproval {
            approval_id,
            deadline_at,
            summary,
            ..
        } => serde_json::json!({
            "decision": "pending_approval",
            "approval_id": approval_id,
            "deadline_at": deadline_at,
            "summary": summary,
        }),
    }
}

/// Drain a single plugin with a bounded timeout, recording the
/// outcome in `report`.
async fn drain_one(
    id: String,
    class: &'static str,
    fut: impl Future<Output = ()>,
    per_plugin_timeout: Duration,
    report: &mut ShutdownReport,
) {
    info!(plugin_id = %id, plugin_class = class, "plugin shutdown begin");
    let started = Instant::now();
    match timeout(per_plugin_timeout, fut).await {
        Ok(()) => {
            let elapsed = started.elapsed();
            info!(
                plugin_id = %id,
                plugin_class = class,
                elapsed_ms = elapsed.as_millis() as u64,
                "plugin shutdown end"
            );
            report.clean += 1;
        }
        Err(_) => {
            warn!(
                plugin_id = %id,
                plugin_class = class,
                timeout_ms = per_plugin_timeout.as_millis() as u64,
                "plugin shutdown timed out — abandoning"
            );
            report.timed_out.push(id);
        }
    }
}

/// Merge two JSON values. If both are objects, keys from `b` are merged into `a`.
/// Otherwise, `b` replaces `a`.
fn merge_json_objects(a: serde_json::Value, b: serde_json::Value) -> serde_json::Value {
    match (a, b) {
        (serde_json::Value::Object(mut a_map), serde_json::Value::Object(b_map)) => {
            for (k, v) in b_map {
                a_map.insert(k, v);
            }
            serde_json::Value::Object(a_map)
        }
        (_, b) => b,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::{
        BackendError, BackendRequest, BackendResponse, PluginClass, PluginContext, PluginIdentity,
        WatchError, WatchEvent, WatchEventSink, WatchHandle, async_trait, capability::Capability,
    };

    fn test_context() -> PluginContext {
        PluginContext {
            surface: "tool".to_owned(),
            request_id: "req-1".into(),
            session_id: None,
            tool_name: "test.tool".into(),
            identity: PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: std::collections::BTreeMap::new(),
            },
            transport: "http".into(),
        }
    }

    fn test_manifest(id: &str, class: PluginClass) -> PluginManifest {
        PluginManifest {
            id: id.into(),
            version: "0.1.0".into(),
            name: format!("Test {}", id),
            plugin_class: class,
            protocol_version: "1.0".to_owned(),
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

    // -- Allow-all gate plugin -----------------------------------------------

    struct AllowGatePlugin(PluginManifest);

    #[async_trait]
    impl ToolGatePlugin for AllowGatePlugin {
        fn manifest(&self) -> &PluginManifest {
            &self.0
        }
        async fn evaluate_pre_dispatch(
            &self,
            _ctx: &PluginContext,
            _args: &serde_json::Value,
            _meta: Option<&serde_json::Value>,
            _config: &serde_json::Value,
        ) -> GateDecision {
            GateDecision::allow()
        }
    }

    // -- Deny gate plugin ----------------------------------------------------

    struct DenyGatePlugin(PluginManifest);

    #[async_trait]
    impl ToolGatePlugin for DenyGatePlugin {
        fn manifest(&self) -> &PluginManifest {
            &self.0
        }
        async fn evaluate_pre_dispatch(
            &self,
            _ctx: &PluginContext,
            _args: &serde_json::Value,
            _meta: Option<&serde_json::Value>,
            _config: &serde_json::Value,
        ) -> GateDecision {
            GateDecision::Deny {
                http_status: 403,
                code: -32044,
                message: "denied by test".into(),
                error_data: None,
            }
        }
    }

    // -- Metadata-returning gate plugin --------------------------------------

    struct MetadataGatePlugin {
        manifest: PluginManifest,
        metadata: serde_json::Value,
    }

    #[async_trait]
    impl ToolGatePlugin for MetadataGatePlugin {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn evaluate_pre_dispatch(
            &self,
            _ctx: &PluginContext,
            _args: &serde_json::Value,
            _meta: Option<&serde_json::Value>,
            _config: &serde_json::Value,
        ) -> GateDecision {
            GateDecision::allow_with_metadata(self.metadata.clone())
        }
    }

    // -- Tests ---------------------------------------------------------------

    #[tokio::test]
    async fn empty_registry_allows_everything() {
        let reg = PluginRegistry::new();
        assert!(!reg.has_tool_gate_plugins());
        assert_eq!(reg.total_count(), 0);
        let decision = reg
            .evaluate_tool_gates_pre(&test_context(), &serde_json::json!({}), None)
            .await;
        assert!(decision.is_allow());
    }

    #[tokio::test]
    async fn single_allow_plugin_allows() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(AllowGatePlugin(test_manifest(
                "allow.1",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        assert!(reg.has_tool_gate_plugins());
        assert_eq!(reg.total_count(), 1);
        let decision = reg
            .evaluate_tool_gates_pre(&test_context(), &serde_json::json!({}), None)
            .await;
        assert!(decision.is_allow());
    }

    #[tokio::test]
    async fn multi_instance_same_manifest_id_distinct_aliases_register_cleanly() {
        // Conformance test for the alias-keyed chain registry. Two
        // AllowGatePlugin instances share the SAME manifest id
        // (`dev.mcpg.test.gate`); the duplicate check keys on the
        // operator alias instead, so registering under distinct
        // aliases (`gate.tenant-a` / `gate.tenant-b`) succeeds.
        // Both instances end up in the chain side-by-side.
        let mut reg = PluginRegistry::new();
        let shared_manifest_id = "dev.mcpg.test.gate";

        reg.register_tool_gate_with_alias(
            Some("gate.tenant-a".into()),
            Box::new(AllowGatePlugin(test_manifest(
                shared_manifest_id,
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({"tenant": "a"}),
            true,
        )
        .expect("first alias should register");

        reg.register_tool_gate_with_alias(
            Some("gate.tenant-b".into()),
            Box::new(AllowGatePlugin(test_manifest(
                shared_manifest_id,
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({"tenant": "b"}),
            true,
        )
        .expect("second alias on same manifest id should register (not a duplicate alias)");

        assert_eq!(reg.tool_gate_chain.len(), 2);
        assert_eq!(reg.tool_gate_chain[0].alias, "gate.tenant-a");
        assert_eq!(reg.tool_gate_chain[1].alias, "gate.tenant-b");
        assert_eq!(reg.tool_gate_chain[0].manifest.id, shared_manifest_id);
        assert_eq!(reg.tool_gate_chain[1].manifest.id, shared_manifest_id);
    }

    #[tokio::test]
    async fn duplicate_alias_is_rejected_even_when_manifest_ids_differ() {
        // The mirror of the multi-instance test: two plugins with
        // DISTINCT manifest ids registered under the SAME alias must
        // be refused. Pre-v25 keying on manifest id would have let
        // this through; v25 keys on alias and refuses.
        let mut reg = PluginRegistry::new();

        reg.register_tool_gate_with_alias(
            Some("shared".into()),
            Box::new(AllowGatePlugin(test_manifest(
                "dev.mcpg.test.gate-one",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
            true,
        )
        .expect("first registration accepted");

        let err = reg
            .register_tool_gate_with_alias(
                Some("shared".into()),
                Box::new(AllowGatePlugin(test_manifest(
                    "dev.mcpg.test.gate-two",
                    PluginClass::ToolGate,
                ))),
                PluginTier::Native,
                serde_json::json!({}),
                true,
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("alias"),
            "expected duplicate-alias error, got: {err}"
        );
    }

    #[tokio::test]
    async fn deny_plugin_short_circuits_chain() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(AllowGatePlugin(test_manifest(
                "allow.1",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        reg.register_tool_gate(
            Box::new(DenyGatePlugin(test_manifest(
                "deny.1",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        assert_eq!(reg.total_count(), 2);
        let decision = reg
            .evaluate_tool_gates_pre(&test_context(), &serde_json::json!({}), None)
            .await;
        assert!(!decision.is_allow());
    }

    #[test]
    fn duplicate_plugin_id_rejected() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(AllowGatePlugin(test_manifest(
                "dup.1",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        let result = reg.register_tool_gate(
            Box::new(AllowGatePlugin(test_manifest(
                "dup.1",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duplicate"));
    }

    #[test]
    fn incompatible_protocol_version_rejected() {
        let mut reg = PluginRegistry::new();
        let mut manifest = test_manifest("bad.protocol", PluginClass::ToolGate);
        manifest.protocol_version = "2.0".to_owned();
        let result = reg.register_tool_gate(
            Box::new(AllowGatePlugin(manifest)),
            PluginTier::Native,
            serde_json::json!({}),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("protocol_version"));
    }

    #[test]
    fn empty_plugin_id_rejected() {
        let mut reg = PluginRegistry::new();
        let manifest = test_manifest("", PluginClass::ToolGate);
        let result = reg.register_tool_gate(
            Box::new(AllowGatePlugin(manifest)),
            PluginTier::Native,
            serde_json::json!({}),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty id"));
    }

    #[test]
    fn loaded_plugins_returns_info() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(AllowGatePlugin(test_manifest(
                "info.1",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        let info = reg.loaded_plugins();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].id, "info.1");
        assert_eq!(info[0].tier, "native");
    }

    #[tokio::test]
    async fn post_dispatch_default_allows() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(AllowGatePlugin(test_manifest(
                "post.1",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        let decision = reg
            .evaluate_tool_gates_post(
                &test_context(),
                &serde_json::json!({}),
                &serde_json::json!({"content": []}),
                100,
            )
            .await;
        assert!(decision.is_allow());
    }

    // -- Transform tests -----------------------------------------------------

    struct UppercaseTransform(PluginManifest);

    #[async_trait]
    impl TransformPlugin for UppercaseTransform {
        fn manifest(&self) -> &PluginManifest {
            &self.0
        }
        async fn transform_arguments(
            &self,
            _ctx: &PluginContext,
            args: &serde_json::Value,
            _config: &serde_json::Value,
        ) -> TransformResult {
            if let Some(s) = args.get("name").and_then(|v| v.as_str()) {
                let mut cloned = args.clone();
                cloned["name"] = serde_json::Value::String(s.to_uppercase());
                TransformResult::Modified { value: cloned }
            } else {
                TransformResult::Unchanged
            }
        }
        async fn transform_result(
            &self,
            _ctx: &PluginContext,
            _result: &serde_json::Value,
            _config: &serde_json::Value,
        ) -> TransformResult {
            TransformResult::Unchanged
        }
    }

    #[tokio::test]
    async fn transform_chain_applies_mutations() {
        let mut reg = PluginRegistry::new();
        reg.register_transform(
            Box::new(UppercaseTransform(test_manifest(
                "upper.1",
                PluginClass::Transform,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        let input = serde_json::json!({"name": "alice"});
        let output = reg.apply_transforms_pre(&test_context(), &input).await;
        assert_eq!(output["name"], "ALICE");
    }

    #[tokio::test]
    async fn empty_transform_chain_passes_through() {
        let reg = PluginRegistry::new();
        let input = serde_json::json!({"name": "alice"});
        let output = reg.apply_transforms_pre(&test_context(), &input).await;
        assert_eq!(output, input);
    }

    // -- Identity tests ------------------------------------------------------

    struct AlwaysResolveIdentity(PluginManifest);

    #[async_trait]
    impl IdentityProviderPlugin for AlwaysResolveIdentity {
        fn manifest(&self) -> &PluginManifest {
            &self.0
        }
        async fn resolve_identity(
            &self,
            _headers: &[(String, String)],
            _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
            _config: &serde_json::Value,
        ) -> IdentityResolution {
            IdentityResolution::Resolved {
                identity: PluginIdentity {
                    kind: "verified".into(),
                    trust_level: "verified".into(),
                    subject_id: Some("plugin-user".into()),
                    auth_provider: Some("test-plugin".into()),
                    issuer: None,
                    roles: Vec::new(),
                    groups: Vec::new(),
                    scopes: Vec::new(),
                    attributes: std::collections::BTreeMap::new(),
                },
            }
        }
    }

    #[tokio::test]
    async fn identity_chain_returns_first_resolved() {
        let mut reg = PluginRegistry::new();
        reg.register_identity(
            Box::new(AlwaysResolveIdentity(test_manifest(
                "id.1",
                PluginClass::IdentityProvider,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        let result = reg
            .resolve_identity(
                &[],
                &mcpg_plugin_protocol::types::RequestMetadata::default(),
            )
            .await;
        match result {
            ChainIdentityOutcome::Resolved(identity) => {
                assert_eq!(identity.subject_id.as_deref(), Some("plugin-user"));
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_identity_chain_returns_none() {
        let reg = PluginRegistry::new();
        let result = reg
            .resolve_identity(
                &[],
                &mcpg_plugin_protocol::types::RequestMetadata::default(),
            )
            .await;
        assert!(matches!(result, ChainIdentityOutcome::NoCredential));
    }

    /// A credential a plugin explicitly rejected must not be reported as
    /// "no credential" — that fails open to anonymous — and must not be
    /// handed to the next plugin, which would let a token rejected by a
    /// strict verifier be re-adjudicated by a laxer one.
    #[tokio::test]
    async fn rejected_credential_stops_the_chain() {
        struct RejectingIdentity(PluginManifest);
        #[async_trait]
        impl IdentityProviderPlugin for RejectingIdentity {
            fn manifest(&self) -> &PluginManifest {
                &self.0
            }
            async fn resolve_identity(
                &self,
                _headers: &[(String, String)],
                _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
                _config: &serde_json::Value,
            ) -> IdentityResolution {
                IdentityResolution::Invalid {
                    reason: "expired token".to_owned(),
                }
            }
        }

        let mut reg = PluginRegistry::new();
        reg.register_identity(
            Box::new(RejectingIdentity(test_manifest(
                "id.strict",
                PluginClass::IdentityProvider,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        // A laxer plugin behind it must never be consulted.
        reg.register_identity(
            Box::new(AlwaysResolveIdentity(test_manifest(
                "id.lax",
                PluginClass::IdentityProvider,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();

        let result = reg
            .resolve_identity(
                &[],
                &mcpg_plugin_protocol::types::RequestMetadata::default(),
            )
            .await;
        match result {
            ChainIdentityOutcome::Rejected { plugin_id, reason } => {
                assert_eq!(plugin_id, "id.strict");
                assert!(reason.contains("expired"), "got: {reason}");
            }
            other => panic!("expected Rejected (chain must stop), got {other:?}"),
        }
    }

    // -- Binding / watch-strategy plugin tests ------------------------------

    struct EchoBackendPlugin {
        manifest: PluginManifest,
        kind: String,
    }

    #[async_trait]
    impl BackendPlugin for EchoBackendPlugin {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn kind(&self) -> &str {
            &self.kind
        }
        async fn register_profile(
            &self,
            _name: &str,
            _spec: &serde_json::Value,
            _host: std::sync::Arc<dyn mcpg_plugin_protocol::BackendHost>,
        ) -> Result<(), BackendError> {
            Ok(())
        }
        async fn execute(
            &self,
            _name: &str,
            req: BackendRequest,
        ) -> Result<BackendResponse, BackendError> {
            Ok(BackendResponse {
                payload: req.payload,
                truncated: false,
            })
        }
    }

    struct NoopWatchPlugin {
        manifest: PluginManifest,
        kind: String,
    }

    struct NoopWatchHandle;
    #[async_trait]
    impl WatchHandle for NoopWatchHandle {
        async fn cancel(&self) {}
    }

    #[async_trait]
    impl WatchStrategyPlugin for NoopWatchPlugin {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn kind(&self) -> &str {
            &self.kind
        }
        async fn watch(
            &self,
            _uri: &str,
            _spec: &serde_json::Value,
            _sink: Arc<dyn WatchEventSink>,
        ) -> Result<Box<dyn WatchHandle>, WatchError> {
            Ok(Box::new(NoopWatchHandle))
        }
    }

    #[tokio::test]
    async fn register_backend_and_lookup_by_kind() {
        let mut reg = PluginRegistry::new();
        reg.register_backend(
            Arc::new(EchoBackendPlugin {
                manifest: test_manifest("nats.binding.1", PluginClass::ToolGate),
                kind: "nats".into(),
            }),
            PluginTier::Native,
        )
        .unwrap();
        assert_eq!(reg.backend_kinds(), vec!["nats".to_string()]);
        let plugin = reg.backend("nats").expect("nats plugin present");
        let resp = plugin
            .execute(
                "my-binding",
                BackendRequest {
                    payload: b"ping".to_vec(),
                    headers: vec![],
                    request_id: "r1".into(),
                    session_id: None,
                    identity: None,
                    idempotency: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(resp.payload, b"ping");
        assert!(reg.backend("unknown").is_none());
    }

    #[test]
    fn duplicate_binding_kind_is_rejected() {
        let mut reg = PluginRegistry::new();
        reg.register_backend(
            Arc::new(EchoBackendPlugin {
                manifest: test_manifest("nats.binding.a", PluginClass::ToolGate),
                kind: "nats".into(),
            }),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .register_backend(
                Arc::new(EchoBackendPlugin {
                    manifest: test_manifest("nats.binding.b", PluginClass::ToolGate),
                    kind: "nats".into(),
                }),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[test]
    fn empty_binding_kind_is_rejected() {
        let mut reg = PluginRegistry::new();
        let err = reg
            .register_backend(
                Arc::new(EchoBackendPlugin {
                    manifest: test_manifest("bad.kind", PluginClass::ToolGate),
                    kind: "".into(),
                }),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("empty kind"));
    }

    #[tokio::test]
    async fn register_watch_strategy_and_lookup_by_kind() {
        let mut reg = PluginRegistry::new();
        reg.register_watch_strategy(
            Arc::new(NoopWatchPlugin {
                manifest: test_manifest("watch.nats.1", PluginClass::ToolGate),
                kind: "nats_topic".into(),
            }),
            PluginTier::Native,
        )
        .unwrap();
        assert_eq!(reg.watch_strategy_kinds(), vec!["nats_topic".to_string()]);

        struct NullSink;
        #[async_trait]
        impl WatchEventSink for NullSink {
            async fn emit(&self, _event: WatchEvent) {}
        }

        let plugin = reg.watch_strategy("nats_topic").expect("watcher present");
        let _handle = plugin
            .watch("mem://res", &serde_json::json!({}), Arc::new(NullSink))
            .await
            .unwrap();
        assert!(reg.watch_strategy("missing").is_none());
    }

    #[test]
    fn loaded_plugins_includes_binding_and_watch() {
        let mut reg = PluginRegistry::new();
        reg.register_backend(
            Arc::new(EchoBackendPlugin {
                manifest: test_manifest("kafka.binding.1", PluginClass::ToolGate),
                kind: "kafka".into(),
            }),
            PluginTier::Native,
        )
        .unwrap();
        reg.register_watch_strategy(
            Arc::new(NoopWatchPlugin {
                manifest: test_manifest("kafka.watch.1", PluginClass::ToolGate),
                kind: "kafka_topic".into(),
            }),
            PluginTier::Native,
        )
        .unwrap();
        let info = reg.loaded_plugins();
        assert_eq!(info.len(), 2);
        assert!(info.iter().any(|p| p.plugin_class == "binding:kafka"));
        assert!(
            info.iter()
                .any(|p| p.plugin_class == "watch_strategy:kafka_topic")
        );
        assert_eq!(reg.total_count(), 2);
    }

    // -- http_route tests ----------------------------------------------------

    struct StubHttpRoute {
        manifest: PluginManifest,
        routes: Vec<mcpg_plugin_protocol::http_route::RouteSpec>,
        status: u16,
    }

    #[async_trait]
    impl mcpg_plugin_protocol::http_route::HttpRoute for StubHttpRoute {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn routes(&self) -> Vec<mcpg_plugin_protocol::http_route::RouteSpec> {
            self.routes.clone()
        }
        async fn handle(
            &self,
            _req: mcpg_plugin_protocol::http_route::HttpRouteRequest,
        ) -> mcpg_plugin_protocol::http_route::HttpRouteResponse {
            mcpg_plugin_protocol::http_route::HttpRouteResponse::status(self.status)
        }
    }

    fn stub_route(path: &str) -> mcpg_plugin_protocol::http_route::RouteSpec {
        mcpg_plugin_protocol::http_route::RouteSpec {
            method: "GET".into(),
            path: path.into(),
            requires_identity: false,
            streaming: false,
            max_body_bytes: None,
        }
    }

    #[tokio::test]
    async fn register_http_route_and_dispatch() {
        let mut reg = PluginRegistry::new();
        reg.register_http_route(
            "health",
            Arc::new(StubHttpRoute {
                manifest: test_manifest("dev.mcpg.health", PluginClass::HttpRoute),
                routes: vec![stub_route("/")],
                status: 204,
            }),
            PluginTier::Native,
        )
        .unwrap();
        let handle = reg
            .http_route("dev.mcpg.health", "health")
            .expect("entity present");
        let req = mcpg_plugin_protocol::http_route::HttpRouteRequest {
            method: "GET".into(),
            full_path: "/plugins/dev.mcpg.health/health/".into(),
            path_params: Default::default(),
            query: vec![],
            headers: vec![],
            body: bytes::Bytes::new(),
            identity: None,
            request_id: "r1".into(),
            remote_addr: None,
        };
        let resp = handle.handle(req).await;
        assert_eq!(resp.status, 204);
        assert!(reg.http_route("dev.mcpg.health", "missing").is_none());
        assert!(reg.http_route("missing", "health").is_none());
    }

    #[test]
    fn http_route_same_plugin_multi_entity_allowed() {
        let mut reg = PluginRegistry::new();
        reg.register_http_route(
            "health",
            Arc::new(StubHttpRoute {
                manifest: test_manifest("dev.mcpg.ops", PluginClass::HttpRoute),
                routes: vec![stub_route("/")],
                status: 200,
            }),
            PluginTier::Native,
        )
        .unwrap();
        reg.register_http_route(
            "metrics",
            Arc::new(StubHttpRoute {
                manifest: test_manifest("dev.mcpg.ops", PluginClass::HttpRoute),
                routes: vec![stub_route("/")],
                status: 200,
            }),
            PluginTier::Native,
        )
        .unwrap();
        assert_eq!(reg.http_route_entries().len(), 2);
        assert!(reg.http_route("dev.mcpg.ops", "health").is_some());
        assert!(reg.http_route("dev.mcpg.ops", "metrics").is_some());
    }

    #[test]
    fn http_route_duplicate_entity_name_rejected() {
        let mut reg = PluginRegistry::new();
        reg.register_http_route(
            "health",
            Arc::new(StubHttpRoute {
                manifest: test_manifest("dev.mcpg.ops", PluginClass::HttpRoute),
                routes: vec![stub_route("/")],
                status: 200,
            }),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .register_http_route(
                "health",
                Arc::new(StubHttpRoute {
                    manifest: test_manifest("dev.mcpg.ops", PluginClass::HttpRoute),
                    routes: vec![stub_route("/")],
                    status: 200,
                }),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[test]
    fn http_route_empty_entity_name_rejected() {
        let mut reg = PluginRegistry::new();
        let err = reg
            .register_http_route(
                "",
                Arc::new(StubHttpRoute {
                    manifest: test_manifest("dev.mcpg.ops", PluginClass::HttpRoute),
                    routes: vec![stub_route("/")],
                    status: 200,
                }),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("empty entity_name"));
    }

    #[test]
    fn http_route_empty_routes_rejected() {
        let mut reg = PluginRegistry::new();
        let err = reg
            .register_http_route(
                "health",
                Arc::new(StubHttpRoute {
                    manifest: test_manifest("dev.mcpg.ops", PluginClass::HttpRoute),
                    routes: vec![],
                    status: 200,
                }),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("declared no routes"));
    }

    #[test]
    fn http_route_disabled_is_skipped_in_lookup() {
        let mut reg = PluginRegistry::new();
        reg.register_http_route(
            "health",
            Arc::new(StubHttpRoute {
                manifest: test_manifest("dev.mcpg.health", PluginClass::HttpRoute),
                routes: vec![stub_route("/")],
                status: 200,
            }),
            PluginTier::Native,
        )
        .unwrap();
        assert!(reg.http_route("dev.mcpg.health", "health").is_some());
        reg.disable("dev.mcpg.health").unwrap();
        assert!(reg.http_route("dev.mcpg.health", "health").is_none());
        // But it still shows up in the full listing — admin surfaces
        // want to see disabled entities.
        let entries = reg.http_route_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].state, PluginState::Disabled);
    }

    #[test]
    fn http_route_overrides_stored_and_retrieved() {
        let mut reg = PluginRegistry::new();
        reg.register_http_route_with_overrides(
            "health",
            Arc::new(StubHttpRoute {
                manifest: test_manifest("dev.mcpg.ops", PluginClass::HttpRoute),
                routes: vec![stub_route("/")],
                status: 200,
            }),
            PluginTier::Native,
            HttpRouteOverrides {
                max_body_bytes: Some(2048),
                requires_identity: Some(true),
                allow_path_override: false,
            },
            &[],
        )
        .unwrap();
        let ovr = reg
            .http_route_overrides("dev.mcpg.ops", "health")
            .expect("overrides present");
        assert_eq!(ovr.max_body_bytes, Some(2048));
        assert_eq!(ovr.requires_identity, Some(true));
        assert!(reg.http_route_overrides("missing", "x").is_none());
    }

    #[test]
    fn http_route_override_rejected_without_capability() {
        let mut reg = PluginRegistry::new();
        // Plugin does not declare the typed HttpRouteServe capability
        // but operator config asks for allow_path_override: true —
        // privilege escalation, registry must refuse.
        let err = reg
            .register_http_route_with_overrides(
                "hook",
                Arc::new(StubHttpRoute {
                    manifest: test_manifest("dev.mcpg.nohookcap", PluginClass::HttpRoute),
                    routes: vec![stub_route("/webhooks/test")],
                    status: 200,
                }),
                PluginTier::Native,
                HttpRouteOverrides {
                    allow_path_override: true,
                    ..Default::default()
                },
                &[],
            )
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("allow_path_override"), "got: {msg}");
        assert!(msg.contains("HttpRouteServe"), "got: {msg}");
    }

    #[test]
    fn set_manifest_caps_derives_onto_stored_manifest() {
        use mcpg_plugin_protocol::capability::Capability;
        let mut reg = PluginRegistry::new();
        let manifest = test_manifest("dev.mcpg.derive", PluginClass::ToolGate);
        assert!(
            manifest.required_capabilities.is_empty(),
            "plugins author no manifest caps under the host-derived design"
        );
        reg.register_tool_gate(
            Box::new(AllowGatePlugin(manifest)),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        // Host-derive the authoritative typed caps onto the stored manifest
        // (alias == id for a single-entity plugin).
        reg.set_manifest_caps("dev.mcpg.derive", &[Capability::NetworkOutbound]);
        let detail = reg.plugin_detail("dev.mcpg.derive").expect("registered");
        assert_eq!(
            detail.required_capabilities,
            vec!["network_outbound".to_owned()],
            "plugin_detail must surface the host-derived typed cap (as its kind)"
        );
    }

    #[test]
    fn http_route_override_ignores_display_only_manifest_string() {
        // Security regression guard: the manifest's `required_capabilities`
        // is display-only — even when it claims `HttpRouteServe`, override
        // mode is granted ONLY by the typed declared-capability slice
        // threaded into the register call (here `&[]`), never the manifest.
        let mut reg = PluginRegistry::new();
        let mut manifest = test_manifest("dev.mcpg.spoof", PluginClass::HttpRoute);
        manifest.required_capabilities =
            vec![mcpg_plugin_protocol::capability::Capability::HttpRouteServe];
        let err = reg
            .register_http_route_with_overrides(
                "hook",
                Arc::new(StubHttpRoute {
                    manifest,
                    routes: vec![stub_route("/webhooks/spoof")],
                    status: 200,
                }),
                PluginTier::Native,
                HttpRouteOverrides {
                    allow_path_override: true,
                    ..Default::default()
                },
                // Typed declared set is empty — string claim must not suffice.
                &[],
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("HttpRouteServe"),
            "spoofed manifest string must not grant override: {err}"
        );
    }

    #[test]
    fn http_route_override_accepted_with_capability() {
        let mut reg = PluginRegistry::new();
        // The manifest's display-only Vec<String> is left empty on
        // purpose — the gate must accept based on the typed declared
        // capability slice alone, proving it no longer reads the string.
        let manifest = test_manifest("dev.mcpg.override", PluginClass::HttpRoute);
        reg.register_http_route_with_overrides(
            "hook",
            Arc::new(StubHttpRoute {
                manifest,
                routes: vec![stub_route("/hooks/stripe")],
                status: 200,
            }),
            PluginTier::Native,
            HttpRouteOverrides {
                allow_path_override: true,
                ..Default::default()
            },
            &[Capability::HttpRouteServe],
        )
        .expect("override mode with declared cap");

        let entries = reg.http_route_override_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/hooks/stripe");
        assert_eq!(entries[0].plugin_id, "dev.mcpg.override");
    }

    #[test]
    fn http_route_override_reserved_path_rejected() {
        let mut reg = PluginRegistry::new();
        let manifest = test_manifest("dev.mcpg.badpath", PluginClass::HttpRoute);
        for reserved in ["/", "/mcp", "/metrics", "/.well-known/foo", "/plugins/x"] {
            let err = reg
                .register_http_route_with_overrides(
                    "e",
                    Arc::new(StubHttpRoute {
                        manifest: manifest.clone(),
                        routes: vec![stub_route(reserved)],
                        status: 200,
                    }),
                    PluginTier::Native,
                    HttpRouteOverrides {
                        allow_path_override: true,
                        ..Default::default()
                    },
                    &[Capability::HttpRouteServe],
                )
                .unwrap_err();
            assert!(
                err.to_string().contains("reserved"),
                "path {reserved} should be rejected: {err}"
            );
        }
    }

    #[test]
    fn http_route_override_entries_excludes_namespaced() {
        let mut reg = PluginRegistry::new();
        // Namespaced entity — not in the override listing.
        reg.register_http_route(
            "status",
            Arc::new(StubHttpRoute {
                manifest: test_manifest("dev.mcpg.ns", PluginClass::HttpRoute),
                routes: vec![stub_route("/")],
                status: 200,
            }),
            PluginTier::Native,
        )
        .unwrap();
        // Override entity.
        let manifest = test_manifest("dev.mcpg.ov", PluginClass::HttpRoute);
        reg.register_http_route_with_overrides(
            "hook",
            Arc::new(StubHttpRoute {
                manifest,
                routes: vec![stub_route("/hook")],
                status: 200,
            }),
            PluginTier::Native,
            HttpRouteOverrides {
                allow_path_override: true,
                ..Default::default()
            },
            &[Capability::HttpRouteServe],
        )
        .unwrap();
        let entries = reg.http_route_override_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].plugin_id, "dev.mcpg.ov");
    }

    #[test]
    fn is_reserved_override_path_matches_expected_set() {
        assert!(is_reserved_override_path("/"));
        assert!(is_reserved_override_path("/mcp"));
        assert!(is_reserved_override_path("/metrics"));
        assert!(is_reserved_override_path("/.well-known/anything"));
        assert!(is_reserved_override_path("/plugins/foo"));
        assert!(is_reserved_override_path("/healthz"));
        assert!(is_reserved_override_path("/webhooks/resource-updated/tok"));
        assert!(!is_reserved_override_path("/hooks/stripe"));
        assert!(!is_reserved_override_path("/admin/custom"));
    }

    #[test]
    fn http_route_default_has_empty_overrides() {
        let mut reg = PluginRegistry::new();
        reg.register_http_route(
            "health",
            Arc::new(StubHttpRoute {
                manifest: test_manifest("dev.mcpg.ops", PluginClass::HttpRoute),
                routes: vec![stub_route("/")],
                status: 200,
            }),
            PluginTier::Native,
        )
        .unwrap();
        let ovr = reg
            .http_route_overrides("dev.mcpg.ops", "health")
            .expect("overrides present");
        assert_eq!(ovr, &HttpRouteOverrides::default());
    }

    #[test]
    fn http_route_shows_up_in_loaded_plugins() {
        let mut reg = PluginRegistry::new();
        reg.register_http_route(
            "health",
            Arc::new(StubHttpRoute {
                manifest: test_manifest("dev.mcpg.health", PluginClass::HttpRoute),
                routes: vec![stub_route("/")],
                status: 200,
            }),
            PluginTier::Native,
        )
        .unwrap();
        let info = reg.loaded_plugins();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].plugin_class, "http_route:health");
        assert_eq!(reg.total_count(), 1);
    }

    // -- audit_sink tests ----------------------------------------------------

    struct InMemoryAuditSink {
        manifest: PluginManifest,
        emitted: tokio::sync::Mutex<Vec<mcpg_plugin_protocol::audit::AuditEvent>>,
        fail_with: Option<mcpg_plugin_protocol::audit::AuditError>,
    }

    #[async_trait]
    impl mcpg_plugin_protocol::audit::AuditSink for InMemoryAuditSink {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn emit(
            &self,
            event: &mcpg_plugin_protocol::audit::AuditEvent,
        ) -> Result<
            mcpg_plugin_protocol::audit::AuditReceipt,
            mcpg_plugin_protocol::audit::AuditError,
        > {
            if let Some(e) = &self.fail_with {
                return Err(e.clone());
            }
            self.emitted.lock().await.push(event.clone());
            Ok(mcpg_plugin_protocol::audit::AuditReceipt {
                sink_id: self.manifest.id.clone(),
                persisted_at: "2026-04-24T12:00:00Z".into(),
                durable_hash: "0".repeat(64),
            })
        }
    }

    fn audit_sink(id: &str) -> Arc<InMemoryAuditSink> {
        Arc::new(InMemoryAuditSink {
            manifest: test_manifest(id, PluginClass::AuditSink),
            emitted: tokio::sync::Mutex::new(Vec::new()),
            fail_with: None,
        })
    }

    fn audit_event() -> mcpg_plugin_protocol::audit::AuditEvent {
        mcpg_plugin_protocol::audit::AuditEvent {
            event_id: "evt-1".into(),
            occurred_at: "2026-04-24T12:00:00Z".into(),
            actor: test_context().identity,
            action: "mcpg.lifecycle.gateway_started".into(),
            resource: None,
            outcome: mcpg_plugin_protocol::audit::AuditOutcome::Success,
            request_id: None,
            node_id: None,
            details: serde_json::json!({}),
            prev_event_hash: None,
        }
    }

    #[tokio::test]
    async fn register_audit_sink_fans_out_event_to_every_sink() {
        let mut reg = PluginRegistry::new();
        let sink_a = audit_sink("dev.test.audit.a");
        let sink_b = audit_sink("dev.test.audit.b");
        reg.register_audit_sink(sink_a.clone(), PluginTier::Native)
            .unwrap();
        reg.register_audit_sink(sink_b.clone(), PluginTier::Native)
            .unwrap();
        assert_eq!(reg.audit_sink_ids().len(), 2);

        let event = audit_event();
        let results = reg.emit_audit_event(&event).await;
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.result.is_ok()));
        assert_eq!(sink_a.emitted.lock().await.len(), 1);
        assert_eq!(sink_b.emitted.lock().await.len(), 1);
    }

    #[test]
    fn audit_sink_duplicate_id_rejected() {
        let mut reg = PluginRegistry::new();
        reg.register_audit_sink(audit_sink("dev.test.audit"), PluginTier::Native)
            .unwrap();
        let err = reg
            .register_audit_sink(audit_sink("dev.test.audit"), PluginTier::Native)
            .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[tokio::test]
    async fn audit_sink_failure_still_emits_to_other_sinks() {
        let mut reg = PluginRegistry::new();
        let failing = Arc::new(InMemoryAuditSink {
            manifest: test_manifest("dev.test.audit.fail", PluginClass::AuditSink),
            emitted: tokio::sync::Mutex::new(Vec::new()),
            fail_with: Some(mcpg_plugin_protocol::audit::AuditError::WriteFailed {
                reason: "disk full".into(),
            }),
        });
        let working = audit_sink("dev.test.audit.ok");
        reg.register_audit_sink(failing, PluginTier::Native)
            .unwrap();
        reg.register_audit_sink(working.clone(), PluginTier::Native)
            .unwrap();

        let event = audit_event();
        let results = reg.emit_audit_event(&event).await;
        assert_eq!(results.len(), 2);
        assert!(results[0].result.is_err());
        assert!(results[1].result.is_ok());
        // Working sink still saw the event — fan-out continued.
        assert_eq!(working.emitted.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn audit_sink_disabled_is_skipped_on_emit() {
        let mut reg = PluginRegistry::new();
        let sink = audit_sink("dev.test.audit");
        reg.register_audit_sink(sink.clone(), PluginTier::Native)
            .unwrap();
        reg.disable("dev.test.audit").unwrap();
        let results = reg.emit_audit_event(&audit_event()).await;
        assert!(results.is_empty());
        assert!(sink.emitted.lock().await.is_empty());
        assert!(!reg.has_serving_audit_sink());
    }

    #[test]
    fn audit_sink_shows_up_in_loaded_plugins() {
        let mut reg = PluginRegistry::new();
        reg.register_audit_sink(audit_sink("dev.test.audit"), PluginTier::Native)
            .unwrap();
        let info = reg.loaded_plugins();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].plugin_class, "audit_sink");
        assert_eq!(reg.total_count(), 1);
    }

    #[tokio::test]
    async fn audit_sink_has_serving_checks_state() {
        let mut reg = PluginRegistry::new();
        assert!(!reg.has_serving_audit_sink());
        reg.register_audit_sink(audit_sink("dev.test.audit"), PluginTier::Native)
            .unwrap();
        assert!(reg.has_serving_audit_sink());
    }

    // -- emit_audit_event_enforced tests ------------------------------------

    fn failing_audit_sink(id: &str) -> Arc<InMemoryAuditSink> {
        Arc::new(InMemoryAuditSink {
            manifest: test_manifest(id, PluginClass::AuditSink),
            emitted: tokio::sync::Mutex::new(Vec::new()),
            fail_with: Some(mcpg_plugin_protocol::audit::AuditError::WriteFailed {
                reason: "disk full".into(),
            }),
        })
    }

    #[tokio::test]
    async fn enforced_emit_fail_open_returns_ok_even_on_sink_failure() {
        let mut reg = PluginRegistry::new();
        reg.register_audit_sink(
            failing_audit_sink("dev.test.audit.fail"),
            PluginTier::Native,
        )
        .unwrap();
        let results = reg
            .emit_audit_event_enforced(&audit_event(), AuditEmitPolicy::FailOpen)
            .await
            .expect("fail_open always returns Ok");
        assert_eq!(results.len(), 1);
        assert!(results[0].result.is_err(), "sink failure still observable");
    }

    #[tokio::test]
    async fn enforced_emit_fail_closed_returns_err_on_sink_failure() {
        let mut reg = PluginRegistry::new();
        reg.register_audit_sink(
            failing_audit_sink("dev.test.audit.fail"),
            PluginTier::Native,
        )
        .unwrap();
        reg.register_audit_sink(audit_sink("dev.test.audit.ok"), PluginTier::Native)
            .unwrap();
        let failure = reg
            .emit_audit_event_enforced(&audit_event(), AuditEmitPolicy::FailClosed)
            .await
            .expect_err("fail_closed should surface sink failure");
        // All sinks still attempted — fan-out doesn't short-circuit.
        assert_eq!(failure.results.len(), 2);
        // Only the failing sink appears in failed_sinks().
        let failed: Vec<&str> = failure.failed_sinks().map(|(s, _)| s).collect();
        assert_eq!(failed, vec!["dev.test.audit.fail"]);
    }

    #[tokio::test]
    async fn enforced_emit_fail_closed_returns_ok_when_every_sink_succeeds() {
        let mut reg = PluginRegistry::new();
        reg.register_audit_sink(audit_sink("dev.test.audit.a"), PluginTier::Native)
            .unwrap();
        reg.register_audit_sink(audit_sink("dev.test.audit.b"), PluginTier::Native)
            .unwrap();
        let results = reg
            .emit_audit_event_enforced(&audit_event(), AuditEmitPolicy::FailClosed)
            .await
            .expect("all sinks succeed → fail_closed passes");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.result.is_ok()));
    }

    #[tokio::test]
    async fn enforced_emit_no_sinks_always_returns_ok() {
        // Zero registered sinks: no failures possible, so both
        // policies return Ok(empty). The `required: true` +
        // zero-sinks combo is refused at startup; this just
        // confirms the enforcement helper doesn't mint a spurious
        // error out of an empty sink list.
        let reg = PluginRegistry::new();
        let fo = reg
            .emit_audit_event_enforced(&audit_event(), AuditEmitPolicy::FailOpen)
            .await
            .expect("fail_open + no sinks → Ok(empty)");
        assert!(fo.is_empty());
        let fc = reg
            .emit_audit_event_enforced(&audit_event(), AuditEmitPolicy::FailClosed)
            .await
            .expect("fail_closed + no sinks → Ok(empty)");
        assert!(fc.is_empty());
    }

    #[tokio::test]
    async fn enforcement_failure_display_lists_failed_sinks() {
        let mut reg = PluginRegistry::new();
        reg.register_audit_sink(
            failing_audit_sink("dev.test.audit.fail"),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .emit_audit_event_enforced(&audit_event(), AuditEmitPolicy::FailClosed)
            .await
            .unwrap_err();
        let display = err.to_string();
        assert!(display.contains("fail_closed"), "got: {display}");
        assert!(display.contains("dev.test.audit.fail"), "got: {display}");
    }

    // -- store tests ---------------------------------------------------------

    struct NoopStore {
        manifest: PluginManifest,
        supported: Vec<mcpg_plugin_protocol::store::StoreRole>,
    }

    #[async_trait]
    impl mcpg_plugin_protocol::store::Store for NoopStore {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn supported_roles(&self) -> Vec<mcpg_plugin_protocol::store::StoreRole> {
            self.supported.clone()
        }
        async fn get(
            &self,
            _role: mcpg_plugin_protocol::store::StoreRole,
            _key: &str,
        ) -> Result<
            Option<mcpg_plugin_protocol::store::StoreValue>,
            mcpg_plugin_protocol::store::StoreError,
        > {
            Ok(None)
        }
        async fn put(
            &self,
            _role: mcpg_plugin_protocol::store::StoreRole,
            _key: &str,
            _value: mcpg_plugin_protocol::store::StoreValue,
        ) -> Result<(), mcpg_plugin_protocol::store::StoreError> {
            Ok(())
        }
        async fn delete(
            &self,
            _role: mcpg_plugin_protocol::store::StoreRole,
            _key: &str,
        ) -> Result<(), mcpg_plugin_protocol::store::StoreError> {
            Ok(())
        }
        async fn list(
            &self,
            _role: mcpg_plugin_protocol::store::StoreRole,
            _prefix: &str,
            _cursor: Option<String>,
        ) -> Result<mcpg_plugin_protocol::store::StorePage, mcpg_plugin_protocol::store::StoreError>
        {
            Ok(mcpg_plugin_protocol::store::StorePage {
                items: vec![],
                next_cursor: None,
            })
        }
        async fn compare_and_swap(
            &self,
            _role: mcpg_plugin_protocol::store::StoreRole,
            _key: &str,
            _expected: Option<mcpg_plugin_protocol::store::StoreValue>,
            _new: mcpg_plugin_protocol::store::StoreValue,
        ) -> Result<bool, mcpg_plugin_protocol::store::StoreError> {
            Ok(true)
        }
        async fn watch(
            &self,
            _role: mcpg_plugin_protocol::store::StoreRole,
            _key: &str,
        ) -> Result<
            mcpg_plugin_protocol::store::BoxStoreEventStream,
            mcpg_plugin_protocol::store::StoreError,
        > {
            Err(mcpg_plugin_protocol::store::StoreError::Unsupported { op: "watch".into() })
        }
    }

    fn store_plugin(
        id: &str,
        roles: Vec<mcpg_plugin_protocol::store::StoreRole>,
    ) -> Arc<NoopStore> {
        Arc::new(NoopStore {
            manifest: test_manifest(id, PluginClass::Store),
            supported: roles,
        })
    }

    #[test]
    fn register_store_records_supported_roles() {
        let mut reg = PluginRegistry::new();
        reg.register_store(
            store_plugin(
                "dev.test.store",
                vec![
                    mcpg_plugin_protocol::store::StoreRole::Session,
                    mcpg_plugin_protocol::store::StoreRole::Task,
                ],
            ),
            PluginTier::Native,
        )
        .unwrap();
        assert_eq!(reg.store_plugin_ids(), vec!["dev.test.store".to_string()]);
    }

    #[test]
    fn register_store_refuses_duplicate_id() {
        let mut reg = PluginRegistry::new();
        reg.register_store(
            store_plugin(
                "dev.test.store",
                vec![mcpg_plugin_protocol::store::StoreRole::Session],
            ),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .register_store(
                store_plugin(
                    "dev.test.store",
                    vec![mcpg_plugin_protocol::store::StoreRole::Task],
                ),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[test]
    fn register_store_refuses_empty_supported_roles() {
        let mut reg = PluginRegistry::new();
        let err = reg
            .register_store(store_plugin("dev.test.empty", vec![]), PluginTier::Native)
            .unwrap_err();
        assert!(err.to_string().contains("supported_roles() = []"));
    }

    #[test]
    fn bind_store_role_resolves_lookup() {
        let mut reg = PluginRegistry::new();
        reg.register_store(
            store_plugin(
                "dev.test.store",
                vec![
                    mcpg_plugin_protocol::store::StoreRole::Session,
                    mcpg_plugin_protocol::store::StoreRole::Task,
                ],
            ),
            PluginTier::Native,
        )
        .unwrap();
        reg.bind_store_role(
            mcpg_plugin_protocol::store::StoreRole::Session,
            "dev.test.store",
        )
        .unwrap();
        assert!(
            reg.store_for_role(&mcpg_plugin_protocol::store::StoreRole::Session)
                .is_some()
        );
        assert!(
            reg.store_for_role(&mcpg_plugin_protocol::store::StoreRole::Replay)
                .is_none()
        );
    }

    #[test]
    fn bind_store_role_refuses_unsupported_role() {
        let mut reg = PluginRegistry::new();
        reg.register_store(
            store_plugin(
                "dev.test.store",
                vec![mcpg_plugin_protocol::store::StoreRole::Session],
            ),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .bind_store_role(
                mcpg_plugin_protocol::store::StoreRole::Replay,
                "dev.test.store",
            )
            .unwrap_err();
        assert!(err.to_string().contains("does not support role"));
    }

    #[test]
    fn bind_store_role_refuses_unknown_plugin() {
        let mut reg = PluginRegistry::new();
        let err = reg
            .bind_store_role(
                mcpg_plugin_protocol::store::StoreRole::Session,
                "missing.plugin",
            )
            .unwrap_err();
        assert!(err.to_string().contains("is not registered"));
    }

    #[test]
    fn bind_store_role_refuses_non_serving_plugin() {
        let mut reg = PluginRegistry::new();
        reg.register_store(
            store_plugin(
                "dev.test.store",
                vec![mcpg_plugin_protocol::store::StoreRole::Session],
            ),
            PluginTier::Native,
        )
        .unwrap();
        reg.disable("dev.test.store").unwrap();
        let err = reg
            .bind_store_role(
                mcpg_plugin_protocol::store::StoreRole::Session,
                "dev.test.store",
            )
            .unwrap_err();
        assert!(err.to_string().contains("is not serving traffic"));
    }

    #[test]
    fn bound_store_roles_lists_all_bindings() {
        let mut reg = PluginRegistry::new();
        reg.register_store(
            store_plugin(
                "dev.test.store",
                vec![
                    mcpg_plugin_protocol::store::StoreRole::Session,
                    mcpg_plugin_protocol::store::StoreRole::Task,
                ],
            ),
            PluginTier::Native,
        )
        .unwrap();
        reg.bind_store_role(
            mcpg_plugin_protocol::store::StoreRole::Session,
            "dev.test.store",
        )
        .unwrap();
        reg.bind_store_role(
            mcpg_plugin_protocol::store::StoreRole::Task,
            "dev.test.store",
        )
        .unwrap();
        let bindings = reg.bound_store_roles();
        assert_eq!(bindings.len(), 2);
        assert!(
            bindings
                .iter()
                .any(|(r, _)| r == &mcpg_plugin_protocol::store::StoreRole::Session)
        );
        assert!(
            bindings
                .iter()
                .any(|(r, _)| r == &mcpg_plugin_protocol::store::StoreRole::Task)
        );
    }

    #[test]
    fn store_plugin_shows_up_in_loaded_plugins() {
        let mut reg = PluginRegistry::new();
        reg.register_store(
            store_plugin(
                "dev.test.store",
                vec![mcpg_plugin_protocol::store::StoreRole::Session],
            ),
            PluginTier::Native,
        )
        .unwrap();
        let info = reg.loaded_plugins();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].plugin_class, "store:session");
        assert_eq!(reg.total_count(), 1);
    }

    // -- cache tests ---------------------------------------------------------

    struct NoopCache {
        manifest: PluginManifest,
        supported: Vec<String>,
        any: bool,
    }

    #[async_trait]
    impl mcpg_plugin_protocol::cache::Cache for NoopCache {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn supported_namespaces(&self) -> Vec<String> {
            self.supported.clone()
        }
        fn serves_any_namespace(&self) -> bool {
            self.any
        }
        async fn get(&self, _ns: &str, _key: &str) -> Option<bytes::Bytes> {
            None
        }
        async fn put(
            &self,
            _ns: &str,
            _key: &str,
            _value: bytes::Bytes,
            _ttl: std::time::Duration,
        ) -> Result<(), mcpg_plugin_protocol::cache::CacheError> {
            Ok(())
        }
        async fn delete(&self, _ns: &str, _key: &str) {}
        async fn clear(&self, _ns: &str) -> Result<(), mcpg_plugin_protocol::cache::CacheError> {
            Ok(())
        }
        async fn incr(
            &self,
            _ns: &str,
            _key: &str,
            by: i64,
            _ttl: std::time::Duration,
        ) -> Result<i64, mcpg_plugin_protocol::cache::CacheError> {
            Ok(by)
        }
    }

    fn cache_plugin(id: &str, supported: Vec<String>, any: bool) -> Arc<NoopCache> {
        Arc::new(NoopCache {
            manifest: test_manifest(id, PluginClass::Cache),
            supported,
            any,
        })
    }

    #[test]
    fn register_cache_records_supported_namespaces() {
        let mut reg = PluginRegistry::new();
        reg.register_cache(
            cache_plugin(
                "dev.test.cache",
                vec!["response-cache".into(), "jwks".into()],
                false,
            ),
            PluginTier::Native,
        )
        .unwrap();
        assert_eq!(reg.cache_plugin_ids(), vec!["dev.test.cache".to_string()]);
    }

    #[test]
    fn register_cache_refuses_duplicate_id() {
        let mut reg = PluginRegistry::new();
        reg.register_cache(
            cache_plugin("dev.test.cache", vec!["jwks".into()], false),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .register_cache(
                cache_plugin("dev.test.cache", vec!["rate-limit".into()], false),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[test]
    fn register_cache_refuses_plugin_with_no_reach() {
        let mut reg = PluginRegistry::new();
        // Empty supported_namespaces + serves_any=false = unreachable.
        let err = reg
            .register_cache(
                cache_plugin("dev.test.unreach", vec![], false),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("unreachable"));
    }

    #[test]
    fn register_cache_accepts_serves_any_with_empty_list() {
        let mut reg = PluginRegistry::new();
        reg.register_cache(
            cache_plugin("dev.test.generic", vec![], true),
            PluginTier::Native,
        )
        .expect("generic KV backend registration");
    }

    #[test]
    fn bind_cache_namespace_resolves_lookup() {
        let mut reg = PluginRegistry::new();
        reg.register_cache(
            cache_plugin("dev.test.cache", vec!["jwks".into()], false),
            PluginTier::Native,
        )
        .unwrap();
        reg.bind_cache_namespace("jwks", "dev.test.cache").unwrap();
        assert!(reg.cache_for_namespace("jwks").is_some());
        assert!(reg.cache_for_namespace("response-cache").is_none());
    }

    #[test]
    fn bind_cache_namespace_refuses_unsupported_namespace() {
        let mut reg = PluginRegistry::new();
        reg.register_cache(
            cache_plugin("dev.test.cache", vec!["jwks".into()], false),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .bind_cache_namespace("response-cache", "dev.test.cache")
            .unwrap_err();
        assert!(err.to_string().contains("does not support namespace"));
    }

    #[test]
    fn bind_cache_namespace_accepts_serves_any_plugin() {
        let mut reg = PluginRegistry::new();
        reg.register_cache(
            cache_plugin("dev.test.generic", vec![], true),
            PluginTier::Native,
        )
        .unwrap();
        // Arbitrary namespace works on a serves-any plugin.
        reg.bind_cache_namespace("whatever-the-operator-wants", "dev.test.generic")
            .unwrap();
        assert!(
            reg.cache_for_namespace("whatever-the-operator-wants")
                .is_some()
        );
    }

    #[test]
    fn bind_cache_namespace_refuses_unknown_plugin() {
        let mut reg = PluginRegistry::new();
        let err = reg
            .bind_cache_namespace("jwks", "missing.plugin")
            .unwrap_err();
        assert!(err.to_string().contains("is not registered"));
    }

    #[test]
    fn bind_cache_namespace_refuses_non_serving_plugin() {
        let mut reg = PluginRegistry::new();
        reg.register_cache(
            cache_plugin("dev.test.cache", vec!["jwks".into()], false),
            PluginTier::Native,
        )
        .unwrap();
        reg.disable("dev.test.cache").unwrap();
        let err = reg
            .bind_cache_namespace("jwks", "dev.test.cache")
            .unwrap_err();
        assert!(err.to_string().contains("is not serving traffic"));
    }

    #[test]
    fn cache_plugin_shows_up_in_loaded_plugins() {
        let mut reg = PluginRegistry::new();
        reg.register_cache(
            cache_plugin(
                "dev.test.cache",
                vec!["jwks".into(), "response-cache".into()],
                false,
            ),
            PluginTier::Native,
        )
        .unwrap();
        let info = reg.loaded_plugins();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].plugin_class, "cache:jwks,response-cache");
        assert_eq!(reg.total_count(), 1);
    }

    #[test]
    fn cache_serves_any_class_uses_wildcard() {
        let mut reg = PluginRegistry::new();
        reg.register_cache(
            cache_plugin("dev.test.generic", vec![], true),
            PluginTier::Native,
        )
        .unwrap();
        let info = reg.loaded_plugins();
        assert_eq!(info[0].plugin_class, "cache:*");
    }

    // -- secret_provider tests ----------------------------------------------

    struct FixedSecretProvider {
        manifest: PluginManifest,
        schemes: Vec<String>,
        bytes: bytes::Bytes,
    }

    #[async_trait]
    impl mcpg_plugin_protocol::secret::SecretProvider for FixedSecretProvider {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn supported_schemes(&self) -> Vec<String> {
            self.schemes.clone()
        }
        async fn get(
            &self,
            _secret_ref: &str,
        ) -> Result<
            mcpg_plugin_protocol::secret::SecretValue,
            mcpg_plugin_protocol::secret::SecretError,
        > {
            Ok(mcpg_plugin_protocol::secret::SecretValue::new(
                self.bytes.clone(),
            ))
        }
    }

    fn secret_provider(id: &str, schemes: Vec<&str>) -> Arc<FixedSecretProvider> {
        Arc::new(FixedSecretProvider {
            manifest: test_manifest(id, PluginClass::SecretProvider),
            schemes: schemes.into_iter().map(String::from).collect(),
            bytes: bytes::Bytes::from_static(b"hunter2"),
        })
    }

    #[test]
    fn register_secret_provider_records_schemes() {
        let mut reg = PluginRegistry::new();
        reg.register_secret_provider(
            secret_provider("dev.test.secret", vec!["env", "file"]),
            PluginTier::Native,
        )
        .unwrap();
        assert_eq!(
            reg.secret_provider_ids(),
            vec!["dev.test.secret".to_string()]
        );
    }

    #[test]
    fn register_secret_provider_refuses_duplicate_id() {
        let mut reg = PluginRegistry::new();
        reg.register_secret_provider(
            secret_provider("dev.test.secret", vec!["env"]),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .register_secret_provider(
                secret_provider("dev.test.secret", vec!["file"]),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[test]
    fn register_secret_provider_refuses_plugin_with_no_schemes() {
        let mut reg = PluginRegistry::new();
        let err = reg
            .register_secret_provider(
                secret_provider("dev.test.empty", vec![]),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("unreachable"));
    }

    #[test]
    fn bind_secret_scheme_resolves_lookup() {
        let mut reg = PluginRegistry::new();
        reg.register_secret_provider(
            secret_provider("dev.test.secret", vec!["vault", "aws"]),
            PluginTier::Native,
        )
        .unwrap();
        reg.bind_secret_scheme("vault", "dev.test.secret").unwrap();
        assert!(reg.secret_provider_for_scheme("vault").is_some());
        assert!(reg.secret_provider_for_scheme("aws").is_none());
    }

    #[test]
    fn bind_secret_scheme_refuses_reserved_scheme_for_non_builtin() {
        let mut reg = PluginRegistry::new();
        reg.register_secret_provider(
            secret_provider("dev.test.secret", vec!["env", "file"]),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .bind_secret_scheme("env", "dev.test.secret")
            .unwrap_err();
        assert!(err.to_string().contains("reserved scheme"));
    }

    #[test]
    fn bind_secret_scheme_refuses_unsupported_scheme() {
        let mut reg = PluginRegistry::new();
        reg.register_secret_provider(
            secret_provider("dev.test.secret", vec!["env"]),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .bind_secret_scheme("vault", "dev.test.secret")
            .unwrap_err();
        assert!(err.to_string().contains("does not support scheme"));
    }

    #[test]
    fn bind_secret_scheme_refuses_unknown_plugin() {
        let mut reg = PluginRegistry::new();
        let err = reg
            .bind_secret_scheme("vault", "missing.plugin")
            .unwrap_err();
        assert!(err.to_string().contains("is not registered"));
    }

    #[test]
    fn bind_secret_scheme_refuses_non_serving_plugin() {
        let mut reg = PluginRegistry::new();
        reg.register_secret_provider(
            secret_provider("dev.test.secret", vec!["vault"]),
            PluginTier::Native,
        )
        .unwrap();
        reg.disable("dev.test.secret").unwrap();
        let err = reg
            .bind_secret_scheme("vault", "dev.test.secret")
            .unwrap_err();
        assert!(err.to_string().contains("is not serving traffic"));
    }

    #[tokio::test]
    async fn resolve_secret_dispatches_by_scheme() {
        let mut reg = PluginRegistry::new();
        reg.register_secret_provider(
            secret_provider("dev.test.secret", vec!["vault"]),
            PluginTier::Native,
        )
        .unwrap();
        reg.bind_secret_scheme("vault", "dev.test.secret").unwrap();
        let v = reg.resolve_secret("vault://DB_PASS").await.unwrap();
        assert_eq!(v.bytes.as_ref(), b"hunter2");
    }

    #[tokio::test]
    async fn resolve_secret_unbound_scheme_errors_cleanly() {
        let reg = PluginRegistry::new();
        let err = reg
            .resolve_secret("vault://secret/data/db#password")
            .await
            .unwrap_err();
        assert_eq!(err.kind_label(), "unsupported_scheme");
    }

    #[tokio::test]
    async fn resolve_secret_malformed_ref_errors_cleanly() {
        let reg = PluginRegistry::new();
        let err = reg.resolve_secret("not-a-uri").await.unwrap_err();
        assert_eq!(err.kind_label(), "invalid_reference");
    }

    #[test]
    fn secret_provider_shows_up_in_loaded_plugins() {
        let mut reg = PluginRegistry::new();
        reg.register_secret_provider(
            secret_provider("dev.test.secret", vec!["env", "file"]),
            PluginTier::Native,
        )
        .unwrap();
        let info = reg.loaded_plugins();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].plugin_class, "secret_provider:env,file");
        assert_eq!(reg.total_count(), 1);
    }

    // -- config_provider tests ----------------------------------------------

    struct FixedConfigProvider {
        manifest: PluginManifest,
        schemes: Vec<String>,
        values: serde_json::Value,
    }

    #[async_trait]
    impl mcpg_plugin_protocol::config::ConfigProvider for FixedConfigProvider {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn supported_schemes(&self) -> Vec<String> {
            self.schemes.clone()
        }
        async fn snapshot(
            &self,
            reference: &str,
        ) -> Result<
            mcpg_plugin_protocol::config::ConfigSnapshot,
            mcpg_plugin_protocol::config::ConfigError,
        > {
            Ok(mcpg_plugin_protocol::config::ConfigSnapshot {
                version: "v1".into(),
                values: self.values.clone(),
                fetched_at: "2026-04-23T00:00:00Z".into(),
                source: reference.to_owned(),
            })
        }
    }

    fn config_provider(
        id: &str,
        schemes: Vec<&str>,
        values: serde_json::Value,
    ) -> Arc<FixedConfigProvider> {
        Arc::new(FixedConfigProvider {
            manifest: test_manifest(id, PluginClass::ConfigProvider),
            schemes: schemes.into_iter().map(String::from).collect(),
            values,
        })
    }

    #[test]
    fn register_config_provider_records_schemes() {
        let mut reg = PluginRegistry::new();
        reg.register_config_provider(
            config_provider(
                "dev.test.config",
                vec!["file", "consul"],
                serde_json::json!({}),
            ),
            PluginTier::Native,
        )
        .unwrap();
        assert_eq!(
            reg.config_provider_ids(),
            vec!["dev.test.config".to_string()]
        );
    }

    #[test]
    fn register_config_provider_refuses_duplicate_id() {
        let mut reg = PluginRegistry::new();
        reg.register_config_provider(
            config_provider("dev.test.config", vec!["file"], serde_json::json!({})),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .register_config_provider(
                config_provider("dev.test.config", vec!["consul"], serde_json::json!({})),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[test]
    fn register_config_provider_refuses_plugin_with_no_schemes() {
        let mut reg = PluginRegistry::new();
        let err = reg
            .register_config_provider(
                config_provider("dev.test.empty", vec![], serde_json::json!({})),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("unreachable"));
    }

    #[test]
    fn bind_config_scheme_resolves_lookup() {
        let mut reg = PluginRegistry::new();
        reg.register_config_provider(
            config_provider(
                "dev.test.config",
                vec!["consul", "k8s-cm"],
                serde_json::json!({}),
            ),
            PluginTier::Native,
        )
        .unwrap();
        reg.bind_config_scheme("consul", "dev.test.config").unwrap();
        assert!(reg.config_provider_for_scheme("consul").is_some());
        assert!(reg.config_provider_for_scheme("k8s-cm").is_none());
    }

    #[test]
    fn bind_config_scheme_refuses_reserved_scheme_for_non_builtin() {
        let mut reg = PluginRegistry::new();
        reg.register_config_provider(
            config_provider("dev.test.config", vec!["file"], serde_json::json!({})),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .bind_config_scheme("file", "dev.test.config")
            .unwrap_err();
        assert!(err.to_string().contains("reserved scheme"));
    }

    #[test]
    fn bind_config_scheme_refuses_unsupported_scheme() {
        let mut reg = PluginRegistry::new();
        reg.register_config_provider(
            config_provider("dev.test.config", vec!["file"], serde_json::json!({})),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .bind_config_scheme("consul", "dev.test.config")
            .unwrap_err();
        assert!(err.to_string().contains("does not support scheme"));
    }

    #[test]
    fn bind_config_scheme_refuses_unknown_plugin() {
        let mut reg = PluginRegistry::new();
        let err = reg
            .bind_config_scheme("consul", "missing.plugin")
            .unwrap_err();
        assert!(err.to_string().contains("is not registered"));
    }

    #[test]
    fn bind_config_scheme_refuses_non_serving_plugin() {
        let mut reg = PluginRegistry::new();
        reg.register_config_provider(
            config_provider("dev.test.config", vec!["consul"], serde_json::json!({})),
            PluginTier::Native,
        )
        .unwrap();
        reg.disable("dev.test.config").unwrap();
        let err = reg
            .bind_config_scheme("consul", "dev.test.config")
            .unwrap_err();
        assert!(err.to_string().contains("is not serving traffic"));
    }

    #[tokio::test]
    async fn snapshot_config_dispatches_by_scheme() {
        let mut reg = PluginRegistry::new();
        reg.register_config_provider(
            config_provider(
                "dev.test.config",
                vec!["consul"],
                serde_json::json!({"feature_x": true}),
            ),
            PluginTier::Native,
        )
        .unwrap();
        reg.bind_config_scheme("consul", "dev.test.config").unwrap();
        let snap = reg
            .snapshot_config("consul:///etc/mcpg/cfg.yaml")
            .await
            .unwrap();
        assert_eq!(snap.values["feature_x"], true);
        assert_eq!(snap.source, "consul:///etc/mcpg/cfg.yaml");
    }

    #[tokio::test]
    async fn snapshot_config_unbound_scheme_errors_cleanly() {
        let reg = PluginRegistry::new();
        let err = reg
            .snapshot_config("consul://kv/mcpg/config")
            .await
            .unwrap_err();
        assert_eq!(err.kind_label(), "unsupported_scheme");
    }

    #[tokio::test]
    async fn snapshot_config_malformed_ref_errors_cleanly() {
        let reg = PluginRegistry::new();
        let err = reg.snapshot_config("not-a-uri").await.unwrap_err();
        assert_eq!(err.kind_label(), "invalid_reference");
    }

    #[test]
    fn config_provider_shows_up_in_loaded_plugins() {
        let mut reg = PluginRegistry::new();
        reg.register_config_provider(
            config_provider(
                "dev.test.config",
                vec!["file", "consul"],
                serde_json::json!({}),
            ),
            PluginTier::Native,
        )
        .unwrap();
        let info = reg.loaded_plugins();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].plugin_class, "config_provider:file,consul");
        assert_eq!(reg.total_count(), 1);
    }

    // -- auto-bind sweep tests ---------------------------------------------

    #[test]
    fn auto_bind_secret_provider_schemes_binds_every_advertised_scheme() {
        let mut reg = PluginRegistry::new();
        reg.register_secret_provider(
            secret_provider("dev.test.vault", vec!["vault"]),
            PluginTier::Native,
        )
        .unwrap();
        reg.register_secret_provider(
            secret_provider("dev.test.aws", vec!["aws-sm"]),
            PluginTier::Native,
        )
        .unwrap();
        reg.auto_bind_secret_provider_schemes().unwrap();
        assert!(reg.secret_provider_for_scheme("vault").is_some());
        assert!(reg.secret_provider_for_scheme("aws-sm").is_some());
        assert!(reg.secret_provider_for_scheme("env").is_none());
    }

    #[test]
    fn auto_bind_secret_provider_schemes_skips_already_bound() {
        let mut reg = PluginRegistry::new();
        reg.register_secret_provider(
            secret_provider("dev.test.multi", vec!["vault", "aws-sm"]),
            PluginTier::Native,
        )
        .unwrap();
        reg.bind_secret_scheme("vault", "dev.test.multi").unwrap();
        // Auto-sweep must succeed even though "vault" is already bound, and
        // must add the previously unbound "aws-sm" scheme.
        reg.auto_bind_secret_provider_schemes().unwrap();
        assert!(reg.secret_provider_for_scheme("vault").is_some());
        assert!(reg.secret_provider_for_scheme("aws-sm").is_some());
    }

    // SECURITY: a non-builtin plugin must not auto-bind a reserved scheme
    // (env:// / file://) and shadow the gateway's built-in resolvers.
    #[test]
    fn auto_bind_rejects_reserved_scheme_from_non_builtin() {
        let mut reg = PluginRegistry::new();
        reg.register_secret_provider(
            secret_provider("dev.evil.secret", vec!["env"]),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg.auto_bind_secret_provider_schemes().unwrap_err();
        assert!(err.to_string().contains("reserved scheme"), "got: {err}");
        assert!(reg.secret_provider_for_scheme("env").is_none());

        let mut creg = PluginRegistry::new();
        creg.register_config_provider(
            config_provider("dev.evil.config", vec!["file"], serde_json::json!({})),
            PluginTier::Native,
        )
        .unwrap();
        let cerr = creg.auto_bind_config_provider_schemes().unwrap_err();
        assert!(cerr.to_string().contains("reserved scheme"), "got: {cerr}");
    }

    // The static `provides_schemes` declaration, when present,
    // must match the runtime `supported_schemes()` — fail-closed on drift.
    #[test]
    fn cross_check_provides_schemes_behaviour() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();

        // Empty provides_schemes opts out — supported_schemes() stays
        // authoritative, no assertion.
        assert!(cross_check_provides_schemes("secret_provider", "p", &[], &s(&["vault"])).is_ok());
        // Match (order-independent).
        assert!(
            cross_check_provides_schemes(
                "secret_provider",
                "p",
                &s(&["aws-sm", "vault"]),
                &s(&["vault", "aws-sm"]),
            )
            .is_ok()
        );
        // Drift: declares a scheme it doesn't actually serve.
        let err = cross_check_provides_schemes(
            "secret_provider",
            "dev.test.vault",
            &s(&["vault", "gcp-sm"]),
            &s(&["vault"]),
        )
        .unwrap_err();
        assert!(err.to_string().contains("scheme drift"), "got: {err}");
    }

    // A built-in (dev.mcpg.builtin.*) IS the legitimate owner of env/file and
    // auto-binds them fine.
    #[test]
    fn auto_bind_allows_reserved_scheme_for_builtin() {
        let mut reg = PluginRegistry::new();
        reg.register_secret_provider(
            secret_provider("dev.mcpg.builtin.secret.env", vec!["env"]),
            PluginTier::Native,
        )
        .unwrap();
        reg.auto_bind_secret_provider_schemes().unwrap();
        assert!(reg.secret_provider_for_scheme("env").is_some());
    }

    // Per-call capability enforcement: the registry records
    // operator-granted typed capabilities by alias, and the scheme/kind check
    // is `Capability::covers`. Unknown alias ⇒ empty ⇒ fail-closed.
    #[test]
    fn granted_capabilities_recorded_and_scoped_by_alias() {
        use mcpg_plugin_protocol::capability::Capability;
        let mut reg = PluginRegistry::new();
        // Unknown alias ⇒ no grant.
        assert!(reg.granted_capabilities_for_alias("dev.unknown").is_empty());

        reg.record_granted_capabilities(
            "dev.test.consumer".into(),
            vec![Capability::SecretsRead {
                schemes: vec!["vault".into()],
            }],
        );
        let granted = reg.granted_capabilities_for_alias("dev.test.consumer");
        let needs_vault = Capability::SecretsRead {
            schemes: vec!["vault".into()],
        };
        let needs_env = Capability::SecretsRead {
            schemes: vec!["env".into()],
        };
        let needs_config = Capability::ConfigRead {
            schemes: vec!["vault".into()],
        };
        // Covered: the granted vault scheme.
        assert!(granted.iter().any(|g| g.covers(&needs_vault)));
        // Not covered: a scheme that wasn't granted...
        assert!(!granted.iter().any(|g| g.covers(&needs_env)));
        // ...nor a different capability family.
        assert!(!granted.iter().any(|g| g.covers(&needs_config)));
    }

    #[test]
    fn cred_resolve_allowlist_scoped_by_alias_and_issuer() {
        let mut reg = PluginRegistry::new();
        // Unknown alias ⇒ nothing allowed (fail-closed).
        assert!(!reg.cred_resolve_issuer_allowed("dev.unknown", "vault-pg"));

        let mut issuers = std::collections::HashSet::new();
        issuers.insert("vault-pg".to_owned());
        reg.record_cred_resolve_allowlist("dev.backend.sql".into(), issuers);

        // The configured issuer is allowed for this alias...
        assert!(reg.cred_resolve_issuer_allowed("dev.backend.sql", "vault-pg"));
        // ...but an issuer not in the alias's config is not...
        assert!(!reg.cred_resolve_issuer_allowed("dev.backend.sql", "vault-admin"));
        // ...and a different alias gets no access to the same issuer.
        assert!(!reg.cred_resolve_issuer_allowed("dev.backend.http", "vault-pg"));
    }

    #[test]
    fn cred_resolve_ref_allowlist_gates_the_exact_target() {
        let mut reg = PluginRegistry::new();
        // Unknown alias ⇒ nothing allowed (fail-closed).
        assert!(!reg.cred_resolve_ref_allowed("dev.unknown", "vault-pg", "orders-ro"));

        let mut refs = std::collections::HashSet::new();
        refs.insert(crate::credential_resolver::cred_ref_key(
            "vault-pg",
            "orders-ro",
        ));
        reg.record_cred_resolve_ref_allowlist("dev.backend.sql".into(), refs);

        // The configured (issuer, target) pair is allowed...
        assert!(reg.cred_resolve_ref_allowed("dev.backend.sql", "vault-pg", "orders-ro"));
        // ...but a DIFFERENT target on the SAME (referenced) issuer is not —
        // the issuer being in config is not enough.
        assert!(!reg.cred_resolve_ref_allowed("dev.backend.sql", "vault-pg", "payroll-rw"));
        // ...nor a different alias.
        assert!(!reg.cred_resolve_ref_allowed("dev.backend.http", "vault-pg", "orders-ro"));
    }

    #[test]
    fn resource_resolve_allowlist_gates_the_concrete_resource() {
        let mut reg = PluginRegistry::new();
        // Unknown alias ⇒ nothing allowed (fail-closed).
        assert!(!reg.resource_resolve_allowed("dev.unknown", "env://API_KEY"));

        let mut resources = std::collections::HashSet::new();
        // Whole-resource grants (no anchor in config).
        resources.insert("env://OPENAI_KEY".to_owned());
        resources.insert("file:///etc/mcpg/db.json".to_owned());
        reg.record_resource_resolve_allowlist("dev.backend.llm".into(), resources);

        // The config-referenced whole resources are allowed — and because the
        // bare path is a whole-resource grant, any `#field` on it is too (the
        // env/file providers ignore the anchor anyway).
        assert!(reg.resource_resolve_allowed("dev.backend.llm", "env://OPENAI_KEY"));
        assert!(reg.resource_resolve_allowed("dev.backend.llm", "env://OPENAI_KEY#ignored"));
        assert!(
            reg.resource_resolve_allowed("dev.backend.llm", "file:///etc/mcpg/db.json#password")
        );
        // A different var on the SAME scheme is refused (scheme-cap is not
        // enough — the concrete resource must be config-referenced).
        assert!(!reg.resource_resolve_allowed("dev.backend.llm", "env://AWS_SECRET_ACCESS_KEY"));
        assert!(!reg.resource_resolve_allowed("dev.backend.llm", "file:///etc/shadow"));
        // Non-URI input ⇒ refused.
        assert!(!reg.resource_resolve_allowed("dev.backend.llm", "not-a-uri"));
        // A different alias gets nothing.
        assert!(!reg.resource_resolve_allowed("dev.backend.http", "env://OPENAI_KEY"));
    }

    #[test]
    fn resource_resolve_field_grant_does_not_widen_to_sibling_fields() {
        // A multi-key Vault path: `#field` selects a DISTINCT secret read from
        // one path. A plugin that references one field must not reach its
        // siblings via an anchor-stripping bypass.
        let mut reg = PluginRegistry::new();
        let mut resources = std::collections::HashSet::new();
        resources.insert("vault://secret/data/api-keys#github".to_owned());
        reg.record_resource_resolve_allowlist("dev.backend.ci".into(), resources);

        // The referenced field is allowed...
        assert!(
            reg.resource_resolve_allowed("dev.backend.ci", "vault://secret/data/api-keys#github")
        );
        // ...but a SIBLING field on the same path is refused (a field grant
        // does not widen)...
        assert!(
            !reg.resource_resolve_allowed("dev.backend.ci", "vault://secret/data/api-keys#stripe")
        );
        // ...nor does it widen to the WHOLE path (which would return every
        // field).
        assert!(!reg.resource_resolve_allowed("dev.backend.ci", "vault://secret/data/api-keys"));
    }

    #[test]
    fn resource_resolve_whole_resource_grant_covers_any_field() {
        // A bare-path reference grants the whole resource → any `#field` on it.
        let mut reg = PluginRegistry::new();
        let mut resources = std::collections::HashSet::new();
        resources.insert("vault://secret/data/db".to_owned());
        reg.record_resource_resolve_allowlist("dev.backend.sql".into(), resources);

        assert!(reg.resource_resolve_allowed("dev.backend.sql", "vault://secret/data/db"));
        assert!(reg.resource_resolve_allowed("dev.backend.sql", "vault://secret/data/db#password"));
        assert!(reg.resource_resolve_allowed("dev.backend.sql", "vault://secret/data/db#username"));
        // A different path is still refused.
        assert!(!reg.resource_resolve_allowed("dev.backend.sql", "vault://secret/data/other#x"));
    }

    #[test]
    fn auto_bind_secret_provider_schemes_refuses_conflict() {
        let mut reg = PluginRegistry::new();
        reg.register_secret_provider(
            secret_provider("dev.test.a", vec!["vault"]),
            PluginTier::Native,
        )
        .unwrap();
        reg.register_secret_provider(
            secret_provider("dev.test.b", vec!["vault"]),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg.auto_bind_secret_provider_schemes().unwrap_err();
        assert!(err.to_string().contains("scheme conflict"));
        assert!(err.to_string().contains("vault"));
    }

    #[test]
    fn auto_bind_config_provider_schemes_binds_every_advertised_scheme() {
        let mut reg = PluginRegistry::new();
        reg.register_config_provider(
            config_provider("dev.test.consul", vec!["consul"], serde_json::json!({})),
            PluginTier::Native,
        )
        .unwrap();
        reg.register_config_provider(
            config_provider("dev.test.k8s", vec!["k8s-cm"], serde_json::json!({})),
            PluginTier::Native,
        )
        .unwrap();
        reg.auto_bind_config_provider_schemes().unwrap();
        assert!(reg.config_provider_for_scheme("consul").is_some());
        assert!(reg.config_provider_for_scheme("k8s-cm").is_some());
        assert!(reg.config_provider_for_scheme("file").is_none());
    }

    #[test]
    fn auto_bind_config_provider_schemes_refuses_conflict() {
        let mut reg = PluginRegistry::new();
        reg.register_config_provider(
            config_provider("dev.test.a", vec!["consul"], serde_json::json!({})),
            PluginTier::Native,
        )
        .unwrap();
        reg.register_config_provider(
            config_provider("dev.test.b", vec!["consul"], serde_json::json!({})),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg.auto_bind_config_provider_schemes().unwrap_err();
        assert!(err.to_string().contains("scheme conflict"));
        assert!(err.to_string().contains("consul"));
    }

    // -- transport tests ----------------------------------------------------

    struct FixedTransport {
        manifest: PluginManifest,
        name: String,
    }

    #[async_trait]
    impl mcpg_plugin_protocol::transport::Transport for FixedTransport {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn name(&self) -> &str {
            &self.name
        }
        async fn start(
            &self,
            _listener_config: &serde_json::Value,
            _dispatcher: Arc<dyn mcpg_plugin_protocol::transport::MessageDispatcher>,
        ) -> Result<
            Box<dyn mcpg_plugin_protocol::transport::TransportHandle>,
            mcpg_plugin_protocol::transport::TransportError,
        > {
            Err(mcpg_plugin_protocol::transport::TransportError::Shutdown)
        }
    }

    fn transport_plugin(id: &str, name: &str) -> Arc<FixedTransport> {
        Arc::new(FixedTransport {
            manifest: test_manifest(id, PluginClass::Transport),
            name: name.to_owned(),
        })
    }

    #[test]
    fn register_transport_records_name() {
        let mut reg = PluginRegistry::new();
        reg.register_transport(
            transport_plugin("dev.test.transport.http", "http-v1"),
            PluginTier::Native,
        )
        .unwrap();
        assert_eq!(
            reg.transport_plugin_ids(),
            vec!["dev.test.transport.http".to_string()]
        );
        assert_eq!(reg.transport_names(), vec!["http-v1".to_string()]);
    }

    #[test]
    fn register_transport_refuses_duplicate_id() {
        let mut reg = PluginRegistry::new();
        reg.register_transport(
            transport_plugin("dev.test.transport", "http-v1"),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .register_transport(
                transport_plugin("dev.test.transport", "stdio-v1"),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[test]
    fn register_transport_refuses_duplicate_name() {
        let mut reg = PluginRegistry::new();
        reg.register_transport(
            transport_plugin("dev.test.transport.a", "http-v1"),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .register_transport(
                transport_plugin("dev.test.transport.b", "http-v1"),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("already served by"), "got: {err}");
    }

    #[test]
    fn register_transport_refuses_empty_name() {
        let mut reg = PluginRegistry::new();
        let err = reg
            .register_transport(
                transport_plugin("dev.test.transport.empty", ""),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("empty name"));
    }

    #[test]
    fn transport_by_name_resolves_lookup() {
        let mut reg = PluginRegistry::new();
        reg.register_transport(
            transport_plugin("dev.test.transport.http", "http-v1"),
            PluginTier::Native,
        )
        .unwrap();
        assert!(reg.transport_by_name("http-v1").is_some());
        assert!(reg.transport_by_name("stdio-v1").is_none());
    }

    #[test]
    fn transport_names_are_sorted() {
        let mut reg = PluginRegistry::new();
        reg.register_transport(
            transport_plugin("dev.test.transport.ws", "websocket-v1"),
            PluginTier::Native,
        )
        .unwrap();
        reg.register_transport(
            transport_plugin("dev.test.transport.http", "http-v1"),
            PluginTier::Native,
        )
        .unwrap();
        assert_eq!(
            reg.transport_names(),
            vec!["http-v1".to_string(), "websocket-v1".to_string()]
        );
    }

    #[test]
    fn transport_shows_up_in_loaded_plugins() {
        let mut reg = PluginRegistry::new();
        reg.register_transport(
            transport_plugin("dev.test.transport.http", "http-v1"),
            PluginTier::Native,
        )
        .unwrap();
        let info = reg.loaded_plugins();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].plugin_class, "transport:http-v1");
        assert_eq!(reg.total_count(), 1);
    }

    // -- approval_notifier tests --------------------------------------------

    struct StubApprovalNotifier {
        manifest: PluginManifest,
    }

    #[async_trait]
    impl mcpg_plugin_protocol::approval_notifier::ApprovalNotifier for StubApprovalNotifier {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn notify(
            &self,
            _request: &mcpg_plugin_protocol::approval_notifier::NotificationRequest,
        ) -> Result<
            mcpg_plugin_protocol::approval_notifier::NotificationResult,
            mcpg_plugin_protocol::approval_notifier::NotificationError,
        > {
            Ok(
                mcpg_plugin_protocol::approval_notifier::NotificationResult {
                    channel: format!("ch:{}", self.manifest.id),
                    metadata: Default::default(),
                },
            )
        }
    }

    fn approval_notifier_plugin(id: &str) -> Arc<StubApprovalNotifier> {
        Arc::new(StubApprovalNotifier {
            manifest: test_manifest(id, PluginClass::ApprovalNotifier),
        })
    }

    #[test]
    fn approval_notifier_register_and_lookup() {
        let mut reg = PluginRegistry::new();
        reg.register_approval_notifier(
            approval_notifier_plugin("dev.test.notify.slack"),
            PluginTier::Native,
        )
        .unwrap();
        assert!(reg.approval_notifier("dev.test.notify.slack").is_some());
        assert!(reg.approval_notifier("dev.test.notify.email").is_none());
        assert_eq!(
            reg.approval_notifier_plugin_ids(),
            vec!["dev.test.notify.slack".to_string()]
        );
        assert_eq!(reg.total_count(), 1);
    }

    #[test]
    fn approval_notifier_register_rejects_duplicate() {
        let mut reg = PluginRegistry::new();
        reg.register_approval_notifier(
            approval_notifier_plugin("dev.test.notify.slack"),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg.register_approval_notifier(
            approval_notifier_plugin("dev.test.notify.slack"),
            PluginTier::Native,
        );
        assert!(err.is_err());
    }

    #[test]
    fn approval_notifier_resolve_empty_targets_fans_out() {
        let mut reg = PluginRegistry::new();
        reg.register_approval_notifier(
            approval_notifier_plugin("dev.test.notify.slack"),
            PluginTier::Native,
        )
        .unwrap();
        reg.register_approval_notifier(
            approval_notifier_plugin("dev.test.notify.email"),
            PluginTier::Native,
        )
        .unwrap();
        let resolved = reg.resolve_approval_notifiers(&[]);
        assert_eq!(resolved.len(), 2);
    }

    #[test]
    fn approval_notifier_resolve_targeted_filters_to_listed() {
        let mut reg = PluginRegistry::new();
        reg.register_approval_notifier(
            approval_notifier_plugin("dev.test.notify.slack"),
            PluginTier::Native,
        )
        .unwrap();
        reg.register_approval_notifier(
            approval_notifier_plugin("dev.test.notify.email"),
            PluginTier::Native,
        )
        .unwrap();
        let resolved = reg.resolve_approval_notifiers(&[
            "dev.test.notify.slack".into(),
            "dev.test.notify.unknown".into(),
        ]);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].manifest().id, "dev.test.notify.slack");
    }

    #[test]
    fn approval_notifier_shows_up_in_loaded_plugins() {
        let mut reg = PluginRegistry::new();
        reg.register_approval_notifier(
            approval_notifier_plugin("dev.test.notify.slack"),
            PluginTier::Native,
        )
        .unwrap();
        let info = reg.loaded_plugins();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].id, "dev.test.notify.slack");
        assert_eq!(info[0].plugin_class, "approval_notifier");
    }

    // -- policy_engine tests ------------------------------------------------

    struct FixedPolicy {
        manifest: PluginManifest,
        name: String,
        effect: mcpg_plugin_protocol::policy::PolicyEffect,
    }

    #[async_trait]
    impl mcpg_plugin_protocol::policy::PolicyEngine for FixedPolicy {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn name(&self) -> &str {
            &self.name
        }
        async fn evaluate(
            &self,
            _decision_point: &str,
            _input: &serde_json::Value,
            _context: &mcpg_plugin_protocol::PluginContext,
        ) -> mcpg_plugin_protocol::policy::PolicyDecision {
            use mcpg_plugin_protocol::policy::{PolicyDecision, PolicyEffect};
            match self.effect {
                PolicyEffect::Allow => PolicyDecision::allow("sha256:test"),
                PolicyEffect::Deny => PolicyDecision::deny("test denies", "sha256:test"),
                PolicyEffect::NotApplicable => PolicyDecision::not_applicable("sha256:test"),
            }
        }
        async fn policy_version(&self) -> mcpg_plugin_protocol::policy::PolicyVersion {
            mcpg_plugin_protocol::policy::PolicyVersion {
                hash: "sha256:test".into(),
                loaded_at: "2026-04-23T00:00:00Z".into(),
                source: "test".into(),
            }
        }
    }

    fn policy_plugin(
        id: &str,
        name: &str,
        effect: mcpg_plugin_protocol::policy::PolicyEffect,
    ) -> Arc<FixedPolicy> {
        Arc::new(FixedPolicy {
            manifest: test_manifest(id, PluginClass::PolicyEngine),
            name: name.to_owned(),
            effect,
        })
    }

    #[test]
    fn register_policy_engine_records_name() {
        use mcpg_plugin_protocol::policy::PolicyEffect;
        let mut reg = PluginRegistry::new();
        reg.register_policy_engine(
            policy_plugin("dev.test.policy.opa", "opa", PolicyEffect::Allow),
            PluginTier::Native,
        )
        .unwrap();
        assert_eq!(
            reg.policy_engine_plugin_ids(),
            vec!["dev.test.policy.opa".to_string()]
        );
        assert_eq!(reg.policy_engine_names(), vec!["opa".to_string()]);
    }

    #[test]
    fn register_policy_engine_refuses_duplicate_id() {
        use mcpg_plugin_protocol::policy::PolicyEffect;
        let mut reg = PluginRegistry::new();
        reg.register_policy_engine(
            policy_plugin("dev.test.policy", "opa", PolicyEffect::Allow),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .register_policy_engine(
                policy_plugin("dev.test.policy", "cedar", PolicyEffect::Allow),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[test]
    fn register_policy_engine_refuses_duplicate_name() {
        use mcpg_plugin_protocol::policy::PolicyEffect;
        let mut reg = PluginRegistry::new();
        reg.register_policy_engine(
            policy_plugin("dev.test.policy.a", "opa", PolicyEffect::Allow),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg
            .register_policy_engine(
                policy_plugin("dev.test.policy.b", "opa", PolicyEffect::Allow),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("already served by"));
    }

    #[test]
    fn register_policy_engine_refuses_empty_name() {
        use mcpg_plugin_protocol::policy::PolicyEffect;
        let mut reg = PluginRegistry::new();
        let err = reg
            .register_policy_engine(
                policy_plugin("dev.test.policy.empty", "", PolicyEffect::Allow),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("empty name"));
    }

    #[test]
    fn policy_engine_by_name_resolves_lookup() {
        use mcpg_plugin_protocol::policy::PolicyEffect;
        let mut reg = PluginRegistry::new();
        reg.register_policy_engine(
            policy_plugin("dev.test.policy.opa", "opa", PolicyEffect::Allow),
            PluginTier::Native,
        )
        .unwrap();
        assert!(reg.policy_engine_by_name("opa").is_some());
        assert!(reg.policy_engine_by_name("cedar").is_none());
    }

    #[tokio::test]
    async fn evaluate_policy_dispatches_by_engine_name() {
        use mcpg_plugin_protocol::policy::PolicyEffect;
        let mut reg = PluginRegistry::new();
        reg.register_policy_engine(
            policy_plugin("dev.test.policy.opa", "opa", PolicyEffect::Deny),
            PluginTier::Native,
        )
        .unwrap();
        let ctx = mcpg_plugin_protocol::PluginContext {
            request_id: "r1".into(),
            session_id: None,
            tool_name: "test-tool".into(),
            surface: "tool".into(),
            identity: mcpg_plugin_protocol::PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: Default::default(),
            },
            transport: "http".into(),
        };
        let d = reg
            .evaluate_policy("opa", "tool.call.pre", &serde_json::json!({}), &ctx)
            .await;
        assert_eq!(d.effect, PolicyEffect::Deny);
        assert_eq!(d.reason.as_deref(), Some("test denies"));
    }

    #[tokio::test]
    async fn evaluate_policy_unknown_engine_returns_not_applicable() {
        use mcpg_plugin_protocol::policy::PolicyEffect;
        let reg = PluginRegistry::new();
        let ctx = mcpg_plugin_protocol::PluginContext {
            request_id: "r1".into(),
            session_id: None,
            tool_name: "test-tool".into(),
            surface: "tool".into(),
            identity: mcpg_plugin_protocol::PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: Default::default(),
            },
            transport: "http".into(),
        };
        let d = reg
            .evaluate_policy(
                "missing-engine",
                "tool.call.pre",
                &serde_json::json!({}),
                &ctx,
            )
            .await;
        assert_eq!(d.effect, PolicyEffect::NotApplicable);
        assert!(d.policy_version.is_empty());
    }

    #[test]
    fn policy_engine_shows_up_in_loaded_plugins() {
        use mcpg_plugin_protocol::policy::PolicyEffect;
        let mut reg = PluginRegistry::new();
        reg.register_policy_engine(
            policy_plugin("dev.test.policy.opa", "opa", PolicyEffect::Allow),
            PluginTier::Native,
        )
        .unwrap();
        let info = reg.loaded_plugins();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].plugin_class, "policy_engine:opa");
        assert_eq!(reg.total_count(), 1);
    }

    fn policy_chain_ctx() -> mcpg_plugin_protocol::PluginContext {
        mcpg_plugin_protocol::PluginContext {
            request_id: "r1".into(),
            session_id: None,
            tool_name: "test-tool".into(),
            surface: "tool".into(),
            identity: mcpg_plugin_protocol::PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: Default::default(),
            },
            transport: "http".into(),
        }
    }

    #[tokio::test]
    async fn policy_chain_empty_returns_not_applicable() {
        let reg = PluginRegistry::new();
        let outcome = reg
            .evaluate_policy_chain(
                &[],
                "tool.call.pre",
                &serde_json::json!({}),
                &policy_chain_ctx(),
            )
            .await;
        assert!(matches!(outcome, PolicyChainOutcome::NotApplicable));
    }

    #[tokio::test]
    async fn policy_chain_first_deny_short_circuits() {
        use mcpg_plugin_protocol::policy::PolicyEffect;
        let mut reg = PluginRegistry::new();
        reg.register_policy_engine(
            policy_plugin("dev.test.policy.a", "alpha", PolicyEffect::Allow),
            PluginTier::Native,
        )
        .unwrap();
        reg.register_policy_engine(
            policy_plugin("dev.test.policy.b", "bravo", PolicyEffect::Deny),
            PluginTier::Native,
        )
        .unwrap();
        // Run with the deny-engine FIRST in the chain.
        let outcome = reg
            .evaluate_policy_chain(
                &["bravo".into(), "alpha".into()],
                "tool.call.pre",
                &serde_json::json!({}),
                &policy_chain_ctx(),
            )
            .await;
        match outcome {
            PolicyChainOutcome::Deny { engine, reason, .. } => {
                assert_eq!(engine, "bravo");
                assert!(reason.contains("test denies"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn policy_chain_allow_overrides_subsequent_not_applicable() {
        use mcpg_plugin_protocol::policy::PolicyEffect;
        let mut reg = PluginRegistry::new();
        reg.register_policy_engine(
            policy_plugin("dev.test.policy.a", "alpha", PolicyEffect::Allow),
            PluginTier::Native,
        )
        .unwrap();
        reg.register_policy_engine(
            policy_plugin("dev.test.policy.b", "bravo", PolicyEffect::NotApplicable),
            PluginTier::Native,
        )
        .unwrap();
        let outcome = reg
            .evaluate_policy_chain(
                &["alpha".into(), "bravo".into()],
                "tool.call.pre",
                &serde_json::json!({}),
                &policy_chain_ctx(),
            )
            .await;
        match outcome {
            PolicyChainOutcome::Allow { engine, .. } => {
                assert_eq!(engine, "alpha");
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn policy_chain_all_not_applicable_returns_not_applicable() {
        use mcpg_plugin_protocol::policy::PolicyEffect;
        let mut reg = PluginRegistry::new();
        reg.register_policy_engine(
            policy_plugin("dev.test.policy.a", "alpha", PolicyEffect::NotApplicable),
            PluginTier::Native,
        )
        .unwrap();
        reg.register_policy_engine(
            policy_plugin("dev.test.policy.b", "bravo", PolicyEffect::NotApplicable),
            PluginTier::Native,
        )
        .unwrap();
        let outcome = reg
            .evaluate_policy_chain(
                &["alpha".into(), "bravo".into()],
                "tool.call.pre",
                &serde_json::json!({}),
                &policy_chain_ctx(),
            )
            .await;
        assert!(matches!(outcome, PolicyChainOutcome::NotApplicable));
    }

    #[tokio::test]
    async fn evaluate_plugin_registration_policy_empty_chain() {
        let reg = PluginRegistry::new();
        let manifest = test_manifest("dev.test.plugin", PluginClass::ToolGate);
        let outcome = reg.evaluate_plugin_registration_policy(&manifest).await;
        assert!(matches!(outcome, PolicyChainOutcome::NotApplicable));
    }

    #[tokio::test]
    async fn evaluate_plugin_registration_policy_passes_manifest_to_engine() {
        use mcpg_plugin_protocol::policy::PolicyEffect;
        // Engine that always denies — we just verify the helper
        // calls it with the right shape (and the chain short-
        // circuits as expected).
        let mut reg = PluginRegistry::new();
        reg.register_policy_engine(
            policy_plugin("dev.test.policy.deny", "deny-all", PolicyEffect::Deny),
            PluginTier::Native,
        )
        .unwrap();
        let mut manifest = test_manifest("dev.test.plugin", PluginClass::ToolGate);
        manifest.tags = vec!["experimental".into()];
        let outcome = reg.evaluate_plugin_registration_policy(&manifest).await;
        match outcome {
            PolicyChainOutcome::Deny { engine, .. } => {
                assert_eq!(engine, "deny-all");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn policy_chain_skips_unknown_engine_names() {
        use mcpg_plugin_protocol::policy::PolicyEffect;
        let mut reg = PluginRegistry::new();
        reg.register_policy_engine(
            policy_plugin("dev.test.policy.a", "alpha", PolicyEffect::Allow),
            PluginTier::Native,
        )
        .unwrap();
        // Operator typo: chain references "alphaa" + the real
        // "alpha". The unknown one is silently skipped (warn-
        // logged); the chain still produces Allow from the
        // known engine.
        let outcome = reg
            .evaluate_policy_chain(
                &["alphaa".into(), "alpha".into()],
                "tool.call.pre",
                &serde_json::json!({}),
                &policy_chain_ctx(),
            )
            .await;
        match outcome {
            PolicyChainOutcome::Allow { engine, .. } => {
                assert_eq!(engine, "alpha");
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    // -- cluster_backend tests ------------------------------------------

    struct FixedCluster {
        manifest: PluginManifest,
    }

    #[async_trait]
    impl mcpg_cluster_api::ClusterBackend for FixedCluster {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn node_info(&self) -> mcpg_cluster_api::ClusterNodeInfo {
            mcpg_cluster_api::ClusterNodeInfo {
                node_id: "n1".into(),
                address: "local".into(),
                version: "0.1.0".into(),
                started_at: "2026-04-23T00:00:00Z".into(),
                roles: vec![],
            }
        }
        async fn list_peers(&self) -> Vec<mcpg_cluster_api::ClusterPeer> {
            vec![]
        }
        async fn watch_peers(&self) -> mcpg_cluster_api::BoxPeerEventStream {
            Box::pin(empty_stream())
        }
        async fn acquire_leadership(
            &self,
            _role: &str,
            _lease_ttl: std::time::Duration,
        ) -> Result<mcpg_cluster_api::BoxActiveLease, mcpg_cluster_api::ClusterError> {
            Err(mcpg_cluster_api::ClusterError::Shutdown)
        }
        async fn acquire_lock(
            &self,
            _key: &str,
            _lease_ttl: std::time::Duration,
        ) -> Result<mcpg_cluster_api::BoxActiveLease, mcpg_cluster_api::ClusterError> {
            Err(mcpg_cluster_api::ClusterError::Shutdown)
        }
        async fn publish(
            &self,
            _topic: &str,
            _routing_key: Option<&str>,
            _payload: bytes::Bytes,
        ) -> Result<(), mcpg_cluster_api::ClusterError> {
            Ok(())
        }
        async fn subscribe(
            &self,
            _topic: &str,
            _group: Option<&str>,
            _routing_key: Option<&str>,
        ) -> Result<mcpg_cluster_api::BoxPublishedMessageStream, mcpg_cluster_api::ClusterError>
        {
            Ok(Box::pin(empty_stream()))
        }
    }

    /// A never-yielding stream. Generic — works for both
    /// `PeerEvent` + `PublishedMessage` without needing a
    /// separate futures crate dependency just for tests.
    fn empty_stream<T: Send + 'static>() -> impl futures_core::Stream<Item = T> + Send + 'static {
        struct Empty<T>(std::marker::PhantomData<T>);
        // SAFETY of Send: `Empty<T>` holds only a `PhantomData<T>`
        // which has no runtime storage; safely Send + Sync for any
        // `T: Send + 'static`.
        unsafe impl<T: Send> Send for Empty<T> {}
        impl<T> futures_core::Stream for Empty<T> {
            type Item = T;
            fn poll_next(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<T>> {
                std::task::Poll::Ready(None)
            }
        }
        Empty::<T>(std::marker::PhantomData)
    }

    fn cluster_plugin(id: &str) -> Arc<FixedCluster> {
        Arc::new(FixedCluster {
            manifest: test_manifest(id, PluginClass::Cluster),
        })
    }

    #[test]
    fn register_cluster_backend_singleton() {
        let mut reg = PluginRegistry::new();
        assert!(!reg.has_cluster_backend());
        reg.register_cluster_backend(cluster_plugin("dev.test.cluster.a"), PluginTier::Native)
            .unwrap();
        assert!(reg.has_cluster_backend());
        assert_eq!(
            reg.cluster_backend_plugin_id(),
            Some("dev.test.cluster.a".to_string())
        );
    }

    #[test]
    fn register_cluster_backend_refuses_replacement() {
        let mut reg = PluginRegistry::new();
        reg.register_cluster_backend(cluster_plugin("dev.test.cluster.a"), PluginTier::Native)
            .unwrap();
        let err = reg
            .register_cluster_backend(cluster_plugin("dev.test.cluster.b"), PluginTier::Native)
            .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[tokio::test]
    async fn cluster_backend_accessor_returns_registered_instance() {
        let mut reg = PluginRegistry::new();
        reg.register_cluster_backend(cluster_plugin("dev.test.cluster.a"), PluginTier::Native)
            .unwrap();
        let cc = reg.cluster_backend().unwrap();
        let info = cc.node_info().await;
        assert_eq!(info.node_id, "n1");
    }

    #[test]
    fn cluster_backend_shows_up_in_loaded_plugins() {
        let mut reg = PluginRegistry::new();
        reg.register_cluster_backend(cluster_plugin("dev.test.cluster.a"), PluginTier::Native)
            .unwrap();
        let info = reg.loaded_plugins();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].plugin_class, "cluster");
        assert_eq!(reg.total_count(), 1);
    }

    // -- telemetry_sink + log_sink tests ------------------------------------

    struct CountingTelemetry {
        manifest: PluginManifest,
        spans_started: std::sync::atomic::AtomicUsize,
        spans_ended: std::sync::atomic::AtomicUsize,
        metrics: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl mcpg_plugin_protocol::telemetry::TelemetrySink for CountingTelemetry {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn span_started(&self, _span: mcpg_plugin_protocol::telemetry::SpanStart) {
            self.spans_started
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        async fn span_ended(&self, _span: mcpg_plugin_protocol::telemetry::SpanEnd) {
            self.spans_ended
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        async fn metric_recorded(&self, _m: mcpg_plugin_protocol::telemetry::MetricPoint) {
            self.metrics
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        async fn flush(
            &self,
            _timeout: std::time::Duration,
        ) -> Result<(), mcpg_plugin_protocol::telemetry::TelemetryError> {
            Ok(())
        }
    }

    fn telemetry_sink(id: &str) -> Arc<CountingTelemetry> {
        Arc::new(CountingTelemetry {
            manifest: test_manifest(id, PluginClass::TelemetrySink),
            spans_started: std::sync::atomic::AtomicUsize::new(0),
            spans_ended: std::sync::atomic::AtomicUsize::new(0),
            metrics: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn sample_span_start() -> mcpg_plugin_protocol::telemetry::SpanStart {
        mcpg_plugin_protocol::telemetry::SpanStart {
            trace_id: "t1".into(),
            span_id: "s1".into(),
            parent_id: None,
            name: "op".into(),
            kind: mcpg_plugin_protocol::telemetry::SpanKind::Internal,
            start_ns: 0,
            attributes: Default::default(),
        }
    }

    fn sample_span_end() -> mcpg_plugin_protocol::telemetry::SpanEnd {
        mcpg_plugin_protocol::telemetry::SpanEnd {
            trace_id: "t1".into(),
            span_id: "s1".into(),
            end_ns: 1,
            status: mcpg_plugin_protocol::telemetry::SpanStatus::Ok,
            events: vec![],
            additional_attributes: Default::default(),
        }
    }

    fn sample_metric() -> mcpg_plugin_protocol::telemetry::MetricPoint {
        mcpg_plugin_protocol::telemetry::MetricPoint {
            name: "m".into(),
            unit: None,
            kind: mcpg_plugin_protocol::telemetry::MetricKind::Counter,
            value: mcpg_plugin_protocol::telemetry::MetricValue::I64 { value: 1 },
            labels: Default::default(),
            timestamp_ns: 0,
        }
    }

    #[tokio::test]
    async fn telemetry_fan_out_reaches_every_sink() {
        let mut reg = PluginRegistry::new();
        let a = telemetry_sink("dev.test.telemetry.a");
        let b = telemetry_sink("dev.test.telemetry.b");
        reg.register_telemetry_sink(a.clone(), PluginTier::Native)
            .unwrap();
        reg.register_telemetry_sink(b.clone(), PluginTier::Native)
            .unwrap();
        assert_eq!(reg.telemetry_sink_ids().len(), 2);

        reg.emit_telemetry_span_started(&sample_span_start()).await;
        reg.emit_telemetry_span_ended(&sample_span_end()).await;
        reg.emit_telemetry_metric(&sample_metric()).await;

        for sink in [&a, &b] {
            assert_eq!(
                sink.spans_started
                    .load(std::sync::atomic::Ordering::Acquire),
                1
            );
            assert_eq!(
                sink.spans_ended.load(std::sync::atomic::Ordering::Acquire),
                1
            );
            assert_eq!(sink.metrics.load(std::sync::atomic::Ordering::Acquire), 1);
        }
    }

    #[test]
    fn telemetry_sink_duplicate_id_rejected() {
        let mut reg = PluginRegistry::new();
        reg.register_telemetry_sink(telemetry_sink("dev.test.t"), PluginTier::Native)
            .unwrap();
        let err = reg
            .register_telemetry_sink(telemetry_sink("dev.test.t"), PluginTier::Native)
            .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[tokio::test]
    async fn telemetry_disabled_is_skipped_on_fan_out() {
        let mut reg = PluginRegistry::new();
        let sink = telemetry_sink("dev.test.t");
        reg.register_telemetry_sink(sink.clone(), PluginTier::Native)
            .unwrap();
        reg.disable("dev.test.t").unwrap();
        reg.emit_telemetry_span_started(&sample_span_start()).await;
        assert_eq!(
            sink.spans_started
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );
    }

    #[tokio::test]
    async fn telemetry_filtered_routes_only_to_allowed_ids() {
        let mut reg = PluginRegistry::new();
        let a = telemetry_sink("dev.test.t.a");
        let b = telemetry_sink("dev.test.t.b");
        reg.register_telemetry_sink(a.clone(), PluginTier::Native)
            .unwrap();
        reg.register_telemetry_sink(b.clone(), PluginTier::Native)
            .unwrap();

        let allowed: std::collections::HashSet<String> =
            ["dev.test.t.a".to_owned()].into_iter().collect();
        reg.emit_telemetry_span_started_filtered(&sample_span_start(), &allowed)
            .await;
        reg.emit_telemetry_span_ended_filtered(&sample_span_end(), &allowed)
            .await;
        reg.emit_telemetry_metric_filtered(&sample_metric(), &allowed)
            .await;

        assert_eq!(
            a.spans_started.load(std::sync::atomic::Ordering::Acquire),
            1
        );
        assert_eq!(a.spans_ended.load(std::sync::atomic::Ordering::Acquire), 1);
        assert_eq!(a.metrics.load(std::sync::atomic::Ordering::Acquire), 1);
        assert_eq!(
            b.spans_started.load(std::sync::atomic::Ordering::Acquire),
            0
        );
        assert_eq!(b.spans_ended.load(std::sync::atomic::Ordering::Acquire), 0);
        assert_eq!(b.metrics.load(std::sync::atomic::Ordering::Acquire), 0);
    }

    struct CountingLog {
        manifest: PluginManifest,
        emitted: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl mcpg_plugin_protocol::logs::LogSink for CountingLog {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn emit(&self, _record: &mcpg_plugin_protocol::logs::LogRecord) {
            self.emitted
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        async fn flush(
            &self,
            _timeout: std::time::Duration,
        ) -> Result<(), mcpg_plugin_protocol::logs::LogError> {
            Ok(())
        }
    }

    fn log_sink(id: &str) -> Arc<CountingLog> {
        Arc::new(CountingLog {
            manifest: test_manifest(id, PluginClass::LogSink),
            emitted: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn sample_log_record() -> mcpg_plugin_protocol::logs::LogRecord {
        mcpg_plugin_protocol::logs::LogRecord {
            timestamp_ns: 0,
            level: mcpg_plugin_protocol::logs::LogLevel::Info,
            target: "mcpg".into(),
            message: "hi".into(),
            fields: Default::default(),
            span_id: None,
            trace_id: None,
            request_id: None,
            identity: None,
            node_id: None,
            plugin_id: None,
        }
    }

    #[tokio::test]
    async fn log_fan_out_reaches_every_sink() {
        let mut reg = PluginRegistry::new();
        let a = log_sink("dev.test.log.a");
        let b = log_sink("dev.test.log.b");
        reg.register_log_sink(a.clone(), PluginTier::Native)
            .unwrap();
        reg.register_log_sink(b.clone(), PluginTier::Native)
            .unwrap();
        assert_eq!(reg.log_sink_ids().len(), 2);

        reg.emit_log_record(&sample_log_record()).await;
        reg.emit_log_record(&sample_log_record()).await;

        for sink in [&a, &b] {
            assert_eq!(sink.emitted.load(std::sync::atomic::Ordering::Acquire), 2);
        }
    }

    #[test]
    fn log_sink_duplicate_id_rejected() {
        let mut reg = PluginRegistry::new();
        reg.register_log_sink(log_sink("dev.test.log"), PluginTier::Native)
            .unwrap();
        let err = reg
            .register_log_sink(log_sink("dev.test.log"), PluginTier::Native)
            .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[tokio::test]
    async fn log_filtered_routes_only_to_allowed_ids() {
        let mut reg = PluginRegistry::new();
        let a = log_sink("dev.test.log.a");
        let b = log_sink("dev.test.log.b");
        let c = log_sink("dev.test.log.c");
        reg.register_log_sink(a.clone(), PluginTier::Native)
            .unwrap();
        reg.register_log_sink(b.clone(), PluginTier::Native)
            .unwrap();
        reg.register_log_sink(c.clone(), PluginTier::Native)
            .unwrap();

        let allowed: std::collections::HashSet<String> =
            ["dev.test.log.a".to_owned(), "dev.test.log.c".to_owned()]
                .into_iter()
                .collect();
        reg.emit_log_record_filtered(&sample_log_record(), &allowed)
            .await;

        assert_eq!(a.emitted.load(std::sync::atomic::Ordering::Acquire), 1);
        assert_eq!(b.emitted.load(std::sync::atomic::Ordering::Acquire), 0);
        assert_eq!(c.emitted.load(std::sync::atomic::Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn log_filtered_with_empty_allow_list_routes_to_none() {
        let mut reg = PluginRegistry::new();
        let a = log_sink("dev.test.log.a");
        reg.register_log_sink(a.clone(), PluginTier::Native)
            .unwrap();

        let allowed = std::collections::HashSet::new();
        reg.emit_log_record_filtered(&sample_log_record(), &allowed)
            .await;

        assert_eq!(a.emitted.load(std::sync::atomic::Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn log_disabled_is_skipped_on_fan_out() {
        let mut reg = PluginRegistry::new();
        let sink = log_sink("dev.test.log");
        reg.register_log_sink(sink.clone(), PluginTier::Native)
            .unwrap();
        reg.disable("dev.test.log").unwrap();
        reg.emit_log_record(&sample_log_record()).await;
        assert_eq!(sink.emitted.load(std::sync::atomic::Ordering::Acquire), 0);
    }

    // -----------------------------------------------------------------
    // metrics_sink
    // -----------------------------------------------------------------

    struct CountingMetrics {
        manifest: PluginManifest,
        emitted: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl mcpg_plugin_protocol::metrics::MetricsSink for CountingMetrics {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn emit(&self, _metric: &mcpg_plugin_protocol::metrics::MetricPoint) {
            self.emitted
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        async fn flush(
            &self,
            _timeout: std::time::Duration,
        ) -> Result<(), mcpg_plugin_protocol::metrics::MetricsError> {
            Ok(())
        }
    }

    fn metrics_sink(id: &str) -> Arc<CountingMetrics> {
        Arc::new(CountingMetrics {
            manifest: test_manifest(id, PluginClass::MetricsSink),
            emitted: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn sample_metric_point() -> mcpg_plugin_protocol::metrics::MetricPoint {
        mcpg_plugin_protocol::metrics::MetricPoint {
            name: "mcpg_test".into(),
            unit: None,
            kind: mcpg_plugin_protocol::metrics::MetricKind::Counter,
            value: mcpg_plugin_protocol::metrics::MetricValue::I64 { value: 1 },
            labels: Default::default(),
            timestamp_ns: 0,
        }
    }

    #[tokio::test]
    async fn metrics_fan_out_reaches_every_sink() {
        let mut reg = PluginRegistry::new();
        let a = metrics_sink("dev.test.metrics.a");
        let b = metrics_sink("dev.test.metrics.b");
        reg.register_metrics_sink(a.clone(), PluginTier::Native)
            .unwrap();
        reg.register_metrics_sink(b.clone(), PluginTier::Native)
            .unwrap();
        assert_eq!(reg.metrics_sink_ids().len(), 2);

        reg.emit_metric_event(&sample_metric_point()).await;
        reg.emit_metric_event(&sample_metric_point()).await;

        for sink in [&a, &b] {
            assert_eq!(sink.emitted.load(std::sync::atomic::Ordering::Acquire), 2);
        }
    }

    #[test]
    fn metrics_sink_duplicate_id_rejected() {
        let mut reg = PluginRegistry::new();
        reg.register_metrics_sink(metrics_sink("dev.test.metrics"), PluginTier::Native)
            .unwrap();
        let err = reg
            .register_metrics_sink(metrics_sink("dev.test.metrics"), PluginTier::Native)
            .unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }

    #[tokio::test]
    async fn metrics_filtered_routes_only_to_allowed_ids() {
        let mut reg = PluginRegistry::new();
        let a = metrics_sink("dev.test.metrics.a");
        let b = metrics_sink("dev.test.metrics.b");
        let c = metrics_sink("dev.test.metrics.c");
        reg.register_metrics_sink(a.clone(), PluginTier::Native)
            .unwrap();
        reg.register_metrics_sink(b.clone(), PluginTier::Native)
            .unwrap();
        reg.register_metrics_sink(c.clone(), PluginTier::Native)
            .unwrap();

        let allowed: std::collections::HashSet<String> =
            ["dev.test.metrics.b".to_owned()].into_iter().collect();
        reg.emit_metric_event_filtered(&sample_metric_point(), &allowed)
            .await;

        assert_eq!(a.emitted.load(std::sync::atomic::Ordering::Acquire), 0);
        assert_eq!(b.emitted.load(std::sync::atomic::Ordering::Acquire), 1);
        assert_eq!(c.emitted.load(std::sync::atomic::Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn metrics_disabled_is_skipped_on_fan_out() {
        let mut reg = PluginRegistry::new();
        let sink = metrics_sink("dev.test.metrics");
        reg.register_metrics_sink(sink.clone(), PluginTier::Native)
            .unwrap();
        reg.disable("dev.test.metrics").unwrap();
        reg.emit_metric_event(&sample_metric_point()).await;
        assert_eq!(sink.emitted.load(std::sync::atomic::Ordering::Acquire), 0);
    }

    #[test]
    fn metrics_sink_shows_up_in_loaded_plugins_with_metrics_sink_class() {
        let mut reg = PluginRegistry::new();
        reg.register_metrics_sink(metrics_sink("dev.test.metrics"), PluginTier::Native)
            .unwrap();
        let info = reg.loaded_plugins();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].plugin_class, "metrics_sink");
        assert_eq!(reg.total_count(), 1);

        let detail = reg.plugin_detail("dev.test.metrics").unwrap();
        assert_eq!(detail.plugin_class, "metrics_sink");
    }

    #[test]
    fn telemetry_log_sinks_show_up_in_loaded_plugins() {
        let mut reg = PluginRegistry::new();
        reg.register_telemetry_sink(telemetry_sink("dev.test.t"), PluginTier::Native)
            .unwrap();
        reg.register_log_sink(log_sink("dev.test.l"), PluginTier::Native)
            .unwrap();
        let info = reg.loaded_plugins();
        assert_eq!(info.len(), 2);
        assert!(info.iter().any(|p| p.plugin_class == "telemetry_sink"));
        assert!(info.iter().any(|p| p.plugin_class == "log_sink"));
        assert_eq!(reg.total_count(), 2);
    }

    #[test]
    fn merge_json_objects_combines_keys() {
        let a = serde_json::json!({"a": 1, "b": 2});
        let b = serde_json::json!({"b": 3, "c": 4});
        let merged = super::merge_json_objects(a, b);
        assert_eq!(merged, serde_json::json!({"a": 1, "b": 3, "c": 4}));
    }

    #[test]
    fn merge_json_objects_non_object_replaces() {
        let a = serde_json::json!({"a": 1});
        let b = serde_json::json!("scalar");
        let merged = super::merge_json_objects(a, b);
        assert_eq!(merged, serde_json::json!("scalar"));
    }

    #[tokio::test]
    async fn pre_dispatch_chain_merges_allow_metadata() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(MetadataGatePlugin {
                manifest: test_manifest("meta.1", PluginClass::ToolGate),
                metadata: serde_json::json!({"receipt": "abc"}),
            }),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        reg.register_tool_gate(
            Box::new(AllowGatePlugin(test_manifest(
                "allow.2",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        let decision = reg
            .evaluate_tool_gates_pre(&test_context(), &serde_json::json!({}), None)
            .await;
        match decision {
            GateDecision::Allow { metadata, .. } => {
                let meta = metadata.expect("metadata should be present");
                assert_eq!(meta["receipt"], "abc");
            }
            other => panic!("expected Allow, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn pre_dispatch_chain_merges_multiple_metadata() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(MetadataGatePlugin {
                manifest: test_manifest("meta.1", PluginClass::ToolGate),
                metadata: serde_json::json!({"receipt": "abc"}),
            }),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        reg.register_tool_gate(
            Box::new(MetadataGatePlugin {
                manifest: test_manifest("meta.2", PluginClass::ToolGate),
                metadata: serde_json::json!({"audit": "xyz"}),
            }),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        let decision = reg
            .evaluate_tool_gates_pre(&test_context(), &serde_json::json!({}), None)
            .await;
        match decision {
            GateDecision::Allow { metadata, .. } => {
                let meta = metadata.expect("metadata should be present");
                assert_eq!(meta["receipt"], "abc");
                assert_eq!(meta["audit"], "xyz");
            }
            other => panic!("expected Allow, got: {:?}", other),
        }
    }

    // -- Shadow mode tests (enforce flag) ---

    #[tokio::test]
    async fn shadow_mode_pre_dispatch_overrides_deny_to_allow() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate_with_enforce(
            Box::new(DenyGatePlugin(test_manifest(
                "shadow.deny",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
            false, // shadow mode
        )
        .unwrap();
        let decision = reg
            .evaluate_tool_gates_pre(&test_context(), &serde_json::json!({}), None)
            .await;
        assert!(matches!(decision, GateDecision::Allow { .. }));
    }

    #[tokio::test]
    async fn enforced_mode_pre_dispatch_denies() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate_with_enforce(
            Box::new(DenyGatePlugin(test_manifest(
                "enforced.deny",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
            true, // enforced
        )
        .unwrap();
        let decision = reg
            .evaluate_tool_gates_pre(&test_context(), &serde_json::json!({}), None)
            .await;
        assert!(matches!(decision, GateDecision::Deny { .. }));
    }

    // Post-dispatch deny plugin for shadow mode test
    struct DenyPostGatePlugin(PluginManifest);

    #[async_trait]
    impl ToolGatePlugin for DenyPostGatePlugin {
        fn manifest(&self) -> &PluginManifest {
            &self.0
        }
        async fn evaluate_pre_dispatch(
            &self,
            _ctx: &PluginContext,
            _args: &serde_json::Value,
            _meta: Option<&serde_json::Value>,
            _config: &serde_json::Value,
        ) -> GateDecision {
            GateDecision::allow()
        }
        async fn evaluate_post_dispatch(
            &self,
            _ctx: &PluginContext,
            _args: &serde_json::Value,
            _result: &serde_json::Value,
            _duration_ms: u64,
            _config: &serde_json::Value,
        ) -> GateDecision {
            GateDecision::Deny {
                http_status: 403,
                code: -32044,
                message: "post-denied by test".into(),
                error_data: None,
            }
        }
    }

    #[tokio::test]
    async fn shadow_mode_post_dispatch_overrides_deny_to_allow() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate_with_enforce(
            Box::new(DenyPostGatePlugin(test_manifest(
                "shadow.post",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
            false, // shadow mode
        )
        .unwrap();
        let decision = reg
            .evaluate_tool_gates_post(
                &test_context(),
                &serde_json::json!({}),
                &serde_json::json!({"content": []}),
                50,
            )
            .await;
        assert!(matches!(decision, GateDecision::Allow { .. }));
    }

    #[tokio::test]
    async fn enforced_mode_post_dispatch_denies() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate_with_enforce(
            Box::new(DenyPostGatePlugin(test_manifest(
                "enforced.post",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
            true, // enforced
        )
        .unwrap();
        let decision = reg
            .evaluate_tool_gates_post(
                &test_context(),
                &serde_json::json!({}),
                &serde_json::json!({"content": []}),
                50,
            )
            .await;
        assert!(matches!(decision, GateDecision::Deny { .. }));
    }

    // A gate that exercises the protocol's Allow mutations: rewrites the
    // arguments + supplies a pre-dispatch short-circuit result (pre), and
    // rewrites the result (post). Used to prove the chain THREADS these
    // instead of dropping them.
    struct MutatingGatePlugin(PluginManifest);

    #[async_trait]
    impl ToolGatePlugin for MutatingGatePlugin {
        fn manifest(&self) -> &PluginManifest {
            &self.0
        }
        async fn evaluate_pre_dispatch(
            &self,
            _ctx: &PluginContext,
            _args: &serde_json::Value,
            _meta: Option<&serde_json::Value>,
            _config: &serde_json::Value,
        ) -> GateDecision {
            GateDecision::Allow {
                modified_arguments: Some(serde_json::json!({"rewritten": true})),
                modified_result: Some(serde_json::json!({"content": [], "cached": true})),
                metadata: None,
            }
        }
        async fn evaluate_post_dispatch(
            &self,
            _ctx: &PluginContext,
            _args: &serde_json::Value,
            _result: &serde_json::Value,
            _duration_ms: u64,
            _config: &serde_json::Value,
        ) -> GateDecision {
            GateDecision::Allow {
                modified_arguments: None,
                modified_result: Some(serde_json::json!({"content": [], "redacted": true})),
                metadata: None,
            }
        }
    }

    #[tokio::test]
    async fn pre_chain_threads_modified_arguments_and_result() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(MutatingGatePlugin(test_manifest(
                "mut.gate",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        let decision = reg
            .evaluate_tool_gates_pre(&test_context(), &serde_json::json!({"orig": 1}), None)
            .await;
        match decision {
            GateDecision::Allow {
                modified_arguments,
                modified_result,
                ..
            } => {
                assert_eq!(
                    modified_arguments,
                    Some(serde_json::json!({"rewritten": true}))
                );
                assert_eq!(
                    modified_result,
                    Some(serde_json::json!({"content": [], "cached": true}))
                );
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn post_chain_threads_modified_result() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(MutatingGatePlugin(test_manifest(
                "mut.gate",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        let decision = reg
            .evaluate_tool_gates_post(
                &test_context(),
                &serde_json::json!({}),
                &serde_json::json!({"content": []}),
                1,
            )
            .await;
        match decision {
            GateDecision::Allow {
                modified_result, ..
            } => {
                assert_eq!(
                    modified_result,
                    Some(serde_json::json!({"content": [], "redacted": true}))
                );
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    // -- Bounded-shutdown tests ---------------------------------------------

    /// A gate plugin whose `shutdown()` sleeps for a configurable
    /// duration, used to exercise the per-plugin shutdown budget.
    struct SlowShutdownGate {
        manifest: PluginManifest,
        delay: Duration,
    }

    #[async_trait]
    impl ToolGatePlugin for SlowShutdownGate {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn evaluate_pre_dispatch(
            &self,
            _ctx: &PluginContext,
            _args: &serde_json::Value,
            _meta: Option<&serde_json::Value>,
            _config: &serde_json::Value,
        ) -> GateDecision {
            GateDecision::allow()
        }
        async fn shutdown(&self) {
            tokio::time::sleep(self.delay).await;
        }
    }

    #[tokio::test]
    async fn shutdown_report_clean_when_all_fast() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(SlowShutdownGate {
                manifest: test_manifest("fast", PluginClass::ToolGate),
                delay: Duration::from_millis(1),
            }),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();

        let report = reg
            .shutdown_all_with_timeout(Duration::from_millis(250))
            .await;
        assert_eq!(report.clean, 1);
        assert!(report.is_clean());
        assert!(report.timed_out.is_empty());
    }

    #[tokio::test]
    async fn shutdown_report_abandons_slow_plugin() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(SlowShutdownGate {
                manifest: test_manifest("slow", PluginClass::ToolGate),
                delay: Duration::from_secs(10),
            }),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();

        let started = Instant::now();
        let report = reg
            .shutdown_all_with_timeout(Duration::from_millis(50))
            .await;
        let elapsed = started.elapsed();

        assert_eq!(report.clean, 0);
        assert!(!report.is_clean());
        assert_eq!(report.timed_out, vec!["slow".to_owned()]);
        // Must give up long before the plugin's own 10s sleep.
        assert!(elapsed < Duration::from_secs(1), "elapsed was {elapsed:?}");
    }

    #[tokio::test]
    async fn shutdown_report_mixes_clean_and_abandoned() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(SlowShutdownGate {
                manifest: test_manifest("fast", PluginClass::ToolGate),
                delay: Duration::from_millis(1),
            }),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        reg.register_tool_gate(
            Box::new(SlowShutdownGate {
                manifest: test_manifest("slow", PluginClass::ToolGate),
                delay: Duration::from_secs(10),
            }),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();

        let report = reg
            .shutdown_all_with_timeout(Duration::from_millis(50))
            .await;
        assert_eq!(report.clean, 1);
        assert_eq!(report.timed_out, vec!["slow".to_owned()]);
    }

    #[tokio::test]
    async fn shutdown_default_timeout_uses_five_seconds() {
        // Sanity check on the public constant — tests that rely on
        // it catch an accidental change to the default.
        assert_eq!(DEFAULT_PLUGIN_SHUTDOWN_TIMEOUT, Duration::from_secs(5));
    }

    /// An audit sink that records whether shutdown() was invoked. Proves
    /// the drain reaches non-chain classes.
    struct ShutdownRecordingSink {
        manifest: PluginManifest,
        hit: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait]
    impl mcpg_plugin_protocol::audit::AuditSink for ShutdownRecordingSink {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn emit(
            &self,
            _event: &mcpg_plugin_protocol::audit::AuditEvent,
        ) -> std::result::Result<
            mcpg_plugin_protocol::audit::AuditReceipt,
            mcpg_plugin_protocol::audit::AuditError,
        > {
            unreachable!("emit is not exercised by the shutdown test")
        }
        async fn shutdown(&self) {
            self.hit.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn shutdown_all_drains_non_chain_classes() {
        let hit = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut reg = PluginRegistry::new();
        reg.register_audit_sink(
            Arc::new(ShutdownRecordingSink {
                manifest: test_manifest("audit.drain", PluginClass::AuditSink),
                hit: hit.clone(),
            }),
            PluginTier::Native,
        )
        .unwrap();
        let report = reg.shutdown_all().await;
        assert!(
            hit.load(std::sync::atomic::Ordering::SeqCst),
            "shutdown_all must invoke shutdown() on audit sinks (a non-chain class)"
        );
        assert_eq!(report.clean, 1);
        assert!(report.timed_out.is_empty());
    }

    // -- Lifecycle state tracking -------------------------------------------

    #[test]
    fn registered_plugin_reports_active_state() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(AllowGatePlugin(test_manifest("a", PluginClass::ToolGate))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        assert_eq!(reg.lifecycle_state("a"), Some(PluginState::Active));
    }

    #[test]
    fn unregistered_id_has_no_lifecycle_state() {
        let reg = PluginRegistry::new();
        assert_eq!(reg.lifecycle_state("nope"), None);
    }

    #[test]
    fn loaded_plugins_includes_state_field() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(AllowGatePlugin(test_manifest("a", PluginClass::ToolGate))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        let info = reg.loaded_plugins();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].state, "active");
    }

    // -- Descriptor validation after registration ---------------------------

    fn make_descriptor_matching(
        manifest: &PluginManifest,
    ) -> mcpg_plugin_protocol::PluginDescriptor {
        mcpg_plugin_protocol::PluginDescriptor {
            schema: mcpg_plugin_protocol::DESCRIPTOR_SCHEMA_V1.into(),
            id: manifest.id.clone(),
            name: manifest.name.clone(),
            description: String::new(),
            class: manifest.plugin_class,
            runtime: mcpg_plugin_protocol::RuntimeClass::StaticFirstparty,
            protocol_version: manifest.protocol_version.clone(),
            // The manifest carries the legacy
            // `Vec<String>` form (display-only); the descriptor's
            // typed Vec<Capability> is initialised empty here
            // because this synthesised descriptor is used solely
            // for cross-check tests where capabilities aren't
            // exercised. Real descriptors come from plugin.yaml.
            license: None,
            required_capabilities: Vec::new(),
            tags: manifest.tags.clone(),
            provides: manifest.provides.clone(),
            provides_schemes: manifest.provides_schemes.clone(),
        }
    }

    #[test]
    fn validate_registered_descriptor_happy_path() {
        let mut reg = PluginRegistry::new();
        let manifest = test_manifest("a", PluginClass::ToolGate);
        reg.register_tool_gate(
            Box::new(AllowGatePlugin(manifest.clone())),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        let d = make_descriptor_matching(&manifest);
        assert!(reg.validate_registered_descriptor(&d).is_ok());
    }

    #[test]
    fn validate_registered_descriptor_detects_class_drift() {
        let mut reg = PluginRegistry::new();
        let manifest = test_manifest("a", PluginClass::ToolGate);
        reg.register_tool_gate(
            Box::new(AllowGatePlugin(manifest.clone())),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        let mut d = make_descriptor_matching(&manifest);
        d.class = PluginClass::Transform;
        let err = reg.validate_registered_descriptor(&d).unwrap_err();
        assert!(err.to_string().contains("class"));
    }

    #[test]
    fn validate_registered_descriptor_errors_on_unknown_id() {
        let reg = PluginRegistry::new();
        let d = make_descriptor_matching(&test_manifest("ghost", PluginClass::ToolGate));
        let err = reg.validate_registered_descriptor(&d).unwrap_err();
        assert!(err.to_string().contains("unregistered plugin id"));
    }

    // -- Runtime disable / enable -------------------------------------------

    #[tokio::test]
    async fn disabled_tool_gate_is_skipped() {
        // Disabled plugins must not see traffic. The AllowGate/DenyGate
        // pair proves that disabling the deny-gate lets the allow-gate
        // decide — i.e. the disabled plugin contributes nothing.
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(DenyGatePlugin(test_manifest("deny", PluginClass::ToolGate))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        reg.register_tool_gate(
            Box::new(AllowGatePlugin(test_manifest(
                "allow",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();

        // With deny first, the chain denies.
        let d = reg
            .evaluate_tool_gates_pre(&test_context(), &serde_json::json!({}), None)
            .await;
        assert!(matches!(d, GateDecision::Deny { .. }));

        // Disable deny → chain sees only allow.
        reg.disable("deny").unwrap();
        let d = reg
            .evaluate_tool_gates_pre(&test_context(), &serde_json::json!({}), None)
            .await;
        assert!(matches!(d, GateDecision::Allow { .. }));

        // Re-enable → chain denies again.
        reg.enable("deny").unwrap();
        let d = reg
            .evaluate_tool_gates_pre(&test_context(), &serde_json::json!({}), None)
            .await;
        assert!(matches!(d, GateDecision::Deny { .. }));
    }

    #[test]
    fn disable_unknown_plugin_errors() {
        let reg = PluginRegistry::new();
        let err = reg.disable("nope").unwrap_err();
        assert!(err.to_string().contains("not registered"));
    }

    #[test]
    fn enable_plugin_that_isnt_disabled_errors() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(AllowGatePlugin(test_manifest("a", PluginClass::ToolGate))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        // Plugin is Active, enabling is a no-op error.
        let err = reg.enable("a").unwrap_err();
        assert!(err.to_string().contains("not disabled"));
    }

    #[test]
    fn disable_flips_lifecycle_state() {
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(AllowGatePlugin(test_manifest("a", PluginClass::ToolGate))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        assert_eq!(reg.lifecycle_state("a"), Some(PluginState::Active));
        reg.disable("a").unwrap();
        assert_eq!(reg.lifecycle_state("a"), Some(PluginState::Disabled));
        reg.enable("a").unwrap();
        assert_eq!(reg.lifecycle_state("a"), Some(PluginState::Active));
    }

    #[test]
    fn disable_is_lock_free_via_shared_reference() {
        // The real-world usage: the registry sits behind an Arc on
        // GatewayRuntime. Admin-plane holds an Arc<PluginRegistry>
        // and calls disable() via &self — no &mut needed.
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(AllowGatePlugin(test_manifest("a", PluginClass::ToolGate))),
            PluginTier::Native,
            serde_json::json!({}),
        )
        .unwrap();
        let shared = std::sync::Arc::new(reg);
        let admin_handle = shared.clone();
        admin_handle.disable("a").unwrap();
        assert_eq!(shared.lifecycle_state("a"), Some(PluginState::Disabled));
    }

    #[test]
    fn disabled_binding_is_not_returned_by_lookup() {
        use async_trait::async_trait;
        use mcpg_plugin_api_types::{BackendError, BackendRequest, BackendResponse};
        // Trait-object stub is already present elsewhere; reuse
        // AllowGatePlugin is not a binding, so wrap a tiny in-file
        // binding plugin.
        struct NoopBackend(PluginManifest);
        #[async_trait]
        impl BackendPlugin for NoopBackend {
            fn manifest(&self) -> &PluginManifest {
                &self.0
            }
            fn kind(&self) -> &str {
                "noop"
            }
            async fn register_profile(
                &self,
                _backend_name: &str,
                _spec: &serde_json::Value,
                _host: std::sync::Arc<dyn mcpg_plugin_protocol::BackendHost>,
            ) -> Result<(), BackendError> {
                Ok(())
            }
            async fn execute(
                &self,
                _backend_name: &str,
                _request: BackendRequest,
            ) -> Result<BackendResponse, BackendError> {
                Ok(BackendResponse {
                    payload: Vec::new(),
                    truncated: false,
                })
            }
        }

        let mut reg = PluginRegistry::new();
        reg.register_backend(
            Arc::new(NoopBackend(test_manifest("noop.b", PluginClass::Backend))),
            PluginTier::Native,
        )
        .unwrap();
        assert!(reg.backend("noop").is_some());
        reg.disable("noop.b").unwrap();
        assert!(reg.backend("noop").is_none());
        reg.enable("noop.b").unwrap();
        assert!(reg.backend("noop").is_some());
    }

    // -----------------------------------------------------------------
    // Drain + detail — T1-A
    // -----------------------------------------------------------------

    /// Tool-gate that blocks inside `evaluate_pre_dispatch` until a
    /// caller-supplied `tokio::sync::Notify` is fired. Lets drain
    /// tests hold a call "in flight" while they manipulate state.
    struct BlockingToolGate {
        manifest: PluginManifest,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl ToolGatePlugin for BlockingToolGate {
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
            self.release.notified().await;
            GateDecision::allow()
        }
    }

    fn blocking_tool_gate(id: &str) -> (BlockingToolGate, Arc<tokio::sync::Notify>) {
        let release = Arc::new(tokio::sync::Notify::new());
        let plugin = BlockingToolGate {
            manifest: test_manifest(id, PluginClass::ToolGate),
            release: Arc::clone(&release),
        };
        (plugin, release)
    }

    #[tokio::test]
    async fn mark_draining_rejects_new_calls_and_completes_on_release() {
        let (plugin, release) = blocking_tool_gate("dev.test.drain");
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(Box::new(plugin), PluginTier::Native, serde_json::json!({}))
            .unwrap();
        let reg = Arc::new(reg);

        // Kick off a call that will park inside the plugin.
        let reg_clone = Arc::clone(&reg);
        let inflight_handle = tokio::spawn(async move {
            reg_clone
                .evaluate_tool_gates_pre(&test_context(), &serde_json::json!({}), None)
                .await
        });

        // Wait for the in-flight counter to see the call.
        for _ in 0..50 {
            if let Some(d) = reg.plugin_detail("dev.test.drain")
                && d.inflight == Some(1)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(
            reg.plugin_detail("dev.test.drain").and_then(|d| d.inflight),
            Some(1)
        );

        // Mark draining; state flips, but the in-flight call stays.
        let token = reg.mark_draining("dev.test.drain").unwrap();
        assert_eq!(
            reg.lifecycle_state("dev.test.drain"),
            Some(PluginState::Draining)
        );
        assert_eq!(token.inflight(), 1);

        // A new request during drain should see `serves_traffic() ==
        // false` and skip the plugin — no blocking, no inflight bump.
        let empty = reg
            .evaluate_tool_gates_pre(&test_context(), &serde_json::json!({}), None)
            .await;
        matches!(empty, GateDecision::Allow { .. });
        assert_eq!(
            reg.plugin_detail("dev.test.drain").and_then(|d| d.inflight),
            Some(1),
            "new request must not bump inflight for a draining plugin"
        );

        // Release the parked call and wait for drain to complete.
        release.notify_waiters();
        let outcome = token.wait(std::time::Duration::from_secs(2)).await;
        assert_eq!(outcome, DrainOutcome::Completed);
        inflight_handle.await.unwrap();
    }

    #[tokio::test]
    async fn mark_draining_times_out_when_calls_wont_release() {
        let (plugin, _release) = blocking_tool_gate("dev.test.stuck");
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(Box::new(plugin), PluginTier::Native, serde_json::json!({}))
            .unwrap();
        let reg = Arc::new(reg);

        let reg_clone = Arc::clone(&reg);
        let _handle = tokio::spawn(async move {
            reg_clone
                .evaluate_tool_gates_pre(&test_context(), &serde_json::json!({}), None)
                .await
        });

        // Wait for the in-flight call to register.
        for _ in 0..50 {
            if reg.plugin_detail("dev.test.stuck").and_then(|d| d.inflight) == Some(1) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        let token = reg.mark_draining("dev.test.stuck").unwrap();
        let outcome = token.wait(std::time::Duration::from_millis(40)).await;
        match outcome {
            DrainOutcome::TimedOut { inflight } => assert_eq!(inflight, 1),
            other => panic!("expected TimedOut, got {other:?}"),
        }
        // Plugin is still Draining — drain didn't finalise.
        assert_eq!(
            reg.lifecycle_state("dev.test.stuck"),
            Some(PluginState::Draining)
        );
    }

    #[tokio::test]
    async fn mark_disabled_after_drain_transitions_to_disabled() {
        let (plugin, _release) = blocking_tool_gate("dev.test.finalise");
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(Box::new(plugin), PluginTier::Native, serde_json::json!({}))
            .unwrap();

        let _token = reg.mark_draining("dev.test.finalise").unwrap();
        assert_eq!(
            reg.lifecycle_state("dev.test.finalise"),
            Some(PluginState::Draining)
        );
        reg.mark_disabled_after_drain("dev.test.finalise").unwrap();
        assert_eq!(
            reg.lifecycle_state("dev.test.finalise"),
            Some(PluginState::Disabled)
        );
        // Idempotent.
        reg.mark_disabled_after_drain("dev.test.finalise").unwrap();
    }

    #[test]
    fn mark_draining_refuses_for_non_chain_plugins() {
        struct NoopBackend(PluginManifest);
        #[async_trait::async_trait]
        impl BackendPlugin for NoopBackend {
            fn manifest(&self) -> &PluginManifest {
                &self.0
            }
            fn kind(&self) -> &str {
                "noop"
            }
            async fn register_profile(
                &self,
                _binding: &str,
                _spec: &serde_json::Value,
                _host: std::sync::Arc<dyn mcpg_plugin_api_types::BackendHost>,
            ) -> std::result::Result<(), mcpg_plugin_api_types::BackendError> {
                Ok(())
            }
            async fn execute(
                &self,
                _binding: &str,
                _request: mcpg_plugin_api_types::BackendRequest,
            ) -> std::result::Result<
                mcpg_plugin_api_types::BackendResponse,
                mcpg_plugin_api_types::BackendError,
            > {
                Ok(mcpg_plugin_api_types::BackendResponse {
                    payload: vec![],
                    truncated: false,
                })
            }
        }

        let mut reg = PluginRegistry::new();
        reg.register_backend(
            Arc::new(NoopBackend(test_manifest(
                "dev.test.bind",
                PluginClass::Backend,
            ))),
            PluginTier::Native,
        )
        .unwrap();
        let err = reg.mark_draining("dev.test.bind").unwrap_err();
        assert!(err.to_string().contains("not a chain plugin"), "got: {err}");
    }

    #[test]
    fn plugin_detail_returns_manifest_state_and_timestamps() {
        struct NoopTG(PluginManifest);
        #[async_trait::async_trait]
        impl ToolGatePlugin for NoopTG {
            fn manifest(&self) -> &PluginManifest {
                &self.0
            }
            async fn evaluate_pre_dispatch(
                &self,
                _ctx: &PluginContext,
                _args: &serde_json::Value,
                _meta: Option<&serde_json::Value>,
                _cfg: &serde_json::Value,
            ) -> GateDecision {
                GateDecision::allow()
            }
        }
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate(
            Box::new(NoopTG(test_manifest(
                "dev.test.detail",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({"foo": "bar"}),
        )
        .unwrap();
        let detail = reg.plugin_detail("dev.test.detail").expect("detail");
        assert_eq!(detail.id, "dev.test.detail");
        assert_eq!(detail.plugin_class, "tool_gate");
        assert_eq!(detail.tier, "native");
        assert_eq!(detail.state, "active");
        assert_eq!(detail.enforce, Some(true));
        assert_eq!(detail.inflight, Some(0));
        assert_eq!(detail.config["foo"], "bar");
        // Registered in the test window — timestamp should be recent.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(detail.registered_at_unix_secs <= now);
        assert!(detail.registered_at_unix_secs + 60 >= now);
    }

    #[test]
    fn plugin_detail_none_for_unknown_id() {
        let reg = PluginRegistry::new();
        assert!(reg.plugin_detail("dev.test.none").is_none());
    }

    // -- multi-entity alias composition -------------------------------

    #[test]
    fn multi_entity_plugin_registers_under_distinct_composed_aliases() {
        // One cdylib providing several entities of DIFFERENT kinds (the
        // slack-approval shape: tool_gate + http_route + approval_notifier)
        // registers fine when each entity uses a distinct
        // `{id}:{inner_name}` alias — even though they share one manifest id.
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate_with_alias(
            Some("dev.test.multi:gate".to_owned()),
            Box::new(AllowGatePlugin(test_manifest(
                "dev.test.multi",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
            true,
        )
        .unwrap();
        reg.register_http_route_with_alias_and_overrides(
            Some("dev.test.multi:route".to_owned()),
            "route",
            Arc::new(StubHttpRoute {
                manifest: test_manifest("dev.test.multi", PluginClass::HttpRoute),
                routes: vec![stub_route("/")],
                status: 200,
            }),
            PluginTier::Native,
            HttpRouteOverrides::default(),
            &[],
        )
        .unwrap();
        reg.register_approval_notifier_with_alias(
            Some("dev.test.multi:notifier".to_owned()),
            approval_notifier_plugin("dev.test.multi"),
            PluginTier::Native,
        )
        .unwrap();
        assert_eq!(reg.total_count(), 3, "all three entities coexist");
    }

    #[test]
    fn same_alias_across_kinds_still_collides() {
        // The pre-fix bug: registering two entities of one plugin under the
        // SAME alias (entry.id, no inner_name composition) is rejected by the
        // global cross-kind duplicate check — which is precisely why the boot
        // loop must compose a distinct alias per entity.
        let mut reg = PluginRegistry::new();
        reg.register_tool_gate_with_alias(
            Some("dev.test.collide".to_owned()),
            Box::new(AllowGatePlugin(test_manifest(
                "dev.test.collide",
                PluginClass::ToolGate,
            ))),
            PluginTier::Native,
            serde_json::json!({}),
            true,
        )
        .unwrap();
        let err = reg
            .register_approval_notifier_with_alias(
                Some("dev.test.collide".to_owned()),
                approval_notifier_plugin("dev.test.collide"),
                PluginTier::Native,
            )
            .unwrap_err();
        assert!(err.to_string().contains("already registered"), "got: {err}");
    }
}

// Re-export the types used by the disabled_binding test so the
// cfg(test) harness can construct them inline.
#[cfg(test)]
mod mcpg_plugin_api_types {
    pub use mcpg_plugin_protocol::{BackendError, BackendHost, BackendRequest, BackendResponse};
}

/// Outcome of running the identity-plugin chain.
///
/// The distinction between "nobody recognised a credential" and "a plugin
/// rejected the credential presented" is the whole point: collapsing them
/// turns a forged or expired token into an anonymous request.
#[derive(Debug)]
pub enum ChainIdentityOutcome {
    /// A plugin authenticated the caller.
    Resolved(mcpg_plugin_protocol::PluginIdentity),
    /// No plugin recognised a credential in this request.
    NoCredential,
    /// A plugin explicitly rejected the presented credential.
    Rejected { plugin_id: String, reason: String },
}
