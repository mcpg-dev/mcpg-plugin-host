//! `HostServices` trait — the host-side service surface that
//! [`HostBridge`](crate::host_bridge::HostBridge) dispatches into
//! from each native plugin's FFI calls back into the host.
//!
//! This module defines the trait
//! and a [`NullHostServices`] implementation that returns errors
//! for fallible methods and no-ops for infallible ones. Each
//! [`HostBridge`] slot calls the trait,
//! and the gateway provides a real `GatewayHostServices` impl that
//! routes into [`PluginRegistry`](crate::registry::PluginRegistry)
//! and the global metrics + tracing subsystems.
//!
//! # Design rationale
//!
//! `HostServices` lives in `mcpg-plugin-host` (this crate) rather
//! than in the gateway runtime because the FFI bridge that consumes
//! it lives here too — keeping the trait close to its primary
//! consumer avoids a cross-crate boundary on every host call.
//!
//! Each method takes the calling plugin's `alias` explicitly. This
//! is the operator-chosen entry id (e.g. `"rate-limit"`), not the
//! manifest id — so multi-instance plugins get distinct attribution
//! on audit events, metrics, spans, and per-plugin capability
//! filtering. The bridge ctx carries the alias; the bridge passes
//! it as the first arg of every call.
//!
//! # Sync ↔ async bridge
//!
//! The trait methods that talk to async host services (secret /
//! credential / config / audit) are `async fn`. The HostBridge
//! synchronous `extern "C"` slots call them via a captured
//! `tokio::runtime::Handle` + `Handle::block_on(...)`, on a
//! `spawn_blocking`-issued OS thread that's outside the runtime's
//! worker pool (so we don't risk deadlocking the worker). The
//! infallible methods (metric_emit / span_*) stay sync because
//! their host backings (metrics-rs, tracing) are themselves sync.
//!
//! # LateBoundHostServices
//!
//! Native plugin adapters are constructed during boot **before**
//! the `PluginRegistry` is wrapped in `Arc` and shared. To break
//! the chicken-and-egg cycle, the gateway boots
//! [`LateBoundHostServices::new()`], threads its `Arc<dyn ...>`
//! into every adapter, then calls
//! [`LateBoundHostServices::set`] once the registry is final.
//! Mirrors the `LateBoundBackendHost` pattern in
//! `mcpg-plugin-protocol`.

use std::sync::Arc;

use std::sync::RwLock;

use async_trait::async_trait;

use mcpg_plugin_protocol::{
    audit::{AuditError, AuditEvent, AuditReceipt},
    backend::{
        BackendHostError, BackendInvocationContext, BackendResource, CredentialRevocationCallback,
        CredentialRevocationSubscription, SecretRotationCallback, SecretRotationSubscription,
    },
    config::{ConfigError, ConfigSnapshot},
    credential::{CredentialError, IssuedCredential},
    secret::{SecretError, SecretValue},
    types::PluginIdentity,
};

/// A single metric data point emitted by a plugin through
/// [`HostServices::metric_emit`]. The host appends a
/// `plugin_alias=<alias>` label before forwarding to the
/// `metrics-rs` recorder so dashboards can filter per plugin.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MetricPoint {
    /// Monotonically-increasing counter; host calls `counter!(name, ..labels).increment(value)`.
    Counter {
        name: String,
        value: u64,
        #[serde(default)]
        labels: Vec<(String, String)>,
    },
    /// Set-the-current-value gauge; host calls `gauge!(name, ..labels).set(value)`.
    Gauge {
        name: String,
        value: f64,
        #[serde(default)]
        labels: Vec<(String, String)>,
    },
    /// Record-a-single-observation histogram; host calls `histogram!(name, ..labels).record(value)`.
    Histogram {
        name: String,
        value: f64,
        #[serde(default)]
        labels: Vec<(String, String)>,
    },
}

/// Host service surface called by the FFI bridge on plugin host
/// callbacks (`resolve_secret`, `audit_event`, etc.). Every method
/// receives the calling plugin's operator alias for attribution +
/// per-plugin capability enforcement.
///
/// The async methods route to the gateway's secret / credential /
/// config / audit subsystems; the sync methods route to global
/// recorders (metrics-rs, tracing).
#[async_trait]
pub trait HostServices: Send + Sync + 'static {
    /// Resolve a `scheme://path` secret reference. The host filters
    /// against the calling plugin's typed capabilities — schemes
    /// outside `SecretsRead{schemes}` produce
    /// [`SecretError::UnsupportedScheme`].
    async fn resolve_secret(&self, alias: &str, uri: &str) -> Result<SecretValue, SecretError>;

    /// Issue a per-caller credential for an outbound call. `identity`
    /// is the request-scoped subject the credential is minted for.
    /// Filtered by the plugin's `CredentialIssue{kinds}` grant.
    async fn issue_credential(
        &self,
        alias: &str,
        uri: &str,
        identity: PluginIdentity,
    ) -> Result<IssuedCredential, CredentialError>;

    /// Read a `scheme://path` config snapshot. Filtered by the
    /// plugin's `ConfigRead{schemes}` grant.
    async fn config_snapshot(&self, alias: &str, uri: &str) -> Result<ConfigSnapshot, ConfigError>;

    /// Emit an audit event. The host force-overwrites
    /// `event.plugin_alias` with `alias` before fan-out so plugins
    /// can't spoof another plugin's audit trail.
    async fn audit_event(&self, alias: &str, event: AuditEvent)
    -> Result<AuditReceipt, AuditError>;

    /// Emit a metric point. The host prepends a `plugin_alias` label
    /// before forwarding to the global recorder.
    fn metric_emit(&self, alias: &str, point: MetricPoint);

    /// Start a tracing span. Returns a host-allocated span id the
    /// plugin can later pass to [`span_end`](Self::span_end) /
    /// [`span_event`](Self::span_event). The span carries
    /// `plugin_alias=<alias>` so distributed-tracing back-ends can
    /// filter per plugin.
    fn span_start(&self, alias: &str, name: &str, attrs: serde_json::Value) -> u64;

    /// End a tracing span previously returned by `span_start`.
    /// Silently no-ops if `span_id` is unknown (e.g. ended twice).
    fn span_end(&self, span_id: u64);

    /// Record an event on an active span. Silently no-ops if
    /// `span_id` is unknown.
    fn span_event(&self, span_id: u64, name: &str, attrs: serde_json::Value);

    // ── Backend host services ──────────────────────────────────────────
    // These back the cdylib host-FFI slots that let dynamically-loaded
    // BACKEND plugins (kafka/nats/sql) reach the same host services the
    // statically-linked backends get via `BackendHost`. Default impls
    // mirror `BackendHost`'s defaults so existing `HostServices` impls
    // (hook-plugin hosts) compile unchanged + behave as before.

    /// Resolve `cred://…` URIs inside `value` against the gateway's
    /// credential cache, substituting in place. Returns the count of
    /// substitutions. Default: no-op success (no `cred://` refs to
    /// resolve in a host without credential wiring).
    async fn resolve_credentials(
        &self,
        _alias: &str,
        _value: &mut serde_json::Value,
        _identity: Option<PluginIdentity>,
    ) -> Result<usize, BackendHostError> {
        Ok(0)
    }

    /// Look up a cached response by opaque hash key. Default: cache miss.
    async fn cache_get(
        &self,
        _alias: &str,
        _key: &str,
    ) -> Result<Option<bytes::Bytes>, BackendHostError> {
        Ok(None)
    }

    /// Fetch host-stored content (multimodal inputs) by
    /// `mcpg-resource://` URI. Default: not found (`Ok(None)`).
    async fn fetch_content(
        &self,
        _alias: &str,
        _uri: &str,
    ) -> Result<Option<bytes::Bytes>, BackendHostError> {
        Ok(None)
    }

    /// Store content (generated images / audio) in the host's content
    /// store, returning the resulting [`BackendResource`]. Default: not
    /// implemented (no content store wired).
    async fn store_content(
        &self,
        _alias: &str,
        _bytes: bytes::Bytes,
        _mime_type: String,
        _ttl: Option<std::time::Duration>,
    ) -> Result<BackendResource, BackendHostError> {
        Err(BackendHostError::NotImplemented)
    }

    /// Invoke another gateway tool on behalf of a backend (the agentic
    /// child-tool call). `ctx` is the caller's invocation context,
    /// carrying depth / parent_request_id for the host's depth-cap +
    /// cycle detection. Default: not implemented (no dispatcher wired).
    async fn invoke_tool(
        &self,
        _ctx: &BackendInvocationContext,
        _tool_name: &str,
        _args: &serde_json::Value,
    ) -> Result<serde_json::Value, BackendHostError> {
        Err(BackendHostError::NotImplemented)
    }

    /// Subscribe to credential-revocation events `(plugin_id, target)`.
    /// Default: no-op guard (host without credential wiring never fires).
    fn subscribe_credential_revoked(
        &self,
        _alias: &str,
        _cb: CredentialRevocationCallback,
    ) -> CredentialRevocationSubscription {
        CredentialRevocationSubscription::noop()
    }

    /// Subscribe to secret-rotation events `(secret_ref, version)`.
    /// Default: no-op guard.
    fn subscribe_secret_rotation(
        &self,
        _alias: &str,
        _cb: SecretRotationCallback,
    ) -> SecretRotationSubscription {
        SecretRotationSubscription::noop()
    }
}

/// Stub implementation that returns "service unavailable" / no-op
/// for every slot. Used by [`HostBridge::stub`](crate::host_bridge::HostBridge::stub)
/// during `peek_manifest` / `derive_manifest` paths where the
/// plugin is instantiated solely to read its manifest. Plugins that
/// call host services from those paths get a typed error rather
/// than UB.
pub struct NullHostServices;

#[async_trait]
impl HostServices for NullHostServices {
    async fn resolve_secret(&self, _alias: &str, _uri: &str) -> Result<SecretValue, SecretError> {
        Err(SecretError::Backend {
            reason: "host services not wired (NullHostServices)".to_owned(),
        })
    }

    async fn issue_credential(
        &self,
        _alias: &str,
        _uri: &str,
        _identity: PluginIdentity,
    ) -> Result<IssuedCredential, CredentialError> {
        Err(CredentialError::Backend {
            reason: "host services not wired (NullHostServices)".to_owned(),
        })
    }

    async fn config_snapshot(
        &self,
        _alias: &str,
        _uri: &str,
    ) -> Result<ConfigSnapshot, ConfigError> {
        Err(ConfigError::Backend {
            reason: "host services not wired (NullHostServices)".to_owned(),
        })
    }

    async fn audit_event(
        &self,
        _alias: &str,
        _event: AuditEvent,
    ) -> Result<AuditReceipt, AuditError> {
        Err(AuditError::WriteFailed {
            reason: "host services not wired (NullHostServices)".to_owned(),
        })
    }

    fn metric_emit(&self, _alias: &str, _point: MetricPoint) {}

    fn span_start(&self, _alias: &str, _name: &str, _attrs: serde_json::Value) -> u64 {
        0
    }

    fn span_end(&self, _span_id: u64) {}

    fn span_event(&self, _span_id: u64, _name: &str, _attrs: serde_json::Value) {}
}

/// Late-bind wrapper for [`HostServices`]. Mirrors
/// `LateBoundBackendHost` in `mcpg-plugin-protocol`: native plugin
/// adapters are constructed during gateway boot **before** the
/// `PluginRegistry` is wrapped in `Arc`. The adapter receives this
/// late-bound handle; calls before `set()` route to a
/// [`NullHostServices`] stub that surfaces typed errors.
#[derive(Clone)]
pub struct LateBoundHostServices {
    inner: Arc<RwLock<Option<Arc<dyn HostServices>>>>,
}

impl LateBoundHostServices {
    /// Construct a not-yet-bound handle. Calls before [`set`](Self::set)
    /// route to [`NullHostServices`].
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
        }
    }

    /// Resolve the underlying services. Returns a fresh
    /// [`NullHostServices`] when no real impl has been bound yet so
    /// the bridge's slot bodies stay infallible.
    pub fn resolve(&self) -> Arc<dyn HostServices> {
        match self
            .inner
            .read()
            .expect("LateBoundHostServices RwLock poisoned")
            .clone()
        {
            Some(s) => s,
            None => Arc::new(NullHostServices),
        }
    }

    /// Bind the production implementation. Idempotent — a second
    /// call replaces the binding. Typically called once at gateway
    /// boot after the registry is finalised.
    pub fn set(&self, services: Arc<dyn HostServices>) {
        *self
            .inner
            .write()
            .expect("LateBoundHostServices RwLock poisoned") = Some(services);
    }

    /// Return true when a real implementation has been bound.
    /// Tests + admin endpoints use this to surface boot readiness.
    pub fn is_bound(&self) -> bool {
        self.inner
            .read()
            .expect("LateBoundHostServices RwLock poisoned")
            .is_some()
    }
}

impl Default for LateBoundHostServices {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::audit::AuditOutcome;

    fn test_identity() -> PluginIdentity {
        PluginIdentity {
            kind: "anonymous".to_owned(),
            trust_level: "unauthenticated".to_owned(),
            subject_id: None,
            auth_provider: None,
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: Default::default(),
        }
    }

    #[tokio::test]
    async fn null_services_returns_unwired_for_async_methods() {
        let svc = NullHostServices;
        let err = svc
            .resolve_secret("plugin-a", "vault://kv/foo")
            .await
            .unwrap_err();
        assert!(matches!(err, SecretError::Backend { .. }));

        let err = svc
            .issue_credential("plugin-a", "cred://x", test_identity())
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialError::Backend { .. }));

        let err = svc
            .config_snapshot("plugin-a", "env://X")
            .await
            .unwrap_err();
        assert!(matches!(err, ConfigError::Backend { .. }));

        let event = AuditEvent {
            event_id: "evt-test".to_owned(),
            occurred_at: "2026-05-11T00:00:00Z".to_owned(),
            actor: test_identity(),
            action: "test.event".to_owned(),
            resource: None,
            outcome: AuditOutcome::Success,
            request_id: None,
            node_id: None,
            details: serde_json::json!({}),
            prev_event_hash: None,
        };
        let err = svc.audit_event("plugin-a", event).await.unwrap_err();
        assert!(matches!(err, AuditError::WriteFailed { .. }));
    }

    #[test]
    fn null_services_sync_methods_are_silent_noops() {
        let svc = NullHostServices;
        svc.metric_emit(
            "plugin-a",
            MetricPoint::Counter {
                name: "test".to_owned(),
                value: 1,
                labels: vec![],
            },
        );
        let id = svc.span_start("plugin-a", "test", serde_json::json!({}));
        assert_eq!(id, 0);
        svc.span_end(id);
        svc.span_event(id, "evt", serde_json::json!({}));
    }

    #[test]
    fn late_bound_is_unbound_by_default() {
        let lb = LateBoundHostServices::new();
        assert!(!lb.is_bound());
        // Resolving an unbound handle still returns something safe.
        let svc = lb.resolve();
        svc.metric_emit(
            "plugin-a",
            MetricPoint::Gauge {
                name: "test".to_owned(),
                value: 1.0,
                labels: vec![],
            },
        );
    }

    #[test]
    fn late_bound_set_then_resolve() {
        let lb = LateBoundHostServices::new();
        lb.set(Arc::new(NullHostServices));
        assert!(lb.is_bound());
        let _svc = lb.resolve();
    }

    #[tokio::test]
    async fn metric_point_serde_round_trip() {
        let original = MetricPoint::Histogram {
            name: "latency".to_owned(),
            value: 0.012,
            labels: vec![("route".to_owned(), "/v1/foo".to_owned())],
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: MetricPoint = serde_json::from_str(&json).unwrap();
        match parsed {
            MetricPoint::Histogram {
                name,
                value,
                labels,
            } => {
                assert_eq!(name, "latency");
                assert!((value - 0.012).abs() < 1e-9);
                assert_eq!(labels, vec![("route".to_owned(), "/v1/foo".to_owned())]);
            }
            _ => panic!("wrong variant"),
        }
    }
}
