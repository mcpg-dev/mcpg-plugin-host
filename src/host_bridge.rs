//! HostBridge — host-side implementation of the
//! [`HostHandleRef`](mcpg_plugin_protocol::abi::HostHandleRef)
//! bidirectional API the gateway threads into every native plugin
//! `make` slot (ABI v26).
//!
//! Each `Native*Adapter` builds its own `HostBridge`, hands the
//! plugin a [`HostHandleRef`] that points at the bridge, and keeps
//! the bridge alive on the adapter for the full plugin lifetime.
//! The bridge's vtable slots dispatch back into host services
//! (cluster coordinator, secret resolver, audit ledger, …); slots
//! that are not yet wired to a real implementation return safe
//! defaults (`RNone`, empty `RString`) so plugins that opt in early
//! degrade gracefully on the first few protocol minor releases.
//!
//! # Lifetime contract
//!
//! The plugin SDK derives transient `Option<ClusterClient>` /
//! `secret(uri)` / `audit_event(...)` calls from this vtable
//! synchronously inside the plugin's request paths. The bridge MUST
//! outlive the plugin's `RPluginHandle` — the adapter owns it as an
//! `Arc<HostBridge>` and the FFI ref points at the bridge's stable
//! address, never released until `drop_instance` returns.
//!
//! # Slot semantics
//!
//! - `cluster` — returns an `RSome(ClusterClientRef)` when the
//!   gateway has a registered cluster coordinator and the bridge
//!   was built with `with_cluster(_)`; `RNone` otherwise.
//! - `alias` — operator alias for this plugin entry; used by the
//!   plugin SDK to log "plugin <alias>" lines and tag emitted
//!   metrics. Always populated.
//! - `resolve_secret` / `issue_credential` / `config_snapshot` /
//!   `audit_event` / `metric_emit` / `span_*` — currently stubs
//!   that emit a structured warning the first time they're called,
//!   so plugins that opt in early get a deterministic "host has not
//!   wired this yet" signal rather than UB. The gateway will land
//!   real implementations behind these slots later; bumping the
//!   bridge to a wired implementation does not require an ABI bump
//!   (the slot contract is unchanged).

use std::sync::Arc;
use std::time::Instant;

use std::sync::atomic::Ordering;

use abi_stable::std_types::{RNone, ROption, RString};
use base64::Engine as _;
use mcpg_plugin_protocol::abi::{
    ClusterClientRef, CredRevokedCallbackFfi, HostHandleRef, HostServicesVTable,
    SecretRotationCallbackFfi,
};
use mcpg_plugin_protocol::audit::{AuditError, AuditEvent};
use mcpg_plugin_protocol::backend::{
    BackendHostError, CredentialRevocationCallback, SecretRotationCallback,
};
use mcpg_plugin_protocol::config::ConfigError;
use mcpg_plugin_protocol::credential::CredentialError;
use mcpg_plugin_protocol::result_envelope::respond_result_rstring;
use mcpg_plugin_protocol::secret::{SecretError, SecretValueWire};
use mcpg_plugin_protocol::types::PluginIdentity;

use crate::host_services::{HostServices, MetricPoint, NullHostServices};

/// Host-side bridge that backs a plugin's [`HostHandleRef`].
///
/// Cheap to clone (it's an `Arc`); each adapter keeps its own
/// `HostBridge` so the FFI ref is stable across the plugin's
/// lifetime.
#[derive(Clone)]
pub struct HostBridge {
    inner: Arc<HostBridgeInner>,
}

/// Inner state held behind an Arc so the bridge's address is stable
/// across moves of the public `HostBridge` handle. The plugin's
/// [`HostHandleRef::ctx`] is a raw pointer to this inner; clones of
/// the public wrapper share one underlying state.
struct HostBridgeInner {
    /// Optional cluster client ref. `RSome` when the host has a
    /// registered cluster coordinator and the operator wants this
    /// plugin to share its state across replicas; `RNone` otherwise.
    cluster: ROption<ClusterClientRef>,
    /// Operator alias — the `id` of the plugin entry in
    /// `plugins[*]`. Empty when the bridge is built for
    /// peek/derive paths that never call into the plugin's request
    /// surface.
    alias: String,
    /// Host services backing the resolve_secret / issue_credential /
    /// config_snapshot / audit_event / metric_emit / span_* slots.
    /// Defaults to [`NullHostServices`] (returns `Backend{reason}`
    /// for fallible methods, no-ops for sync) when the bridge is
    /// built via `stub()` / `new()`; the gateway uses
    /// [`HostBridge::with_services`] to plug in a real implementation.
    services: Arc<dyn HostServices>,
    /// Tokio runtime handle captured at build time so the async
    /// `HostServices` methods can be `block_on`'d from the synchronous
    /// FFI slots. `None` when the bridge is constructed outside a
    /// tokio runtime (peek/derive paths) — slot dispatch returns the
    /// same "no runtime" envelope as NullHostServices in that case.
    runtime: Option<tokio::runtime::Handle>,
    /// Active subscription guards from `subscribe_credential_revoked` /
    /// `subscribe_secret_rotation`, keyed by the opaque id handed back to
    /// the plugin. `host_unsubscribe(id)` removes (drops) an entry, which
    /// runs the underlying host-side guard's `Drop`. The plugin's RAII
    /// wrapper calls `host_unsubscribe` when it drops.
    subscriptions: std::sync::Mutex<std::collections::HashMap<u64, SubscriptionEntry>>,
    /// Monotonic subscription-id allocator. `0` is reserved for "no
    /// subscription" so a failed/late-host subscribe can return `0`.
    next_sub_id: std::sync::atomic::AtomicU64,
    /// Dispatches currently in flight toward this plugin. Each host
    /// integrity tag names the dispatch it was minted for, and stops
    /// verifying once that dispatch leaves this set — which is what keeps
    /// a plugin from banking a privileged identity and relaying it on a
    /// later, unrelated call. Held behind its own `Arc` so
    /// [`DispatchGuard`] can retire an entry without keeping the whole
    /// bridge alive.
    live_dispatches: LiveDispatches,
    /// Monotonic dispatch-nonce allocator. `0` is never issued, so a
    /// zeroed / defaulted tag names no dispatch.
    next_dispatch: std::sync::atomic::AtomicU64,
}

/// Set of in-flight dispatch nonces for one plugin instance.
type LiveDispatches = Arc<std::sync::Mutex<std::collections::HashSet<u64>>>;

impl HostBridgeInner {
    /// Is `nonce` a dispatch still running toward this plugin?
    fn is_dispatch_live(&self, nonce: u64) -> bool {
        self.live_dispatches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&nonce)
    }
}

/// Keeps a dispatch's host integrity tag verifiable. Dropping it retires
/// the tag: any identity the plugin banked from that dispatch stops being
/// accepted on the host callbacks.
///
/// Hold one for exactly as long as the plugin may legitimately relay the
/// identity back — the body of a unary call, or the lifetime of a stream.
pub struct DispatchGuard {
    live: LiveDispatches,
    nonce: u64,
}

impl Drop for DispatchGuard {
    fn drop(&mut self) {
        // Never panic in a Drop that can run during unwinding: a poisoned
        // lock still holds a coherent set of `u64`.
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.nonce);
    }
}

/// A live subscription guard parked in the bridge's registry. Dropping
/// the entry (via `host_unsubscribe` or bridge teardown) runs the
/// host-side guard's `Drop`, which performs the actual unsubscribe.
///
/// The inner guards are never read — they exist solely for their `Drop`
/// side-effect (the whole point of an RAII subscription handle).
#[allow(dead_code)]
enum SubscriptionEntry {
    CredentialRevoked(mcpg_plugin_protocol::backend::CredentialRevocationSubscription),
    SecretRotation(mcpg_plugin_protocol::backend::SecretRotationSubscription),
}

impl HostBridge {
    /// Build a bridge backed by no real host services. Used by
    /// `peek_manifest` / `derive_manifest` paths that construct +
    /// drop a plugin instance solely to read its manifest.
    pub fn stub() -> Self {
        Self {
            inner: Arc::new(HostBridgeInner {
                cluster: RNone,
                alias: String::new(),
                services: Arc::new(NullHostServices),
                runtime: tokio::runtime::Handle::try_current().ok(),
                subscriptions: std::sync::Mutex::new(std::collections::HashMap::new()),
                next_sub_id: std::sync::atomic::AtomicU64::new(1),
                live_dispatches: Default::default(),
                next_dispatch: std::sync::atomic::AtomicU64::new(1),
            }),
        }
    }

    /// Build a bridge for a real plugin instance with optional
    /// cluster wiring and the operator alias. Other host slots
    /// (secret/audit/metric/span/config) default to
    /// [`NullHostServices`]; use [`Self::with_services`] to plug in
    /// the gateway's host services.
    pub fn new(cluster: Option<ClusterClientRef>, alias: impl Into<String>) -> Self {
        let cluster = match cluster {
            Some(c) => ROption::RSome(c),
            None => RNone,
        };
        Self {
            inner: Arc::new(HostBridgeInner {
                cluster,
                alias: alias.into(),
                services: Arc::new(NullHostServices),
                runtime: tokio::runtime::Handle::try_current().ok(),
                subscriptions: std::sync::Mutex::new(std::collections::HashMap::new()),
                next_sub_id: std::sync::atomic::AtomicU64::new(1),
                live_dispatches: Default::default(),
                next_dispatch: std::sync::atomic::AtomicU64::new(1),
            }),
        }
    }

    /// Build a fully-wired bridge with cluster, alias, and host
    /// services. Captures the current tokio runtime handle so the
    /// FFI slots that dispatch to async `HostServices` methods can
    /// `block_on` from inside a `spawn_blocking` thread.
    ///
    /// Must be called from inside a tokio runtime; panics otherwise.
    /// The gateway always boots inside a runtime, so this is sound
    /// at every adapter construction site.
    pub fn with_services(
        cluster: Option<ClusterClientRef>,
        alias: impl Into<String>,
        services: Arc<dyn HostServices>,
    ) -> Self {
        let cluster = match cluster {
            Some(c) => ROption::RSome(c),
            None => RNone,
        };
        let runtime = tokio::runtime::Handle::try_current()
            .expect("HostBridge::with_services must be called from inside a tokio runtime");
        Self {
            inner: Arc::new(HostBridgeInner {
                cluster,
                alias: alias.into(),
                services,
                runtime: Some(runtime),
                subscriptions: std::sync::Mutex::new(std::collections::HashMap::new()),
                next_sub_id: std::sync::atomic::AtomicU64::new(1),
                live_dispatches: Default::default(),
                next_dispatch: std::sync::atomic::AtomicU64::new(1),
            }),
        }
    }

    /// Open a dispatch toward this plugin and stamp the host integrity
    /// tag on the caller identity crossing into it.
    ///
    /// The tag verifies only while the returned guard is alive, so hold it
    /// for exactly as long as the plugin may legitimately relay this
    /// identity back through a host callback: the body of a unary call, or
    /// the lifetime of a stream. Dropping it retires the tag — an identity
    /// the plugin kept from a finished dispatch no longer resolves
    /// credentials, mints credentials, or attributes a tool call.
    #[must_use = "the identity's tag stops verifying as soon as the guard drops"]
    pub fn begin_dispatch(&self, identity: &mut PluginIdentity) -> DispatchGuard {
        let nonce = self.inner.next_dispatch.fetch_add(1, Ordering::Relaxed);
        self.inner
            .live_dispatches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(nonce);
        crate::identity_sig::sign(identity, &self.inner.alias, nonce);
        DispatchGuard {
            live: Arc::clone(&self.inner.live_dispatches),
            nonce,
        }
    }

    /// Return an FFI ref pointing at this bridge. The returned ref
    /// is only valid as long as the `HostBridge` (or one of its
    /// clones) is alive — the adapter holds the bridge for the full
    /// plugin lifetime, so threading the ref into `make` is sound.
    pub fn as_ffi_ref(&self) -> HostHandleRef {
        HostHandleRef {
            ctx: Arc::as_ptr(&self.inner) as usize,
            vtable: HOST_SERVICES_VTABLE,
        }
    }
}

const HOST_SERVICES_VTABLE: HostServicesVTable = HostServicesVTable {
    resolve_secret: host_resolve_secret,
    issue_credential: host_issue_credential,
    config_snapshot: host_config_snapshot,
    audit_event: host_audit_event,
    metric_emit: host_metric_emit,
    cluster: host_cluster,
    span_start: host_span_start,
    span_end: host_span_end,
    span_event: host_span_event,
    alias: host_alias,
    resolve_credentials: host_resolve_credentials,
    cache_get: host_cache_get,
    fetch_content: host_fetch_content,
    store_content: host_store_content,
    invoke_tool: host_invoke_tool,
    subscribe_credential_revoked: host_subscribe_credential_revoked,
    subscribe_secret_rotation: host_subscribe_secret_rotation,
    host_unsubscribe,
};

/// Re-borrow the `Arc<HostBridgeInner>` from a raw context pointer
/// without taking ownership. The pointer was obtained from
/// `Arc::as_ptr`; the bridge's owning `Arc` is held by the
/// `Native*Adapter` for the plugin's full lifetime, so this borrow
/// is sound for any call between `make` and `drop_instance`.
///
/// SAFETY: callers must pass a `ctx` produced by
/// [`HostBridge::as_ffi_ref`]; the returned reference is valid for
/// the duration of the call only.
unsafe fn inner_ref<'a>(ctx: usize) -> &'a HostBridgeInner {
    let ptr = ctx as *const HostBridgeInner;
    debug_assert!(!ptr.is_null(), "HostBridge ctx is null — vtable misuse");
    unsafe { &*ptr }
}

/// Record `mcpg_plugin_host_call_duration_seconds` for a single
/// plugin→host call. `outcome` is `"ok"` or `"err"`; `op` is the
/// vtable slot name (`"resolve_secret"`, `"audit_event"`, …).
/// Labels are bounded — `alias` is set at boot from
/// `plugins[*].id`, `op` is one of 8 static strings, and
/// `outcome` is one of two. No risk of label-cardinality blow-up.
fn record_host_call(alias: &str, op: &'static str, outcome: &'static str, start: Instant) {
    metrics::histogram!(
        "mcpg_plugin_host_call_duration_seconds",
        "alias" => alias.to_owned(),
        "op" => op,
        "outcome" => outcome,
    )
    .record(start.elapsed().as_secs_f64());
}

extern "C" fn host_cluster(ctx: usize) -> ROption<ClusterClientRef> {
    let inner = unsafe { inner_ref(ctx) };
    inner.cluster
}

extern "C" fn host_alias(ctx: usize) -> RString {
    let inner = unsafe { inner_ref(ctx) };
    RString::from(inner.alias.as_str())
}

extern "C" fn host_resolve_secret(ctx: usize, uri: RString) -> RString {
    let inner = unsafe { inner_ref(ctx) };
    let start = Instant::now();
    let result: Result<SecretValueWire, SecretError> = match &inner.runtime {
        Some(rt) => {
            let services = Arc::clone(&inner.services);
            let alias = inner.alias.clone();
            let uri = uri.into_string();
            // Route through the spawn-and-block helper, not a bare
            // `rt.block_on`: this slot is reachable on a thread that already
            // has a tokio runtime entered (inline_dispatch / boot-time make),
            // where a nested `block_on` panics and unwinds across the
            // `extern "C"` boundary (UB/abort).
            block_on_host_service(
                rt,
                async move { services.resolve_secret(&alias, &uri).await },
                || {
                    Err(SecretError::Backend {
                        reason: HOST_SERVICE_UNAVAILABLE.to_owned(),
                    })
                },
            )
            .map(SecretValueWire::from)
        }
        None => Err(SecretError::Backend {
            reason: "host bridge has no tokio runtime".to_owned(),
        }),
    };
    record_host_call(
        &inner.alias,
        "resolve_secret",
        if result.is_ok() { "ok" } else { "err" },
        start,
    );
    respond_result_rstring(&result)
}

// ── Backend host services (v31) ────────────────────────────────────────
// These back the cdylib host-FFI slots dynamic backends use. The
// request/response pair (resolve_credentials, cache_get) mirrors
// host_resolve_secret. The subscribe_* pair registers a host-side guard
// in the bridge's subscription registry + hands the plugin an opaque id;
// host_unsubscribe drops the guard.

/// Run a host-service future to completion from a synchronous backend
/// host-FFI slot.
///
/// The cdylib backend bridge drives the plugin's async `execute` via its
/// own `Runtime::block_on`, so a backend host-service slot (resolve_
/// credentials / cache_get / invoke_tool / fetch_content / store_content)
/// can be reached on a thread that already has the *plugin* runtime
/// entered. A bare `Handle::block_on` there panics ("Cannot start a
/// runtime from within a runtime") and the panic would unwind across the
/// `extern "C"` boundary. Instead, spawn the future onto the gateway
/// runtime (where it belongs) and block the FFI thread on a channel — no
/// nested `block_on`, works whether or not a runtime is entered on the
/// calling thread.
fn block_on_host_service<F, T>(
    rt: &tokio::runtime::Handle,
    fut: F,
    on_unavailable: impl FnOnce() -> T,
) -> T
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    rt.spawn(async move {
        let _ = tx.send(fut.await);
    });
    // recv only errors if the spawned task was dropped without sending — the
    // future panicked (tokio isolates the panic and drops the sender) or the
    // gateway runtime is shutting down. This runs on a plugin-initiated
    // `extern "C"` FFI thread, so a panic here would unwind across that
    // boundary and abort the whole process (rustc >= 1.81). Fail closed with
    // the caller's error value instead of propagating.
    rx.recv().unwrap_or_else(|_| on_unavailable())
}

/// Fail-closed reason handed back to a plugin when a host-service call could
/// not complete because the gateway runtime is shutting down or the service
/// future panicked. Kept generic so it never leaks internal detail.
const HOST_SERVICE_UNAVAILABLE: &str =
    "host service unavailable (gateway draining or internal error)";

/// Fail-closed [`BackendHostError`] for the backend-class host-FFI slots when
/// their service call could not complete (see [`block_on_host_service`]).
/// Generic over the success type so each slot infers its own.
fn host_service_unavailable_backend<T>() -> Result<T, BackendHostError> {
    Err(BackendHostError::Backend {
        tool_name: String::new(),
        cause: mcpg_plugin_protocol::BackendError::Transport {
            message: HOST_SERVICE_UNAVAILABLE.to_owned(),
        },
    })
}

extern "C" fn host_resolve_credentials(
    ctx: usize,
    value_json: RString,
    identity_json: RString,
) -> RString {
    let inner = unsafe { inner_ref(ctx) };
    let start = Instant::now();
    let result: Result<serde_json::Value, BackendHostError> = match &inner.runtime {
        Some(rt) => {
            match serde_json::from_str::<serde_json::Value>(value_json.as_str()) {
                Ok(mut value) => {
                    // identity_json is `null` (system call) or a serialized
                    // PluginIdentity. Treat parse failure as "no identity".
                    let identity: Option<PluginIdentity> =
                        serde_json::from_str(identity_json.as_str()).unwrap_or(None);
                    // Trust the relayed identity ONLY if it carries the host
                    // integrity tag this plugin's alias was stamped with, for
                    // a dispatch still in flight; a forged/mutated/stale
                    // identity falls back to None (system call), which the
                    // resolver treats as "cannot use cred://".
                    let identity =
                        crate::identity_sig::verified_or_none(identity, &inner.alias, |nonce| {
                            inner.is_dispatch_live(nonce)
                        });
                    let services = Arc::clone(&inner.services);
                    let alias = inner.alias.clone();
                    block_on_host_service(
                        rt,
                        async move {
                            let count = services
                                .resolve_credentials(&alias, &mut value, identity)
                                .await?;
                            Ok(serde_json::json!({ "value": value, "count": count }))
                        },
                        host_service_unavailable_backend,
                    )
                }
                Err(e) => Err(BackendHostError::Backend {
                    tool_name: String::new(),
                    cause: mcpg_plugin_protocol::BackendError::Transport {
                        message: format!("resolve_credentials: invalid value JSON: {e}"),
                    },
                }),
            }
        }
        None => Err(BackendHostError::NotImplemented),
    };
    record_host_call(
        &inner.alias,
        "resolve_credentials",
        if result.is_ok() { "ok" } else { "err" },
        start,
    );
    respond_result_rstring(&result)
}

extern "C" fn host_cache_get(ctx: usize, key: RString) -> RString {
    let inner = unsafe { inner_ref(ctx) };
    let start = Instant::now();
    // Wire shape: Ok(Option<base64 string>). None = cache miss.
    let result: Result<Option<String>, BackendHostError> = match &inner.runtime {
        Some(rt) => {
            let services = Arc::clone(&inner.services);
            let alias = inner.alias.clone();
            let key = key.into_string();
            block_on_host_service(
                rt,
                async move { services.cache_get(&alias, &key).await },
                host_service_unavailable_backend,
            )
            .map(|opt| opt.map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)))
        }
        None => Err(BackendHostError::NotImplemented),
    };
    record_host_call(
        &inner.alias,
        "cache_get",
        if result.is_ok() { "ok" } else { "err" },
        start,
    );
    respond_result_rstring(&result)
}

extern "C" fn host_invoke_tool(
    ctx: usize,
    ctx_json: RString,
    tool_name: RString,
    args_json: RString,
) -> RString {
    let inner = unsafe { inner_ref(ctx) };
    let start = Instant::now();
    let result: Result<serde_json::Value, BackendHostError> = match &inner.runtime {
        Some(rt) => {
            let bctx = serde_json::from_str::<
                mcpg_plugin_protocol::backend::BackendInvocationContext,
            >(ctx_json.as_str());
            match bctx {
                Ok(mut bctx) => {
                    let args: serde_json::Value =
                        serde_json::from_str(args_json.as_str()).unwrap_or(serde_json::Value::Null);
                    // Don't trust the plugin-supplied invocation context's
                    // authorization-bearing fields. The caller identity is
                    // accepted only if it carries this alias's host tag for a
                    // dispatch still in flight (a legit relay of the identity
                    // the plugin was handed); otherwise it drops to None
                    // (system-initiated child call). `initiating_backend` is
                    // forced to the calling alias so a plugin can't pose as
                    // another binding for attribution, cache/content routing,
                    // or the self-call cycle guard.
                    bctx.identity = crate::identity_sig::verified_or_none(
                        bctx.identity,
                        &inner.alias,
                        |nonce| inner.is_dispatch_live(nonce),
                    );
                    bctx.initiating_backend = inner.alias.clone();
                    let services = Arc::clone(&inner.services);
                    let tool_name = tool_name.into_string();
                    block_on_host_service(
                        rt,
                        async move { services.invoke_tool(&bctx, &tool_name, &args).await },
                        host_service_unavailable_backend,
                    )
                }
                Err(e) => Err(BackendHostError::Backend {
                    tool_name: String::new(),
                    cause: mcpg_plugin_protocol::BackendError::Transport {
                        message: format!("invoke_tool: invalid context JSON: {e}"),
                    },
                }),
            }
        }
        None => Err(BackendHostError::NotImplemented),
    };
    record_host_call(
        &inner.alias,
        "invoke_tool",
        if result.is_ok() { "ok" } else { "err" },
        start,
    );
    respond_result_rstring(&result)
}

extern "C" fn host_fetch_content(ctx: usize, uri: RString) -> RString {
    let inner = unsafe { inner_ref(ctx) };
    let start = Instant::now();
    // Wire shape: Ok(Option<base64 string>). None = not found.
    let result: Result<Option<String>, BackendHostError> = match &inner.runtime {
        Some(rt) => {
            let services = Arc::clone(&inner.services);
            let alias = inner.alias.clone();
            let uri = uri.into_string();
            block_on_host_service(
                rt,
                async move { services.fetch_content(&alias, &uri).await },
                host_service_unavailable_backend,
            )
            .map(|opt| opt.map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)))
        }
        None => Err(BackendHostError::NotImplemented),
    };
    record_host_call(
        &inner.alias,
        "fetch_content",
        if result.is_ok() { "ok" } else { "err" },
        start,
    );
    respond_result_rstring(&result)
}

extern "C" fn host_store_content(ctx: usize, args_json: RString) -> RString {
    use base64::Engine as _;
    let inner = unsafe { inner_ref(ctx) };
    let start = Instant::now();
    // Wire shape in: {"bytes": <base64>, "mime_type": <str>, "ttl_ms": <u64|null>}.
    // Out: Result<BackendResource, BackendHostError>.
    let result: Result<mcpg_plugin_protocol::backend::BackendResource, BackendHostError> =
        match &inner.runtime {
            Some(rt) => {
                let parsed = serde_json::from_str::<serde_json::Value>(args_json.as_str());
                match parsed {
                    Ok(args) => {
                        let b64 = args.get("bytes").and_then(|v| v.as_str()).unwrap_or("");
                        let mime_type = args
                            .get("mime_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("application/octet-stream")
                            .to_owned();
                        let ttl = args
                            .get("ttl_ms")
                            .and_then(|v| v.as_u64())
                            .map(std::time::Duration::from_millis);
                        match base64::engine::general_purpose::STANDARD.decode(b64) {
                            Ok(raw) => {
                                let services = Arc::clone(&inner.services);
                                let alias = inner.alias.clone();
                                let bytes = bytes::Bytes::from(raw);
                                block_on_host_service(
                                    rt,
                                    async move {
                                        services.store_content(&alias, bytes, mime_type, ttl).await
                                    },
                                    host_service_unavailable_backend,
                                )
                            }
                            Err(e) => Err(BackendHostError::Backend {
                                tool_name: String::new(),
                                cause: mcpg_plugin_protocol::BackendError::Transport {
                                    message: format!("store_content: invalid base64 bytes: {e}"),
                                },
                            }),
                        }
                    }
                    Err(e) => Err(BackendHostError::Backend {
                        tool_name: String::new(),
                        cause: mcpg_plugin_protocol::BackendError::Transport {
                            message: format!("store_content: invalid args JSON: {e}"),
                        },
                    }),
                }
            }
            None => Err(BackendHostError::NotImplemented),
        };
    record_host_call(
        &inner.alias,
        "store_content",
        if result.is_ok() { "ok" } else { "err" },
        start,
    );
    respond_result_rstring(&result)
}

extern "C" fn host_subscribe_credential_revoked(ctx: usize, cb: usize, cb_ctx: usize) -> u64 {
    if cb == 0 {
        return 0;
    }
    let inner = unsafe { inner_ref(ctx) };
    // SAFETY: `cb` is a `CredRevokedCallbackFfi` the plugin cast to usize
    // (vtable contract). It points into the dlopen'd plugin image, live
    // for the bridge's lifetime.
    let trampoline: CredRevokedCallbackFfi = unsafe { std::mem::transmute::<usize, _>(cb) };
    let rust_cb: CredentialRevocationCallback = Arc::new(move |plugin_id: &str, target: &str| {
        let pid = RString::from(plugin_id);
        let tgt = RString::from(target);
        // Never let a plugin panic unwind across the FFI boundary.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            trampoline(cb_ctx, pid, tgt);
        }));
    });
    let guard = inner
        .services
        .subscribe_credential_revoked(&inner.alias, rust_cb);
    let id = inner.next_sub_id.fetch_add(1, Ordering::Relaxed);
    inner
        .subscriptions
        .lock()
        .expect("subscription registry poisoned")
        .insert(id, SubscriptionEntry::CredentialRevoked(guard));
    id
}

extern "C" fn host_subscribe_secret_rotation(ctx: usize, cb: usize, cb_ctx: usize) -> u64 {
    if cb == 0 {
        return 0;
    }
    let inner = unsafe { inner_ref(ctx) };
    // SAFETY: see host_subscribe_credential_revoked.
    let trampoline: SecretRotationCallbackFfi = unsafe { std::mem::transmute::<usize, _>(cb) };
    let rust_cb: SecretRotationCallback = Arc::new(move |secret_ref: &str, version: u64| {
        let sref = RString::from(secret_ref);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            trampoline(cb_ctx, sref, version);
        }));
    });
    let guard = inner
        .services
        .subscribe_secret_rotation(&inner.alias, rust_cb);
    let id = inner.next_sub_id.fetch_add(1, Ordering::Relaxed);
    inner
        .subscriptions
        .lock()
        .expect("subscription registry poisoned")
        .insert(id, SubscriptionEntry::SecretRotation(guard));
    id
}

extern "C" fn host_unsubscribe(ctx: usize, sub_id: u64) {
    if sub_id == 0 {
        return;
    }
    let inner = unsafe { inner_ref(ctx) };
    // Removing drops the guard, which runs the host-side unsubscribe.
    inner
        .subscriptions
        .lock()
        .expect("subscription registry poisoned")
        .remove(&sub_id);
}

extern "C" fn host_issue_credential(ctx: usize, uri: RString, identity_json: RString) -> RString {
    let inner = unsafe { inner_ref(ctx) };
    let start = Instant::now();
    let identity: PluginIdentity = match serde_json::from_str(identity_json.as_str()) {
        Ok(id) => id,
        Err(e) => {
            let err = CredentialError::Backend {
                reason: format!("malformed identity_json: {e}"),
            };
            record_host_call(&inner.alias, "issue_credential", "err", start);
            return respond_result_rstring::<(), _>(&Err(err));
        }
    };
    // The principal a plugin mints under must be one the host handed it for a
    // dispatch that is still running: the identity must carry this alias's
    // host integrity tag naming a live dispatch. A forged/unsigned/stale
    // identity is refused (fail-closed) — a plugin cannot mint a credential
    // scoped to a victim principal it never received, nor to one it was handed
    // on some earlier call.
    let identity = match crate::identity_sig::verify_strip(identity, &inner.alias, |nonce| {
        inner.is_dispatch_live(nonce)
    }) {
        Some(id) => id,
        None => {
            record_host_call(&inner.alias, "issue_credential", "err", start);
            return respond_result_rstring::<(), _>(&Err(CredentialError::NotAuthorized {
                reason: format!(
                    "plugin '{}' presented an identity without a valid host tag for a live \
                     dispatch; issue_credential may mint only under the principal of the \
                     request it is currently serving",
                    inner.alias
                ),
            }));
        }
    };
    let result = match &inner.runtime {
        Some(rt) => {
            let services = Arc::clone(&inner.services);
            let alias = inner.alias.clone();
            let uri = uri.into_string();
            block_on_host_service(
                rt,
                async move { services.issue_credential(&alias, &uri, identity).await },
                || {
                    Err(CredentialError::Backend {
                        reason: HOST_SERVICE_UNAVAILABLE.to_owned(),
                    })
                },
            )
        }
        None => Err(CredentialError::Backend {
            reason: "host bridge has no tokio runtime".to_owned(),
        }),
    };
    record_host_call(
        &inner.alias,
        "issue_credential",
        if result.is_ok() { "ok" } else { "err" },
        start,
    );
    respond_result_rstring(&result)
}

extern "C" fn host_config_snapshot(ctx: usize, uri: RString) -> RString {
    let inner = unsafe { inner_ref(ctx) };
    let start = Instant::now();
    let result = match &inner.runtime {
        Some(rt) => {
            let services = Arc::clone(&inner.services);
            let alias = inner.alias.clone();
            let uri = uri.into_string();
            block_on_host_service(
                rt,
                async move { services.config_snapshot(&alias, &uri).await },
                || {
                    Err(ConfigError::Backend {
                        reason: HOST_SERVICE_UNAVAILABLE.to_owned(),
                    })
                },
            )
        }
        None => Err(ConfigError::Backend {
            reason: "host bridge has no tokio runtime".to_owned(),
        }),
    };
    record_host_call(
        &inner.alias,
        "config_snapshot",
        if result.is_ok() { "ok" } else { "err" },
        start,
    );
    respond_result_rstring(&result)
}

extern "C" fn host_audit_event(ctx: usize, event_json: RString) -> RString {
    let inner = unsafe { inner_ref(ctx) };
    let start = Instant::now();
    let event: AuditEvent = match serde_json::from_str(event_json.as_str()) {
        Ok(ev) => ev,
        Err(e) => {
            let err = AuditError::WriteFailed {
                reason: format!("malformed event_json: {e}"),
            };
            record_host_call(&inner.alias, "audit_event", "err", start);
            return respond_result_rstring::<(), _>(&Err(err));
        }
    };
    let result = match &inner.runtime {
        Some(rt) => {
            let services = Arc::clone(&inner.services);
            let alias = inner.alias.clone();
            block_on_host_service(
                rt,
                async move { services.audit_event(&alias, event).await },
                || {
                    Err(AuditError::WriteFailed {
                        reason: HOST_SERVICE_UNAVAILABLE.to_owned(),
                    })
                },
            )
        }
        None => Err(AuditError::WriteFailed {
            reason: "host bridge has no tokio runtime".to_owned(),
        }),
    };
    record_host_call(
        &inner.alias,
        "audit_event",
        if result.is_ok() { "ok" } else { "err" },
        start,
    );
    respond_result_rstring(&result)
}

extern "C" fn host_metric_emit(ctx: usize, point_json: RString) {
    let inner = unsafe { inner_ref(ctx) };
    let start = Instant::now();
    let outcome = match serde_json::from_str::<MetricPoint>(point_json.as_str()) {
        Ok(point) => {
            inner.services.metric_emit(&inner.alias, point);
            "ok"
        }
        // Malformed metric points are dropped silently — metrics are
        // best-effort and the contract has no error return slot. But
        // we still record the duration + an `err` outcome so operators
        // notice the spike in dropped metrics.
        Err(_) => "err",
    };
    record_host_call(&inner.alias, "metric_emit", outcome, start);
}

extern "C" fn host_span_start(ctx: usize, name: RString, attrs_json: RString) -> u64 {
    let inner = unsafe { inner_ref(ctx) };
    let start = Instant::now();
    let attrs = serde_json::from_str(attrs_json.as_str()).unwrap_or_else(|_| serde_json::json!({}));
    let id = inner
        .services
        .span_start(&inner.alias, name.as_str(), attrs);
    record_host_call(&inner.alias, "span_start", "ok", start);
    id
}

extern "C" fn host_span_end(ctx: usize, span_id: u64) {
    let inner = unsafe { inner_ref(ctx) };
    let start = Instant::now();
    inner.services.span_end(span_id);
    record_host_call(&inner.alias, "span_end", "ok", start);
}

extern "C" fn host_span_event(ctx: usize, span_id: u64, name: RString, attrs_json: RString) {
    let inner = unsafe { inner_ref(ctx) };
    let start = Instant::now();
    let attrs = serde_json::from_str(attrs_json.as_str()).unwrap_or_else(|_| serde_json::json!({}));
    inner.services.span_event(span_id, name.as_str(), attrs);
    record_host_call(&inner.alias, "span_event", "ok", start);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for the cdylib host-service nested-`block_on`
    /// panic: backend host slots are reached on a thread
    /// that already has the *plugin* runtime entered (the cdylib bridge's
    /// `Runtime::block_on`). `block_on_host_service` must run the gateway
    /// future without a nested `block_on` panic. A bare `gateway.block_on`
    /// here would panic "Cannot start a runtime from within a runtime".
    #[test]
    fn block_on_host_service_safe_inside_plugin_runtime() {
        let gateway = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let gh = gateway.handle().clone();
        let plugin_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        // Mirror the cdylib bridge: drive the "plugin execute" on the
        // plugin runtime; inside it, a sync host-service slot runs a
        // gateway future via the helper.
        let out: u32 = plugin_rt
            .block_on(async move { block_on_host_service(&gh, async { 123_u32 }, || 0_u32) });
        assert_eq!(out, 123);
    }

    #[test]
    fn block_on_host_service_returns_fallback_when_future_panics() {
        // A panicking host-service future must NOT unwind across the FFI
        // boundary (that aborts the process on rustc >= 1.81); the helper
        // returns the caller's fail-closed value instead.
        let gateway = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let gh = gateway.handle().clone();
        let out: u32 = block_on_host_service(
            &gh,
            async {
                panic!("host service blew up");
                #[allow(unreachable_code)]
                1_u32
            },
            || 42_u32,
        );
        assert_eq!(
            out, 42,
            "panicking future must yield the fallback, not abort"
        );
    }

    #[test]
    fn stub_returns_rnone_cluster() {
        let bridge = HostBridge::stub();
        let ffi = bridge.as_ffi_ref();
        let got = (ffi.vtable.cluster)(ffi.ctx);
        assert!(matches!(got, ROption::RNone));
    }

    #[test]
    fn alias_round_trips() {
        let bridge = HostBridge::new(None, "rate-limit#0");
        let ffi = bridge.as_ffi_ref();
        let got = (ffi.vtable.alias)(ffi.ctx);
        assert_eq!(got.as_str(), "rate-limit#0");
    }

    #[test]
    fn ffi_ref_remains_valid_after_clone() {
        // Cloning the bridge keeps the inner Arc alive even if the
        // original is dropped — the ffi ref must remain usable.
        let bridge = HostBridge::new(None, "test");
        let kept = bridge.clone();
        let ffi = bridge.as_ffi_ref();
        drop(bridge);
        let got = (ffi.vtable.alias)(ffi.ctx);
        assert_eq!(got.as_str(), "test");
        drop(kept);
    }

    #[tokio::test]
    async fn with_services_captures_runtime_handle() {
        let services: Arc<dyn HostServices> = Arc::new(NullHostServices);
        let bridge = HostBridge::with_services(None, "wired", services);
        let ffi = bridge.as_ffi_ref();
        let alias = (ffi.vtable.alias)(ffi.ctx);
        assert_eq!(alias.as_str(), "wired");
        // Inner state has both the services Arc and a runtime handle.
        assert!(bridge.inner.runtime.is_some());
    }

    #[test]
    fn resolve_secret_unwired_returns_no_runtime_envelope() {
        // stub() is built outside a runtime — runtime: None — so the
        // dispatch path returns a Backend{reason} via the envelope
        // without calling into NullHostServices.
        let bridge = HostBridge::stub();
        let ffi = bridge.as_ffi_ref();
        let out = (ffi.vtable.resolve_secret)(ffi.ctx, RString::from("vault://kv/x"));
        let env: serde_json::Value = serde_json::from_str(out.as_str()).expect("valid envelope");
        assert_eq!(env["err"]["kind"], "backend");
        assert!(
            env["err"]["reason"]
                .as_str()
                .unwrap()
                .contains("no tokio runtime")
        );
    }

    #[tokio::test]
    async fn resolve_secret_wired_calls_host_services() {
        use crate::host_services::MetricPoint;
        use async_trait::async_trait;
        use mcpg_plugin_protocol::{
            audit::{AuditError, AuditEvent, AuditReceipt},
            config::{ConfigError, ConfigSnapshot},
            credential::{CredentialError, IssuedCredential},
            secret::SecretValue,
            types::PluginIdentity,
        };
        use std::sync::Mutex;

        #[derive(Default)]
        struct Recorder {
            secret_calls: Mutex<Vec<(String, String)>>,
        }
        #[async_trait]
        impl HostServices for Recorder {
            async fn resolve_secret(
                &self,
                alias: &str,
                uri: &str,
            ) -> Result<SecretValue, SecretError> {
                self.secret_calls
                    .lock()
                    .unwrap()
                    .push((alias.to_owned(), uri.to_owned()));
                Ok(SecretValue::new(b"sekret".to_vec()))
            }
            async fn issue_credential(
                &self,
                _: &str,
                _: &str,
                _: PluginIdentity,
            ) -> Result<IssuedCredential, CredentialError> {
                unreachable!()
            }
            async fn config_snapshot(
                &self,
                _: &str,
                _: &str,
            ) -> Result<ConfigSnapshot, ConfigError> {
                unreachable!()
            }
            async fn audit_event(
                &self,
                _: &str,
                _: AuditEvent,
            ) -> Result<AuditReceipt, AuditError> {
                unreachable!()
            }
            fn metric_emit(&self, _: &str, _: MetricPoint) {}
            fn span_start(&self, _: &str, _: &str, _: serde_json::Value) -> u64 {
                0
            }
            fn span_end(&self, _: u64) {}
            fn span_event(&self, _: u64, _: &str, _: serde_json::Value) {}
        }

        let recorder = Arc::new(Recorder::default());
        let services: Arc<dyn HostServices> = recorder.clone();
        let bridge = HostBridge::with_services(None, "secrets-test", services);
        let ffi = bridge.as_ffi_ref();
        // The FFI slot calls `block_on` internally, which panics if
        // called from inside a tokio runtime worker thread. The real
        // pattern is that plugins run on `spawn_blocking` and the
        // FFI call comes from that blocking thread. Mirror that here.
        let out = tokio::task::spawn_blocking(move || {
            (ffi.vtable.resolve_secret)(ffi.ctx, RString::from("vault://kv/x"))
        })
        .await
        .unwrap();
        let env: serde_json::Value = serde_json::from_str(out.as_str()).expect("valid envelope");
        assert_eq!(env["ok"]["bytes"], serde_json::json!(b"sekret"));
        let calls = recorder.secret_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "secrets-test");
        assert_eq!(calls[0].1, "vault://kv/x");
    }
}
