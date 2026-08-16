//! Dynamic native plugin loader.
//!
//! Binds a verified `.so` / `.dylib` produced by a third party into the
//! gateway process. The cdylib exports a single entry point — see
//! [`mcpg_plugin_protocol::abi`] for the ABI contract — and this module
//! bridges the resulting FFI vtables back onto the in-tree async trait
//! objects (`ToolGatePlugin`, `TransformPlugin`, `IdentityProviderPlugin`).
//!
//! # Safety
//!
//! Loading native code from disk is inherently unsafe. This module relies
//! on three layers of defence:
//!
//! 1. **Signature + hash verification** happens in
//!    [`crate::native::verify_native_artifact`] before we ever call
//!    `libloading::Library::new`.
//! 2. **ABI version sentinel** — the loader aborts if the cdylib's
//!    `abi_version` does not match the host's compiled-in
//!    [`MCPG_PLUGIN_ABI_VERSION`].
//! 3. **Library lifetime** — the `Library` handle is kept alive inside
//!    the plugin adapter; dropping the adapter unloads the library.
//!    Plugin handles returned by `make` MUST only be used while the
//!    owning [`LoadedNativePlugin`] is alive.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use libloading::{Library, Symbol};
use mcpg_cluster_api::{
    ActiveLease, BoxActiveLease, BoxPeerEventStream, BoxPublishedMessageStream, ClusterBackend,
    ClusterError, ClusterNodeInfo, ClusterPeer, Entry, KeyValueStore, KvEntryWire, KvListEntryWire,
    PeerEvent, PubSub, PublishedMessage, Subscription as PubSubSubscription,
};
use mcpg_plugin_protocol::abi::{
    AuditSinkVTable, BackendVTable, BytesSinkRef, CacheVTable, ClusterVTable, ConfigProviderVTable,
    ContentStoreVTable, DispatcherCallbackRef, DispatcherCallbackResult, EventSinkRef,
    HttpRouteVTable, IdentityProviderVTable, LogSinkVTable, MCPG_PLUGIN_ABI_VERSION,
    MCPG_PLUGIN_REGISTER_SYMBOL, MetricsSinkVTable, PluginRegisterFn, PluginRegistration,
    PolicyEngineVTable, RPluginContext, RPluginHandle, SecretProviderVTable, StoreVTable,
    TelemetrySinkVTable, ToolGateVTable, TransformVTable, TransportVTable, WatchStrategyVTable,
};
use mcpg_plugin_protocol::audit::{AuditError, AuditEvent, AuditReceipt, AuditSink};
use mcpg_plugin_protocol::backend::{BackendChunk, BackendChunkStream, CapabilitySet};
use mcpg_plugin_protocol::cache::{Cache, CacheError};
use mcpg_plugin_protocol::config::{
    BoxConfigDeltaStream, ConfigDelta, ConfigError, ConfigProvider, ConfigSnapshot,
};
use mcpg_plugin_protocol::content_store::{
    ContentStore, ContentStoreError, ContentStorePlugin, ContentStoreStats, ContentToStore,
    ResourceContent, ResourceHandle,
};
use mcpg_plugin_protocol::http_route::{
    HttpBody, HttpChunk, HttpChunkWire, HttpRoute, HttpRouteRequest, HttpRouteRequestWire,
    HttpRouteResponse, HttpRouteResponseWire, HttpStreamHead, RouteSpec,
};
use mcpg_plugin_protocol::logs::{LogError, LogRecord, LogSink};
use mcpg_plugin_protocol::metrics::{MetricsError, MetricsSink};
use mcpg_plugin_protocol::policy::{PolicyDecision, PolicyEngine, PolicyVersion};
use mcpg_plugin_protocol::secret::{
    BoxSecretRotationStream, SecretError, SecretProvider, SecretRotation, SecretRotationWire,
    SecretValue, SecretValueWire,
};
use mcpg_plugin_protocol::store::{
    AppendResult, BoxStoreEventStream, Store, StoreError, StoreEvent, StoreEventWire, StorePage,
    StorePageWire, StoreRole, StoreValue, StoreValueWire,
};
use mcpg_plugin_protocol::telemetry::{
    MetricPoint, SpanEnd, SpanStart, TelemetryError, TelemetrySink,
};
use mcpg_plugin_protocol::transport::{
    DispatchResponse, DispatcherError, MessageDispatcher, Transport, TransportError,
    TransportHandle,
};
use mcpg_plugin_protocol::{
    BackendError, BackendPlugin, BackendRequest, BackendResponse, GateDecision,
    IdentityProviderPlugin, IdentityResolution, PluginContext, PluginManifest, ResourcePage,
    ToolGatePlugin, TransformPlugin, TransformResult, WatchError, WatchEvent, WatchEventSink,
    WatchHandle, WatchStrategyPlugin,
};

use crate::native::{NativePluginMeta, NativeVerifyOptions, verify_native_artifact};

/// Effective per-plugin FFI hardening budgets (per-class timeouts +
/// payload cap). Constructed by the gateway boot path from
/// `plugins[].ffi_limits` operator overrides; defaults to the spec
/// constants in [`mcpg_plugin_protocol::abi`].
///
/// Each adapter reads `self.library.ffi_limits` to pick the
/// appropriate per-class timeout + payload cap for every FFI call.
#[derive(Debug, Clone)]
pub struct FfiLimits {
    pub lifecycle_timeout: std::time::Duration,
    pub control_timeout: std::time::Duration,
    pub data_timeout: std::time::Duration,
    pub max_payload_bytes: usize,
}

impl Default for FfiLimits {
    fn default() -> Self {
        use mcpg_plugin_protocol::abi::{
            FFI_CONTROL_TIMEOUT_DEFAULT_MS, FFI_DATA_TIMEOUT_DEFAULT_MS,
            FFI_LIFECYCLE_TIMEOUT_DEFAULT_MS, FFI_MAX_PAYLOAD_BYTES,
        };
        Self {
            lifecycle_timeout: std::time::Duration::from_millis(FFI_LIFECYCLE_TIMEOUT_DEFAULT_MS),
            control_timeout: std::time::Duration::from_millis(FFI_CONTROL_TIMEOUT_DEFAULT_MS),
            data_timeout: std::time::Duration::from_millis(FFI_DATA_TIMEOUT_DEFAULT_MS),
            max_payload_bytes: FFI_MAX_PAYLOAD_BYTES,
        }
    }
}

impl FfiLimits {
    /// Return the wall-clock timeout for the given slot class.
    pub fn timeout_for(
        &self,
        class: mcpg_plugin_protocol::abi::FfiSlotClass,
    ) -> std::time::Duration {
        use mcpg_plugin_protocol::abi::FfiSlotClass;
        match class {
            FfiSlotClass::Lifecycle => self.lifecycle_timeout,
            FfiSlotClass::Control => self.control_timeout,
            FfiSlotClass::Data => self.data_timeout,
        }
    }
}

/// Enforce [`mcpg_plugin_protocol::abi::FFI_MAX_PAYLOAD_BYTES`] (the
/// payload cap) on a single `RString` returning from a cdylib
/// plugin.
///
/// On overflow this logs an error, bumps
/// `mcpg_plugin_payload_oversize_total{plugin_alias, slot}`, and
/// returns `Err(actual_bytes)` so the caller can synthesise a
/// slot-appropriate fallback (transport-error response, empty list,
/// deny decision, …). Within-cap payloads return `Ok(())` and the
/// caller decodes normally.
/// Encode `value` to JSON via a thread-local reusable byte buffer
/// and hand back an [`RString`] for the FFI call.
///
/// The hot sink slots (`metrics_sink.emit`, `log_sink.emit`,
/// `audit_sink.emit`, `telemetry_sink.span_*`) are called up to
/// 50× per tool-call on metric-heavy workloads, so the per-emit
/// allocation cost matters here. A per-thread arena (`RefCell<Vec<u8>>`,
/// capacity reused across emits) absorbs the JSON encode; spawn_blocking
/// runs each closure on its own worker, so the arena is contention-free.
/// The final `RString::from(&str)` copy is unavoidable — the `RString`
/// crosses the FFI boundary and must own its bytes.
///
/// `#[doc(hidden)] pub` so the `ffi_matrix` bench can measure it against a
/// plain `serde_json::to_string`; not part of the public API.
#[doc(hidden)]
pub fn encode_to_rstring_via_arena<T: serde::Serialize + ?Sized>(
    value: &T,
) -> abi_stable::std_types::RString {
    thread_local! {
        static EMIT_BUF: std::cell::RefCell<Vec<u8>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }
    EMIT_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        // serde_json never panics on a buffer Write impl, so the
        // only error path is genuine serialize failure (e.g. a
        // type that returns Err from its Serialize impl). In that
        // case fall back to "{}" — same shape as the old
        // `unwrap_or_else(|_| "{}".into())` behaviour.
        if serde_json::to_writer(&mut *buf, value).is_err() {
            return abi_stable::std_types::RString::from("{}");
        }
        // `serde_json::to_writer` always emits valid UTF-8 (JSON
        // is UTF-8 by spec). Use the unchecked conversion to skip
        // a redundant validation pass on the hot path.
        let s: &str = unsafe { std::str::from_utf8_unchecked(&buf) };
        abi_stable::std_types::RString::from(s)
    })
}

fn enforce_ffi_payload_cap(
    rs: &abi_stable::std_types::RString,
    plugin_alias: &str,
    slot: &'static str,
    cap_bytes: usize,
) -> Result<(), usize> {
    let len = rs.as_str().len();
    if len > cap_bytes {
        tracing::error!(
            plugin_alias = %plugin_alias,
            slot = slot,
            actual_bytes = len,
            cap_bytes = cap_bytes,
            "native plugin returned an FFI payload exceeding the host cap; rejecting"
        );
        metrics::counter!(
            "mcpg_plugin_payload_oversize_total",
            "plugin_alias" => plugin_alias.to_owned(),
            "slot" => slot,
        )
        .increment(1);
        return Err(len);
    }
    Ok(())
}

/// Wrapper to transport `RPluginHandle` (`*mut ()`) across the
/// `spawn_blocking` boundary. Safety contract: the raw pointer is owned by the
/// `NativeToolGateAdapter` which is already `unsafe impl Send + Sync` and keeps
/// the backing `Library` alive via `Arc<LoadedNativePlugin>`. The handle is only
/// used inside `spawn_blocking` closures that run to completion before the adapter
/// can be dropped, so the pointer remains valid for the duration of use.
///
/// Made `pub` to support the `http_route_adapter_seam`
/// integration test, which exercises
/// [`dispatch_http_route_via_vtable`] without constructing a full
/// [`LoadedNativePlugin`].
pub struct SendHandle(RPluginHandle);
unsafe impl Send for SendHandle {}
unsafe impl Sync for SendHandle {}
impl SendHandle {
    pub fn new(handle: RPluginHandle) -> Self {
        Self(handle)
    }
    pub fn ptr(&self) -> RPluginHandle {
        self.0
    }
}

/// Generic Send/Sync wrapper for a raw pointer the adapter needs
/// to hold across an `.await` point. Used by the streaming
/// adapters to carry `*mut StreamBridge` into + out of
/// `spawn_blocking` without violating async-trait's Send bound.
/// Safety: raw pointers here always point at a `Box`-allocated
/// value the adapter solely owns, mutated only inside the FFI
/// callback (which takes its own `usize` cast and does not race
/// with the adapter's Drop).
struct SendPtr<T>(*mut T);
unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}

/// Owner of a dynamically-loaded cdylib and the plugin handles it vends.
/// Dropping this value unloads the library; any still-live trait objects
/// referencing the library's vtables become invalid — the registry keeps
/// `Arc<LoadedNativePlugin>` references on each returned plugin so the
/// drop order is correct.
///
/// # Field order is load-bearing
///
/// Rust drops struct fields in declaration order. `registration` contains
/// `RString`s whose backing storage was allocated inside the cdylib; their
/// `Drop` impls call back through the shared library's allocator. If
/// `_library` dropped first we'd unload the `.so`, then the RStrings would
/// attempt to free memory through a now-unmapped allocator and segfault.
/// Keep `_library` LAST so it unloads after every field it owns memory for.
pub struct LoadedNativePlugin {
    pub registration: PluginRegistration,
    pub meta: NativePluginMeta,
    /// Per-plugin FFI hardening budgets — populated from
    /// `plugins[].ffi_limits` at boot or defaulted to the spec
    /// constants. Read by every adapter for per-class timeouts +
    /// payload caps.
    pub ffi_limits: FfiLimits,
    /// Typed required capabilities decoded from
    /// `registration.capabilities`. Cached on
    /// load so per-call sites don't repeat the JSON decode. Boot
    /// validation compares this against the operator's
    /// `granted_capabilities` set via
    /// [`mcpg_plugin_protocol::capability::validate_typed_capabilities`].
    pub required_capabilities: Vec<mcpg_plugin_protocol::capability::Capability>,
    /// The dlopened shared library. `None` only for a `synthetic()`
    /// instance (FFI-equivalence test seam) whose vtable fn
    /// pointers live in the test binary, not a `.so` — there is no
    /// mapping to keep alive and no cross-allocator free hazard (all
    /// RStrings are host-allocated). Still declared LAST so a real
    /// `Some(lib)` unloads after every field it owns memory for.
    _library: Option<Library>,
}

#[cfg(any(test, feature = "cluster-ffi-test-seam"))]
impl LoadedNativePlugin {
    /// FFI-equivalence test seam: a `LoadedNativePlugin` with NO
    /// backing `.so`. Carries default `ffi_limits` (the only field the
    /// cluster adapter reads off `library`) + the supplied `meta.manifest`,
    /// and empty registration/capabilities (never consulted by the cluster
    /// dispatch path, which uses the vtable directly). Lets an in-process
    /// test wrap a macro-built `ClusterVTable` in a real
    /// `NativeClusterAdapter` — exercising the production FFI dispatch
    /// (`spawn_blocking`, JSON marshalling, result envelopes, the
    /// refcounted instance, lease/stream guards) — without a dlopen.
    pub fn synthetic(manifest: PluginManifest) -> Self {
        LoadedNativePlugin {
            registration: PluginRegistration {
                abi_version: mcpg_plugin_protocol::abi::MCPG_PLUGIN_ABI_VERSION,
                plugin_id: abi_stable::std_types::RString::new(),
                plugin_version: abi_stable::std_types::RString::new(),
                module_path_prefix: abi_stable::std_types::RString::new(),
                entities: abi_stable::std_types::RVec::new(),
                capabilities: abi_stable::std_types::RVec::new(),
                backend_profile_json: abi_stable::std_types::ROption::RNone,
                descriptor_yaml: Default::default(),
            },
            meta: NativePluginMeta {
                manifest,
                source_path: None,
                signature_verified: false,
                artifact_hash: None,
            },
            ffi_limits: FfiLimits::default(),
            required_capabilities: Vec::new(),
            _library: None,
        }
    }
}

/// Peek the cdylib's `PluginManifest` without registering the
/// plugin. Used by the gateway boot path to run the
/// `plugin.lifecycle.register` policy chain BEFORE committing to
/// register a plugin's adapters into the registry.
///
/// Constructs whichever populated vtable's instance, calls
/// `manifest_json` once, drops the instance — same `make` +
/// `drop_instance` cost the registration path would pay anyway,
/// just paid earlier so the policy can refuse without leaving
/// half-registered state behind.
///
/// `config_json` is the operator-supplied plugin config; the
/// `make` slot consumes it. If multiple vtables are populated
/// (a multi-vtable cdylib like the Slack approval plugin), the
/// first matching slot is used — every vtable's `manifest_json`
/// returns the same plugin-wide manifest by convention.
///
/// A plugin carrying its descriptor answers from that instead: the policy
/// chain wants the plugin's identity, and identity does not require a
/// running instance. Construction is what makes this fragile — the
/// registration policy runs before the plugin's config has been validated,
/// so a plugin that fails closed on a bad config would be judged
/// unloadable rather than misconfigured.
pub fn peek_manifest_from_loaded(
    loaded: &Arc<LoadedNativePlugin>,
    config_json: serde_json::Value,
) -> Result<PluginManifest> {
    use abi_stable::std_types::RString;
    use mcpg_plugin_protocol::abi::EntityRegistration;

    if !loaded.registration.descriptor_yaml.is_empty() {
        return manifest_from_descriptor(&loaded.registration);
    }

    let cfg_str =
        RString::from(serde_json::to_string(&config_json).unwrap_or_else(|_| "{}".into()));

    // Every `make` slot takes
    // `(host: HostHandleRef, config_json, inner_name)`. Peek
    // constructs + immediately drops the instance solely to read
    // its manifest, so a stub HostBridge with no real services is
    // sufficient — the bridge's `cluster()` returns `RNone`.
    let host_bridge = crate::host_bridge::HostBridge::stub();
    let host_ref = host_bridge.as_ffi_ref();
    let inner_name = RString::new();

    macro_rules! peek_with_host {
        ($vt:expr, $kind:literal) => {{
            let cfg = cfg_str.clone();
            let handle = guard_ffi_make(|| ($vt.make)(host_ref, cfg, inner_name.clone()));
            if handle.is_null() {
                return Err(anyhow!(
                    "peek_manifest: native {} `make` returned null",
                    $kind
                ));
            }
            let raw = guard_ffi_rstring("manifest_json", || ($vt.manifest_json)(handle));
            let raw = raw.as_str().to_owned();
            guard_ffi_drop(|| ($vt.drop_instance)(handle));
            if raw.is_empty() {
                return Err(anyhow!(
                    "peek_manifest: native {} returned empty manifest",
                    $kind
                ));
            }
            return serde_json::from_str(&raw)
                .with_context(|| format!("peek_manifest: invalid manifest from native {}", $kind));
        }};
    }

    let first = loaded.registration.entities.first().ok_or_else(|| {
        anyhow!(
            "peek_manifest: native plugin `{}` registers no entities",
            loaded.registration.plugin_id.as_str()
        )
    })?;

    match first {
        EntityRegistration::ToolGate { vtable, .. } => peek_with_host!(vtable, "tool_gate"),
        EntityRegistration::Transform { vtable, .. } => peek_with_host!(vtable, "transform"),
        EntityRegistration::IdentityProvider { vtable, .. } => {
            peek_with_host!(vtable, "identity_provider")
        }
        EntityRegistration::Backend { vtable, .. } => peek_with_host!(vtable, "backend"),
        EntityRegistration::WatchStrategy { vtable, .. } => {
            peek_with_host!(vtable, "watch_strategy")
        }
        EntityRegistration::HttpRoute { vtable, .. } => peek_with_host!(vtable, "http_route"),
        EntityRegistration::AuditSink { vtable, .. } => peek_with_host!(vtable, "audit_sink"),
        EntityRegistration::LogSink { vtable, .. } => peek_with_host!(vtable, "log_sink"),
        EntityRegistration::TelemetrySink { vtable, .. } => {
            peek_with_host!(vtable, "telemetry_sink")
        }
        EntityRegistration::MetricsSink { vtable, .. } => {
            peek_with_host!(vtable, "metrics_sink")
        }
        EntityRegistration::Store { vtable, .. } => peek_with_host!(vtable, "store"),
        EntityRegistration::Cache { vtable, .. } => peek_with_host!(vtable, "cache"),
        EntityRegistration::SecretProvider { vtable, .. } => {
            peek_with_host!(vtable, "secret_provider")
        }
        EntityRegistration::ConfigProvider { vtable, .. } => {
            peek_with_host!(vtable, "config_provider")
        }
        EntityRegistration::PolicyEngine { vtable, .. } => {
            peek_with_host!(vtable, "policy_engine")
        }
        EntityRegistration::Cluster { vtable, .. } => {
            peek_with_host!(vtable, "cluster")
        }
        EntityRegistration::Transport { vtable, .. } => peek_with_host!(vtable, "transport"),
        EntityRegistration::CatalogProvider { vtable, .. } => {
            peek_with_host!(vtable, "catalog_provider")
        }
        EntityRegistration::CredentialIssuer { vtable, .. } => {
            peek_with_host!(vtable, "credential_issuer")
        }
        EntityRegistration::ApprovalNotifier { vtable, .. } => {
            peek_with_host!(vtable, "approval_notifier")
        }
        EntityRegistration::ContentStore { vtable, .. } => {
            peek_with_host!(vtable, "content_store")
        }
    }
}

/// Dynamically load a verified native plugin from disk.
///
/// Performs verification, opens the library, looks up the register
/// symbol, checks the ABI version sentinel, and returns a handle that
/// owns the loaded library for the caller's lifetime.
pub fn load_native_plugin(
    artifact_path: &Path,
    options: &NativeVerifyOptions,
    ffi_limits: FfiLimits,
) -> Result<Arc<LoadedNativePlugin>> {
    let verified = verify_native_artifact(artifact_path, options)
        .with_context(|| format!("verifying '{}'", artifact_path.display()))?;

    // Close the verify→dlopen TOCTOU. `verify_native_artifact`
    // reads the artifact by PATH (hash + signature) and `Library::new`
    // re-opens the same PATH — an attacker who can replace the file in
    // that window loads code that was never verified while hash + Ed25519
    // both reported success on the stale bytes. Re-hash the artifact
    // immediately before `dlopen` and compare to the digest computed
    // during verification: a SHA-256 content hash detects ANY change
    // (in-place edit or unlink+replace, length-preserving or not) and —
    // unlike a stat/inode/mtime pin — is not attacker-forgeable (mtime can
    // be reset via utimensat/SetFileTime; a content hash cannot). The
    // digest is always present (verification hashes the artifact
    // unconditionally), so this runs for every native load. Residual: the
    // microsecond window between this re-hash and `Library::new` (both read
    // the path); fully closing it requires OS-specific in-memory/fd load,
    // tracked as follow-up hardening.
    let reload_hash = crate::verify::sha256_file(artifact_path)
        .with_context(|| format!("re-hashing '{}' before load", artifact_path.display()))?;
    if reload_hash != verified.artifact_hash {
        metrics::counter!(
            "mcpg_plugin_load_toctou_refusals_total",
            "reason" => "artifact_changed_during_verify",
        )
        .increment(1);
        return Err(anyhow!(
            "native plugin '{}' changed on disk between verification and load \
             (TOCTOU guard): verified sha256 {} != load-time sha256 {} — \
             refusing to dlopen unverified bytes",
            artifact_path.display(),
            verified.artifact_hash,
            reload_hash,
        ));
    }

    // Safety: the artifact has been hash-pinned and signature-verified
    // above, and the load-time re-hash confirmed its bytes did not change
    // between verification and this load. Loading any library from disk is
    // intrinsically unsafe; the verify + re-hash steps are what make this
    // acceptable.
    let library = unsafe { Library::new(artifact_path) }
        .with_context(|| format!("dlopen '{}'", artifact_path.display()))?;

    // Structurally verify the cdylib's `PluginRegistration` type
    // layout BEFORE calling `mcpg_plugin_register`. The numeric
    // `abi_version` sentinel below is only read AFTER the by-value struct
    // is materialised, so a cdylib built against a different layout (which,
    // under the frozen-ABI policy, still reports version 1) would be read
    // with the host's layout first — UB. `verify_abi_layout` runs
    // abi_stable's `check_layout_compatibility`, so a layout-incompatible
    // struct is refused before it is ever read.
    verify_abi_layout(&library)
        .with_context(|| format!("verifying ABI layout for '{}'", artifact_path.display()))?;

    // Safety: `register` is the single exported entry point the ABI
    // contract requires; its layout was just confirmed compatible. The SDK
    // macro wraps the author's body in a panic guard, so a panic during
    // registration comes back as a `PluginRegistration` carrying the panic
    // sentinel `abi_version` rather than unwinding across the FFI boundary;
    // the immediately following `validate_registration` rejects both that
    // sentinel and any genuine ABI-version mismatch.
    let registration = unsafe {
        let register: Symbol<PluginRegisterFn> = library
            .get(MCPG_PLUGIN_REGISTER_SYMBOL)
            .context("missing mcpg_plugin_register symbol — not an MCPG plugin cdylib")?;
        // Host-side panic guard: maps a caught registration panic to a clean
        // load error. The SDK macro already returns the panic sentinel
        // plugin-side; this covers a host-frame panic / `extern "C-unwind"`
        // plugin (a foreign `extern "C"` panic aborts at its own boundary on
        // modern rustc — safe, not convertible here).
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| register())).map_err(|_| {
            metrics::counter!(
                "mcpg_plugin_load_panic_refusals_total",
                "slot" => "register",
            )
            .increment(1);
            anyhow::anyhow!(
                "native plugin '{}' panicked during registration — refusing to load",
                artifact_path.display(),
            )
        })?
    };

    validate_registration(&registration)
        .with_context(|| format!("validating registration for '{}'", artifact_path.display()))?;

    // The cdylib's manifest is carried on the per-class vtables; the
    // registry uses the first available class to populate
    // `NativePluginMeta.manifest`. Callers that need all three classes
    // extract them from the registration directly.
    let mut manifest = derive_manifest(&registration)?;
    // Host-derive the backend profile from the authoritative FFI
    // declaration (`PluginRegistration.backend_profile_json`), exactly
    // like the capability decls below. A plugin's own `manifest()` ships
    // `None`; the single authoring point is `declare_plugin! {
    // backend_profile: ... }`. `RNone` (every non-backend plugin and
    // every backend that declares nothing) leaves the field `None`.
    manifest.backend_profile = decode_backend_profile(&registration)
        .with_context(|| format!("decoding backend profile for '{}'", artifact_path.display()))?;
    let meta = verified.into_meta(manifest);

    // Decode the typed capability declarations off the
    // registration into native enum form. Decode failures
    // (unknown kind, malformed args_json) fail the load with a
    // clear error mentioning the plugin id; the operator sees the
    // bad capability at startup, not at first request.
    let required_capabilities = decode_capabilities(&registration)
        .with_context(|| format!("decoding capabilities for '{}'", artifact_path.display()))?;

    Ok(Arc::new(LoadedNativePlugin {
        _library: Some(library),
        registration,
        meta,
        ffi_limits,
        required_capabilities,
    }))
}

/// Decode the cdylib's `registration.capabilities` (a vec of
/// `TypedCapabilityDecl`) into the native typed `Capability` form.
/// A decode failure on the cdylib side is a hard load error — the
/// operator must learn at boot that the plugin is broken, not at
/// first request.
fn decode_capabilities(
    reg: &PluginRegistration,
) -> Result<Vec<mcpg_plugin_protocol::capability::Capability>> {
    let mut out = Vec::with_capacity(reg.capabilities.len());
    for decl in reg.capabilities.iter() {
        let cap = decl.to_capability().map_err(|e| {
            anyhow!(
                "plugin '{}' declares invalid capability {:?}: {}",
                reg.plugin_id.as_str(),
                decl.kind.as_str(),
                e
            )
        })?;
        out.push(cap);
    }
    Ok(out)
}

/// Decode the cdylib's `registration.backend_profile_json` (an
/// `ROption<RString>` carrying a JSON-encoded
/// [`BackendProfile`](mcpg_plugin_protocol::manifest::BackendProfile))
/// into the typed manifest field. `RNone` (every non-backend plugin and
/// every backend that declares nothing) decodes to `None` —
/// behaviour-neutral. A malformed JSON payload is a hard load error: the
/// operator must learn at boot the plugin is broken, exactly like
/// [`decode_capabilities`].
fn decode_backend_profile(
    reg: &PluginRegistration,
) -> Result<Option<mcpg_plugin_protocol::manifest::BackendProfile>> {
    match reg.backend_profile_json.as_ref() {
        abi_stable::std_types::ROption::RNone => Ok(None),
        abi_stable::std_types::ROption::RSome(json) => {
            let profile = serde_json::from_str(json.as_str()).map_err(|e| {
                anyhow!(
                    "plugin '{}' declares an invalid backend_profile: {}",
                    reg.plugin_id.as_str(),
                    e
                )
            })?;
            Ok(Some(profile))
        }
    }
}

/// Validate an FFI `PluginRegistration` is well-formed for the current host.
///
/// `PluginRegistration` carries `entities: RVec<EntityRegistration>`.
/// Validation reduces to "ABI version matches" + "the entities vec is
/// non-empty"; per-variant correctness is enforced structurally by the
/// enum.
/// Verify a loaded cdylib's `PluginRegistration` `abi_stable`
/// type layout is structurally compatible with the host's, BEFORE the
/// host materialises the by-value struct that `mcpg_plugin_register`
/// returns.
///
/// Looks up the `mcpg_plugin_abi_layout` export (emitted by
/// `declare_plugin!`), which returns a pointer to the cdylib's `'static`
/// `TypeLayout` for `PluginRegistration`, and runs abi_stable's
/// `check_layout_compatibility` against the host's own layout. A missing
/// symbol (a foreign cdylib) or any layout mismatch refuses the load —
/// fail-closed, before any field of a potentially foreign-layout struct
/// is read.
///
/// Soundness: the returned pointer is read as `&'static TypeLayout`, and
/// `check_layout_compatibility` then traverses that layout *graph* —
/// dereferencing the cdylib's `'static` sub-layout pointers and invoking
/// its `type_id` `extern "C" fn` — so the host touches foreign-controlled
/// pointers + a foreign fn-pointer during the check (it does NOT read any
/// by-value field of `PluginRegistration`, which is the part deferred
/// until after the check passes). This is sound for any cdylib built
/// against the same `abi_stable` version (the whole tree pins
/// `abi_stable = "0.11"` and rebuilds together, so `TypeLayout`'s own
/// representation is identical on both sides; the comparison detects a
/// divergent `PluginRegistration` layout, it does not UB on one). It is
/// also gated behind the Ed25519 signature verify + load-time re-hash
/// that run BEFORE `dlopen`, so any cdylib reaching this point is already
/// integrity-checked. A cdylib built against a different `abi_stable`
/// major could in principle return a malformed layout — the narrow
/// residual that full `abi_stable` `RootModule`/`LibHeader` adoption
/// (which version-stamps the envelope before any layout is touched) would
/// close; tracked as follow-up hardening.
fn verify_abi_layout(library: &Library) -> Result<()> {
    use mcpg_plugin_protocol::abi::{AbiLayoutPtr, MCPG_PLUGIN_ABI_LAYOUT_SYMBOL};

    let layout_fn: Symbol<extern "C" fn() -> AbiLayoutPtr> = unsafe {
        library.get(MCPG_PLUGIN_ABI_LAYOUT_SYMBOL).context(
            "missing mcpg_plugin_abi_layout symbol — plugin predates the \
             ABI type-identity check or was built against an incompatible MCPG \
             protocol; rebuild it against this host",
        )?
    };
    let raw = layout_fn();
    if raw.is_null() {
        return Err(anyhow!(
            "plugin returned a null ABI layout descriptor (mcpg_plugin_abi_layout)"
        ));
    }
    // Safety: `raw` points to the cdylib's `'static` TypeLayout (held alive
    // by `library`); we only read it. See the fn doc for the same-abi_stable
    // -version soundness argument.
    let plugin_layout: &'static abi_stable::type_layout::TypeLayout = unsafe { &*raw };
    let host_layout = <PluginRegistration as abi_stable::StableAbi>::LAYOUT;
    abi_stable::abi_stability::abi_checking::check_layout_compatibility(host_layout, plugin_layout)
        .map_err(|errs| {
            metrics::counter!(
                "mcpg_plugin_load_abi_layout_refusals_total",
                "reason" => "layout_incompatible",
            )
            .increment(1);
            anyhow!(
                "plugin ABI layout is incompatible with the host (type-identity \
             check) — the cdylib was built against a different PluginRegistration \
             layout; rebuild it against this host. Details: {errs:?}"
            )
        })?;
    Ok(())
}

pub fn validate_registration(reg: &PluginRegistration) -> Result<()> {
    if reg.abi_version == mcpg_plugin_protocol::abi::MCPG_PLUGIN_ABI_PANIC_SENTINEL {
        return Err(anyhow!(
            "plugin panicked during mcpg_plugin_register — registration carries the \
             panic sentinel abi_version. The cdylib is broken; rebuild and re-sign."
        ));
    }
    if reg.abi_version != MCPG_PLUGIN_ABI_VERSION {
        return Err(anyhow!(
            "plugin declares ABI version {} but host expects {}",
            reg.abi_version,
            MCPG_PLUGIN_ABI_VERSION
        ));
    }
    if reg.entities.is_empty() {
        return Err(anyhow!("plugin registration exports no entities"));
    }
    Ok(())
}

/// Build the plugin-wide manifest from the descriptor the cdylib carries.
///
/// Preferred over instance construction because it needs no config: the
/// host has no operator config at manifest time and passes `{}`, which a
/// plugin that fails closed on an invalid config rightly rejects — making
/// it permanently unloadable. The descriptor is the same `plugin.yaml` the
/// packaged path already cross-checks, so this reads identity from the
/// declaration rather than from a throwaway instance.
///
/// `version` / `module_path_prefix` come off the registration; capabilities
/// and the backend profile are host-derived by the caller.
fn manifest_from_descriptor(reg: &PluginRegistration) -> Result<PluginManifest> {
    let descriptor: mcpg_plugin_protocol::PluginDescriptor =
        serde_yaml::from_str(reg.descriptor_yaml.as_str())
            .context("parsing the plugin's embedded descriptor_yaml")?;
    Ok(PluginManifest {
        id: descriptor.id,
        version: reg.plugin_version.as_str().to_owned(),
        name: descriptor.name,
        plugin_class: descriptor.class,
        protocol_version: descriptor.protocol_version,
        license: descriptor.license,
        required_capabilities: Vec::new(),
        tags: descriptor.tags,
        provides: descriptor.provides,
        provides_schemes: descriptor.provides_schemes,
        module_path_prefix: reg.module_path_prefix.as_str().to_owned(),
        backend_profile: None,
    })
}

fn derive_manifest(reg: &PluginRegistration) -> Result<PluginManifest> {
    // Every SDK-built plugin carries its descriptor, so the common path
    // never constructs an instance. Hand-built registrations (built-ins,
    // test fixtures) leave it empty and fall through to the probe below.
    if !reg.descriptor_yaml.is_empty() {
        return manifest_from_descriptor(reg);
    }

    // We have the id/version on the registration but not the full
    // manifest; call into the first registered entity's vtable to
    // get it. Every vtable kind exposes `make`/`manifest_json`/
    // `drop_instance` and returns the same plugin-wide manifest by
    // convention, so the choice is arbitrary.
    //
    // `make` is panic-guarded in the SDK; a panic there yields a null
    // handle. Check for null before dispatching to `manifest_json` /
    // `drop_instance` — dereferencing a null handle inside the plugin
    // would be UB. An empty `manifest_json` return (caused by a panic
    // inside manifest()) fails serde parsing below, which is the same
    // "plugin is broken" signal we want.
    use abi_stable::std_types::RString;
    use mcpg_plugin_protocol::abi::EntityRegistration;

    let first = reg
        .entities
        .first()
        .ok_or_else(|| anyhow!("plugin registration exports no entities"))?;

    // Every `make` slot takes
    // `(host: HostHandleRef, config_json, inner_name)`. Manifest
    // derivation builds + immediately drops the instance; a stub
    // HostBridge is sufficient (cluster slot returns RNone).
    let host_bridge = crate::host_bridge::HostBridge::stub();
    let host_ref = host_bridge.as_ffi_ref();
    let inner_name = RString::new();

    // Manifest derivation builds + immediately drops an instance only to read
    // its plugin-wide manifest. It passes an EMPTY config (`{}`) — a plugin
    // that eagerly constructs from / strictly validates its config (cluster
    // coordinators, the strict identity resolvers) treats an empty config as
    // this manifest probe and returns a lazy, non-connecting placeholder for it
    // while still rejecting a NON-empty-but-invalid REAL config at its real
    // `make`. A `{}`-tolerant plugin (all-defaults) builds a normal instance.
    macro_rules! make_with_host {
        ($vt:expr, $kind:literal) => {
            make_with_host!($vt, $kind, "{}")
        };
        ($vt:expr, $kind:literal, $cfg:expr) => {{
            let cfg = RString::from($cfg);
            let handle = guard_ffi_make(|| ($vt.make)(host_ref, cfg, inner_name.clone()));
            if handle.is_null() {
                return Err(anyhow!(
                    "plugin panicked during {}::make — construction returned null handle",
                    $kind
                ));
            }
            let json = guard_ffi_rstring("manifest_json", || ($vt.manifest_json)(handle));
            guard_ffi_drop(|| ($vt.drop_instance)(handle));
            return parse_manifest(json.as_str(), $kind);
        }};
    }

    match first {
        EntityRegistration::ToolGate { vtable, .. } => make_with_host!(vtable, "tool_gate"),
        EntityRegistration::Transform { vtable, .. } => make_with_host!(vtable, "transform"),
        EntityRegistration::IdentityProvider { vtable, .. } => {
            make_with_host!(vtable, "identity_provider")
        }
        EntityRegistration::Backend { vtable, .. } => make_with_host!(vtable, "backend"),
        EntityRegistration::WatchStrategy { vtable, .. } => {
            make_with_host!(vtable, "watch_strategy")
        }
        EntityRegistration::HttpRoute { vtable, .. } => make_with_host!(vtable, "http_route"),
        EntityRegistration::AuditSink { vtable, .. } => make_with_host!(vtable, "audit_sink"),
        EntityRegistration::LogSink { vtable, .. } => make_with_host!(vtable, "log_sink"),
        EntityRegistration::TelemetrySink { vtable, .. } => {
            make_with_host!(vtable, "telemetry_sink")
        }
        EntityRegistration::MetricsSink { vtable, .. } => {
            make_with_host!(vtable, "metrics_sink")
        }
        EntityRegistration::Store { vtable, .. } => make_with_host!(vtable, "store"),
        EntityRegistration::Cache { vtable, .. } => make_with_host!(vtable, "cache"),
        EntityRegistration::SecretProvider { vtable, .. } => {
            make_with_host!(vtable, "secret_provider")
        }
        EntityRegistration::ConfigProvider { vtable, .. } => {
            make_with_host!(vtable, "config_provider")
        }
        EntityRegistration::PolicyEngine { vtable, .. } => {
            make_with_host!(vtable, "policy_engine")
        }
        EntityRegistration::Cluster { vtable, .. } => {
            make_with_host!(vtable, "cluster")
        }
        EntityRegistration::Transport { vtable, .. } => make_with_host!(vtable, "transport"),
        EntityRegistration::CatalogProvider { vtable, .. } => {
            make_with_host!(vtable, "catalog_provider")
        }
        EntityRegistration::CredentialIssuer { vtable, .. } => {
            make_with_host!(vtable, "credential_issuer")
        }
        EntityRegistration::ApprovalNotifier { vtable, .. } => {
            make_with_host!(vtable, "approval_notifier")
        }
        EntityRegistration::ContentStore { vtable, .. } => {
            make_with_host!(vtable, "content_store")
        }
    }
}

/// Shared tail end of `derive_manifest`'s per-vtable arms: parse the
/// `manifest_json()` payload returned by the cdylib into a
/// `PluginManifest`, mapping empty payloads (panic in `manifest()`)
/// and serde failures into actionable errors.
fn parse_manifest(json: &str, kind: &str) -> Result<PluginManifest> {
    if json.is_empty() {
        return Err(anyhow!(
            "plugin {kind}::manifest_json() returned empty — likely panicked during manifest()"
        ));
    }
    serde_json::from_str(json).with_context(|| {
        format!("plugin {kind}::manifest_json() did not return a valid PluginManifest")
    })
}

// ---------------------------------------------------------------------------
// Adapters: bridge ABI vtables onto in-tree async trait objects
// ---------------------------------------------------------------------------

/// Why a ferried Tier-1 dispatch failed — distinguishes the two fallbacks.
#[derive(Clone, Copy)]
pub(crate) enum DispatchFail {
    Panicked,
    TimedOut,
}

/// Run one Tier-1 vtable call under the chosen dispatch policy (v38).
///
/// `call_vtable` owns its captured args (`RPluginContext`, the JSON `String`s,
/// the handle, the fn pointer) and produces the typed result `R` by reborrowing
/// its owned strings as `RStr` *inside* itself — so it is `Send + 'static` and
/// works in **both** modes:
/// - **inline** (`inline_fast`, operator-trusted): call it directly — zero-copy,
///   no thread hop, no timeout (~33×). A hung plugin wedges this worker.
/// - **ferried** (default): `spawn_blocking` + per-call timeout — a hung/slow
///   plugin can't freeze the runtime. The owned strings ride into the closure.
///
/// `fail` maps a ferried failure to the slot's typed fallback (e.g. `Deny`).
/// Panics at the FFI boundary are already caught by the plugin's `catch_panic_*`
/// wrapper regardless of mode; the `Panicked` arm here covers a `spawn_blocking`
/// JoinError (which shouldn't happen given the wrapper, but fails closed).
pub(crate) async fn dispatch_tier1<R: Send + 'static>(
    inline_fast: bool,
    timeout: std::time::Duration,
    plugin_id: &str,
    metric: crate::ffi_metering::FfiCall,
    call_vtable: impl FnOnce() -> R + Send + 'static,
    fail: impl Fn(DispatchFail) -> R,
) -> R {
    if inline_fast {
        let r = call_vtable();
        metric.end_ok(0);
        return r;
    }
    match tokio::time::timeout(timeout, tokio::task::spawn_blocking(call_vtable)).await {
        Ok(Ok(r)) => {
            metric.end_ok(0);
            r
        }
        Ok(Err(e)) => {
            metric.end_err(0);
            tracing::error!(plugin_id = %plugin_id, error = %e, "native plugin slot panicked");
            fail(DispatchFail::Panicked)
        }
        Err(_) => {
            metric.end_err(0);
            tracing::error!(plugin_id = %plugin_id, "native plugin slot timed out");
            metrics::counter!("mcpg_native_plugin_timeout_total", "plugin_id" => plugin_id.to_owned())
                .increment(1);
            fail(DispatchFail::TimedOut)
        }
    }
}

/// Async-trait adapter that dispatches to a [`ToolGateVTable`] living inside
/// a dynamically-loaded cdylib.
pub struct NativeToolGateAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: ToolGateVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    /// Operator alias for this plugin entry — stable through the
    /// adapter's lifetime; surfaced to the plugin via the
    /// `HostHandleRef::alias()` slot.
    #[allow(dead_code)]
    alias: String,
    /// Fast-slot prototype (ABI v38): when set, `evaluate_pre_dispatch` calls
    /// the typed/borrowed `evaluate_pre_dispatch_fast` slot **inline** — no
    /// `spawn_blocking` ferry, no per-call timeout. This is an operator-trust
    /// decision (the plugin's gate must be fast/non-blocking/bounded), set from
    /// deployment config; defaults to `false` (the ferried path). See
    /// [`Self::set_inline_fast`].
    inline_fast: bool,
    _host_bridge: crate::host_bridge::HostBridge,
}

// Safety: the plugin's FFI surface is expected to be thread-safe
// (plugins that are not can guard with their own locks). The library
// handle is Send+Sync because libloading::Library is Send+Sync.
unsafe impl Send for NativeToolGateAdapter {}
unsafe impl Sync for NativeToolGateAdapter {}

impl NativeToolGateAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_tool_gate() {
            Some(vt) => clone_tool_gate(vt),
            None => {
                return Err(anyhow!("plugin does not export a ToolGate vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!(
                "native tool-gate plugin panicked during make (null handle returned)"
            ));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!(
                "native tool-gate plugin panicked during manifest() (empty RString returned)"
            ));
        }
        let manifest: PluginManifest = match serde_json::from_str(manifest_json.as_str()) {
            Ok(m) => m,
            Err(e) => {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                return Err(
                    anyhow::Error::from(e).context("invalid manifest from native tool-gate plugin")
                );
            }
        };
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            alias,
            inline_fast: false,
            _host_bridge: host_bridge,
        })
    }

    /// Opt this gate into **inline fast-slot dispatch** (ABI v38 prototype).
    /// The operator asserts the plugin's pre-dispatch is fast, non-blocking,
    /// and bounded; in exchange the host drops the `spawn_blocking` ferry +
    /// per-call timeout (the ~30 µs cost) and calls the typed/borrowed
    /// `evaluate_pre_dispatch_fast` slot directly. A misbehaving plugin would
    /// then block a runtime worker with no backstop — hence the explicit
    /// operator opt-in.
    pub fn set_inline_fast(&mut self, enabled: bool) {
        self.inline_fast = enabled;
    }
}

impl Drop for NativeToolGateAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        // Library unloads when the last Arc is dropped; keep `library`
        // alive at least until our handle is released.
        let _ = &self.library;
    }
}

#[async_trait]
impl ToolGatePlugin for NativeToolGateAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn evaluate_pre_dispatch(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        meta: Option<&serde_json::Value>,
        config: &serde_json::Value,
    ) -> GateDecision {
        // One slot, two dispatch policies (v38): the host serialises args/meta/
        // config to owned `String`s, then `dispatch_tier1` either calls inline
        // (zero-copy reborrow) or ferries (spawn_blocking + timeout, strings
        // owned in the closure). See `dispatch_tier1`.
        let r_ctx: RPluginContext = ctx.into();
        let args_str = serde_json::to_string(arguments).unwrap_or_else(|_| "null".into());
        let meta_str = meta.map(|v| serde_json::to_string(v).unwrap_or_else(|_| "null".into()));
        let cfg_str = serde_json::to_string(config).unwrap_or_else(|_| "{}".into());
        let req_bytes =
            args_str.len() + meta_str.as_deref().map(str::len).unwrap_or(0) + cfg_str.len();
        let metric = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "tool_gate",
            "evaluate_pre_dispatch",
            req_bytes,
        );
        let vtable_fn = self.vtable.evaluate_pre_dispatch;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        dispatch_tier1(
            self.inline_fast,
            self.library.ffi_limits.data_timeout,
            &self.manifest.id,
            metric,
            move || -> GateDecision {
                let args = abi_stable::std_types::RStr::from(args_str.as_str());
                let meta_r: abi_stable::std_types::ROption<abi_stable::std_types::RStr> = meta_str
                    .as_deref()
                    .map(abi_stable::std_types::RStr::from)
                    .into();
                let cfg = abi_stable::std_types::RStr::from(cfg_str.as_str());
                vtable_fn(handle.ptr(), r_ctx, args, meta_r, cfg).into()
            },
            move |f| GateDecision::Deny {
                http_status: match f {
                    DispatchFail::TimedOut => 504,
                    DispatchFail::Panicked => 500,
                },
                code: -32603,
                message: match f {
                    DispatchFail::TimedOut => format!("native plugin '{plugin_id}' timed out"),
                    DispatchFail::Panicked => format!("native plugin '{plugin_id}' panicked"),
                },
                error_data: None,
            },
        )
        .await
    }

    async fn evaluate_post_dispatch(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        result: &serde_json::Value,
        execution_duration_ms: u64,
        config: &serde_json::Value,
    ) -> GateDecision {
        let r_ctx: RPluginContext = ctx.into();
        let args_str = serde_json::to_string(arguments).unwrap_or_else(|_| "null".into());
        let res_str = serde_json::to_string(result).unwrap_or_else(|_| "null".into());
        let cfg_str = serde_json::to_string(config).unwrap_or_else(|_| "{}".into());
        let req_bytes = args_str.len() + res_str.len() + cfg_str.len();
        let metric = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "tool_gate",
            "evaluate_post_dispatch",
            req_bytes,
        );
        let vtable_fn = self.vtable.evaluate_post_dispatch;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        let dur = execution_duration_ms;
        dispatch_tier1(
            self.inline_fast,
            self.library.ffi_limits.data_timeout,
            &self.manifest.id,
            metric,
            move || -> GateDecision {
                let args = abi_stable::std_types::RStr::from(args_str.as_str());
                let res = abi_stable::std_types::RStr::from(res_str.as_str());
                let cfg = abi_stable::std_types::RStr::from(cfg_str.as_str());
                vtable_fn(handle.ptr(), r_ctx, args, res, dur, cfg).into()
            },
            move |f| GateDecision::Deny {
                http_status: match f {
                    DispatchFail::TimedOut => 504,
                    DispatchFail::Panicked => 500,
                },
                code: -32603,
                message: match f {
                    DispatchFail::TimedOut => format!("native plugin '{plugin_id}' timed out"),
                    DispatchFail::Panicked => format!("native plugin '{plugin_id}' panicked"),
                },
                error_data: None,
            },
        )
        .await
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

/// Async-trait adapter that dispatches to a [`TransformVTable`].
pub struct NativeTransformAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: TransformVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    #[allow(dead_code)]
    alias: String,
    /// Fast-slot prototype (v38): inline + typed/borrowed transforms. Operator
    /// trust opt-in; default false. See [`NativeToolGateAdapter::set_inline_fast`].
    inline_fast: bool,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeTransformAdapter {}
unsafe impl Sync for NativeTransformAdapter {}

impl NativeTransformAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_transform() {
            Some(vt) => clone_transform(vt),
            None => {
                return Err(anyhow!("plugin does not export a Transform vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!(
                "native transform plugin panicked during make (null handle returned)"
            ));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!(
                "native transform plugin panicked during manifest() (empty RString returned)"
            ));
        }
        let manifest: PluginManifest = match serde_json::from_str(manifest_json.as_str()) {
            Ok(m) => m,
            Err(e) => {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                return Err(
                    anyhow::Error::from(e).context("invalid manifest from native transform plugin")
                );
            }
        };
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            alias,
            inline_fast: false,
            _host_bridge: host_bridge,
        })
    }

    /// Opt this transform into inline fast-slot dispatch (v38). See
    /// [`NativeToolGateAdapter::set_inline_fast`] for the trust contract.
    pub fn set_inline_fast(&mut self, enabled: bool) {
        self.inline_fast = enabled;
    }
}

impl Drop for NativeTransformAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

#[async_trait]
impl TransformPlugin for NativeTransformAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn transform_arguments(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        config: &serde_json::Value,
    ) -> TransformResult {
        let r_ctx: RPluginContext = ctx.into();
        let args_str = serde_json::to_string(arguments).unwrap_or_else(|_| "null".into());
        let cfg_str = serde_json::to_string(config).unwrap_or_else(|_| "{}".into());
        let req_bytes = args_str.len() + cfg_str.len();
        let metric = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "transform",
            "transform_arguments",
            req_bytes,
        );
        let vtable_fn = self.vtable.transform_arguments;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        dispatch_tier1(
            self.inline_fast,
            self.library.ffi_limits.data_timeout,
            &self.manifest.id,
            metric,
            move || -> TransformResult {
                let args = abi_stable::std_types::RStr::from(args_str.as_str());
                let cfg = abi_stable::std_types::RStr::from(cfg_str.as_str());
                vtable_fn(handle.ptr(), r_ctx, args, cfg).into()
            },
            move |f| TransformResult::Error {
                message: match f {
                    DispatchFail::TimedOut => format!("native transform '{plugin_id}' timed out"),
                    DispatchFail::Panicked => format!("native transform '{plugin_id}' panicked"),
                },
            },
        )
        .await
    }

    async fn transform_result(
        &self,
        ctx: &PluginContext,
        result: &serde_json::Value,
        config: &serde_json::Value,
    ) -> TransformResult {
        let r_ctx: RPluginContext = ctx.into();
        let res_str = serde_json::to_string(result).unwrap_or_else(|_| "null".into());
        let cfg_str = serde_json::to_string(config).unwrap_or_else(|_| "{}".into());
        let req_bytes = res_str.len() + cfg_str.len();
        let metric = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "transform",
            "transform_result",
            req_bytes,
        );
        let vtable_fn = self.vtable.transform_result;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        dispatch_tier1(
            self.inline_fast,
            self.library.ffi_limits.data_timeout,
            &self.manifest.id,
            metric,
            move || -> TransformResult {
                let res = abi_stable::std_types::RStr::from(res_str.as_str());
                let cfg = abi_stable::std_types::RStr::from(cfg_str.as_str());
                vtable_fn(handle.ptr(), r_ctx, res, cfg).into()
            },
            move |f| TransformResult::Error {
                message: match f {
                    DispatchFail::TimedOut => format!("native transform '{plugin_id}' timed out"),
                    DispatchFail::Panicked => format!("native transform '{plugin_id}' panicked"),
                },
            },
        )
        .await
    }

    /// Forwards to the cdylib's `TransformVTable::shutdown` function pointer.
    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

/// Async-trait adapter that dispatches to an [`IdentityProviderVTable`].
pub struct NativeIdentityProviderAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: IdentityProviderVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    #[allow(dead_code)]
    alias: String,
    /// Fast-slot prototype (v38): typed/borrowed identity resolution. Already
    /// inline (no ferry), so this is a marshaling win only. Opt-in; default off.
    inline_fast: bool,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeIdentityProviderAdapter {}
unsafe impl Sync for NativeIdentityProviderAdapter {}

impl NativeIdentityProviderAdapter {
    /// Construct an Identity adapter. The optional `cluster` ref
    /// points at the host's registered `cluster` plugin; when
    /// present, identity plugins (workload, …) opt into shared
    /// state via [`HostHandleRef::cluster()`]. The cluster ref is
    /// folded into the
    /// [`HostBridge`](crate::host_bridge::HostBridge) and surfaced
    /// to the plugin through the host vtable; the make slot itself
    /// does not take a separate cluster arg.
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
        cluster: Option<mcpg_plugin_protocol::abi::ClusterClientRef>,
    ) -> Result<Self> {
        let vt = match library.registration.first_identity_provider() {
            Some(vt) => clone_identity(vt),
            None => {
                return Err(anyhow!("plugin does not export an Identity vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(cluster, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!(
                "native identity plugin panicked during make (null handle returned)"
            ));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!(
                "native identity plugin panicked during manifest() (empty RString returned)"
            ));
        }
        let manifest: PluginManifest = match serde_json::from_str(manifest_json.as_str()) {
            Ok(m) => m,
            Err(e) => {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                return Err(
                    anyhow::Error::from(e).context("invalid manifest from native identity plugin")
                );
            }
        };
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            alias,
            inline_fast: false,
            _host_bridge: host_bridge,
        })
    }

    /// Opt this identity provider into the typed/borrowed fast slot (v38).
    /// (Already inline, so this is a marshaling win only — and identity
    /// providers doing network JWKS/OIDC work should NOT be opted in.)
    pub fn set_inline_fast(&mut self, enabled: bool) {
        self.inline_fast = enabled;
    }
}

impl Drop for NativeIdentityProviderAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

#[async_trait]
impl IdentityProviderPlugin for NativeIdentityProviderAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn resolve_identity(
        &self,
        headers: &[(String, String)],
        metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        config: &serde_json::Value,
    ) -> IdentityResolution {
        let headers_json: serde_json::Value = serde_json::Value::Array(
            headers
                .iter()
                .map(|(k, v)| {
                    serde_json::Value::Array(vec![
                        serde_json::Value::String(k.clone()),
                        serde_json::Value::String(v.clone()),
                    ])
                })
                .collect(),
        );
        let h_str = serde_json::to_string(&headers_json).unwrap_or_else(|_| "[]".into());
        let m_str = serde_json::to_string(metadata).unwrap_or_else(|_| "{}".into());
        let cfg_str = serde_json::to_string(config).unwrap_or_else(|_| "{}".into());
        let req_bytes = h_str.len() + m_str.len() + cfg_str.len();
        let metric = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "identity_provider",
            "resolve_identity",
            req_bytes,
        );
        let vtable_fn = self.vtable.resolve_identity;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        dispatch_tier1(
            self.inline_fast,
            self.library.ffi_limits.data_timeout,
            &self.manifest.id,
            metric,
            move || -> IdentityResolution {
                let h = abi_stable::std_types::RStr::from(h_str.as_str());
                let m = abi_stable::std_types::RStr::from(m_str.as_str());
                let cfg = abi_stable::std_types::RStr::from(cfg_str.as_str());
                vtable_fn(handle.ptr(), h, m, cfg).into()
            },
            // Fail closed: a timed-out / panicked resolver yields no identity.
            move |f| IdentityResolution::Invalid {
                reason: match f {
                    DispatchFail::TimedOut => format!("native identity '{plugin_id}' timed out"),
                    DispatchFail::Panicked => format!("native identity '{plugin_id}' panicked"),
                },
                response_headers: Vec::new(),
            },
        )
        .await
    }
}

// Plain-old-data copies. The vtable is repr(C) + StableAbi, so this is
// just a memcpy of function pointers — ABI Clone/Copy is not required.
fn clone_tool_gate(vt: &ToolGateVTable) -> ToolGateVTable {
    ToolGateVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        evaluate_pre_dispatch: vt.evaluate_pre_dispatch,
        evaluate_post_dispatch: vt.evaluate_post_dispatch,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

fn clone_transform(vt: &TransformVTable) -> TransformVTable {
    TransformVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        transform_arguments: vt.transform_arguments,
        transform_result: vt.transform_result,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

fn clone_identity(vt: &IdentityProviderVTable) -> IdentityProviderVTable {
    IdentityProviderVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        resolve_identity: vt.resolve_identity,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

fn clone_backend(vt: &BackendVTable) -> BackendVTable {
    BackendVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        kind: vt.kind,
        register_profile: vt.register_profile,
        execute: vt.execute,
        execute_streaming: vt.execute_streaming,
        cancel_stream: vt.cancel_stream,
        execute_transaction: vt.execute_transaction,
        input_schema_json: vt.input_schema_json,
        output_schema_json: vt.output_schema_json,
        complete_template_variable: vt.complete_template_variable,
        list_resources: vt.list_resources,
        audit_metadata: vt.audit_metadata,
        expand_capabilities: vt.expand_capabilities,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

fn clone_watch_strategy(vt: &WatchStrategyVTable) -> WatchStrategyVTable {
    WatchStrategyVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        kind: vt.kind,
        watch: vt.watch,
        cancel: vt.cancel,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

fn clone_content_store(vt: &ContentStoreVTable) -> ContentStoreVTable {
    ContentStoreVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        kind: vt.kind,
        register_profile: vt.register_profile,
        put: vt.put,
        get: vt.get,
        delete: vt.delete,
        signed_url: vt.signed_url,
        stats: vt.stats,
        sweep_expired: vt.sweep_expired,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

// ---------------------------------------------------------------------------
// content_store adapter (factory + per-profile handle)
// ---------------------------------------------------------------------------

/// Owns the loaded cdylib's `content_store` instance handle. Shared
/// (`Arc`) between the [`NativeContentStorePlugin`] factory and every
/// [`NativeContentStoreProfile`] it hands out, so the cdylib `make`
/// instance lives until the factory AND all profiles drop — at which
/// point `shutdown` + `drop_instance` fire exactly once.
struct NativeContentStoreInstance {
    library: Arc<LoadedNativePlugin>,
    vtable: ContentStoreVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    kind: String,
    _host_bridge: crate::host_bridge::HostBridge,
}

// SAFETY: same contract as the other native adapters — the cdylib's
// instance is internally synchronised; the host serialises lifecycle.
unsafe impl Send for NativeContentStoreInstance {}
unsafe impl Sync for NativeContentStoreInstance {}

impl NativeContentStoreInstance {
    /// Invoke an enveloped vtable slot: serialise `args`, call the fn,
    /// meter the boundary, enforce the payload cap, and decode the
    /// `{"ok"|"err"}` envelope into `Result<T, ContentStoreError>`.
    fn call_enveloped<T: serde::de::DeserializeOwned>(
        &self,
        slot: &'static str,
        vtable_fn: extern "C" fn(
            RPluginHandle,
            abi_stable::std_types::RString,
        ) -> abi_stable::std_types::RString,
        args: serde_json::Value,
    ) -> Result<T, ContentStoreError> {
        let args_json = serde_json::to_string(&args).unwrap_or_default();
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "content_store",
            slot,
            args_json.len(),
        );
        // Off the async worker, under the data timeout, with a panic
        // backstop: every caller is an `async fn` whose body is this one
        // blocking FFI call, so it never yields and a slow or hung store
        // would pin a tokio worker uncancellably.
        let handle = SendHandle::new(self.handle);
        let payload = abi_stable::std_types::RString::from(args_json);
        let out = call_sync_vtable_bounded(
            self.library.ffi_limits.data_timeout,
            move || vtable_fn(handle.ptr(), payload),
            abi_stable::std_types::RString::new,
        );
        let resp_bytes = out.len();
        if out.is_empty() {
            call.end_err(0);
            return Err(ContentStoreError::Storage {
                message: format!(
                    "content_store plugin returned no {slot} response \
                     (panicked, or exceeded the host data timeout)"
                ),
            });
        }
        if let Err(actual) = enforce_ffi_payload_cap(
            &out,
            &self.manifest.id,
            slot,
            self.library.ffi_limits.max_payload_bytes,
        ) {
            call.end_err(resp_bytes);
            return Err(ContentStoreError::Storage {
                message: format!(
                    "content_store plugin returned an FFI payload of {actual} bytes \
                     exceeding the host cap"
                ),
            });
        }
        match mcpg_plugin_protocol::result_envelope::decode_result_envelope::<T, ContentStoreError>(
            out.as_str(),
        ) {
            Ok(Ok(v)) => {
                call.end_ok(resp_bytes);
                Ok(v)
            }
            Ok(Err(e)) => {
                call.end_err(resp_bytes);
                Err(e)
            }
            Err(e) => {
                call.end_err(resp_bytes);
                Err(ContentStoreError::Storage {
                    message: format!(
                        "content_store plugin returned undecodable {slot} envelope: {e}"
                    ),
                })
            }
        }
    }

    /// Invoke a bare-JSON vtable slot (`stats` / `sweep_expired`): the
    /// plugin returns the value directly (no envelope). A malformed /
    /// panicked payload degrades to `T::default()`.
    fn call_bare<T: serde::de::DeserializeOwned + Default>(
        &self,
        vtable_fn: extern "C" fn(
            RPluginHandle,
            abi_stable::std_types::RString,
        ) -> abi_stable::std_types::RString,
        args: serde_json::Value,
    ) -> T {
        let args_json = serde_json::to_string(&args).unwrap_or_default();
        // Bounded like `call_enveloped`; a failed call degrades to
        // `T::default()`, which is already this slot's contract.
        let handle = SendHandle::new(self.handle);
        let payload = abi_stable::std_types::RString::from(args_json);
        let out = call_sync_vtable_bounded(
            self.library.ffi_limits.data_timeout,
            move || vtable_fn(handle.ptr(), payload),
            abi_stable::std_types::RString::new,
        );
        serde_json::from_str(out.as_str()).unwrap_or_default()
    }
}

impl Drop for NativeContentStoreInstance {
    fn drop(&mut self) {
        // Graceful FFI teardown: flush via `shutdown`, then reclaim the
        // boxed instance. Fires once, when the factory and all profiles
        // have been dropped (Arc refcount → 0).
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

/// Adapter implementing the [`ContentStorePlugin`] factory over a loaded
/// cdylib's [`ContentStoreVTable`]. `build_profile` registers the profile
/// inside the cdylib then returns a [`NativeContentStoreProfile`] bound to
/// that profile name.
pub struct NativeContentStorePlugin {
    inner: Arc<NativeContentStoreInstance>,
}

impl std::fmt::Debug for NativeContentStorePlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeContentStorePlugin")
            .field("kind", &self.inner.kind)
            .field("id", &self.inner.manifest.id)
            .finish()
    }
}

impl NativeContentStorePlugin {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_content_store() {
            Some(vt) => clone_content_store(vt),
            None => return Err(anyhow!("plugin does not export a ContentStore vtable")),
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!(
                "native content_store plugin panicked during make (null handle)"
            ));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        let manifest: PluginManifest = match parse_manifest(manifest_json.as_str(), "content_store")
        {
            Ok(m) => m,
            Err(e) => {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                return Err(e);
            }
        };
        let kind = guard_ffi_rstring("kind", || (vt.kind)(handle))
            .as_str()
            .to_owned();
        if kind.is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!("native content_store plugin returned empty kind()"));
        }
        Ok(Self {
            inner: Arc::new(NativeContentStoreInstance {
                library,
                vtable: vt,
                handle,
                manifest,
                kind,
                _host_bridge: host_bridge,
            }),
        })
    }
}

#[async_trait]
impl ContentStorePlugin for NativeContentStorePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn kind(&self) -> &str {
        &self.inner.kind
    }

    async fn build_profile(
        &self,
        profile_name: &str,
        spec: &serde_json::Value,
    ) -> Result<Arc<dyn ContentStore>, ContentStoreError> {
        self.inner.call_enveloped::<()>(
            "register_profile",
            self.inner.vtable.register_profile,
            serde_json::json!({ "profile_name": profile_name, "spec": spec }),
        )?;
        Ok(Arc::new(NativeContentStoreProfile {
            inner: Arc::clone(&self.inner),
            profile_name: profile_name.to_owned(),
        }))
    }
}

/// A single-profile [`ContentStore`] handle over the shared cdylib
/// instance — re-attaches its `profile_name` to every vtable call.
struct NativeContentStoreProfile {
    inner: Arc<NativeContentStoreInstance>,
    profile_name: String,
}

impl std::fmt::Debug for NativeContentStoreProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeContentStoreProfile")
            .field("kind", &self.inner.kind)
            .field("profile_name", &self.profile_name)
            .finish()
    }
}

#[async_trait]
impl ContentStore for NativeContentStoreProfile {
    async fn put(&self, content: ContentToStore) -> Result<ResourceHandle, ContentStoreError> {
        self.inner.call_enveloped::<ResourceHandle>(
            "put",
            self.inner.vtable.put,
            serde_json::json!({ "profile_name": self.profile_name, "content": content }),
        )
    }

    async fn get(&self, id: &str) -> Result<Option<ResourceContent>, ContentStoreError> {
        self.inner.call_enveloped::<Option<ResourceContent>>(
            "get",
            self.inner.vtable.get,
            serde_json::json!({ "profile_name": self.profile_name, "id": id }),
        )
    }

    async fn delete(&self, id: &str) -> Result<(), ContentStoreError> {
        self.inner.call_enveloped::<()>(
            "delete",
            self.inner.vtable.delete,
            serde_json::json!({ "profile_name": self.profile_name, "id": id }),
        )
    }

    async fn signed_url(
        &self,
        id: &str,
        ttl: std::time::Duration,
    ) -> Result<Option<String>, ContentStoreError> {
        self.inner.call_enveloped::<Option<String>>(
            "signed_url",
            self.inner.vtable.signed_url,
            serde_json::json!({
                "profile_name": self.profile_name,
                "id": id,
                "ttl_seconds": ttl.as_secs(),
            }),
        )
    }

    fn stats(&self) -> ContentStoreStats {
        self.inner.call_bare::<ContentStoreStats>(
            self.inner.vtable.stats,
            serde_json::json!({ "profile_name": self.profile_name }),
        )
    }

    async fn sweep_expired(&self) -> usize {
        self.inner.call_bare::<usize>(
            self.inner.vtable.sweep_expired,
            serde_json::json!({ "profile_name": self.profile_name }),
        )
    }

    // The cdylib instance's `shutdown` slot is fired once on
    // `NativeContentStoreInstance::drop` (when the factory + all profiles
    // release their `Arc`), so the per-profile hook is a no-op to avoid
    // shutting the shared manager down while sibling profiles are live.
    async fn shutdown(&self) {}
}

// ---------------------------------------------------------------------------
// Backend adapter
// ---------------------------------------------------------------------------

/// Adapter that implements [`BackendPlugin`] over a loaded cdylib's
/// [`BackendVTable`]. JSON-marshalled payloads — every non-trivial type
/// is serde-encoded across the FFI boundary (JSON is preferred over
/// abi_stable mirror types here to keep the wire format stable).
pub struct NativeBackendAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: BackendVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    kind: String,
    #[allow(dead_code)]
    alias: String,
    /// Fast-slot dispatch (operator-trusted): when set, `execute` calls the
    /// synchronous vtable slot **inline** on the caller's task — no
    /// `spawn_blocking` ferry and no per-call `timeout`. For an in-process
    /// backend the ferry + timer are pure overhead, so this lets the sync
    /// dispatch path resolve the future on its first poll and skip
    /// `block_in_place` entirely. It is an operator-trust decision (the
    /// backend must be fast / non-blocking / bounded — a hung backend wedges
    /// this worker); set from deployment config, defaults to `false` (the
    /// ferried path). Mirrors [`NativeToolGateAdapter::set_inline_fast`].
    inline_fast: bool,
    host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeBackendAdapter {}
unsafe impl Sync for NativeBackendAdapter {}

impl NativeBackendAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_backend() {
            Some(vt) => clone_backend(vt),
            None => {
                return Err(anyhow!("plugin does not export a Backend vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!(
                "native backend plugin panicked during make (null handle)"
            ));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!(
                "native backend plugin returned empty manifest JSON"
            ));
        }
        let manifest: PluginManifest =
            serde_json::from_str(manifest_json.as_str()).map_err(|e| {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                anyhow::Error::from(e).context("invalid manifest from native backend plugin")
            })?;
        let kind = guard_ffi_rstring("kind", || (vt.kind)(handle))
            .as_str()
            .to_owned();
        if kind.is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!("native backend plugin returned empty kind()"));
        }
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            kind,
            alias,
            inline_fast: false,
            host_bridge,
        })
    }

    /// Enable inline fast-slot dispatch for `execute`. See the
    /// [`inline_fast`](Self::inline_fast) field for the trust contract.
    pub fn set_inline_fast(&mut self, enabled: bool) {
        self.inline_fast = enabled;
    }
}

impl Drop for NativeBackendAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

#[async_trait]
impl BackendPlugin for NativeBackendAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        &self.kind
    }

    async fn register_profile(
        &self,
        backend_name: &str,
        spec: &serde_json::Value,
        _host: std::sync::Arc<dyn mcpg_plugin_protocol::BackendHost>,
    ) -> Result<(), BackendError> {
        // The C-FFI vtable for cdylib plugins (`BackendVTable::register_profile`
        // in plugin-protocol/src/abi.rs) does not currently propagate
        // `BackendHost` — extending it requires designing a callback-table FFI
        // for the host's async methods, which is a separate vtable revision.
        // For the present trait extension cdylib plugins discard the host
        // argument; if a cdylib binding ever needs host capability the FFI
        // surface will be revised later. First-party static
        // bindings (the LLM generator binding etc.) receive the host directly
        // through the Rust trait.
        let spec_json = serde_json::to_string(spec).unwrap_or_default();
        let req_bytes = backend_name.len() + spec_json.len();
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "backend",
            "register_profile",
            req_bytes,
        );
        // Bounded like the other backend slots: an empty return already
        // decodes to a transport-class error below, so a panic or timeout
        // surfaces as a failed registration rather than a wedged worker.
        let vtable_fn = self.vtable.register_profile;
        let handle = SendHandle(self.handle);
        let name = abi_stable::std_types::RString::from(backend_name);
        let spec_arg = abi_stable::std_types::RString::from(spec_json);
        let out = call_sync_vtable_bounded(
            self.library.ffi_limits.data_timeout,
            move || vtable_fn(handle.ptr(), name, spec_arg),
            abi_stable::std_types::RString::new,
        );
        let resp_bytes = out.len();
        // Result envelope: `{"ok": null}` = success,
        // `{"err": BackendError}` = failure, any other shape
        // (empty / panicked / malformed) is transport-class.
        match mcpg_plugin_protocol::result_envelope::decode_result_envelope::<(), BackendError>(
            out.as_str(),
        ) {
            Ok(Ok(())) => {
                call.end_ok(resp_bytes);
                Ok(())
            }
            Ok(Err(e)) => {
                call.end_err(resp_bytes);
                Err(e)
            }
            Err(e) => {
                call.end_err(resp_bytes);
                Err(BackendError::Transport {
                    message: format!(
                        "binding plugin returned undecodable register_profile envelope: {e}"
                    ),
                })
            }
        }
    }

    async fn execute(
        &self,
        backend_name: &str,
        mut request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        // Stamp the host integrity tag on the caller identity before it
        // crosses the FFI, bound to this plugin's alias and to this dispatch.
        // When the plugin relays the identity back through a host callback
        // (resolve_credentials / invoke_tool), the host verifies the tag — a
        // plugin cannot forge or mutate the principal it was handed. The guard
        // lives to the end of this call, so the tag dies with the dispatch and
        // a banked identity is useless afterwards.
        let _dispatch = request
            .identity
            .as_mut()
            .map(|id| self.host_bridge.begin_dispatch(id));
        // Measure host→plugin call duration + payload sizes.
        // Start the clock BEFORE the request encode: `request.payload` is a
        // `Vec<u8>` that serialises as a JSON number-array, so for large
        // payloads the encode is a real chunk of the FFI boundary cost (the
        // `ffi_matrix` payload-scaling bench shows ms-scale at 32 KiB). The
        // span therefore covers encode → vtable → decode; response size is the
        // RString the plugin returns.
        let call =
            crate::ffi_metering::FfiCall::begin_no_request(&self.manifest.id, "backend", "execute");
        let req_json = serde_json::to_string(&request).unwrap_or_default();
        call.record_request(req_json.len());
        // Run the synchronous vtable call off the async worker under the
        // per-plugin data timeout, so a slow / hung / panicking backend
        // cannot pin a tokio worker indefinitely (matching http_route /
        // notify / execute_streaming).
        let vtable_fn = self.vtable.execute;
        let handle = SendHandle(self.handle);
        let name = abi_stable::std_types::RString::from(backend_name);
        let req = abi_stable::std_types::RString::from(req_json);
        let out = if self.inline_fast {
            // Operator-trusted inline path: run the synchronous vtable call
            // directly on this task — no thread hop, no timeout. A plugin
            // panic is still caught by the plugin's own FFI `catch_panic`
            // wrapper (it returns an error-encoded payload rather than
            // unwinding); a hung/blocking backend wedges this worker (the
            // trust contract). This resolves on the first poll, letting the
            // sync dispatch bridge skip `block_in_place`.
            vtable_fn(handle.ptr(), name, req)
        } else {
            // Run the synchronous vtable call off the async worker under the
            // per-plugin data timeout, so a slow / hung / panicking backend
            // cannot pin a tokio worker indefinitely (matching http_route /
            // notify / execute_streaming).
            let data_timeout = self.library.ffi_limits.data_timeout;
            match tokio::time::timeout(
                data_timeout,
                tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), name, req)),
            )
            .await
            {
                Ok(Ok(out)) => out,
                Ok(Err(_join)) => {
                    call.end_err(0);
                    return Err(BackendError::Transport {
                        message: format!(
                            "native plugin '{}' panicked during execute",
                            self.manifest.id
                        ),
                    });
                }
                Err(_elapsed) => {
                    call.end_err(0);
                    metrics::counter!(
                        "mcpg_native_plugin_timeout_total",
                        "plugin_id" => self.manifest.id.clone(),
                    )
                    .increment(1);
                    return Err(BackendError::Timeout {
                        timeout_ms: data_timeout.as_millis().min(u64::MAX as u128) as u64,
                    });
                }
            }
        };
        let resp_bytes = out.len();
        if let Err(actual_bytes) = enforce_ffi_payload_cap(
            &out,
            &self.manifest.id,
            "backend.execute",
            self.library.ffi_limits.max_payload_bytes,
        ) {
            call.end_err(resp_bytes);
            return Err(BackendError::Transport {
                message: format!(
                    "backend plugin returned an FFI payload of {} bytes exceeding the host cap of {} bytes",
                    actual_bytes,
                    mcpg_plugin_protocol::abi::FFI_MAX_PAYLOAD_BYTES,
                ),
            });
        }
        // Wire form: JSON-encoded `Result<BackendResponse,
        // BackendError>` using the `{"ok": ..., "err": ...}`
        // convention. We serde-decode into an internal enum.
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Ok { ok: BackendResponse },
            Err { err: BackendError },
        }
        match serde_json::from_str::<Wire>(out.as_str()) {
            Ok(Wire::Ok { ok }) => {
                call.end_ok(resp_bytes);
                Ok(ok)
            }
            Ok(Wire::Err { err }) => {
                call.end_err(resp_bytes);
                Err(err)
            }
            Err(e) => {
                call.end_err(resp_bytes);
                Err(BackendError::Transport {
                    message: format!("binding plugin returned undecodable response: {e}"),
                })
            }
        }
    }

    async fn execute_streaming(
        &self,
        backend_name: &str,
        mut request: BackendRequest,
    ) -> Result<BackendChunkStream, BackendError> {
        // v34 (backend-plugin-migration): bridge the cdylib's
        // `EventSinkRef`-driven chunk stream into a `BackendChunkStream`.
        // Mirrors the watch / store-watch streaming adapters: an mpsc
        // bridge backs the sink; the plugin pushes one result-envelope
        // JSON per chunk; the returned stream decodes each + the cancel
        // guard tears down on drop.
        // Host integrity tag on the relayed caller identity (see `execute`).
        // A stream may legitimately relay the identity for as long as it runs,
        // so the guard rides on the returned stream and retires the tag at
        // teardown rather than when this function returns.
        let dispatch = request
            .identity
            .as_mut()
            .map(|id| self.host_bridge.begin_dispatch(id));
        let (bridge_ptr_raw, sink, rx) = make_stream_bridge(&self.manifest.id);
        let bridge_ptr = SendPtr(bridge_ptr_raw);
        let req_json = abi_stable::std_types::RString::from(
            serde_json::to_string(&request).unwrap_or_default(),
        );
        let name = abi_stable::std_types::RString::from(backend_name);
        let vtable_fn = self.vtable.execute_streaming;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        let spawn_result =
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), name, req_json, sink))
                .await;
        let result = match spawn_result {
            Ok(r) => r,
            Err(_) => {
                // SAFETY: bridge_ptr came from `Box::into_raw` in
                // `make_stream_bridge` and has not been freed; the plugin
                // panicked before installing a callback pointer.
                unsafe {
                    drop(Box::from_raw(bridge_ptr.0));
                }
                return Err(BackendError::Transport {
                    message: format!(
                        "native plugin '{plugin_id}' panicked during execute_streaming"
                    ),
                });
            }
        };
        if result.handle == 0 {
            // SAFETY: same as above — plugin declined to start the stream.
            unsafe {
                drop(Box::from_raw(bridge_ptr.0));
            }
            let err = serde_json::from_str::<BackendError>(result.error_json.as_str())
                .unwrap_or_else(|_| BackendError::Transport {
                    message: format!(
                        "native plugin '{plugin_id}' returned undecodable execute_streaming error"
                    ),
                });
            return Err(err);
        }
        let guard = StreamCancelGuard {
            library: Arc::clone(&self.library),
            cancel_fn: self.vtable.cancel_stream,
            plugin_handle: self.handle,
            watch_handle: result.handle,
            bridge_ptr: bridge_ptr.0,
        };
        Ok(Box::pin(BackendChunkWireStream {
            rx,
            _guard: guard,
            _dispatch: dispatch,
        }))
    }

    async fn execute_transaction(
        &self,
        backend_name: &str,
        tx_group: &serde_json::Value,
    ) -> Result<serde_json::Value, BackendError> {
        // v35: atomic transaction group — single JSON round-trip (the
        // plugin owns begin/per-step/commit-or-rollback).
        let tx_json = serde_json::to_string(tx_group).unwrap_or_default();
        let req_bytes = backend_name.len() + tx_json.len();
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "backend",
            "execute_transaction",
            req_bytes,
        );
        // Bound the synchronous vtable call under the per-plugin data timeout
        // (matching `execute`): an atomic transaction group is load-bearing, so
        // a slow / hung / panicking backend must surface as an error rather than
        // pin a tokio worker indefinitely.
        let vtable_fn = self.vtable.execute_transaction;
        let handle = SendHandle(self.handle);
        let name = abi_stable::std_types::RString::from(backend_name);
        let tx = abi_stable::std_types::RString::from(tx_json);
        let out = if self.inline_fast {
            vtable_fn(handle.ptr(), name, tx)
        } else {
            let data_timeout = self.library.ffi_limits.data_timeout;
            match tokio::time::timeout(
                data_timeout,
                tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), name, tx)),
            )
            .await
            {
                Ok(Ok(out)) => out,
                Ok(Err(_join)) => {
                    call.end_err(0);
                    return Err(BackendError::Transport {
                        message: format!(
                            "native plugin '{}' panicked during execute_transaction",
                            self.manifest.id
                        ),
                    });
                }
                Err(_elapsed) => {
                    call.end_err(0);
                    metrics::counter!(
                        "mcpg_native_plugin_timeout_total",
                        "plugin_id" => self.manifest.id.clone(),
                    )
                    .increment(1);
                    return Err(BackendError::Timeout {
                        timeout_ms: data_timeout.as_millis().min(u64::MAX as u128) as u64,
                    });
                }
            }
        };
        let resp_bytes = out.len();
        if let Err(actual_bytes) = enforce_ffi_payload_cap(
            &out,
            &self.manifest.id,
            "backend.execute_transaction",
            self.library.ffi_limits.max_payload_bytes,
        ) {
            call.end_err(resp_bytes);
            return Err(BackendError::Transport {
                message: format!(
                    "backend plugin returned an FFI payload of {} bytes exceeding the host cap of {} bytes",
                    actual_bytes,
                    mcpg_plugin_protocol::abi::FFI_MAX_PAYLOAD_BYTES,
                ),
            });
        }
        match mcpg_plugin_protocol::result_envelope::decode_result_envelope::<
            serde_json::Value,
            BackendError,
        >(out.as_str())
        {
            Ok(Ok(v)) => {
                call.end_ok(resp_bytes);
                Ok(v)
            }
            Ok(Err(e)) => {
                call.end_err(resp_bytes);
                Err(e)
            }
            Err(e) => {
                call.end_err(resp_bytes);
                Err(BackendError::Transport {
                    message: format!(
                        "binding plugin returned undecodable execute_transaction envelope: {e}"
                    ),
                })
            }
        }
    }

    fn input_schema(&self, backend_name: &str) -> Option<serde_json::Value> {
        let vtable_fn = self.vtable.input_schema_json;
        let handle = SendHandle(self.handle);
        let name = abi_stable::std_types::RString::from(backend_name);
        let out = call_sync_vtable_bounded(
            self.library.ffi_limits.data_timeout,
            move || vtable_fn(handle.ptr(), name),
            || abi_stable::std_types::ROption::RNone,
        );
        match out.into_option() {
            Some(s) => {
                if enforce_ffi_payload_cap(
                    &s,
                    &self.manifest.id,
                    "backend.input_schema",
                    self.library.ffi_limits.max_payload_bytes,
                )
                .is_err()
                {
                    return None;
                }
                serde_json::from_str(s.as_str()).ok()
            }
            None => None,
        }
    }

    fn output_schema(&self, backend_name: &str) -> Option<serde_json::Value> {
        let vtable_fn = self.vtable.output_schema_json;
        let handle = SendHandle(self.handle);
        let name = abi_stable::std_types::RString::from(backend_name);
        let out = call_sync_vtable_bounded(
            self.library.ffi_limits.data_timeout,
            move || vtable_fn(handle.ptr(), name),
            || abi_stable::std_types::ROption::RNone,
        );
        match out.into_option() {
            Some(s) => {
                if enforce_ffi_payload_cap(
                    &s,
                    &self.manifest.id,
                    "backend.output_schema",
                    self.library.ffi_limits.max_payload_bytes,
                )
                .is_err()
                {
                    return None;
                }
                serde_json::from_str(s.as_str()).ok()
            }
            None => None,
        }
    }

    async fn list_resources(
        &self,
        backend_name: &str,
        cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        let req_bytes = backend_name.len() + cursor.map(str::len).unwrap_or(0);
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "backend",
            "list_resources",
            req_bytes,
        );
        let cursor_opt: abi_stable::std_types::ROption<abi_stable::std_types::RString> =
            cursor.map(abi_stable::std_types::RString::from).into();
        // Off the worker under the data timeout, with a panic backstop:
        // this `async fn` body is one blocking FFI call and never yields,
        // so a caller-side `timeout` around it cannot fire.
        let vtable_fn = self.vtable.list_resources;
        let handle = SendHandle(self.handle);
        let name = abi_stable::std_types::RString::from(backend_name);
        let out = call_sync_vtable_bounded(
            self.library.ffi_limits.data_timeout,
            move || vtable_fn(handle.ptr(), name, cursor_opt),
            abi_stable::std_types::RString::new,
        );
        let resp_bytes = out.len();
        if let Err(actual_bytes) = enforce_ffi_payload_cap(
            &out,
            &self.manifest.id,
            "backend.list_resources",
            self.library.ffi_limits.max_payload_bytes,
        ) {
            call.end_err(resp_bytes);
            return Err(BackendError::Transport {
                message: format!(
                    "backend plugin returned a list_resources page of {} bytes exceeding the host cap of {} bytes",
                    actual_bytes,
                    mcpg_plugin_protocol::abi::FFI_MAX_PAYLOAD_BYTES,
                ),
            });
        }
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Ok { ok: ResourcePage },
            Err { err: BackendError },
        }
        match serde_json::from_str::<Wire>(out.as_str()) {
            Ok(Wire::Ok { ok }) => {
                call.end_ok(resp_bytes);
                Ok(ok)
            }
            Ok(Wire::Err { err }) => {
                call.end_err(resp_bytes);
                Err(err)
            }
            Err(e) => {
                // Malformed → empty page, which is indistinguishable from a
                // store that genuinely holds nothing. Say so: a cdylib whose
                // async->sync bridge panics returns an empty `RString` here,
                // and `resources/list` then reports no resources forever.
                call.end_err(resp_bytes);
                metrics::counter!(
                    "mcpg_native_plugin_empty_envelope_total",
                    "plugin_id" => self.manifest.id.clone(),
                    "slot" => "backend.list_resources",
                )
                .increment(1);
                tracing::warn!(
                    plugin_id = %self.manifest.id,
                    backend = %backend_name,
                    bytes = resp_bytes,
                    error = %e,
                    "list_resources returned an undecodable envelope; reporting an empty page. \
                     An empty response usually means the plugin panicked or timed out"
                );
                Ok(ResourcePage::empty())
            }
        }
    }

    fn audit_metadata(&self, backend_name: &str) -> serde_json::Map<String, serde_json::Value> {
        // v36: forward the cdylib's domain-specific audit fields (e.g.
        // SQL's db.driver / db.query_ref). Best-effort — a malformed or
        // non-object return decodes to an empty map.
        let vtable_fn = self.vtable.audit_metadata;
        let handle = SendHandle(self.handle);
        let name = abi_stable::std_types::RString::from(backend_name);
        let out = call_sync_vtable_bounded(
            self.library.ffi_limits.data_timeout,
            move || vtable_fn(handle.ptr(), name),
            abi_stable::std_types::RString::new,
        );
        match serde_json::from_str::<serde_json::Value>(out.as_str()) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    /// Dispatch capability expansion to the cdylib
    /// via the parameterless `BackendVTable.expand_capabilities` slot.
    /// Malformed/empty decodes to the empty set (no capabilities).
    async fn expand_capabilities(&self) -> Result<CapabilitySet, BackendError> {
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "backend",
            "expand_capabilities",
            0,
        );
        // Bounded like `list_resources`: the body is one blocking FFI call.
        let vtable_fn = self.vtable.expand_capabilities;
        let handle = SendHandle(self.handle);
        let out = call_sync_vtable_bounded(
            self.library.ffi_limits.data_timeout,
            move || vtable_fn(handle.ptr()),
            abi_stable::std_types::RString::new,
        );
        let resp_bytes = out.len();
        if let Err(actual_bytes) = enforce_ffi_payload_cap(
            &out,
            &self.manifest.id,
            "backend.expand_capabilities",
            self.library.ffi_limits.max_payload_bytes,
        ) {
            call.end_err(resp_bytes);
            return Err(BackendError::Transport {
                message: format!(
                    "backend plugin returned an expand_capabilities set of {} bytes exceeding the host cap of {} bytes",
                    actual_bytes,
                    mcpg_plugin_protocol::abi::FFI_MAX_PAYLOAD_BYTES,
                ),
            });
        }
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Ok { ok: CapabilitySet },
            Err { err: BackendError },
        }
        match serde_json::from_str::<Wire>(out.as_str()) {
            Ok(Wire::Ok { ok }) => {
                call.end_ok(resp_bytes);
                Ok(ok)
            }
            Ok(Wire::Err { err }) => {
                call.end_err(resp_bytes);
                Err(err)
            }
            Err(e) => {
                // Same degradation as `list_resources`: the default set is
                // indistinguishable from a plugin that declares nothing.
                call.end_err(resp_bytes);
                metrics::counter!(
                    "mcpg_native_plugin_empty_envelope_total",
                    "plugin_id" => self.manifest.id.clone(),
                    "slot" => "backend.expand_capabilities",
                )
                .increment(1);
                tracing::warn!(
                    plugin_id = %self.manifest.id,
                    bytes = resp_bytes,
                    error = %e,
                    "expand_capabilities returned an undecodable envelope; falling back to the \
                     default set. An empty response usually means the plugin panicked or timed out"
                );
                Ok(CapabilitySet::default())
            }
        }
    }

    /// Dispatch resource-template variable completion to the cdylib
    /// via the `BackendVTable.complete_template_variable` slot.
    async fn complete_template_variable(
        &self,
        profile_name: &str,
        variable_name: &str,
        prefix: &str,
        config: &serde_json::Value,
        context: &std::collections::BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        let args = serde_json::json!({
            "profile_name": profile_name,
            "variable_name": variable_name,
            "prefix": prefix,
            "config": config,
            "context": context,
        });
        let args_json = serde_json::to_string(&args).unwrap_or_else(|_| "{}".into());
        let req_bytes = args_json.len();
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "backend",
            "complete_template_variable",
            req_bytes,
        );
        // Bound the synchronous vtable call under the per-plugin data timeout.
        // Completions are advisory, so a panic / timeout yields no suggestions
        // rather than pinning a tokio worker or failing the request.
        let vtable_fn = self.vtable.complete_template_variable;
        let handle = SendHandle(self.handle);
        let args_str = abi_stable::std_types::RString::from(args_json);
        let out = if self.inline_fast {
            vtable_fn(handle.ptr(), args_str)
        } else {
            let data_timeout = self.library.ffi_limits.data_timeout;
            match tokio::time::timeout(
                data_timeout,
                tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), args_str)),
            )
            .await
            {
                Ok(Ok(out)) => out,
                Ok(Err(_join)) => {
                    call.end_err(0);
                    return Ok(vec![]);
                }
                Err(_elapsed) => {
                    call.end_err(0);
                    metrics::counter!(
                        "mcpg_native_plugin_timeout_total",
                        "plugin_id" => self.manifest.id.clone(),
                    )
                    .increment(1);
                    return Ok(vec![]);
                }
            }
        };
        let resp_bytes = out.len();
        if out.as_str().is_empty() {
            // Plugin panicked or returned no envelope — treat as empty.
            call.end_err(resp_bytes);
            return Ok(vec![]);
        }
        if enforce_ffi_payload_cap(
            &out,
            &self.manifest.id,
            "backend.complete_template_variable",
            self.library.ffi_limits.max_payload_bytes,
        )
        .is_err()
        {
            // Truncate to empty rather than failing the completion call —
            // template-variable completions are advisory, not load-bearing.
            call.end_err(resp_bytes);
            return Ok(vec![]);
        }
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Ok { ok: Vec<String> },
            Err { err: BackendError },
        }
        match serde_json::from_str::<Wire>(out.as_str()) {
            Ok(Wire::Ok { ok }) => {
                call.end_ok(resp_bytes);
                Ok(ok)
            }
            Ok(Wire::Err { err }) => {
                call.end_err(resp_bytes);
                Err(err)
            }
            Err(_) => {
                call.end_err(resp_bytes);
                Ok(vec![])
            }
        }
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

// ---------------------------------------------------------------------------
// WatchStrategy adapter
// ---------------------------------------------------------------------------

/// Bundle stored on the heap + handed to a native watch plugin.
/// Keeps the sink + a tokio runtime handle alive for the lifetime of
/// the watch so the C callback can `block_on` `sink.emit(event)` on
/// whatever thread the plugin's watch loop uses.
///
/// `cancelled` is set to `true` by
/// [`NativeWatchHandle::cancel`] **before** the plugin's cancel slot
/// is invoked, so any callback that races past the cancel boundary
/// is short-circuited rather than touching a soon-to-be-freed sink.
/// Spec compliance is the plugin's responsibility (no callbacks
/// after `cancel`); the AtomicBool is defense-in-depth.
struct SinkBridge {
    sink: Arc<dyn WatchEventSink>,
    rt: tokio::runtime::Handle,
    cancelled: std::sync::atomic::AtomicBool,
    plugin_alias: String,
}

extern "C" fn sink_bridge_callback(ctx: usize, event_json: abi_stable::std_types::RString) {
    // SAFETY: `ctx` is a `*const SinkBridge` leaked by `watch()`. It
    // stays live until the owning `NativeWatchHandle` is dropped —
    // which happens **after** the plugin's cancel slot returns, so
    // a well-behaved plugin never sees this pointer become invalid.
    let bridge = unsafe { &*(ctx as *const SinkBridge) };
    // Short-circuit any callback that crosses
    // the cancel boundary so a misbehaving plugin can't drive emits
    // after the host has torn down its sink wiring.
    if bridge.cancelled.load(std::sync::atomic::Ordering::Acquire) {
        metrics::counter!(
            "mcpg_plugin_post_cancel_callbacks_total",
            "plugin_alias" => bridge.plugin_alias.clone(),
            "bridge" => "watch_sink",
        )
        .increment(1);
        return;
    }
    let event: WatchEvent = serde_json::from_str(event_json.as_str()).unwrap_or_default();
    // Plugins run their watch loop on their own threads; we need a
    // tokio runtime to drive emit(). The bridge carries the host's
    // runtime Handle captured at `watch()` time.
    let sink = Arc::clone(&bridge.sink);
    bridge.rt.spawn(async move {
        sink.emit(event).await;
    });
}

// ---------------------------------------------------------------------------
// Generic mpsc-backed event bridge
// ---------------------------------------------------------------------------
//
// The `WatchStrategy` `SinkBridge` above is specific to watch because it
// holds a `WatchEventSink` trait object. The streaming kinds (store,
// secret, config, …) consume the stream as a plain `Stream<Item=T>`
// rather than a fan-out trait object, so their bridge just pushes
// raw JSON strings into a bounded tokio mpsc and hands the
// Receiver-as-Stream back to the caller. The caller's adapter
// parses each JSON line into the kind-specific event.
//
// Buffer size tuned for "slow consumer recovery, not infinite
// queue" — fixed at 1024 with **drop-newest**
// semantics: when the channel is saturated the plugin's emit is
// dropped (counted via `mcpg_plugin_sink_dropped_total`) rather
// than blocking the plugin thread on `blocking_send`. Blocking the
// plugin thread risks deadlock when the consumer is itself driven
// by tokio tasks that share workers with the plugin, and it
// makes a slow consumer back-propagate into upstream watch loops
// that may themselves be holding cluster locks. Dropping is the
// correct shape for streaming sinks: the consumer can re-snapshot
// from the underlying source, the operator sees the drop counter,
// and no plugin thread ever blocks indefinitely.

const STREAM_BRIDGE_CAPACITY: usize = 1024;

struct StreamBridge {
    tx: tokio::sync::mpsc::Sender<String>,
    /// Cancellation defense — see [`SinkBridge::cancelled`].
    cancelled: std::sync::atomic::AtomicBool,
    /// Operator-facing label so the drop / post-cancel counters can
    /// attribute back to the originating plugin alias.
    plugin_alias: String,
}

extern "C" fn stream_bridge_callback(ctx: usize, event_json: abi_stable::std_types::RString) {
    // SAFETY: `ctx` is a `*const StreamBridge` leaked by the
    // adapter's `watch()` call. Stays live until `cancel_watch`
    // runs + the bridge box is dropped via `StreamCancelGuard`.
    let bridge = unsafe { &*(ctx as *const StreamBridge) };
    // Short-circuit any callback that races
    // past the host's cancel.
    if bridge.cancelled.load(std::sync::atomic::Ordering::Acquire) {
        metrics::counter!(
            "mcpg_plugin_post_cancel_callbacks_total",
            "plugin_alias" => bridge.plugin_alias.clone(),
            "bridge" => "stream",
        )
        .increment(1);
        return;
    }
    // Drop-newest under saturation. `try_send`
    // returns `Err(Full)` when the bounded channel is at capacity —
    // we count and drop instead of blocking the plugin thread.
    // `Err(Closed)` means the consumer has been torn down (the
    // adapter dropped the receiver before cancel reached the
    // plugin); same drop path, same counter — the operator sees a
    // unified signal that watch events are being lost.
    if let Err(err) = bridge.tx.try_send(event_json.as_str().to_owned()) {
        let reason = match err {
            tokio::sync::mpsc::error::TrySendError::Full(_) => "full",
            tokio::sync::mpsc::error::TrySendError::Closed(_) => "closed",
        };
        metrics::counter!(
            "mcpg_plugin_sink_dropped_total",
            "plugin_alias" => bridge.plugin_alias.clone(),
            "bridge" => "stream",
            "reason" => reason,
        )
        .increment(1);
    }
}

/// Create a bridge + a receiver stream, returning the ffi-side
/// sink ref ready to hand to a plugin's `watch` vtable slot.
///
/// Caller is responsible for:
/// - holding the returned `*mut StreamBridge` alive until the
///   corresponding `cancel_watch` vtable slot returns, and
/// - dropping the box afterwards (plugin contract: no callbacks
///   after `cancel_watch`).
///
/// The returned `Receiver` streams the plugin's JSON strings;
/// adapters wrap it with kind-specific deserialization.
fn make_stream_bridge(
    plugin_alias: &str,
) -> (
    *mut StreamBridge,
    EventSinkRef,
    tokio::sync::mpsc::Receiver<String>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(STREAM_BRIDGE_CAPACITY);
    let bridge = Box::new(StreamBridge {
        tx,
        cancelled: std::sync::atomic::AtomicBool::new(false),
        plugin_alias: plugin_alias.to_owned(),
    });
    let ptr = Box::into_raw(bridge);
    let sink = EventSinkRef {
        ctx: ptr as usize,
        callback: stream_bridge_callback,
    };
    (ptr, sink, rx)
}

// ---------------------------------------------------------------------------
// Bytes bridge (binary-payload streaming path)
// ---------------------------------------------------------------------------
//
// Parallel to [`StreamBridge`] but the channel carries raw `Vec<u8>`
// chunks instead of JSON strings. Used by HTTP route streaming for
// the binary-payload path (response bodies, blob downloads) where
// the JSON encode/decode tax per chunk is wasted work. Same
// drop-newest + cancellation semantics as the text bridge.

struct BytesBridge {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Cancellation defense — see [`SinkBridge::cancelled`].
    cancelled: std::sync::atomic::AtomicBool,
    plugin_alias: String,
}

extern "C" fn bytes_bridge_callback(ctx: usize, chunk: abi_stable::std_types::RVec<u8>) {
    // SAFETY: `ctx` is a `*const BytesBridge` leaked by the
    // adapter. Stays live until cancel_stream + box drop.
    let bridge = unsafe { &*(ctx as *const BytesBridge) };
    if bridge.cancelled.load(std::sync::atomic::Ordering::Acquire) {
        metrics::counter!(
            "mcpg_plugin_post_cancel_callbacks_total",
            "plugin_alias" => bridge.plugin_alias.clone(),
            "bridge" => "bytes",
        )
        .increment(1);
        return;
    }
    // Empty RVec<u8> ⇒ end-of-stream sentinel (matches the
    // `HttpChunk::End` convention from the text path).
    let payload: Vec<u8> = chunk.into();
    if let Err(err) = bridge.tx.try_send(payload) {
        let reason = match err {
            tokio::sync::mpsc::error::TrySendError::Full(_) => "full",
            tokio::sync::mpsc::error::TrySendError::Closed(_) => "closed",
        };
        metrics::counter!(
            "mcpg_plugin_sink_dropped_total",
            "plugin_alias" => bridge.plugin_alias.clone(),
            "bridge" => "bytes",
            "reason" => reason,
        )
        .increment(1);
    }
}

/// Create a bytes-bridge + a receiver, returning the ffi-side
/// [`BytesSinkRef`] ready to hand to a plugin's binary-streaming
/// vtable slot.
fn make_bytes_bridge(
    plugin_alias: &str,
) -> (
    *mut BytesBridge,
    BytesSinkRef,
    tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(STREAM_BRIDGE_CAPACITY);
    let bridge = Box::new(BytesBridge {
        tx,
        cancelled: std::sync::atomic::AtomicBool::new(false),
        plugin_alias: plugin_alias.to_owned(),
    });
    let ptr = Box::into_raw(bridge);
    let sink = BytesSinkRef {
        ctx: ptr as usize,
        callback: bytes_bridge_callback,
    };
    (ptr, sink, rx)
}

/// RAII guard that cancels the plugin-side watch + drops the
/// bridge box when the stream is dropped. Holding an
/// `Arc<LoadedNativePlugin>` keeps the cdylib alive at least
/// until cancellation completes.
struct StreamCancelGuard {
    library: Arc<LoadedNativePlugin>,
    cancel_fn: extern "C" fn(RPluginHandle, usize),
    plugin_handle: RPluginHandle,
    watch_handle: usize,
    bridge_ptr: *mut StreamBridge,
}

unsafe impl Send for StreamCancelGuard {}
unsafe impl Sync for StreamCancelGuard {}

impl Drop for StreamCancelGuard {
    fn drop(&mut self) {
        // Flip the bridge's `cancelled` flag
        // BEFORE the plugin's cancel slot is invoked, so any
        // late-arriving callback that races past cancel hits the
        // short-circuit in `stream_bridge_callback` and bumps
        // `mcpg_plugin_post_cancel_callbacks_total{bridge="stream"}`
        // instead of pushing into a Receiver the host has logically
        // dropped.
        // SAFETY: `bridge_ptr` came from `Box::into_raw` and remains
        // alive until `drop(Box::from_raw(...))` below.
        unsafe {
            (*self.bridge_ptr)
                .cancelled
                .store(true, std::sync::atomic::Ordering::Release);
        }
        (self.cancel_fn)(self.plugin_handle, self.watch_handle);
        // Plugin's contract: no further callbacks after
        // `cancel_watch` returns. Safe to free the bridge now.
        // SAFETY: `bridge_ptr` was produced by
        // `Box::into_raw(Box::new(StreamBridge { .. }))`.
        unsafe {
            drop(Box::from_raw(self.bridge_ptr));
        }
        let _ = &self.library;
    }
}

/// Stream adapter for `NativeBackendAdapter::execute_streaming` (v34).
/// Pulls one result-envelope JSON per chunk from the bridge channel,
/// decodes each into `Result<BackendChunk, BackendError>`, and yields
/// it. Dropping the stream drops the cancel guard, which cancels the
/// plugin-side stream + frees the bridge. Malformed chunks are skipped
/// (the plugin shouldn't emit them; matches the watch adapters).
struct BackendChunkWireStream {
    rx: tokio::sync::mpsc::Receiver<String>,
    _guard: StreamCancelGuard,
    /// Keeps the caller identity's host integrity tag verifiable while the
    /// stream is open; dropped with the stream, which retires the tag.
    _dispatch: Option<crate::host_bridge::DispatchGuard>,
}

impl futures_core::Stream for BackendChunkWireStream {
    type Item = Result<BackendChunk, BackendError>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            match self.rx.poll_recv(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                std::task::Poll::Ready(Some(json)) => {
                    match mcpg_plugin_protocol::result_envelope::decode_result_envelope::<
                        BackendChunk,
                        BackendError,
                    >(&json)
                    {
                        // `inner` is the decoded `Result<BackendChunk,
                        // BackendError>` — yield it as the stream item.
                        Ok(inner) => return std::task::Poll::Ready(Some(inner)),
                        // Undecodable envelope — skip + keep polling.
                        Err(_) => continue,
                    }
                }
            }
        }
    }
}

/// Adapter over a loaded cdylib's [`WatchStrategyVTable`].
pub struct NativeWatchStrategyAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: WatchStrategyVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    kind: String,
    #[allow(dead_code)]
    alias: String,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeWatchStrategyAdapter {}
unsafe impl Sync for NativeWatchStrategyAdapter {}

impl NativeWatchStrategyAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_watch_strategy() {
            Some(vt) => clone_watch_strategy(vt),
            None => {
                return Err(anyhow!("plugin does not export a WatchStrategy vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!(
                "native watch plugin panicked during make (null handle)"
            ));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!("native watch plugin returned empty manifest JSON"));
        }
        let manifest: PluginManifest =
            serde_json::from_str(manifest_json.as_str()).map_err(|e| {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                anyhow::Error::from(e).context("invalid manifest from native watch plugin")
            })?;
        let kind = guard_ffi_rstring("kind", || (vt.kind)(handle))
            .as_str()
            .to_owned();
        if kind.is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!("native watch plugin returned empty kind()"));
        }
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            kind,
            alias,
            _host_bridge: host_bridge,
        })
    }
}

impl Drop for NativeWatchStrategyAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

/// Handle returned from `watch()` that owns the sink bridge + the
/// plugin's opaque watch handle. Drop NEVER cancels; the host calls
/// [`NativeWatchHandle::cancel`] explicitly so teardown errors are
/// visible (matches `WatchHandle` trait contract).
pub struct NativeWatchHandle {
    /// Cancel vtable slot + plugin instance — used inside
    /// [`WatchHandle::cancel`] to tear down the watcher.
    vtable: WatchStrategyVTable,
    plugin_handle: RPluginHandle,
    watch_handle: usize,
    /// Boxed sink bridge the plugin still holds a pointer to. Dropped
    /// after `cancel()` returns so the plugin can't call back into
    /// freed memory.
    sink_bridge: Option<Box<SinkBridge>>,
}

unsafe impl Send for NativeWatchHandle {}
unsafe impl Sync for NativeWatchHandle {}

#[async_trait]
impl WatchHandle for NativeWatchHandle {
    async fn cancel(&self) {
        // Flip the bridge's `cancelled` flag
        // BEFORE the plugin's cancel slot is invoked. A misbehaving
        // plugin that delivers a callback after cancel returns
        // (against the protocol contract) will hit the short-circuit
        // in `sink_bridge_callback` and bump
        // `mcpg_plugin_post_cancel_callbacks_total{bridge="watch_sink"}`
        // instead of dispatching to a sink that may already have
        // been logically torn down by the host.
        if let Some(bridge) = self.sink_bridge.as_ref() {
            bridge
                .cancelled
                .store(true, std::sync::atomic::Ordering::Release);
        }
        (self.vtable.cancel)(self.plugin_handle, self.watch_handle);
        // Bridge stays alive until this NativeWatchHandle is Drop'd;
        // we don't null the pointer here because the plugin's cancel
        // MUST not emit further events (contract), so leaving the
        // box alive through Drop is fine.
    }
}

impl Drop for NativeWatchHandle {
    fn drop(&mut self) {
        // Drop the boxed bridge here — after cancel() the plugin
        // MUST NOT call back, so releasing the box is safe.
        let _ = self.sink_bridge.take();
    }
}

#[async_trait]
impl WatchStrategyPlugin for NativeWatchStrategyAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        &self.kind
    }

    async fn watch(
        &self,
        resource_uri: &str,
        spec: &serde_json::Value,
        sink: Arc<dyn WatchEventSink>,
    ) -> Result<Box<dyn WatchHandle>, WatchError> {
        let bridge = Box::new(SinkBridge {
            sink,
            rt: tokio::runtime::Handle::current(),
            cancelled: std::sync::atomic::AtomicBool::new(false),
            plugin_alias: self.manifest.id.clone(),
        });
        let ctx = &*bridge as *const SinkBridge as usize;
        let sink_ref = EventSinkRef {
            ctx,
            callback: sink_bridge_callback,
        };
        let spec_json = serde_json::to_string(spec).unwrap_or_else(|_| "{}".into());
        // Instrument the host→plugin `watch` install call. The
        // ongoing stream emit path lives on the plugin thread (via
        // `sink_bridge_callback`) — that's plugin→host and accounted
        // for through the bridge's own metrics, not this one.
        let req_bytes = resource_uri.len() + spec_json.len();
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "watch_strategy",
            "watch",
            req_bytes,
        );
        // Bounded: `watch` only INSTALLS the subscription (the stream then
        // runs on the plugin's own thread through `sink_bridge_callback`),
        // but the install itself is a blocking FFI call on an async worker.
        // A null handle is already the failure path, so a panic or timeout
        // surfaces as a refused subscription.
        let vtable_fn = self.vtable.watch;
        let handle = SendHandle(self.handle);
        let uri = abi_stable::std_types::RString::from(resource_uri);
        let spec_arg = abi_stable::std_types::RString::from(spec_json);
        let result = call_sync_vtable_bounded(
            self.library.ffi_limits.data_timeout,
            move || vtable_fn(handle.ptr(), uri, spec_arg, sink_ref),
            || mcpg_plugin_protocol::abi::StreamHandle {
                handle: 0,
                error_json: abi_stable::std_types::RString::from(
                    "native watch plugin panicked or exceeded the host data timeout",
                ),
                metadata_json: abi_stable::std_types::RString::new(),
            },
        );
        let resp_bytes = result.error_json.len();
        if result.handle == 0 {
            call.end_err(resp_bytes);
        } else {
            call.end_ok(resp_bytes);
        }
        // `watch` returns a `StreamHandle`.
        // `handle == 0` ⇒ failure; `error_json` carries the
        // structured `WatchError` (or the panic-sentinel string
        // when the plugin panicked).
        if result.handle == 0 {
            let err_str = result.error_json.as_str();
            let err = serde_json::from_str::<WatchError>(err_str).unwrap_or_else(|_| {
                WatchError::Subscribe {
                    message: if err_str.is_empty() {
                        "native watch plugin returned null handle".into()
                    } else {
                        err_str.to_owned()
                    },
                }
            });
            return Err(err);
        }
        Ok(Box::new(NativeWatchHandle {
            vtable: clone_watch_strategy(&self.vtable),
            plugin_handle: self.handle,
            watch_handle: result.handle,
            sink_bridge: Some(bridge),
        }))
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

// ---------------------------------------------------------------------------
// HttpRoute adapter
// ---------------------------------------------------------------------------
//
// JSON-over-FFI, bytes-only body. A plugin that returns a streaming
// body through the FFI vtable is rejected in `handle()` with a 500 —
// stream support across the boundary is deferred (see the comment on
// `HttpRouteVTable` in the protocol crate).

fn clone_http_route(vt: &HttpRouteVTable) -> HttpRouteVTable {
    HttpRouteVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        routes_json: vt.routes_json,
        handle: vt.handle,
        handle_streaming: vt.handle_streaming,
        cancel_stream: vt.cancel_stream,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

pub struct NativeHttpRouteAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: HttpRouteVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    routes: Vec<RouteSpec>,
    #[allow(dead_code)]
    alias: String,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeHttpRouteAdapter {}
unsafe impl Sync for NativeHttpRouteAdapter {}

impl NativeHttpRouteAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_http_route() {
            Some(vt) => clone_http_route(vt),
            None => {
                return Err(anyhow!("plugin does not export an HttpRoute vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!(
                "native http_route plugin panicked during make (null handle)"
            ));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!(
                "native http_route plugin returned empty manifest JSON"
            ));
        }
        let manifest: PluginManifest = match serde_json::from_str(manifest_json.as_str()) {
            Ok(m) => m,
            Err(e) => {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                return Err(anyhow::Error::from(e)
                    .context("invalid manifest from native http_route plugin"));
            }
        };
        let routes_json = guard_ffi_rstring("routes_json", || (vt.routes_json)(handle));
        let routes: Vec<RouteSpec> = match serde_json::from_str(routes_json.as_str()) {
            Ok(r) => r,
            Err(e) => {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                return Err(anyhow::Error::from(e)
                    .context("invalid routes JSON from native http_route plugin"));
            }
        };
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            routes,
            alias,
            _host_bridge: host_bridge,
        })
    }
}

impl Drop for NativeHttpRouteAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

/// Host-side panic guard around a cdylib's `make` (constructor) slot,
/// mapping a caught panic to a null handle the caller's null-check turns
/// into a clean load error. The SDK macro already converts an author panic
/// to a null handle plugin-side; this covers a panic raised in the host
/// marshalling frame and any plugin compiled `extern "C-unwind"`. A foreign
/// `extern "C"` cdylib that panics aborts at its own boundary on modern
/// rustc (safe), which the host cannot convert without an ABI change.
fn guard_ffi_make(f: impl FnOnce() -> RPluginHandle) -> RPluginHandle {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| {
        metrics::counter!(
            "mcpg_plugin_load_panic_refusals_total",
            "slot" => "make",
        )
        .increment(1);
        std::ptr::null_mut()
    })
}

/// Host-side panic guard around an `RString`-returning lifecycle slot
/// (`manifest_json` / `routes_json` / `kind`), mapping a caught panic to an
/// empty `RString` the caller's empty-check turns into a clean load error
/// (same boundary caveat as [`guard_ffi_make`]).
fn guard_ffi_rstring(
    slot: &'static str,
    f: impl FnOnce() -> abi_stable::std_types::RString,
) -> abi_stable::std_types::RString {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| {
        metrics::counter!(
            "mcpg_plugin_load_panic_refusals_total",
            "slot" => slot,
        )
        .increment(1);
        abi_stable::std_types::RString::new()
    })
}

/// Catch a panic from a `drop_instance` slot. Returning `Err` from `Drop`
/// is impossible and a panic during unwinding aborts the process, so this
/// swallows the panic silently (mirrors the SDK's silent drop guard).
fn guard_ffi_drop(f: impl FnOnce()) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
}

/// Run a SYNC trait-method vtable slot off the async worker under the
/// per-plugin data timeout, catching a panic so it can't unwind across
/// `extern "C"`. On a multi-thread runtime the call is offloaded via
/// `spawn_blocking` + `tokio::time::timeout` (a hung slot can't pin a
/// worker); on a current-thread runtime / outside tokio it runs directly
/// under `catch_unwind` (no timeout — these are boot / best-effort paths).
/// A timeout, join error, or panic yields `on_fail()`.
fn call_sync_vtable_bounded<R: Send + 'static>(
    data_timeout: std::time::Duration,
    f: impl FnOnce() -> R + Send + 'static,
    on_fail: impl FnOnce() -> R,
) -> R {
    use tokio::runtime::{Handle, RuntimeFlavor};
    let guarded = std::panic::AssertUnwindSafe(f);
    let guarded = move || std::panic::catch_unwind(guarded);
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => {
            let outcome = tokio::task::block_in_place(|| {
                h.block_on(async {
                    tokio::time::timeout(data_timeout, tokio::task::spawn_blocking(guarded)).await
                })
            });
            match outcome {
                Ok(Ok(Ok(v))) => v,
                _ => on_fail(),
            }
        }
        _ => guarded().unwrap_or_else(|_| on_fail()),
    }
}

/// Async dispatch helper exposed for testing.
///
/// Pulls the vtable call + JSON marshalling + error mapping out of
/// the `NativeHttpRouteAdapter::handle` body so integration tests
/// can exercise the decision logic without constructing a full
/// [`LoadedNativePlugin`] (which owns a `libloading::Library` and
/// cannot be faked in-process).
///
/// Semantics:
/// - `vtable_fn` is invoked on a blocking-friendly executor with the
///   caller-supplied `data_timeout` from
///   [`FfiLimits`](crate::native_loader::FfiLimits).
/// - Empty `RString` return ⇒ 500 "plugin panicked".
/// - Decode-failure on the returned JSON ⇒ 500 "malformed".
/// - Timeout ⇒ 504 and bump of `mcpg_native_plugin_timeout_total`.
/// - Payload exceeding `max_payload_bytes` ⇒ 500 "payload too large".
/// - `spawn_blocking` join error ⇒ 500 "plugin panicked".
pub async fn dispatch_http_route_via_vtable(
    vtable_fn: extern "C" fn(
        RPluginHandle,
        abi_stable::std_types::RString,
    ) -> abi_stable::std_types::RString,
    handle: SendHandle,
    plugin_id: String,
    req: HttpRouteRequest,
    ffi_limits: &FfiLimits,
) -> HttpRouteResponse {
    let wire: HttpRouteRequestWire = req.into();
    let payload = abi_stable::std_types::RString::from(
        serde_json::to_string(&wire).unwrap_or_else(|_| "{}".into()),
    );
    let result = tokio::time::timeout(
        ffi_limits.data_timeout,
        tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), payload)),
    )
    .await;
    match result {
        Ok(Ok(out)) => {
            if enforce_ffi_payload_cap(
                &out,
                &plugin_id,
                "http_route.dispatch",
                ffi_limits.max_payload_bytes,
            )
            .is_err()
            {
                return HttpRouteResponse::error_json(
                    500,
                    "native http_route plugin payload exceeded the host FFI cap",
                );
            }
            let raw = out.as_str();
            if raw.is_empty() {
                tracing::error!(
                    plugin_id = %plugin_id,
                    "native http_route plugin returned empty response (likely panic)",
                );
                return HttpRouteResponse::error_json(
                    500,
                    format!("native plugin '{plugin_id}' panicked"),
                );
            }
            match serde_json::from_str::<HttpRouteResponseWire>(raw) {
                Ok(wire) => wire.into(),
                Err(e) => {
                    tracing::error!(
                        plugin_id = %plugin_id,
                        error = %e,
                        "native http_route plugin returned undecodable response",
                    );
                    HttpRouteResponse::error_json(
                        500,
                        format!("native plugin '{plugin_id}' returned malformed response"),
                    )
                }
            }
        }
        Ok(Err(e)) => {
            tracing::error!(
                plugin_id = %plugin_id,
                error = %e,
                "native http_route plugin panicked",
            );
            HttpRouteResponse::error_json(500, format!("native plugin '{plugin_id}' panicked"))
        }
        Err(_) => {
            tracing::error!(
                plugin_id = %plugin_id,
                "native http_route plugin timed out",
            );
            metrics::counter!(
                "mcpg_native_plugin_timeout_total",
                "plugin_id" => plugin_id.clone(),
            )
            .increment(1);
            HttpRouteResponse::error_json(504, format!("native plugin '{plugin_id}' timed out"))
        }
    }
}

#[async_trait]
impl HttpRoute for NativeHttpRouteAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn routes(&self) -> Vec<RouteSpec> {
        self.routes.clone()
    }

    async fn handle(&self, req: HttpRouteRequest) -> HttpRouteResponse {
        // Always dispatch through `handle_streaming`. The
        // plugin returns `HttpHandleResult { handle, head_json }`
        // — we decode head_json either as a full
        // `HttpRouteResponseWire` (bytes case) or as
        // `HttpStreamHead` (streaming case) based on the handle
        // value.
        //
        // Alongside the text/SSE sink the
        // adapter hands the plugin a parallel `BytesSinkRef` for
        // binary streaming (large response bodies, blob downloads).
        // The plugin picks one path; the chunk-stream wrapper reads
        // from whichever receiver yields chunks. Empty `Vec<u8>` on
        // the bytes path acts as the `HttpChunk::End` sentinel.
        let (text_bridge_raw, sink, text_rx) = make_stream_bridge(&self.manifest.id);
        let text_bridge_ptr = SendPtr(text_bridge_raw);
        let (bytes_bridge_raw, bytes_sink, bytes_rx) = make_bytes_bridge(&self.manifest.id);
        let bytes_bridge_ptr: SendPtr<BytesBridge> = SendPtr(bytes_bridge_raw);
        let wire: HttpRouteRequestWire = req.into();
        let request_str = serde_json::to_string(&wire).unwrap_or_else(|_| "{}".into());
        let req_bytes = request_str.len();
        // Instrument the host→plugin `handle_streaming` install
        // call. Streaming body bytes (text + bytes mpsc) are emitted
        // from the plugin's own thread and don't traverse this slot
        // again, so they aren't double-counted here.
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "http_route",
            "handle_streaming",
            req_bytes,
        );
        let request_json = abi_stable::std_types::RString::from(request_str);
        let vtable_fn = self.vtable.handle_streaming;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        let spawn_result = tokio::task::spawn_blocking(move || {
            vtable_fn(handle.ptr(), request_json, sink, bytes_sink)
        })
        .await;
        let result = match spawn_result {
            Ok(r) => r,
            Err(_) => {
                call.end_err(0);
                // Plugin panicked before returning. Free both bridges.
                unsafe {
                    drop(Box::from_raw(text_bridge_ptr.0));
                    drop(Box::from_raw(bytes_bridge_ptr.0));
                }
                return HttpRouteResponse::error_json(
                    500,
                    format!("native plugin '{plugin_id}' panicked"),
                );
            }
        };
        // Account for the head_json envelope only — streaming body
        // bytes are emitted out-of-band through the sink bridges. We
        // mark the FFI call ok when the plugin produced a non-empty
        // head (bytes-buffered path with handle=0 + head, or streaming
        // path with handle!=0); an empty head is treated as a plugin
        // panic and recorded as err.
        let resp_bytes = result.head_json.len();
        if result.head_json.as_str().is_empty() {
            call.end_err(resp_bytes);
        } else {
            call.end_ok(resp_bytes);
        }
        if result.handle == 0 {
            // Bytes-buffered path: head_json IS the full response
            // wire. Neither sink was invoked; drop both bridges.
            unsafe {
                drop(Box::from_raw(text_bridge_ptr.0));
                drop(Box::from_raw(bytes_bridge_ptr.0));
            }
            let raw = result.head_json.as_str();
            if raw.is_empty() {
                return HttpRouteResponse::error_json(
                    500,
                    format!("native plugin '{plugin_id}' returned empty response"),
                );
            }
            return match serde_json::from_str::<HttpRouteResponseWire>(raw) {
                Ok(wire) => wire.into(),
                Err(_) => HttpRouteResponse::error_json(
                    500,
                    format!("native plugin '{plugin_id}' returned malformed response"),
                ),
            };
        }
        // Streaming path: head_json is `HttpStreamHead`; body
        // arrives on either the text sink (`HttpChunkWire`-JSON)
        // or the bytes sink (raw `Vec<u8>` chunks; empty = end).
        let head: HttpStreamHead = match serde_json::from_str(result.head_json.as_str()) {
            Ok(h) => h,
            Err(_) => {
                // Adapter couldn't parse the head — cancel the
                // stream and return a 500.
                (self.vtable.cancel_stream)(self.handle, result.handle);
                unsafe {
                    drop(Box::from_raw(text_bridge_ptr.0));
                    drop(Box::from_raw(bytes_bridge_ptr.0));
                }
                return HttpRouteResponse::error_json(
                    500,
                    format!("native plugin '{plugin_id}' returned malformed stream head"),
                );
            }
        };
        let guard = HttpStreamCancelGuard {
            library: Arc::clone(&self.library),
            cancel_fn: self.vtable.cancel_stream,
            plugin_handle: self.handle,
            watch_handle: result.handle,
            text_bridge_ptr: text_bridge_ptr.0,
            bytes_bridge_ptr: bytes_bridge_ptr.0,
        };
        HttpRouteResponse {
            status: head.status,
            headers: head.headers,
            body: HttpBody::Stream(Box::pin(HttpChunkStream {
                rx: text_rx,
                bytes_rx,
                _guard: guard,
            })),
        }
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

/// Stream adapter for http_route streaming responses. Reads from
/// EITHER the text bridge (JSON-encoded `HttpChunkWire`, the
/// SSE path) OR the bytes bridge (raw `Vec<u8>` chunks; empty
/// vec = end, the binary path) — whichever yields
/// first. Plugins pick one side per response; mixing is undefined.
///
/// Terminates on:
/// - `HttpChunkWire::End` from the text side, or
/// - empty `Vec<u8>` from the bytes side, or
/// - both senders closing without a sentinel (`Poll::Ready(None)`).
///
/// Drop cancels the plugin-side stream via `HttpStreamCancelGuard`.
struct HttpChunkStream {
    rx: tokio::sync::mpsc::Receiver<String>,
    bytes_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    _guard: HttpStreamCancelGuard,
}

impl futures_core::Stream for HttpChunkStream {
    type Item = HttpChunk;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            // Poll the bytes path first — high-volume binary
            // streams are the motivating use case for the binary
            // path. Text/SSE is fallback for plugins that haven't
            // migrated.
            match self.bytes_rx.poll_recv(cx) {
                std::task::Poll::Ready(Some(chunk)) => {
                    if chunk.is_empty() {
                        // Empty Vec<u8> = end-of-stream sentinel.
                        return std::task::Poll::Ready(Some(HttpChunk::End));
                    }
                    return std::task::Poll::Ready(Some(HttpChunk::Data(bytes::Bytes::from(
                        chunk,
                    ))));
                }
                std::task::Poll::Ready(None) => {
                    // Bytes channel closed; fall through to text.
                }
                std::task::Poll::Pending => {
                    // Try the text side; if it has data we deliver
                    // it, otherwise we return Pending after both
                    // pollers have registered their waker.
                }
            }
            match self.rx.poll_recv(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                std::task::Poll::Ready(Some(json)) => {
                    match serde_json::from_str::<HttpChunkWire>(&json) {
                        Ok(HttpChunkWire::End) => {
                            return std::task::Poll::Ready(Some(HttpChunk::End));
                        }
                        Ok(wire) => {
                            return std::task::Poll::Ready(Some(wire.into()));
                        }
                        Err(_) => continue,
                    }
                }
            }
        }
    }
}

/// RAII guard that cancels the plugin-side stream + drops BOTH
/// bridge boxes when the response body stream is dropped.
/// Specialised version of [`StreamCancelGuard`] because HTTP
/// route streaming holds two bridges (text + bytes).
struct HttpStreamCancelGuard {
    library: Arc<LoadedNativePlugin>,
    cancel_fn: extern "C" fn(RPluginHandle, usize),
    plugin_handle: RPluginHandle,
    watch_handle: usize,
    text_bridge_ptr: *mut StreamBridge,
    bytes_bridge_ptr: *mut BytesBridge,
}

unsafe impl Send for HttpStreamCancelGuard {}
unsafe impl Sync for HttpStreamCancelGuard {}

impl Drop for HttpStreamCancelGuard {
    fn drop(&mut self) {
        // Flip cancellation flags on both
        // bridges BEFORE invoking the plugin's cancel slot, so
        // any late callback from either path hits the post-cancel
        // counter rather than pushing into a torn-down receiver.
        // SAFETY: both pointers came from `Box::into_raw` and
        // remain alive until the drops below.
        unsafe {
            (*self.text_bridge_ptr)
                .cancelled
                .store(true, std::sync::atomic::Ordering::Release);
            (*self.bytes_bridge_ptr)
                .cancelled
                .store(true, std::sync::atomic::Ordering::Release);
        }
        (self.cancel_fn)(self.plugin_handle, self.watch_handle);
        // SAFETY: both pointers were produced by `Box::into_raw`
        // and have not been freed yet.
        unsafe {
            drop(Box::from_raw(self.text_bridge_ptr));
            drop(Box::from_raw(self.bytes_bridge_ptr));
        }
        let _ = &self.library;
    }
}

// ---------------------------------------------------------------------------
// AuditSink + LogSink adapters
// ---------------------------------------------------------------------------
//
// JSON-over-FFI. Both adapters use the same pattern as the HTTP route
// adapter: `spawn_blocking` + `timeout(FfiLimits::data_timeout)`, and
// share dispatch helpers with a `pub` signature so the seam
// integration tests can exercise the decision logic without
// constructing a real `LoadedNativePlugin`.

fn clone_audit_sink(vt: &AuditSinkVTable) -> AuditSinkVTable {
    AuditSinkVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        emit: vt.emit,
        flush: vt.flush,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

fn clone_log_sink(vt: &LogSinkVTable) -> LogSinkVTable {
    LogSinkVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        emit: vt.emit,
        flush: vt.flush,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

/// Async dispatch helper for `AuditSink::emit`, exposed for the
/// seam integration test (same rationale as
/// [`dispatch_http_route_via_vtable`]).
///
/// - Empty `RString` return ⇒ `AuditError::WriteFailed` naming the
///   plugin ("plugin panicked").
/// - Malformed JSON ⇒ `AuditError::WriteFailed` ("malformed").
/// - Decoded `{"ok": ...}` / `{"err": ...}` is returned as-is.
/// - Timeout ⇒ `AuditError::Timeout` + metric bump.
/// - `spawn_blocking` join error ⇒ `AuditError::WriteFailed`.
pub async fn dispatch_audit_emit_via_vtable(
    vtable_fn: extern "C" fn(
        RPluginHandle,
        abi_stable::std_types::RString,
    ) -> abi_stable::std_types::RString,
    handle: SendHandle,
    plugin_id: String,
    event: AuditEvent,
    ffi_limits: &FfiLimits,
) -> Result<AuditReceipt, AuditError> {
    // Encode through the thread-local arena to avoid a
    // per-call allocation.
    let event_json = encode_to_rstring_via_arena(&event);
    // Instrument the host→plugin emit call.
    let call =
        crate::ffi_metering::FfiCall::begin(&plugin_id, "audit_sink", "emit", event_json.len());
    let result = tokio::time::timeout(
        ffi_limits.data_timeout,
        tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), event_json)),
    )
    .await;
    match result {
        Ok(Ok(out)) => {
            let raw = out.as_str();
            let resp_bytes = out.len();
            if raw.is_empty() {
                call.end_err(resp_bytes);
                tracing::error!(
                    plugin_id = %plugin_id,
                    "native audit_sink plugin returned empty response (likely panic)",
                );
                return Err(AuditError::WriteFailed {
                    reason: format!("native plugin '{plugin_id}' panicked"),
                });
            }
            #[derive(serde::Deserialize)]
            #[serde(untagged)]
            enum Wire {
                Ok { ok: AuditReceipt },
                Err { err: AuditError },
            }
            match serde_json::from_str::<Wire>(raw) {
                Ok(Wire::Ok { ok }) => {
                    call.end_ok(resp_bytes);
                    Ok(ok)
                }
                Ok(Wire::Err { err }) => {
                    call.end_err(resp_bytes);
                    Err(err)
                }
                Err(e) => {
                    call.end_err(resp_bytes);
                    tracing::error!(
                        plugin_id = %plugin_id,
                        error = %e,
                        "native audit_sink plugin returned undecodable response",
                    );
                    Err(AuditError::WriteFailed {
                        reason: format!("native plugin '{plugin_id}' returned malformed response",),
                    })
                }
            }
        }
        Ok(Err(e)) => {
            call.end_err(0);
            tracing::error!(
                plugin_id = %plugin_id,
                error = %e,
                "native audit_sink plugin panicked during spawn_blocking",
            );
            Err(AuditError::WriteFailed {
                reason: format!("native plugin '{plugin_id}' panicked"),
            })
        }
        Err(_) => {
            call.end_err(0);
            tracing::error!(
                plugin_id = %plugin_id,
                "native audit_sink plugin timed out",
            );
            metrics::counter!(
                "mcpg_native_plugin_timeout_total",
                "plugin_id" => plugin_id.clone(),
            )
            .increment(1);
            Err(AuditError::Timeout)
        }
    }
}

/// Async dispatch helper for `AuditSink::flush`, exposed for the
/// seam integration test. The wire format
/// is the `{"ok": null}` / `{"err": AuditError}` envelope.
pub async fn dispatch_audit_flush_via_vtable(
    vtable_fn: extern "C" fn(RPluginHandle, u64) -> abi_stable::std_types::RString,
    handle: SendHandle,
    plugin_id: String,
    timeout_ms: u64,
    ffi_limits: &FfiLimits,
) -> Result<(), AuditError> {
    // Flush is a control-class op (host-driven drain), so it honours the
    // control timeout rather than the per-event data timeout.
    let result = tokio::time::timeout(
        ffi_limits.control_timeout,
        tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), timeout_ms)),
    )
    .await;
    match result {
        Ok(Ok(out)) => {
            match mcpg_plugin_protocol::result_envelope::decode_result_envelope::<(), AuditError>(
                out.as_str(),
            ) {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(AuditError::WriteFailed {
                    reason: format!(
                        "native plugin '{plugin_id}' returned undecodable flush envelope: {e}",
                    ),
                }),
            }
        }
        Ok(Err(_)) => Err(AuditError::WriteFailed {
            reason: format!("native plugin '{plugin_id}' panicked during flush"),
        }),
        Err(_) => Err(AuditError::Timeout),
    }
}

/// Async dispatch helper for `LogSink::emit`. No return value; a
/// panic inside the plugin is silently dropped (best-effort
/// logging contract). Exposed for the seam test so it can verify
/// the JSON round-trip behaviour.
pub async fn dispatch_log_emit_via_vtable(
    vtable_fn: extern "C" fn(RPluginHandle, abi_stable::std_types::RStr<'_>),
    handle: SendHandle,
    plugin_id: String,
    record: LogRecord,
    inline_fast: bool,
    ffi_limits: &FfiLimits,
) {
    // Encode through the thread-local arena into an owned RString.
    let record_json = encode_to_rstring_via_arena(&record);
    // Instrument the host→plugin emit call. Sync `()` return,
    // so response size is 0; ok/err is timeout vs no-timeout.
    let call =
        crate::ffi_metering::FfiCall::begin(&plugin_id, "log_sink", "emit", record_json.len());
    // ABI v38: one slot, two dispatch policies (see `dispatch_tier1`). The borrowed
    // `RStr` is reborrowed from the owned `record_json` — on the stack for
    // inline, inside the closure for ferried.
    if inline_fast {
        vtable_fn(handle.ptr(), record_json.as_str().into());
        call.end_ok(0);
        return;
    }
    // Ferried (default, best-effort): a plugin panic silently drops the record;
    // the timeout bounds a hung plugin so it can't starve the runtime.
    let result = tokio::time::timeout(
        ffi_limits.data_timeout,
        tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), record_json.as_str().into())),
    )
    .await;
    if result.is_err() {
        call.end_err(0);
        tracing::warn!(
            plugin_id = %plugin_id,
            "native log_sink plugin timed out (record dropped)",
        );
        metrics::counter!(
            "mcpg_native_plugin_timeout_total",
            "plugin_id" => plugin_id.clone(),
        )
        .increment(1);
    } else {
        call.end_ok(0);
    }
}

/// Async dispatch helper for `LogSink::flush`. The wire
/// format is the `{"ok": null}` / `{"err": LogError}` envelope.
pub async fn dispatch_log_flush_via_vtable(
    vtable_fn: extern "C" fn(RPluginHandle, u64) -> abi_stable::std_types::RString,
    handle: SendHandle,
    plugin_id: String,
    timeout_ms: u64,
    ffi_limits: &FfiLimits,
) -> Result<(), LogError> {
    // Flush is control-class.
    let result = tokio::time::timeout(
        ffi_limits.control_timeout,
        tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), timeout_ms)),
    )
    .await;
    match result {
        Ok(Ok(out)) => {
            match mcpg_plugin_protocol::result_envelope::decode_result_envelope::<(), LogError>(
                out.as_str(),
            ) {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(LogError::Backend {
                    reason: format!(
                        "native plugin '{plugin_id}' returned undecodable flush envelope: {e}",
                    ),
                }),
            }
        }
        Ok(Err(_)) => Err(LogError::Backend {
            reason: format!("native plugin '{plugin_id}' panicked during flush"),
        }),
        Err(_) => Err(LogError::Timeout),
    }
}

pub struct NativeAuditSinkAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: AuditSinkVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    #[allow(dead_code)]
    alias: String,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeAuditSinkAdapter {}
unsafe impl Sync for NativeAuditSinkAdapter {}

impl NativeAuditSinkAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_audit_sink() {
            Some(vt) => clone_audit_sink(vt),
            None => {
                return Err(anyhow!("plugin does not export an AuditSink vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!(
                "native audit_sink plugin panicked during make (null handle)"
            ));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!(
                "native audit_sink plugin returned empty manifest JSON"
            ));
        }
        let manifest: PluginManifest = match serde_json::from_str(manifest_json.as_str()) {
            Ok(m) => m,
            Err(e) => {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                return Err(anyhow::Error::from(e)
                    .context("invalid manifest from native audit_sink plugin"));
            }
        };
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            alias,
            _host_bridge: host_bridge,
        })
    }
}

impl Drop for NativeAuditSinkAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

#[async_trait]
impl AuditSink for NativeAuditSinkAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn emit(&self, event: &AuditEvent) -> Result<AuditReceipt, AuditError> {
        dispatch_audit_emit_via_vtable(
            self.vtable.emit,
            SendHandle(self.handle),
            self.manifest.id.clone(),
            event.clone(),
            &self.library.ffi_limits,
        )
        .await
    }

    async fn flush(&self, timeout_ms: u64) -> Result<(), AuditError> {
        dispatch_audit_flush_via_vtable(
            self.vtable.flush,
            SendHandle(self.handle),
            self.manifest.id.clone(),
            timeout_ms,
            &self.library.ffi_limits,
        )
        .await
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

pub struct NativeLogSinkAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: LogSinkVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    #[allow(dead_code)]
    alias: String,
    /// v38 inline-dispatch opt-in (operator trust). Default false → ferried.
    /// For a sink this is largely off the request critical path (emit is often
    /// fire-and-forget), so the win is mostly reduced blocking-pool pressure.
    inline_fast: bool,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeLogSinkAdapter {}
unsafe impl Sync for NativeLogSinkAdapter {}

impl NativeLogSinkAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_log_sink() {
            Some(vt) => clone_log_sink(vt),
            None => {
                return Err(anyhow!("plugin does not export a LogSink vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!(
                "native log_sink plugin panicked during make (null handle)"
            ));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!(
                "native log_sink plugin returned empty manifest JSON"
            ));
        }
        let manifest: PluginManifest = match serde_json::from_str(manifest_json.as_str()) {
            Ok(m) => m,
            Err(e) => {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                return Err(
                    anyhow::Error::from(e).context("invalid manifest from native log_sink plugin")
                );
            }
        };
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            alias,
            inline_fast: false,
            _host_bridge: host_bridge,
        })
    }

    /// Opt this sink into inline emit dispatch (v38). See
    /// [`NativeToolGateAdapter::set_inline_fast`] for the trust contract.
    pub fn set_inline_fast(&mut self, enabled: bool) {
        self.inline_fast = enabled;
    }
}

impl Drop for NativeLogSinkAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

#[async_trait]
impl LogSink for NativeLogSinkAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn emit(&self, record: &LogRecord) {
        dispatch_log_emit_via_vtable(
            self.vtable.emit,
            SendHandle(self.handle),
            self.manifest.id.clone(),
            record.clone(),
            self.inline_fast,
            &self.library.ffi_limits,
        )
        .await;
    }

    async fn flush(&self, timeout: std::time::Duration) -> Result<(), LogError> {
        let timeout_ms = timeout.as_millis().min(u64::MAX as u128) as u64;
        dispatch_log_flush_via_vtable(
            self.vtable.flush,
            SendHandle(self.handle),
            self.manifest.id.clone(),
            timeout_ms,
            &self.library.ffi_limits,
        )
        .await
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

// ---------------------------------------------------------------------------
// TelemetrySink adapter
// ---------------------------------------------------------------------------

fn clone_telemetry_sink(vt: &TelemetrySinkVTable) -> TelemetrySinkVTable {
    TelemetrySinkVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        span_started: vt.span_started,
        span_ended: vt.span_ended,
        metric_recorded: vt.metric_recorded,
        log_recorded: vt.log_recorded,
        flush: vt.flush,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

/// Async dispatch helper for a best-effort telemetry emit slot
/// (span_started / span_ended / metric_recorded / log_recorded).
/// `()` return; timeout silently drops the event.
async fn dispatch_telemetry_emit_via_vtable<T: serde::Serialize + Send + 'static>(
    vtable_fn: extern "C" fn(RPluginHandle, abi_stable::std_types::RString),
    handle: SendHandle,
    plugin_id: String,
    slot: &'static str,
    payload: T,
    ffi_limits: &FfiLimits,
) {
    // Encode through the thread-local arena.
    let json = encode_to_rstring_via_arena(&payload);
    // Instrument the host→plugin emit call.
    let call = crate::ffi_metering::FfiCall::begin(&plugin_id, "telemetry_sink", slot, json.len());
    let result = tokio::time::timeout(
        ffi_limits.data_timeout,
        tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), json)),
    )
    .await;
    if result.is_err() {
        call.end_err(0);
        tracing::warn!(
            plugin_id = %plugin_id,
            "native telemetry_sink plugin timed out (event dropped)",
        );
        metrics::counter!(
            "mcpg_native_plugin_timeout_total",
            "plugin_id" => plugin_id.clone(),
        )
        .increment(1);
    } else {
        call.end_ok(0);
    }
}

/// Async dispatch helper for `TelemetrySink::flush`. The wire
/// format is the `{"ok": null}` / `{"err":
/// TelemetryError}` envelope.
pub async fn dispatch_telemetry_flush_via_vtable(
    vtable_fn: extern "C" fn(RPluginHandle, u64) -> abi_stable::std_types::RString,
    handle: SendHandle,
    plugin_id: String,
    timeout_ms: u64,
    ffi_limits: &FfiLimits,
) -> Result<(), TelemetryError> {
    // Flush is control-class.
    let result = tokio::time::timeout(
        ffi_limits.control_timeout,
        tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), timeout_ms)),
    )
    .await;
    match result {
        Ok(Ok(out)) => {
            match mcpg_plugin_protocol::result_envelope::decode_result_envelope::<(), TelemetryError>(
                out.as_str(),
            ) {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(TelemetryError::Backend {
                    reason: format!(
                        "native plugin '{plugin_id}' returned undecodable flush envelope: {e}",
                    ),
                }),
            }
        }
        Ok(Err(_)) => Err(TelemetryError::Backend {
            reason: format!("native plugin '{plugin_id}' panicked during flush"),
        }),
        Err(_) => Err(TelemetryError::Timeout),
    }
}

pub struct NativeTelemetrySinkAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: TelemetrySinkVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    #[allow(dead_code)]
    alias: String,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeTelemetrySinkAdapter {}
unsafe impl Sync for NativeTelemetrySinkAdapter {}

impl NativeTelemetrySinkAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_telemetry_sink() {
            Some(vt) => clone_telemetry_sink(vt),
            None => {
                return Err(anyhow!("plugin does not export a TelemetrySink vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!(
                "native telemetry_sink plugin panicked during make (null handle)"
            ));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!(
                "native telemetry_sink plugin returned empty manifest JSON"
            ));
        }
        let manifest: PluginManifest = match serde_json::from_str(manifest_json.as_str()) {
            Ok(m) => m,
            Err(e) => {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                return Err(anyhow::Error::from(e)
                    .context("invalid manifest from native telemetry_sink plugin"));
            }
        };
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            alias,
            _host_bridge: host_bridge,
        })
    }
}

impl Drop for NativeTelemetrySinkAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

#[async_trait]
impl TelemetrySink for NativeTelemetrySinkAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn span_started(&self, span: SpanStart) {
        dispatch_telemetry_emit_via_vtable(
            self.vtable.span_started,
            SendHandle(self.handle),
            self.manifest.id.clone(),
            "span_started",
            span,
            &self.library.ffi_limits,
        )
        .await;
    }

    async fn span_ended(&self, span: SpanEnd) {
        dispatch_telemetry_emit_via_vtable(
            self.vtable.span_ended,
            SendHandle(self.handle),
            self.manifest.id.clone(),
            "span_ended",
            span,
            &self.library.ffi_limits,
        )
        .await;
    }

    async fn metric_recorded(&self, metric: MetricPoint) {
        dispatch_telemetry_emit_via_vtable(
            self.vtable.metric_recorded,
            SendHandle(self.handle),
            self.manifest.id.clone(),
            "metric_recorded",
            metric,
            &self.library.ffi_limits,
        )
        .await;
    }

    async fn log_recorded(&self, record: &LogRecord) {
        dispatch_telemetry_emit_via_vtable(
            self.vtable.log_recorded,
            SendHandle(self.handle),
            self.manifest.id.clone(),
            "log_recorded",
            record.clone(),
            &self.library.ffi_limits,
        )
        .await;
    }

    async fn flush(&self, timeout: std::time::Duration) -> Result<(), TelemetryError> {
        let timeout_ms = timeout.as_millis().min(u64::MAX as u128) as u64;
        dispatch_telemetry_flush_via_vtable(
            self.vtable.flush,
            SendHandle(self.handle),
            self.manifest.id.clone(),
            timeout_ms,
            &self.library.ffi_limits,
        )
        .await
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

// ---------------------------------------------------------------------------
// MetricsSink adapter
// ---------------------------------------------------------------------------

fn clone_metrics_sink(vt: &MetricsSinkVTable) -> MetricsSinkVTable {
    MetricsSinkVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        emit: vt.emit,
        flush: vt.flush,
        render_text_exposition: vt.render_text_exposition,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

/// Async dispatch helper for `MetricsSink::emit`. No return value;
/// a panic inside the plugin is silently dropped (best-effort
/// metrics contract). Exposed for the seam test so it can verify
/// the JSON round-trip behaviour.
pub async fn dispatch_metrics_emit_via_vtable(
    vtable_fn: extern "C" fn(RPluginHandle, abi_stable::std_types::RString),
    handle: SendHandle,
    plugin_id: String,
    metric: MetricPoint,
    ffi_limits: &FfiLimits,
) {
    // Encode via the thread-local arena to
    // avoid the per-call double-alloc (serde String + RString
    // copy). MetricsSink emits are the hottest sink path.
    let metric_json = encode_to_rstring_via_arena(&metric);
    // Instrument the host→plugin emit call.
    let call =
        crate::ffi_metering::FfiCall::begin(&plugin_id, "metrics_sink", "emit", metric_json.len());
    let result = tokio::time::timeout(
        ffi_limits.data_timeout,
        tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), metric_json)),
    )
    .await;
    if result.is_err() {
        call.end_err(0);
        tracing::warn!(
            plugin_id = %plugin_id,
            "native metrics_sink plugin timed out (metric dropped)",
        );
        metrics::counter!(
            "mcpg_native_plugin_timeout_total",
            "plugin_id" => plugin_id.clone(),
        )
        .increment(1);
    } else {
        call.end_ok(0);
    }
}

/// Async dispatch helper for `MetricsSink::flush`. The wire
/// format is the `{"ok": null}` / `{"err": MetricsError}`
/// envelope.
pub async fn dispatch_metrics_flush_via_vtable(
    vtable_fn: extern "C" fn(RPluginHandle, u64) -> abi_stable::std_types::RString,
    handle: SendHandle,
    plugin_id: String,
    timeout_ms: u64,
    ffi_limits: &FfiLimits,
) -> Result<(), MetricsError> {
    // Flush is control-class.
    let result = tokio::time::timeout(
        ffi_limits.control_timeout,
        tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), timeout_ms)),
    )
    .await;
    match result {
        Ok(Ok(out)) => {
            match mcpg_plugin_protocol::result_envelope::decode_result_envelope::<(), MetricsError>(
                out.as_str(),
            ) {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(MetricsError::Backend {
                    reason: format!(
                        "native plugin '{plugin_id}' returned undecodable flush envelope: {e}",
                    ),
                }),
            }
        }
        Ok(Err(_)) => Err(MetricsError::Backend {
            reason: format!("native plugin '{plugin_id}' panicked during flush"),
        }),
        Err(_) => Err(MetricsError::Timeout),
    }
}

pub struct NativeMetricsSinkAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: MetricsSinkVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    #[allow(dead_code)]
    alias: String,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeMetricsSinkAdapter {}
unsafe impl Sync for NativeMetricsSinkAdapter {}

impl NativeMetricsSinkAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_metrics_sink() {
            Some(vt) => clone_metrics_sink(vt),
            None => {
                return Err(anyhow!("plugin does not export a MetricsSink vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!(
                "native metrics_sink plugin panicked during make (null handle)"
            ));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!(
                "native metrics_sink plugin returned empty manifest JSON"
            ));
        }
        let manifest: PluginManifest = match serde_json::from_str(manifest_json.as_str()) {
            Ok(m) => m,
            Err(e) => {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                return Err(anyhow::Error::from(e)
                    .context("invalid manifest from native metrics_sink plugin"));
            }
        };
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            alias,
            _host_bridge: host_bridge,
        })
    }
}

impl Drop for NativeMetricsSinkAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

#[async_trait]
impl MetricsSink for NativeMetricsSinkAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn emit(&self, metric: &MetricPoint) {
        dispatch_metrics_emit_via_vtable(
            self.vtable.emit,
            SendHandle(self.handle),
            self.manifest.id.clone(),
            metric.clone(),
            &self.library.ffi_limits,
        )
        .await;
    }

    async fn flush(&self, timeout: std::time::Duration) -> Result<(), MetricsError> {
        let timeout_ms = timeout.as_millis().min(u64::MAX as u128) as u64;
        dispatch_metrics_flush_via_vtable(
            self.vtable.flush,
            SendHandle(self.handle),
            self.manifest.id.clone(),
            timeout_ms,
            &self.library.ffi_limits,
        )
        .await
    }

    async fn render_text_exposition(&self) -> Option<String> {
        // Dispatch through the vtable's optional
        // render slot. Empty `RString` maps to `None` so the
        // gateway's `/metrics` route can short-circuit when the
        // backing plugin is push-only. Bounce through
        // `spawn_blocking` + the same bounded timeout the other
        // native dispatch helpers use.
        let plugin_id = self.manifest.id.clone();
        let vtable_fn = self.vtable.render_text_exposition;
        let handle = SendHandle(self.handle);
        let result = tokio::time::timeout(
            self.library.ffi_limits.control_timeout,
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr())),
        )
        .await;
        match result {
            Ok(Ok(out)) => {
                if out.as_str().is_empty() {
                    None
                } else {
                    Some(out.as_str().to_owned())
                }
            }
            Ok(Err(_)) | Err(_) => {
                tracing::warn!(
                    plugin_id = %plugin_id,
                    "native metrics_sink plugin panicked or timed out during render"
                );
                None
            }
        }
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

// ---------------------------------------------------------------------------
// Store + Cache adapters
// ---------------------------------------------------------------------------

fn clone_store(vt: &StoreVTable) -> StoreVTable {
    StoreVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        supported_roles_json: vt.supported_roles_json,
        get: vt.get,
        put: vt.put,
        delete: vt.delete,
        list: vt.list,
        compare_and_swap: vt.compare_and_swap,
        append: vt.append,
        watch: vt.watch,
        cancel_watch: vt.cancel_watch,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

fn clone_cache(vt: &CacheVTable) -> CacheVTable {
    CacheVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        supported_namespaces_json: vt.supported_namespaces_json,
        serves_any_namespace: vt.serves_any_namespace,
        get: vt.get,
        put: vt.put,
        delete: vt.delete,
        clear: vt.clear,
        incr: vt.incr,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

/// Call a sync vtable slot that returns an `RString`. Used for
/// result-returning store/cache ops. `spawn_blocking`-wrapped with the
/// caller-supplied data-tier timeout (the store/cache adapters thread
/// their per-plugin `self.library.ffi_limits.data_timeout`).
///
/// Instruments the host→plugin call with
/// [`FfiCall`](crate::ffi_metering::FfiCall) so request / response
/// payload sizes + call duration land in the
/// `mcpg_plugin_ffi_call_duration_seconds` /
/// `mcpg_plugin_payload_bytes` histograms. Callers supply the
/// bounded enum labels (`plugin_id`, `kind`, `slot`).
async fn call_json_vtable(
    vtable_fn: extern "C" fn(
        RPluginHandle,
        abi_stable::std_types::RString,
    ) -> abi_stable::std_types::RString,
    handle: SendHandle,
    args: serde_json::Value,
    plugin_id: &str,
    kind: &'static str,
    slot: &'static str,
    data_timeout: std::time::Duration,
) -> Option<abi_stable::std_types::RString> {
    let json_str = serde_json::to_string(&args).unwrap_or_else(|_| "{}".into());
    let req_bytes = json_str.len();
    let call = crate::ffi_metering::FfiCall::begin(plugin_id, kind, slot, req_bytes);
    let json = abi_stable::std_types::RString::from(json_str);
    let result = tokio::time::timeout(
        data_timeout,
        tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), json)),
    )
    .await
    .ok()
    .and_then(|r| r.ok());
    match &result {
        Some(out) => call.end_ok(out.len()),
        None => call.end_err(0),
    }
    result
}

/// Decode the `{"ok": ..., "err": ...}` wire for store ops.
fn decode_store_wire<T: serde::de::DeserializeOwned>(
    raw: &str,
    plugin_id: &str,
) -> Result<T, StoreError> {
    if raw.is_empty() {
        return Err(StoreError::Backend {
            reason: format!("native plugin '{plugin_id}' panicked"),
        });
    }
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Wire<T> {
        Ok { ok: T },
        Err { err: StoreError },
    }
    match serde_json::from_str::<Wire<T>>(raw) {
        Ok(Wire::Ok { ok }) => Ok(ok),
        Ok(Wire::Err { err }) => Err(err),
        Err(e) => Err(StoreError::Backend {
            reason: format!("native plugin '{plugin_id}' returned malformed response: {e}"),
        }),
    }
}

/// Decode the `{"ok": null}` / `{"err": StoreError}` envelope for
/// store `put`/`delete`. An empty RString
/// (panic sentinel) is treated as a transport-class
/// `StoreError::Backend` so the caller doesn't silently swallow
/// plugin failures.
fn decode_store_unit(raw: &str, plugin_id: &str) -> Result<(), StoreError> {
    match mcpg_plugin_protocol::result_envelope::decode_result_envelope::<(), StoreError>(raw) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(StoreError::Backend {
            reason: format!("native plugin '{plugin_id}' returned undecodable envelope: {e}",),
        }),
    }
}

/// Decode the `{"ok": null}` / `{"err": CacheError}` envelope for
/// cache `put`/`clear`.
fn decode_cache_unit(raw: &str, plugin_id: &str) -> Result<(), CacheError> {
    match mcpg_plugin_protocol::result_envelope::decode_result_envelope::<(), CacheError>(raw) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(CacheError::Backend {
            reason: format!("native plugin '{plugin_id}' returned undecodable envelope: {e}",),
        }),
    }
}

fn decode_cache_wire<T: serde::de::DeserializeOwned>(
    raw: &str,
    plugin_id: &str,
) -> Result<T, CacheError> {
    if raw.is_empty() {
        return Err(CacheError::Backend {
            reason: format!("native plugin '{plugin_id}' panicked"),
        });
    }
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Wire<T> {
        Ok { ok: T },
        Err { err: CacheError },
    }
    match serde_json::from_str::<Wire<T>>(raw) {
        Ok(Wire::Ok { ok }) => Ok(ok),
        Ok(Wire::Err { err }) => Err(err),
        Err(e) => Err(CacheError::Backend {
            reason: format!("native plugin '{plugin_id}' returned malformed response: {e}"),
        }),
    }
}

pub struct NativeStoreAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: StoreVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    supported_roles: Vec<StoreRole>,
    #[allow(dead_code)]
    alias: String,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeStoreAdapter {}
unsafe impl Sync for NativeStoreAdapter {}

impl NativeStoreAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_store() {
            Some(vt) => clone_store(vt),
            None => {
                return Err(anyhow!("plugin does not export a Store vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!("native store plugin panicked during make"));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!("native store plugin returned empty manifest JSON"));
        }
        let manifest: PluginManifest =
            serde_json::from_str(manifest_json.as_str()).map_err(|e| {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                anyhow::Error::from(e).context("invalid manifest from native store plugin")
            })?;
        let roles_json = (vt.supported_roles_json)(handle);
        let supported_roles: Vec<StoreRole> =
            serde_json::from_str(roles_json.as_str()).map_err(|e| {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                anyhow::Error::from(e).context("invalid supported_roles JSON")
            })?;
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            supported_roles,
            alias,
            _host_bridge: host_bridge,
        })
    }
}

impl Drop for NativeStoreAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

#[async_trait]
impl Store for NativeStoreAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn supported_roles(&self) -> Vec<StoreRole> {
        self.supported_roles.clone()
    }

    async fn get(&self, role: StoreRole, key: &str) -> Result<Option<StoreValue>, StoreError> {
        let raw = call_json_vtable(
            self.vtable.get,
            SendHandle(self.handle),
            serde_json::json!({ "role": role, "key": key }),
            &self.manifest.id,
            "store",
            "get",
            self.library.ffi_limits.data_timeout,
        )
        .await
        .ok_or(StoreError::Backend {
            reason: format!("native plugin '{}' timed out", self.manifest.id),
        })?;
        let opt: Option<StoreValueWire> = decode_store_wire(raw.as_str(), &self.manifest.id)?;
        Ok(opt.map(StoreValue::from))
    }

    async fn put(&self, role: StoreRole, key: &str, value: StoreValue) -> Result<(), StoreError> {
        let wire: StoreValueWire = value.into();
        let raw = call_json_vtable(
            self.vtable.put,
            SendHandle(self.handle),
            serde_json::json!({ "role": role, "key": key, "value": wire }),
            &self.manifest.id,
            "store",
            "put",
            self.library.ffi_limits.data_timeout,
        )
        .await
        .ok_or(StoreError::Backend {
            reason: format!("native plugin '{}' timed out", self.manifest.id),
        })?;
        decode_store_unit(raw.as_str(), &self.manifest.id)
    }

    async fn delete(&self, role: StoreRole, key: &str) -> Result<(), StoreError> {
        let raw = call_json_vtable(
            self.vtable.delete,
            SendHandle(self.handle),
            serde_json::json!({ "role": role, "key": key }),
            &self.manifest.id,
            "store",
            "delete",
            self.library.ffi_limits.data_timeout,
        )
        .await
        .ok_or(StoreError::Backend {
            reason: format!("native plugin '{}' timed out", self.manifest.id),
        })?;
        decode_store_unit(raw.as_str(), &self.manifest.id)
    }

    async fn list(
        &self,
        role: StoreRole,
        prefix: &str,
        cursor: Option<String>,
    ) -> Result<StorePage, StoreError> {
        let raw = call_json_vtable(
            self.vtable.list,
            SendHandle(self.handle),
            serde_json::json!({ "role": role, "prefix": prefix, "cursor": cursor }),
            &self.manifest.id,
            "store",
            "list",
            self.library.ffi_limits.data_timeout,
        )
        .await
        .ok_or(StoreError::Backend {
            reason: format!("native plugin '{}' timed out", self.manifest.id),
        })?;
        let page: StorePageWire = decode_store_wire(raw.as_str(), &self.manifest.id)?;
        Ok(page.into())
    }

    async fn compare_and_swap(
        &self,
        role: StoreRole,
        key: &str,
        expected: Option<StoreValue>,
        new: StoreValue,
    ) -> Result<bool, StoreError> {
        let expected_wire: Option<StoreValueWire> = expected.map(Into::into);
        let new_wire: StoreValueWire = new.into();
        let raw = call_json_vtable(
            self.vtable.compare_and_swap,
            SendHandle(self.handle),
            serde_json::json!({
                "role": role,
                "key": key,
                "expected": expected_wire,
                "new": new_wire,
            }),
            &self.manifest.id,
            "store",
            "compare_and_swap",
            self.library.ffi_limits.data_timeout,
        )
        .await
        .ok_or(StoreError::Backend {
            reason: format!("native plugin '{}' timed out", self.manifest.id),
        })?;
        decode_store_wire(raw.as_str(), &self.manifest.id)
    }

    async fn append(
        &self,
        role: StoreRole,
        key: &str,
        value: StoreValue,
    ) -> Result<AppendResult, StoreError> {
        let wire: StoreValueWire = value.into();
        let raw = call_json_vtable(
            self.vtable.append,
            SendHandle(self.handle),
            serde_json::json!({ "role": role, "key": key, "value": wire }),
            &self.manifest.id,
            "store",
            "append",
            self.library.ffi_limits.data_timeout,
        )
        .await
        .ok_or(StoreError::Backend {
            reason: format!("native plugin '{}' timed out", self.manifest.id),
        })?;
        decode_store_wire(raw.as_str(), &self.manifest.id)
    }

    async fn watch(&self, role: StoreRole, key: &str) -> Result<BoxStoreEventStream, StoreError> {
        let (bridge_ptr_raw, sink, rx) = make_stream_bridge(&self.manifest.id);
        // Wrap the pointer in a Send-safe newtype so the future
        // carrying it across `.await` satisfies `Send`.
        let bridge_ptr = SendPtr(bridge_ptr_raw);
        let args = serde_json::json!({ "role": role, "key": key });
        let args_json = abi_stable::std_types::RString::from(
            serde_json::to_string(&args).unwrap_or_else(|_| "{}".into()),
        );
        let vtable_fn = self.vtable.watch;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        let spawn_result =
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), args_json, sink)).await;
        let result = match spawn_result {
            Ok(r) => r,
            Err(_) => {
                // `spawn_blocking` join error means the plugin's
                // `watch` slot panicked. Free the bridge — the
                // plugin never installed a callback pointer, so
                // there's nothing pending.
                // SAFETY: bridge_ptr came from `Box::into_raw` in
                // `make_stream_bridge` and has not been freed.
                unsafe {
                    drop(Box::from_raw(bridge_ptr.0));
                }
                return Err(StoreError::Backend {
                    reason: format!("native plugin '{plugin_id}' panicked during watch"),
                });
            }
        };
        if result.handle == 0 {
            // SAFETY: same as above — plugin declined to install.
            unsafe {
                drop(Box::from_raw(bridge_ptr.0));
            }
            let err_str = result.error_json.as_str();
            let err =
                serde_json::from_str::<StoreError>(err_str).unwrap_or_else(|_| {
                    StoreError::Backend {
                        reason: format!(
                            "native plugin '{plugin_id}' returned undecodable watch error",
                        ),
                    }
                });
            return Err(err);
        }
        let guard = StreamCancelGuard {
            library: Arc::clone(&self.library),
            cancel_fn: self.vtable.cancel_watch,
            plugin_handle: self.handle,
            watch_handle: result.handle,
            bridge_ptr: bridge_ptr.0,
        };
        Ok(Box::pin(StoreWatchStream { rx, _guard: guard }))
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

/// Stream adapter: pulls JSON strings from the bridge channel,
/// parses each as `StoreEventWire`, yields `StoreEvent`. Drops
/// the cancel guard when the stream itself drops.
struct StoreWatchStream {
    rx: tokio::sync::mpsc::Receiver<String>,
    _guard: StreamCancelGuard,
}

impl futures_core::Stream for StoreWatchStream {
    type Item = StoreEvent;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            match self.rx.poll_recv(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                std::task::Poll::Ready(Some(json)) => {
                    match serde_json::from_str::<StoreEventWire>(&json) {
                        Ok(wire) => {
                            return std::task::Poll::Ready(Some(wire.into()));
                        }
                        Err(_) => {
                            // Malformed event — skip + keep
                            // polling. Log once per event would
                            // be cardinality-heavy; rely on
                            // plugin-side audit logs to surface
                            // serialisation bugs.
                            continue;
                        }
                    }
                }
            }
        }
    }
}

pub struct NativeCacheAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: CacheVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    supported_namespaces: Vec<String>,
    serves_any: bool,
    #[allow(dead_code)]
    alias: String,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeCacheAdapter {}
unsafe impl Sync for NativeCacheAdapter {}

impl NativeCacheAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_cache() {
            Some(vt) => clone_cache(vt),
            None => {
                return Err(anyhow!("plugin does not export a Cache vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!("native cache plugin panicked during make"));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!("native cache plugin returned empty manifest JSON"));
        }
        let manifest: PluginManifest =
            serde_json::from_str(manifest_json.as_str()).map_err(|e| {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                anyhow::Error::from(e).context("invalid manifest from native cache plugin")
            })?;
        let ns_json = (vt.supported_namespaces_json)(handle);
        let supported_namespaces: Vec<String> =
            serde_json::from_str(ns_json.as_str()).map_err(|e| {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                anyhow::Error::from(e).context("invalid supported_namespaces JSON")
            })?;
        let serves_any = (vt.serves_any_namespace)(handle) != 0;
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            supported_namespaces,
            serves_any,
            alias,
            _host_bridge: host_bridge,
        })
    }
}

impl Drop for NativeCacheAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

#[async_trait]
impl Cache for NativeCacheAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn supported_namespaces(&self) -> Vec<String> {
        self.supported_namespaces.clone()
    }

    fn serves_any_namespace(&self) -> bool {
        self.serves_any
    }

    async fn get(&self, ns: &str, key: &str) -> Option<bytes::Bytes> {
        let raw = call_json_vtable(
            self.vtable.get,
            SendHandle(self.handle),
            serde_json::json!({ "ns": ns, "key": key }),
            &self.manifest.id,
            "cache",
            "get",
            self.library.ffi_limits.data_timeout,
        )
        .await?;
        let opt: Option<Vec<u8>> = serde_json::from_str(raw.as_str()).ok().flatten();
        opt.map(bytes::Bytes::from)
    }

    async fn put(
        &self,
        ns: &str,
        key: &str,
        value: bytes::Bytes,
        ttl: std::time::Duration,
    ) -> Result<(), CacheError> {
        let raw = call_json_vtable(
            self.vtable.put,
            SendHandle(self.handle),
            serde_json::json!({
                "ns": ns,
                "key": key,
                "value": value.to_vec(),
                "ttl_ms": ttl.as_millis().min(u64::MAX as u128) as u64,
            }),
            &self.manifest.id,
            "cache",
            "put",
            self.library.ffi_limits.data_timeout,
        )
        .await
        .ok_or(CacheError::Backend {
            reason: format!("native plugin '{}' timed out", self.manifest.id),
        })?;
        decode_cache_unit(raw.as_str(), &self.manifest.id)
    }

    async fn delete(&self, ns: &str, key: &str) {
        // Instrument the FFI call inline since this slot's
        // return value is `()` (best-effort delete) — no result to
        // funnel through `call_json_vtable`.
        let args = serde_json::json!({ "ns": ns, "key": key });
        let json_str = serde_json::to_string(&args).unwrap_or_else(|_| "{}".into());
        let req_bytes = json_str.len();
        let call =
            crate::ffi_metering::FfiCall::begin(&self.manifest.id, "cache", "delete", req_bytes);
        let json = abi_stable::std_types::RString::from(json_str);
        let vt_fn = self.vtable.delete;
        let handle = SendHandle(self.handle);
        let outcome = tokio::time::timeout(
            self.library.ffi_limits.data_timeout,
            tokio::task::spawn_blocking(move || vt_fn(handle.ptr(), json)),
        )
        .await;
        match outcome {
            Ok(Ok(_)) => call.end_ok(0),
            _ => call.end_err(0),
        }
    }

    async fn clear(&self, ns: &str) -> Result<(), CacheError> {
        let raw = call_json_vtable(
            self.vtable.clear,
            SendHandle(self.handle),
            serde_json::json!({ "ns": ns }),
            &self.manifest.id,
            "cache",
            "clear",
            self.library.ffi_limits.data_timeout,
        )
        .await
        .ok_or(CacheError::Backend {
            reason: format!("native plugin '{}' timed out", self.manifest.id),
        })?;
        decode_cache_unit(raw.as_str(), &self.manifest.id)
    }

    async fn incr(
        &self,
        ns: &str,
        key: &str,
        by: i64,
        ttl: std::time::Duration,
    ) -> Result<i64, CacheError> {
        let raw = call_json_vtable(
            self.vtable.incr,
            SendHandle(self.handle),
            serde_json::json!({
                "ns": ns,
                "key": key,
                "by": by,
                "ttl_ms": ttl.as_millis().min(u64::MAX as u128) as u64,
            }),
            &self.manifest.id,
            "cache",
            "incr",
            self.library.ffi_limits.data_timeout,
        )
        .await
        .ok_or(CacheError::Backend {
            reason: format!("native plugin '{}' timed out", self.manifest.id),
        })?;
        decode_cache_wire(raw.as_str(), &self.manifest.id)
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

// ---------------------------------------------------------------------------
// SecretProvider + ConfigProvider adapters
// ---------------------------------------------------------------------------

fn clone_secret_provider(vt: &SecretProviderVTable) -> SecretProviderVTable {
    SecretProviderVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        supported_schemes_json: vt.supported_schemes_json,
        get: vt.get,
        watch: vt.watch,
        cancel_watch: vt.cancel_watch,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

fn clone_config_provider(vt: &ConfigProviderVTable) -> ConfigProviderVTable {
    ConfigProviderVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        supported_schemes_json: vt.supported_schemes_json,
        snapshot: vt.snapshot,
        watch: vt.watch,
        cancel_watch: vt.cancel_watch,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

pub struct NativeSecretProviderAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: SecretProviderVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    supported_schemes: Vec<String>,
    #[allow(dead_code)]
    alias: String,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeSecretProviderAdapter {}
unsafe impl Sync for NativeSecretProviderAdapter {}

impl NativeSecretProviderAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_secret_provider() {
            Some(vt) => clone_secret_provider(vt),
            None => {
                return Err(anyhow!("plugin does not export a SecretProvider vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!(
                "native secret_provider plugin panicked during make"
            ));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!(
                "native secret_provider plugin returned empty manifest"
            ));
        }
        let manifest: PluginManifest =
            serde_json::from_str(manifest_json.as_str()).map_err(|e| {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                anyhow::Error::from(e).context("invalid manifest from secret_provider")
            })?;
        let schemes_json = (vt.supported_schemes_json)(handle);
        let supported_schemes: Vec<String> =
            serde_json::from_str(schemes_json.as_str()).map_err(|e| {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                anyhow::Error::from(e).context("invalid supported_schemes")
            })?;
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            supported_schemes,
            alias,
            _host_bridge: host_bridge,
        })
    }
}

impl Drop for NativeSecretProviderAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

#[async_trait]
impl SecretProvider for NativeSecretProviderAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn supported_schemes(&self) -> Vec<String> {
        self.supported_schemes.clone()
    }

    async fn get(&self, secret_ref: &str) -> Result<SecretValue, SecretError> {
        let vtable_fn = self.vtable.get;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        // Instrument the host→plugin get call.
        let call = crate::ffi_metering::FfiCall::begin(
            &plugin_id,
            "secret_provider",
            "get",
            secret_ref.len(),
        );
        let reference = abi_stable::std_types::RString::from(secret_ref);
        let result = tokio::time::timeout(
            self.library.ffi_limits.data_timeout,
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), reference)),
        )
        .await;
        let raw = match result {
            Ok(Ok(r)) => r,
            _ => {
                call.end_err(0);
                return Err(SecretError::Backend {
                    reason: format!("native plugin '{plugin_id}' timed out or panicked"),
                });
            }
        };
        let resp_bytes = raw.len();
        let raw_str = raw.as_str();
        if raw_str.is_empty() {
            call.end_err(resp_bytes);
            return Err(SecretError::Backend {
                reason: format!("native plugin '{plugin_id}' panicked"),
            });
        }
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Ok { ok: SecretValueWire },
            Err { err: SecretError },
        }
        match serde_json::from_str::<Wire>(raw_str) {
            Ok(Wire::Ok { ok }) => {
                call.end_ok(resp_bytes);
                Ok(ok.into())
            }
            Ok(Wire::Err { err }) => {
                call.end_err(resp_bytes);
                Err(err)
            }
            Err(e) => {
                call.end_err(resp_bytes);
                Err(SecretError::Backend {
                    reason: format!("native plugin '{plugin_id}' malformed: {e}"),
                })
            }
        }
    }

    async fn watch(&self, secret_ref: &str) -> Result<BoxSecretRotationStream, SecretError> {
        let (bridge_ptr_raw, sink, rx) = make_stream_bridge(&self.manifest.id);
        let bridge_ptr = SendPtr(bridge_ptr_raw);
        let reference = abi_stable::std_types::RString::from(secret_ref);
        let vtable_fn = self.vtable.watch;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        // Instrument the host→plugin watch install call only.
        // Rotation events are emitted on the plugin thread through
        // the stream bridge and aren't double-counted here.
        let call = crate::ffi_metering::FfiCall::begin(
            &plugin_id,
            "secret_provider",
            "watch",
            secret_ref.len(),
        );
        let spawn_result =
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), reference, sink)).await;
        let result = match spawn_result {
            Ok(r) => r,
            Err(_) => {
                call.end_err(0);
                unsafe {
                    drop(Box::from_raw(bridge_ptr.0));
                }
                return Err(SecretError::Backend {
                    reason: format!("native plugin '{plugin_id}' panicked during watch"),
                });
            }
        };
        let resp_bytes = result.error_json.len();
        if result.handle == 0 {
            call.end_err(resp_bytes);
            unsafe {
                drop(Box::from_raw(bridge_ptr.0));
            }
            let err = serde_json::from_str::<SecretError>(result.error_json.as_str()).unwrap_or(
                SecretError::UnsupportedScheme {
                    scheme: "watch".into(),
                },
            );
            return Err(err);
        }
        call.end_ok(resp_bytes);
        let guard = StreamCancelGuard {
            library: Arc::clone(&self.library),
            cancel_fn: self.vtable.cancel_watch,
            plugin_handle: self.handle,
            watch_handle: result.handle,
            bridge_ptr: bridge_ptr.0,
        };
        Ok(Box::pin(SecretWatchStream { rx, _guard: guard }))
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

struct SecretWatchStream {
    rx: tokio::sync::mpsc::Receiver<String>,
    _guard: StreamCancelGuard,
}

impl futures_core::Stream for SecretWatchStream {
    type Item = SecretRotation;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            match self.rx.poll_recv(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                std::task::Poll::Ready(Some(json)) => {
                    match serde_json::from_str::<SecretRotationWire>(&json) {
                        Ok(wire) => {
                            return std::task::Poll::Ready(Some(wire.into()));
                        }
                        Err(_) => continue,
                    }
                }
            }
        }
    }
}

pub struct NativeConfigProviderAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: ConfigProviderVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    supported_schemes: Vec<String>,
    #[allow(dead_code)]
    alias: String,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeConfigProviderAdapter {}
unsafe impl Sync for NativeConfigProviderAdapter {}

impl NativeConfigProviderAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_config_provider() {
            Some(vt) => clone_config_provider(vt),
            None => {
                return Err(anyhow!("plugin does not export a ConfigProvider vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!(
                "native config_provider plugin panicked during make"
            ));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!(
                "native config_provider plugin returned empty manifest"
            ));
        }
        let manifest: PluginManifest =
            serde_json::from_str(manifest_json.as_str()).map_err(|e| {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                anyhow::Error::from(e).context("invalid manifest from config_provider")
            })?;
        let schemes_json = (vt.supported_schemes_json)(handle);
        let supported_schemes: Vec<String> =
            serde_json::from_str(schemes_json.as_str()).map_err(|e| {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                anyhow::Error::from(e).context("invalid supported_schemes")
            })?;
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            supported_schemes,
            alias,
            _host_bridge: host_bridge,
        })
    }
}

impl Drop for NativeConfigProviderAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

#[async_trait]
impl ConfigProvider for NativeConfigProviderAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn supported_schemes(&self) -> Vec<String> {
        self.supported_schemes.clone()
    }

    async fn snapshot(&self, reference: &str) -> Result<ConfigSnapshot, ConfigError> {
        let vtable_fn = self.vtable.snapshot;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        // Instrument the host→plugin snapshot call.
        let call = crate::ffi_metering::FfiCall::begin(
            &plugin_id,
            "config_provider",
            "snapshot",
            reference.len(),
        );
        let r = abi_stable::std_types::RString::from(reference);
        let result = tokio::time::timeout(
            self.library.ffi_limits.control_timeout,
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), r)),
        )
        .await;
        let raw = match result {
            Ok(Ok(r)) => r,
            _ => {
                call.end_err(0);
                return Err(ConfigError::Backend {
                    reason: format!("native plugin '{plugin_id}' timed out or panicked"),
                });
            }
        };
        let resp_bytes = raw.len();
        let raw_str = raw.as_str();
        if raw_str.is_empty() {
            call.end_err(resp_bytes);
            return Err(ConfigError::Backend {
                reason: format!("native plugin '{plugin_id}' panicked"),
            });
        }
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Ok { ok: ConfigSnapshot },
            Err { err: ConfigError },
        }
        match serde_json::from_str::<Wire>(raw_str) {
            Ok(Wire::Ok { ok }) => {
                call.end_ok(resp_bytes);
                Ok(ok)
            }
            Ok(Wire::Err { err }) => {
                call.end_err(resp_bytes);
                Err(err)
            }
            Err(e) => {
                call.end_err(resp_bytes);
                Err(ConfigError::Backend {
                    reason: format!("native plugin '{plugin_id}' malformed: {e}"),
                })
            }
        }
    }

    async fn watch(&self, reference: &str) -> Result<BoxConfigDeltaStream, ConfigError> {
        let (bridge_ptr_raw, sink, rx) = make_stream_bridge(&self.manifest.id);
        let bridge_ptr = SendPtr(bridge_ptr_raw);
        let r = abi_stable::std_types::RString::from(reference);
        let vtable_fn = self.vtable.watch;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        // Instrument the host→plugin watch install call only.
        let call = crate::ffi_metering::FfiCall::begin(
            &plugin_id,
            "config_provider",
            "watch",
            reference.len(),
        );
        let spawn_result =
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), r, sink)).await;
        let result = match spawn_result {
            Ok(r) => r,
            Err(_) => {
                call.end_err(0);
                unsafe {
                    drop(Box::from_raw(bridge_ptr.0));
                }
                return Err(ConfigError::Backend {
                    reason: format!("native plugin '{plugin_id}' panicked during watch"),
                });
            }
        };
        let resp_bytes = result.error_json.len();
        if result.handle == 0 {
            call.end_err(resp_bytes);
            unsafe {
                drop(Box::from_raw(bridge_ptr.0));
            }
            let err = serde_json::from_str::<ConfigError>(result.error_json.as_str()).unwrap_or(
                ConfigError::UnsupportedScheme {
                    scheme: "watch".into(),
                },
            );
            return Err(err);
        }
        call.end_ok(resp_bytes);
        let guard = StreamCancelGuard {
            library: Arc::clone(&self.library),
            cancel_fn: self.vtable.cancel_watch,
            plugin_handle: self.handle,
            watch_handle: result.handle,
            bridge_ptr: bridge_ptr.0,
        };
        Ok(Box::pin(ConfigWatchStream { rx, _guard: guard }))
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

struct ConfigWatchStream {
    rx: tokio::sync::mpsc::Receiver<String>,
    _guard: StreamCancelGuard,
}

impl futures_core::Stream for ConfigWatchStream {
    type Item = ConfigDelta;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            match self.rx.poll_recv(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                std::task::Poll::Ready(Some(json)) => {
                    match serde_json::from_str::<ConfigDelta>(&json) {
                        Ok(delta) => {
                            return std::task::Poll::Ready(Some(delta));
                        }
                        Err(_) => continue,
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyEngine adapter
// ---------------------------------------------------------------------------

fn clone_policy_engine(vt: &PolicyEngineVTable) -> PolicyEngineVTable {
    PolicyEngineVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        name: vt.name,
        evaluate: vt.evaluate,
        policy_version: vt.policy_version,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

pub struct NativePolicyEngineAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: PolicyEngineVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    name: String,
    #[allow(dead_code)]
    alias: String,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativePolicyEngineAdapter {}
unsafe impl Sync for NativePolicyEngineAdapter {}

impl NativePolicyEngineAdapter {
    /// Construct a PolicyEngine adapter. The optional `cluster` ref
    /// lets the engine opt into cluster-coordinated state (cedar
    /// entity-set sync, OPA bundle reload coordination, …). The
    /// cluster ref is folded into the
    /// [`HostBridge`](crate::host_bridge::HostBridge) and surfaced
    /// via [`HostHandleRef::cluster()`]; the make slot itself does
    /// not take a separate cluster arg.
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
        cluster: Option<mcpg_plugin_protocol::abi::ClusterClientRef>,
    ) -> Result<Self> {
        let vt = match library.registration.first_policy_engine() {
            Some(vt) => clone_policy_engine(vt),
            None => {
                return Err(anyhow!("plugin does not export a PolicyEngine vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(cluster, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!("native policy_engine plugin panicked during make"));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!(
                "native policy_engine plugin returned empty manifest"
            ));
        }
        let manifest: PluginManifest =
            serde_json::from_str(manifest_json.as_str()).map_err(|e| {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                anyhow::Error::from(e).context("invalid manifest from policy_engine")
            })?;
        let name_rstr = (vt.name)(handle);
        if name_rstr.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!("native policy_engine plugin returned empty name"));
        }
        let name = name_rstr.as_str().to_owned();
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            name,
            alias,
            _host_bridge: host_bridge,
        })
    }
}

impl Drop for NativePolicyEngineAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

#[async_trait]
impl PolicyEngine for NativePolicyEngineAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn evaluate(
        &self,
        decision_point: &str,
        input: &serde_json::Value,
        context: &PluginContext,
    ) -> PolicyDecision {
        let args = serde_json::json!({
            "decision_point": decision_point,
            "input": input,
            "context": context,
        });
        let args_str = serde_json::to_string(&args).unwrap_or_else(|_| "{}".into());
        let req_bytes = args_str.len();
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "policy_engine",
            "evaluate",
            req_bytes,
        );
        let args_json = abi_stable::std_types::RString::from(args_str);
        let vtable_fn = self.vtable.evaluate;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        let result = tokio::time::timeout(
            self.library.ffi_limits.data_timeout,
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), args_json)),
        )
        .await;
        match result {
            Ok(Ok(out)) => {
                let resp_bytes = out.len();
                let raw = out.as_str();
                if raw.is_empty() {
                    call.end_err(resp_bytes);
                    tracing::error!(
                        plugin_id = %plugin_id,
                        "native policy_engine plugin returned empty response (panic)",
                    );
                    return PolicyDecision::deny(
                        format!("native plugin '{plugin_id}' panicked"),
                        "",
                    );
                }
                match serde_json::from_str::<PolicyDecision>(raw) {
                    Ok(d) => {
                        call.end_ok(resp_bytes);
                        d
                    }
                    Err(_) => {
                        call.end_err(resp_bytes);
                        PolicyDecision::deny(
                            format!("native plugin '{plugin_id}' returned malformed decision"),
                            "",
                        )
                    }
                }
            }
            Ok(Err(_)) => {
                call.end_err(0);
                PolicyDecision::deny(format!("native plugin '{plugin_id}' panicked"), "")
            }
            Err(_) => {
                call.end_err(0);
                metrics::counter!(
                    "mcpg_native_plugin_timeout_total",
                    "plugin_id" => plugin_id.clone(),
                )
                .increment(1);
                PolicyDecision::deny(format!("native plugin '{plugin_id}' timed out"), "")
            }
        }
    }

    async fn policy_version(&self) -> PolicyVersion {
        let vtable_fn = self.vtable.policy_version;
        let handle = SendHandle(self.handle);
        let result = tokio::time::timeout(
            self.library.ffi_limits.control_timeout,
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr())),
        )
        .await;
        let raw = match result {
            Ok(Ok(r)) => r,
            _ => {
                return PolicyVersion {
                    hash: "unknown".into(),
                    loaded_at: "".into(),
                    source: format!("native plugin '{}' (error)", self.manifest.id),
                };
            }
        };
        serde_json::from_str::<PolicyVersion>(raw.as_str()).unwrap_or_else(|_| PolicyVersion {
            hash: "unknown".into(),
            loaded_at: "".into(),
            source: format!("native plugin '{}' (malformed)", self.manifest.id),
        })
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

// ---------------------------------------------------------------------------
// CredentialIssuer adapter
// ---------------------------------------------------------------------------

fn clone_credential_issuer(
    vt: &mcpg_plugin_protocol::abi::CredentialIssuerVTable,
) -> mcpg_plugin_protocol::abi::CredentialIssuerVTable {
    mcpg_plugin_protocol::abi::CredentialIssuerVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        issue: vt.issue,
        revoke: vt.revoke,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

pub struct NativeCredentialIssuerAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: mcpg_plugin_protocol::abi::CredentialIssuerVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    #[allow(dead_code)]
    alias: String,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeCredentialIssuerAdapter {}
unsafe impl Sync for NativeCredentialIssuerAdapter {}

impl NativeCredentialIssuerAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_credential_issuer() {
            Some(vt) => clone_credential_issuer(vt),
            None => {
                return Err(anyhow!("plugin does not export a CredentialIssuer vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!(
                "native credential_issuer plugin panicked during make"
            ));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!(
                "native credential_issuer plugin returned empty manifest"
            ));
        }
        let manifest: PluginManifest =
            serde_json::from_str(manifest_json.as_str()).map_err(|e| {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                anyhow::Error::from(e).context("invalid manifest from credential_issuer")
            })?;
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            alias,
            _host_bridge: host_bridge,
        })
    }
}

impl Drop for NativeCredentialIssuerAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

#[async_trait]
impl mcpg_plugin_protocol::credential::CredentialIssuer for NativeCredentialIssuerAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn issue(
        &self,
        identity: &mcpg_plugin_protocol::types::PluginIdentity,
        target: &str,
        config: &serde_json::Value,
    ) -> Result<
        mcpg_plugin_protocol::credential::IssuedCredential,
        mcpg_plugin_protocol::credential::CredentialError,
    > {
        let args = serde_json::json!({
            "identity": identity,
            "target": target,
            "config": config,
        });
        let args_str = serde_json::to_string(&args).unwrap_or_else(|_| "{}".into());
        let req_bytes = args_str.len();
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "credential_issuer",
            "issue",
            req_bytes,
        );
        let args_json = abi_stable::std_types::RString::from(args_str);
        let vtable_fn = self.vtable.issue;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        let result = tokio::time::timeout(
            self.library.ffi_limits.data_timeout,
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), args_json)),
        )
        .await;
        match result {
            Ok(Ok(out)) => {
                let resp_bytes = out.len();
                let raw = out.as_str();
                if raw.is_empty() {
                    call.end_err(resp_bytes);
                    return Err(mcpg_plugin_protocol::credential::CredentialError::Backend {
                        reason: format!("native plugin '{plugin_id}' panicked"),
                    });
                }
                let decoded: Result<
                    mcpg_plugin_protocol::credential::IssuedCredential,
                    mcpg_plugin_protocol::credential::CredentialError,
                > = serde_json::from_str(raw).unwrap_or_else(|err| {
                    Err(mcpg_plugin_protocol::credential::CredentialError::Backend {
                        reason: format!(
                            "native plugin '{plugin_id}' returned malformed credential JSON: {err}"
                        ),
                    })
                });
                if decoded.is_ok() {
                    call.end_ok(resp_bytes);
                } else {
                    call.end_err(resp_bytes);
                }
                decoded
            }
            Ok(Err(_)) => {
                call.end_err(0);
                Err(mcpg_plugin_protocol::credential::CredentialError::Backend {
                    reason: format!("native plugin '{plugin_id}' blocking task panicked"),
                })
            }
            Err(_) => {
                call.end_err(0);
                metrics::counter!(
                    "mcpg_native_plugin_timeout_total",
                    "plugin_id" => plugin_id.clone(),
                )
                .increment(1);
                Err(mcpg_plugin_protocol::credential::CredentialError::Backend {
                    reason: format!("native plugin '{plugin_id}' timed out"),
                })
            }
        }
    }

    async fn revoke(
        &self,
        lease_id: &str,
    ) -> Result<(), mcpg_plugin_protocol::credential::CredentialError> {
        use mcpg_plugin_protocol::credential::CredentialError;
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "credential_issuer",
            "revoke",
            lease_id.len(),
        );
        let arg = abi_stable::std_types::RString::from(lease_id);
        let vtable_fn = self.vtable.revoke;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        let result = tokio::time::timeout(
            self.library.ffi_limits.control_timeout,
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), arg)),
        )
        .await;
        match result {
            Ok(Ok(out)) => {
                let resp_bytes = out.len();
                // Result envelope: `{"ok": null}` /
                // `{"err": CredentialError}`.
                match mcpg_plugin_protocol::result_envelope::decode_result_envelope::<
                    (),
                    CredentialError,
                >(out.as_str())
                {
                    Ok(Ok(())) => {
                        call.end_ok(resp_bytes);
                        Ok(())
                    }
                    Ok(Err(e)) => {
                        call.end_err(resp_bytes);
                        Err(e)
                    }
                    Err(e) => {
                        call.end_err(resp_bytes);
                        Err(CredentialError::Backend {
                            reason: format!(
                                "native plugin '{plugin_id}' returned undecodable revoke envelope: {e}",
                            ),
                        })
                    }
                }
            }
            _ => {
                call.end_err(0);
                Err(CredentialError::Backend {
                    reason: format!("native plugin '{plugin_id}' revoke timed out"),
                })
            }
        }
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

// ---------------------------------------------------------------------------
// ApprovalNotifier adapter
// ---------------------------------------------------------------------------

fn clone_approval_notifier(
    vt: &mcpg_plugin_protocol::abi::ApprovalNotifierVTable,
) -> mcpg_plugin_protocol::abi::ApprovalNotifierVTable {
    mcpg_plugin_protocol::abi::ApprovalNotifierVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        notify: vt.notify,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

pub struct NativeApprovalNotifierAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: mcpg_plugin_protocol::abi::ApprovalNotifierVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    #[allow(dead_code)]
    alias: String,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeApprovalNotifierAdapter {}
unsafe impl Sync for NativeApprovalNotifierAdapter {}

impl NativeApprovalNotifierAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_approval_notifier() {
            Some(vt) => clone_approval_notifier(vt),
            None => {
                return Err(anyhow!("plugin does not export an ApprovalNotifier vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!(
                "native approval_notifier plugin panicked during make"
            ));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!(
                "native approval_notifier plugin returned empty manifest"
            ));
        }
        let manifest: PluginManifest =
            serde_json::from_str(manifest_json.as_str()).map_err(|e| {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                anyhow::Error::from(e).context("invalid manifest from approval_notifier")
            })?;
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            alias,
            _host_bridge: host_bridge,
        })
    }
}

impl Drop for NativeApprovalNotifierAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

#[async_trait]
impl mcpg_plugin_protocol::approval_notifier::ApprovalNotifier for NativeApprovalNotifierAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn notify(
        &self,
        request: &mcpg_plugin_protocol::approval_notifier::NotificationRequest,
    ) -> Result<
        mcpg_plugin_protocol::approval_notifier::NotificationResult,
        mcpg_plugin_protocol::approval_notifier::NotificationError,
    > {
        let req_str = serde_json::to_string(request).unwrap_or_else(|_| "{}".into());
        let req_bytes = req_str.len();
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "approval_notifier",
            "notify",
            req_bytes,
        );
        let req_json = abi_stable::std_types::RString::from(req_str);
        let vtable_fn = self.vtable.notify;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        let result = tokio::time::timeout(
            self.library.ffi_limits.data_timeout,
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), req_json)),
        )
        .await;
        match result {
            Ok(Ok(out)) => {
                let resp_bytes = out.len();
                let raw = out.as_str();
                if raw.is_empty() {
                    call.end_err(resp_bytes);
                    return Err(
                        mcpg_plugin_protocol::approval_notifier::NotificationError::Internal {
                            reason: format!("native plugin '{plugin_id}' panicked"),
                        },
                    );
                }
                let decoded: Result<
                    mcpg_plugin_protocol::approval_notifier::NotificationResult,
                    mcpg_plugin_protocol::approval_notifier::NotificationError,
                > = serde_json::from_str(raw).unwrap_or_else(|err| {
                    Err(
                        mcpg_plugin_protocol::approval_notifier::NotificationError::Internal {
                            reason: format!(
                                "native plugin '{plugin_id}' returned malformed notify JSON: {err}"
                            ),
                        },
                    )
                });
                if decoded.is_ok() {
                    call.end_ok(resp_bytes);
                } else {
                    call.end_err(resp_bytes);
                }
                decoded
            }
            Ok(Err(_)) => {
                call.end_err(0);
                Err(
                    mcpg_plugin_protocol::approval_notifier::NotificationError::Internal {
                        reason: format!("native plugin '{plugin_id}' blocking task panicked"),
                    },
                )
            }
            Err(_) => {
                call.end_err(0);
                metrics::counter!(
                    "mcpg_native_plugin_timeout_total",
                    "plugin_id" => plugin_id.clone(),
                )
                .increment(1);
                Err(
                    mcpg_plugin_protocol::approval_notifier::NotificationError::Backend {
                        reason: format!("native plugin '{plugin_id}' timed out"),
                    },
                )
            }
        }
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

// ---------------------------------------------------------------------------
// CatalogProvider adapter
// ---------------------------------------------------------------------------

fn clone_catalog_provider(
    vt: &mcpg_plugin_protocol::abi::CatalogProviderVTable,
) -> mcpg_plugin_protocol::abi::CatalogProviderVTable {
    mcpg_plugin_protocol::abi::CatalogProviderVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        filter_and_enrich: vt.filter_and_enrich,
        describe: vt.describe,
        list_catalog: vt.list_catalog,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

pub struct NativeCatalogProviderAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: mcpg_plugin_protocol::abi::CatalogProviderVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    #[allow(dead_code)]
    alias: String,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeCatalogProviderAdapter {}
unsafe impl Sync for NativeCatalogProviderAdapter {}

impl NativeCatalogProviderAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_catalog_provider() {
            Some(vt) => clone_catalog_provider(vt),
            None => {
                return Err(anyhow!("plugin does not export a CatalogProvider vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!(
                "native catalog_provider plugin panicked during make"
            ));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!(
                "native catalog_provider plugin returned empty manifest"
            ));
        }
        let manifest: PluginManifest =
            serde_json::from_str(manifest_json.as_str()).map_err(|e| {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                anyhow::Error::from(e).context("invalid manifest from catalog_provider")
            })?;
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            alias,
            _host_bridge: host_bridge,
        })
    }
}

impl Drop for NativeCatalogProviderAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

#[async_trait]
impl mcpg_plugin_protocol::catalog::CatalogProvider for NativeCatalogProviderAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn filter_and_enrich(
        &self,
        ctx: &PluginContext,
        in_progress: &[mcpg_plugin_protocol::catalog::EnrichedToolDescriptor],
    ) -> Vec<mcpg_plugin_protocol::catalog::EnrichedToolDescriptor> {
        let args = serde_json::json!({
            "ctx": ctx,
            "in_progress": in_progress,
        });
        let args_str = serde_json::to_string(&args).unwrap_or_else(|_| "{}".into());
        let req_bytes = args_str.len();
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "catalog_provider",
            "filter_and_enrich",
            req_bytes,
        );
        let args_json = abi_stable::std_types::RString::from(args_str);
        let vtable_fn = self.vtable.filter_and_enrich;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        let result = tokio::time::timeout(
            self.library.ffi_limits.data_timeout,
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), args_json)),
        )
        .await;
        match result {
            Ok(Ok(out)) => {
                let resp_bytes = out.len();
                let raw = out.as_str();
                if raw.is_empty() {
                    call.end_err(resp_bytes);
                    tracing::error!(
                        plugin_id = %plugin_id,
                        "native catalog_provider plugin returned empty response (panic) — \
                         falling back to empty list (fail-closed)",
                    );
                    return Vec::new();
                }
                match serde_json::from_str::<
                    Vec<mcpg_plugin_protocol::catalog::EnrichedToolDescriptor>,
                >(raw)
                {
                    Ok(list) => {
                        call.end_ok(resp_bytes);
                        list
                    }
                    Err(err) => {
                        call.end_err(resp_bytes);
                        tracing::error!(
                            plugin_id = %plugin_id,
                            error = %err,
                            "native catalog_provider returned malformed JSON — \
                             falling back to empty list",
                        );
                        Vec::new()
                    }
                }
            }
            Ok(Err(_)) => {
                call.end_err(0);
                tracing::error!(
                    plugin_id = %plugin_id,
                    "native catalog_provider blocking task panicked",
                );
                Vec::new()
            }
            Err(_) => {
                call.end_err(0);
                metrics::counter!(
                    "mcpg_native_plugin_timeout_total",
                    "plugin_id" => plugin_id.clone(),
                )
                .increment(1);
                tracing::error!(
                    plugin_id = %plugin_id,
                    "native catalog_provider timed out — falling back to empty list",
                );
                Vec::new()
            }
        }
    }

    async fn describe(&self, tool_id: &str) -> Option<mcpg_plugin_protocol::catalog::CatalogEntry> {
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "catalog_provider",
            "describe",
            tool_id.len(),
        );
        let arg = abi_stable::std_types::RString::from(tool_id);
        let vtable_fn = self.vtable.describe;
        let handle = SendHandle(self.handle);
        let result = tokio::time::timeout(
            self.library.ffi_limits.control_timeout,
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), arg)),
        )
        .await;
        match result {
            Ok(Ok(out)) => {
                let resp_bytes = out.len();
                let raw = out.as_str();
                if raw.is_empty() || raw == "null" {
                    call.end_ok(resp_bytes);
                    None
                } else {
                    let decoded = serde_json::from_str(raw).ok();
                    if decoded.is_some() {
                        call.end_ok(resp_bytes);
                    } else {
                        call.end_err(resp_bytes);
                    }
                    decoded
                }
            }
            _ => {
                call.end_err(0);
                None
            }
        }
    }

    async fn list_catalog(&self) -> Vec<mcpg_plugin_protocol::catalog::CatalogEntry> {
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "catalog_provider",
            "list_catalog",
            0,
        );
        let vtable_fn = self.vtable.list_catalog;
        let handle = SendHandle(self.handle);
        let result = tokio::time::timeout(
            self.library.ffi_limits.data_timeout,
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr())),
        )
        .await;
        match result {
            Ok(Ok(out)) => {
                let resp_bytes = out.len();
                let raw = out.as_str();
                let decoded = serde_json::from_str(raw).unwrap_or_default();
                call.end_ok(resp_bytes);
                decoded
            }
            _ => {
                call.end_err(0);
                Vec::new()
            }
        }
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

// ---------------------------------------------------------------------------
// Cluster adapter
// ---------------------------------------------------------------------------
//
// Read surface + publish/subscribe + leases + leader-election + the
// key/value primitive all cross the FFI here. Streaming subscribe and
// peer-watch ride the shared event-sink callback channel; leases use the
// opaque-handle cookie convention; KV marshals its async trait via the
// per-slot JSON arg/return DTOs.

fn clone_cluster(vt: &ClusterVTable) -> ClusterVTable {
    ClusterVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        node_info: vt.node_info,
        list_peers: vt.list_peers,
        publish: vt.publish,
        subscribe: vt.subscribe,
        watch_peers: vt.watch_peers,
        cancel_stream: vt.cancel_stream,
        acquire_leadership: vt.acquire_leadership,
        acquire_lock: vt.acquire_lock,
        try_acquire_leadership: vt.try_acquire_leadership,
        try_acquire_lock: vt.try_acquire_lock,
        lease_renew: vt.lease_renew,
        lease_release: vt.lease_release,
        lease_drop: vt.lease_drop,
        kv_get: vt.kv_get,
        kv_put: vt.kv_put,
        kv_put_if_absent: vt.kv_put_if_absent,
        kv_delete: vt.kv_delete,
        kv_list_prefix: vt.kv_list_prefix,
        kv_expire: vt.kv_expire,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

// ---------------------------------------------------------------------------
// FFI-backed PubSub primitive
// ---------------------------------------------------------------------------
//
// The `pub_sub()` accessor delegates the primitive's publish/subscribe to
// the coordinator-level publish/subscribe slots (which already cross FFI).
// No new ABI surface — this routes the delivery / cancellation / approval
// buses through the same path the credential-cache bus already uses.

/// Cloneable bundle of the FFI bits the PubSub delegation needs.
struct ClusterPubSubFfi {
    library: Arc<LoadedNativePlugin>,
    publish: extern "C" fn(
        RPluginHandle,
        abi_stable::std_types::RString,
    ) -> abi_stable::std_types::RString,
    subscribe: extern "C" fn(
        RPluginHandle,
        abi_stable::std_types::RString,
        EventSinkRef,
    ) -> mcpg_plugin_protocol::abi::StreamHandle,
    cancel_stream: extern "C" fn(RPluginHandle, usize),
    handle: RPluginHandle,
    plugin_id: String,
    /// Keeps the plugin instance (and cdylib) alive for the bus's life.
    _instance: Arc<NativeClusterInstance>,
}

unsafe impl Send for ClusterPubSubFfi {}
unsafe impl Sync for ClusterPubSubFfi {}

impl ClusterPubSubFfi {
    async fn publish(&self, topic: &str, payload: bytes::Bytes) -> Result<(), ClusterError> {
        let args = serde_json::json!({
            "topic": topic,
            "routing_key": Option::<&str>::None,
            "payload": payload.to_vec(),
        });
        let args_str = serde_json::to_string(&args).unwrap_or_else(|_| "{}".into());
        let call = crate::ffi_metering::FfiCall::begin(
            &self.plugin_id,
            "cluster",
            "pub_sub.publish",
            args_str.len(),
        );
        let args_json = abi_stable::std_types::RString::from(args_str);
        let vt_fn = self.publish;
        let handle = SendHandle(self.handle);
        let plugin_id = self.plugin_id.clone();
        let result = tokio::time::timeout(
            self.library.ffi_limits.data_timeout,
            tokio::task::spawn_blocking(move || vt_fn(handle.ptr(), args_json)),
        )
        .await;
        let raw = match result {
            Ok(Ok(r)) => r,
            _ => {
                call.end_err(0);
                return Err(ClusterError::BackendUnavailable {
                    reason: format!("native plugin '{plugin_id}' timed out or panicked"),
                });
            }
        };
        let resp_bytes = raw.len();
        match mcpg_plugin_protocol::result_envelope::decode_result_envelope::<(), ClusterError>(
            raw.as_str(),
        ) {
            Ok(Ok(())) => {
                call.end_ok(resp_bytes);
                Ok(())
            }
            Ok(Err(e)) => {
                call.end_err(resp_bytes);
                Err(e)
            }
            Err(e) => {
                call.end_err(resp_bytes);
                Err(ClusterError::Internal {
                    reason: format!(
                        "native plugin '{plugin_id}' returned undecodable publish envelope: {e}",
                    ),
                })
            }
        }
    }

    async fn subscribe(
        &self,
        pattern: &str,
        queue_group: Option<&str>,
    ) -> Result<PubSubSubscription, ClusterError> {
        let (bridge_ptr_raw, sink, rx) = make_stream_bridge(&self.plugin_id);
        let bridge_ptr = SendPtr(bridge_ptr_raw);
        let args = serde_json::json!({
            "topic": pattern,
            "group": queue_group,
            "routing_key": Option::<&str>::None,
        });
        let args_str = serde_json::to_string(&args).unwrap_or_else(|_| "{}".into());
        let call = crate::ffi_metering::FfiCall::begin(
            &self.plugin_id,
            "cluster",
            "pub_sub.subscribe",
            args_str.len(),
        );
        let args_json = abi_stable::std_types::RString::from(args_str);
        let vt_fn = self.subscribe;
        let handle = SendHandle(self.handle);
        let plugin_id = self.plugin_id.clone();
        let spawn_result =
            tokio::task::spawn_blocking(move || vt_fn(handle.ptr(), args_json, sink)).await;
        let result = match spawn_result {
            Ok(r) => r,
            Err(_) => {
                call.end_err(0);
                unsafe {
                    drop(Box::from_raw(bridge_ptr.0));
                }
                return Err(ClusterError::BackendUnavailable {
                    reason: format!("native plugin '{plugin_id}' panicked during subscribe"),
                });
            }
        };
        let resp_bytes = result.error_json.len();
        if result.handle == 0 {
            call.end_err(resp_bytes);
            unsafe {
                drop(Box::from_raw(bridge_ptr.0));
            }
            let err = serde_json::from_str::<ClusterError>(result.error_json.as_str()).unwrap_or(
                ClusterError::Internal {
                    reason: format!(
                        "native plugin '{plugin_id}' returned undecodable subscribe error"
                    ),
                },
            );
            return Err(err);
        }
        call.end_ok(resp_bytes);
        let guard = StreamCancelGuard {
            library: Arc::clone(&self.library),
            cancel_fn: self.cancel_stream,
            plugin_handle: self.handle,
            watch_handle: result.handle,
            bridge_ptr: bridge_ptr.0,
        };
        Ok(Box::pin(PrimitiveMessageStream { rx, _guard: guard }))
    }
}

/// `PubSub` impl whose publish/subscribe ride the coordinator-level FFI
/// publish/subscribe slots.
struct NativeClusterPubSub {
    coordinator: ClusterPubSubFfi,
}

impl std::fmt::Debug for NativeClusterPubSub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeClusterPubSub")
            .field("plugin_id", &self.coordinator.plugin_id)
            .finish()
    }
}

#[async_trait]
impl PubSub for NativeClusterPubSub {
    async fn publish(&self, topic: &str, payload: bytes::Bytes) -> Result<(), ClusterError> {
        self.coordinator.publish(topic, payload).await
    }

    async fn subscribe(
        &self,
        pattern: &str,
        queue_group: Option<&str>,
    ) -> Result<PubSubSubscription, ClusterError> {
        self.coordinator.subscribe(pattern, queue_group).await
    }
}

/// Stream of primitive `Message`s decoded from the coordinator-level
/// `PublishedMessage` JSON the bridge forwards. Mirrors
/// [`PublishedMessageStream`] but yields the primitive `Message` shape the
/// `PubSub::subscribe` contract returns.
struct PrimitiveMessageStream {
    rx: tokio::sync::mpsc::Receiver<String>,
    _guard: StreamCancelGuard,
}

impl futures_core::Stream for PrimitiveMessageStream {
    type Item = Result<mcpg_cluster_api::Message, ClusterError>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            match self.rx.poll_recv(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                std::task::Poll::Ready(Some(json)) => {
                    match serde_json::from_str::<PublishedMessage>(&json) {
                        Ok(pm) => {
                            return std::task::Poll::Ready(Some(Ok(mcpg_cluster_api::Message {
                                topic: pm.topic,
                                payload: pm.payload,
                            })));
                        }
                        Err(_) => continue,
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FFI-backed KeyValueStore primitive
// ---------------------------------------------------------------------------
//
// Marshals the async `KeyValueStore` trait onto the coordinator's sync KV
// vtable slots. Each call serialises its args to a JSON DTO
// (`mcpg_cluster_api::key_value`), invokes the slot on a blocking thread
// (the coordinator blocks on its own runtime inside), and decodes the
// result-envelope reply. Bytes + TTL semantics ride the
// `KvEntryWire` / `Kv*Args` DTOs.

struct NativeClusterKv {
    library: Arc<LoadedNativePlugin>,
    kv_get: extern "C" fn(
        RPluginHandle,
        abi_stable::std_types::RString,
    ) -> abi_stable::std_types::RString,
    kv_put: extern "C" fn(
        RPluginHandle,
        abi_stable::std_types::RString,
    ) -> abi_stable::std_types::RString,
    kv_put_if_absent: extern "C" fn(
        RPluginHandle,
        abi_stable::std_types::RString,
    ) -> abi_stable::std_types::RString,
    kv_delete: extern "C" fn(
        RPluginHandle,
        abi_stable::std_types::RString,
    ) -> abi_stable::std_types::RString,
    kv_list_prefix: extern "C" fn(
        RPluginHandle,
        abi_stable::std_types::RString,
    ) -> abi_stable::std_types::RString,
    kv_expire: extern "C" fn(
        RPluginHandle,
        abi_stable::std_types::RString,
    ) -> abi_stable::std_types::RString,
    handle: RPluginHandle,
    plugin_id: String,
    /// Keeps the plugin instance (and cdylib) alive for the KV's life.
    _instance: Arc<NativeClusterInstance>,
}

unsafe impl Send for NativeClusterKv {}
unsafe impl Sync for NativeClusterKv {}

impl std::fmt::Debug for NativeClusterKv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeClusterKv")
            .field("plugin_id", &self.plugin_id)
            .finish()
    }
}

impl NativeClusterKv {
    /// Invoke a sync KV slot on a blocking thread, returning the raw reply
    /// `RString` (the result-envelope body). Maps panic / timeout to
    /// `BackendUnavailable`.
    async fn call_slot(
        &self,
        vt_fn: extern "C" fn(
            RPluginHandle,
            abi_stable::std_types::RString,
        ) -> abi_stable::std_types::RString,
        slot: &'static str,
        args: serde_json::Value,
    ) -> Result<String, ClusterError> {
        let args_str = serde_json::to_string(&args).unwrap_or_else(|_| "{}".into());
        let call =
            crate::ffi_metering::FfiCall::begin(&self.plugin_id, "cluster", slot, args_str.len());
        let args_json = abi_stable::std_types::RString::from(args_str);
        let handle = SendHandle(self.handle);
        let plugin_id = self.plugin_id.clone();
        let result = tokio::time::timeout(
            self.library.ffi_limits.data_timeout,
            tokio::task::spawn_blocking(move || vt_fn(handle.ptr(), args_json)),
        )
        .await;
        match result {
            Ok(Ok(raw)) => {
                call.end_ok(raw.len());
                Ok(raw.as_str().to_owned())
            }
            _ => {
                call.end_err(0);
                Err(ClusterError::BackendUnavailable {
                    reason: format!(
                        "native plugin '{plugin_id}' timed out or panicked during {slot}"
                    ),
                })
            }
        }
    }

    /// Decode a `Result<T, ClusterError>` envelope, mapping an undecodable
    /// reply onto an `Internal` error tagged with the slot name.
    fn decode<T: serde::de::DeserializeOwned>(
        &self,
        slot: &'static str,
        raw: &str,
    ) -> Result<T, ClusterError> {
        match mcpg_plugin_protocol::result_envelope::decode_result_envelope::<T, ClusterError>(raw)
        {
            Ok(inner) => inner,
            Err(e) => Err(ClusterError::Internal {
                reason: format!(
                    "native plugin '{}' returned undecodable {slot} envelope: {e}",
                    self.plugin_id
                ),
            }),
        }
    }
}

#[async_trait]
impl KeyValueStore for NativeClusterKv {
    async fn get(&self, key: &str) -> Result<Option<Entry>, ClusterError> {
        let raw = self
            .call_slot(self.kv_get, "kv_get", serde_json::json!({ "key": key }))
            .await?;
        let wire: Option<KvEntryWire> = self.decode("kv_get", &raw)?;
        Ok(wire.map(KvEntryWire::into_entry))
    }

    async fn put(
        &self,
        key: &str,
        value: bytes::Bytes,
        ttl: Option<std::time::Duration>,
    ) -> Result<(), ClusterError> {
        let args = serde_json::json!({
            "key": key,
            "value": value.to_vec(),
            "ttl_ms": ttl.map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64),
        });
        let raw = self.call_slot(self.kv_put, "kv_put", args).await?;
        self.decode::<()>("kv_put", &raw)
    }

    async fn put_if_absent(
        &self,
        key: &str,
        value: bytes::Bytes,
        ttl: Option<std::time::Duration>,
    ) -> Result<bool, ClusterError> {
        let args = serde_json::json!({
            "key": key,
            "value": value.to_vec(),
            "ttl_ms": ttl.map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64),
        });
        let raw = self
            .call_slot(self.kv_put_if_absent, "kv_put_if_absent", args)
            .await?;
        self.decode::<bool>("kv_put_if_absent", &raw)
    }

    async fn delete(&self, key: &str) -> Result<bool, ClusterError> {
        let raw = self
            .call_slot(
                self.kv_delete,
                "kv_delete",
                serde_json::json!({ "key": key }),
            )
            .await?;
        self.decode::<bool>("kv_delete", &raw)
    }

    async fn list_prefix(
        &self,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<(String, Entry)>, ClusterError> {
        let args = serde_json::json!({ "prefix": prefix, "limit": limit as u64 });
        let raw = self
            .call_slot(self.kv_list_prefix, "kv_list_prefix", args)
            .await?;
        let wire: Vec<KvListEntryWire> = self.decode("kv_list_prefix", &raw)?;
        Ok(wire
            .into_iter()
            .map(|e| (e.key, e.entry.into_entry()))
            .collect())
    }

    async fn expire(
        &self,
        key: &str,
        ttl: Option<std::time::Duration>,
    ) -> Result<bool, ClusterError> {
        let args = serde_json::json!({
            "key": key,
            "ttl_ms": ttl.map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64),
        });
        let raw = self.call_slot(self.kv_expire, "kv_expire", args).await?;
        self.decode::<bool>("kv_expire", &raw)
    }
}

/// Shared owner of the cluster plugin's instance handle + the vtable's
/// `drop_instance` fn. Held via `Arc` by the `NativeClusterAdapter`
/// AND by every outstanding `NativeLeaseHandle`, so the plugin instance is
/// freed exactly once — only after the adapter AND all its leases drop. A
/// `BoxActiveLease` can therefore never outlive the instance its
/// `lease_*` ops dereference. The coordinator is a process-lifetime
/// singleton today (so the adapter always outlives its leases in
/// practice), making this a latent-UAF guard rather than an active fix —
/// but it makes the lifetime sound under a future hot-reload /
/// replaceable-registry / test teardown that drops the adapter while a
/// lease (e.g. a held `ReloadPermit`) is still outstanding.
struct NativeClusterInstance {
    /// Keeps the cdylib mapped while the instance handle is live.
    library: Arc<LoadedNativePlugin>,
    handle: RPluginHandle,
    drop_instance: extern "C" fn(RPluginHandle),
}

unsafe impl Send for NativeClusterInstance {}
unsafe impl Sync for NativeClusterInstance {}

impl Drop for NativeClusterInstance {
    fn drop(&mut self) {
        (self.drop_instance)(self.handle);
        let _ = &self.library;
    }
}

pub struct NativeClusterAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: ClusterVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    #[allow(dead_code)]
    alias: String,
    _host_bridge: crate::host_bridge::HostBridge,
    /// Shared instance owner — freeing the plugin instance is delegated
    /// here so an outstanding lease can keep it alive.
    instance: Arc<NativeClusterInstance>,
}

unsafe impl Send for NativeClusterAdapter {}
unsafe impl Sync for NativeClusterAdapter {}

impl NativeClusterAdapter {
    /// Snapshot of the FFI ref (handle + vtable) the host hands
    /// to consumer plugins (identity / policy_engine) at their
    /// `make` time so they can opt into cluster-coordinated state
    /// via `mcpg_plugin_sdk::ClusterClient`. The returned value
    /// is `Copy`; callers store it in the registry alongside the
    /// loaded coordinator and consult it when registering each
    /// consumer plugin.
    pub fn ffi_ref(&self) -> mcpg_plugin_protocol::abi::ClusterClientRef {
        mcpg_plugin_protocol::abi::ClusterClientRef {
            handle: self.handle as usize,
            vtable: self.vtable,
        }
    }

    /// One-shot synchronous probe: does this coordinator genuinely back the
    /// `KeyValueStore` primitive? Calls the `kv_get` slot with a reserved
    /// sentinel key and treats an `Unsupported` reply (the SDK default for
    /// non-KV coordinators) as "not backed". A genuine KV returns
    /// `Ok(None)` for the absent sentinel; a transient backend error is
    /// treated as "supported" (the accessor stays `Some` and the consumer's
    /// own error handling applies) so a coordinator that's merely unreachable
    /// at boot is not permanently downgraded to MemoryKv.
    fn probe_kv_supported(&self) -> bool {
        let args = abi_stable::std_types::RString::from(
            serde_json::json!({ "key": "__mcpg_kv_probe__" }).to_string(),
        );
        // Bounded: this runs at boot against a coordinator that may be
        // unreachable. A panic or timeout yields an empty envelope, which
        // decodes to neither `Unsupported` nor a value — matching the
        // "transient error means treat as supported" rule above, so an
        // unreachable coordinator is not permanently downgraded.
        let vtable_fn = self.vtable.kv_get;
        let handle = SendHandle(self.handle);
        let raw = call_sync_vtable_bounded(
            self.library.ffi_limits.data_timeout,
            move || vtable_fn(handle.ptr(), args),
            abi_stable::std_types::RString::new,
        );
        let decoded = mcpg_plugin_protocol::result_envelope::decode_result_envelope::<
            Option<KvEntryWire>,
            ClusterError,
        >(raw.as_str());
        !matches!(decoded, Ok(Err(ClusterError::Unsupported { .. })))
    }

    /// Lightweight, cloneable handle carrying exactly the FFI state the
    /// `PubSub` primitive needs to delegate to the coordinator-level
    /// publish/subscribe slots. Lets the `pub_sub()` accessor hand out a
    /// `PubSub` impl without an `Arc`-cycle back to the adapter.
    fn ffi_pub_sub_handle(&self) -> ClusterPubSubFfi {
        ClusterPubSubFfi {
            library: Arc::clone(&self.library),
            publish: self.vtable.publish,
            subscribe: self.vtable.subscribe,
            cancel_stream: self.vtable.cancel_stream,
            handle: self.handle,
            plugin_id: self.manifest.id.clone(),
            _instance: Arc::clone(&self.instance),
        }
    }

    /// FFI-equivalence test seam. Build an adapter directly from a
    /// macro-produced [`ClusterVTable`] + an already-`make`d instance
    /// `handle`, WITHOUT a dlopen. Drives the EXACT production dispatch
    /// path (`spawn_blocking`, JSON arg/result marshalling, result
    /// envelopes, the refcounted [`NativeClusterInstance`], the
    /// lease + stream-cancel guards) as [`Self::new`], but over an
    /// in-process vtable whose fn pointers live in the test binary.
    ///
    /// Contract:
    /// - `vtable`'s fn pointers + `handle` MUST stay valid for the
    ///   adapter's whole life (a macro-built vtable over a `'static`
    ///   plugin type satisfies this automatically).
    /// - `vtable.drop_instance` is invoked exactly once when the adapter
    ///   AND all outstanding leases drop; the macro emits a real
    ///   `Box::from_raw` freeing impl.
    /// - `manifest.id` must be non-empty (it is the FFI-metering label).
    ///
    /// The synthetic `LoadedNativePlugin` carries only default
    /// `ffi_limits` (the sole field the cluster adapter reads off
    /// `library`); no `.so` is mapped.
    #[cfg(any(test, feature = "cluster-ffi-test-seam"))]
    pub fn from_raw(
        vtable: ClusterVTable,
        handle: RPluginHandle,
        manifest: PluginManifest,
        alias: String,
    ) -> Self {
        let library = Arc::new(LoadedNativePlugin::synthetic(manifest.clone()));
        let instance = Arc::new(NativeClusterInstance {
            library: Arc::clone(&library),
            handle,
            drop_instance: vtable.drop_instance,
        });
        Self {
            library,
            vtable,
            handle,
            manifest,
            alias,
            _host_bridge: crate::host_bridge::HostBridge::stub(),
            instance,
        }
    }
}

impl NativeClusterAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_cluster() {
            Some(vt) => clone_cluster(vt),
            None => {
                return Err(anyhow!("plugin does not export a Cluster vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!("native cluster plugin panicked during make"));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!("native cluster plugin returned empty manifest"));
        }
        let manifest: PluginManifest =
            serde_json::from_str(manifest_json.as_str()).map_err(|e| {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                anyhow::Error::from(e).context("invalid manifest from cluster plugin")
            })?;
        // From here on the instance handle is owned by a refcounted
        // `NativeClusterInstance`, NOT the adapter's `Drop`. Any failure
        // ABOVE this point still frees `handle` inline (the plugin owns
        // nothing the host shares yet); below, the Arc owns the free.
        let instance = Arc::new(NativeClusterInstance {
            library: Arc::clone(&library),
            handle,
            drop_instance: vt.drop_instance,
        });
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            alias,
            _host_bridge: host_bridge,
            instance,
        })
    }

    /// Shared acquire-path for leadership + lock. Both vtable
    /// slots return a `LeaseHandle` with the same
    /// semantics; only the args shape + which slot to call
    /// differs.
    async fn acquire_lease_common(
        &self,
        vtable_fn: extern "C" fn(
            RPluginHandle,
            abi_stable::std_types::RString,
        ) -> mcpg_plugin_protocol::abi::LeaseHandle,
        args: serde_json::Value,
        slot: &'static str,
    ) -> Result<BoxActiveLease, ClusterError> {
        let args_str = serde_json::to_string(&args).unwrap_or_else(|_| "{}".into());
        let call =
            crate::ffi_metering::FfiCall::begin(&self.manifest.id, "cluster", slot, args_str.len());
        let args_json = abi_stable::std_types::RString::from(args_str);
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        let result = tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), args_json)).await;
        let result = match result {
            Ok(r) => r,
            Err(_) => {
                call.end_err(0);
                return Err(ClusterError::BackendUnavailable {
                    reason: format!("native plugin '{plugin_id}' panicked during acquire",),
                });
            }
        };
        if result.handle == 0 {
            call.end_err(result.error_json.len());
            return Err(
                serde_json::from_str::<ClusterError>(result.error_json.as_str()).unwrap_or(
                    ClusterError::Internal {
                        reason: format!(
                            "native plugin '{plugin_id}' returned undecodable acquire error",
                        ),
                    },
                ),
            );
        }
        call.end_ok(result.error_json.len());
        Ok(Box::new(NativeLeaseHandle {
            library: Arc::clone(&self.library),
            lease_renew: self.vtable.lease_renew,
            lease_release: self.vtable.lease_release,
            lease_drop: self.vtable.lease_drop,
            plugin_handle: self.handle,
            lease_handle: result.handle,
            fencing_token: result.fencing_token,
            expires_at: std::sync::Mutex::new(result.expires_at.as_str().to_owned()),
            plugin_id: plugin_id.clone(),
            _instance: Arc::clone(&self.instance),
        }))
    }

    /// v21 — try-variant of `acquire_lease_common`. Same vtable
    /// signature; the result-decoding adds the third "declined"
    /// state (`handle == 0 && error_json.is_empty()`).
    async fn try_acquire_lease_common(
        &self,
        vtable_fn: extern "C" fn(
            RPluginHandle,
            abi_stable::std_types::RString,
        ) -> mcpg_plugin_protocol::abi::LeaseHandle,
        args: serde_json::Value,
        slot: &'static str,
    ) -> Result<Option<BoxActiveLease>, ClusterError> {
        let args_str = serde_json::to_string(&args).unwrap_or_else(|_| "{}".into());
        let call =
            crate::ffi_metering::FfiCall::begin(&self.manifest.id, "cluster", slot, args_str.len());
        let args_json = abi_stable::std_types::RString::from(args_str);
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        let result = tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), args_json)).await;
        let result = match result {
            Ok(r) => r,
            Err(_) => {
                call.end_err(0);
                return Err(ClusterError::BackendUnavailable {
                    reason: format!("native plugin '{plugin_id}' panicked during try_acquire",),
                });
            }
        };
        if result.handle != 0 {
            call.end_ok(result.error_json.len());
            return Ok(Some(Box::new(NativeLeaseHandle {
                library: Arc::clone(&self.library),
                lease_renew: self.vtable.lease_renew,
                lease_release: self.vtable.lease_release,
                lease_drop: self.vtable.lease_drop,
                plugin_handle: self.handle,
                lease_handle: result.handle,
                fencing_token: result.fencing_token,
                expires_at: std::sync::Mutex::new(result.expires_at.as_str().to_owned()),
                plugin_id: plugin_id.clone(),
                _instance: Arc::clone(&self.instance),
            })));
        }
        if result.error_json.as_str().is_empty() {
            // Declined — peer holds the lease.
            call.end_ok(0);
            return Ok(None);
        }
        call.end_err(result.error_json.len());
        Err(
            serde_json::from_str::<ClusterError>(result.error_json.as_str()).unwrap_or(
                ClusterError::Internal {
                    reason: format!(
                        "native plugin '{plugin_id}' returned undecodable try_acquire error",
                    ),
                },
            ),
        )
    }
}

/// Host-side adapter wrapping a plugin-owned lease. Impl of the
/// in-tree `ActiveLease` async trait that translates each method
/// into the corresponding lease-op vtable slot + caches the
/// fencing token and the most recent expires_at reply.
pub struct NativeLeaseHandle {
    library: Arc<LoadedNativePlugin>,
    lease_renew: extern "C" fn(RPluginHandle, usize) -> abi_stable::std_types::RString,
    lease_release: extern "C" fn(RPluginHandle, usize) -> abi_stable::std_types::RString,
    lease_drop: extern "C" fn(RPluginHandle, usize),
    plugin_handle: RPluginHandle,
    lease_handle: usize,
    fencing_token: u64,
    expires_at: std::sync::Mutex<String>,
    /// Plugin id label for the FfiCall metering on lease ops.
    plugin_id: String,
    /// Shared owner of the plugin instance. Holding this `Arc`
    /// keeps the instance handle (and the cdylib) alive for as long as
    /// the lease is outstanding, so the `lease_*` vtable calls below can
    /// never dereference a freed handle — even if the parent
    /// `NativeClusterAdapter` was dropped first.
    _instance: Arc<NativeClusterInstance>,
}

unsafe impl Send for NativeLeaseHandle {}
unsafe impl Sync for NativeLeaseHandle {}

#[async_trait]
impl ActiveLease for NativeLeaseHandle {
    fn fencing_token(&self) -> u64 {
        self.fencing_token
    }

    fn expires_at(&self) -> String {
        // Sync std::Mutex — contention is bounded (single reader
        // most of the time) and the critical section is a string
        // clone.
        self.expires_at
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|_| "".into())
    }

    async fn renew(&self) -> Result<(), ClusterError> {
        let call =
            crate::ffi_metering::FfiCall::begin(&self.plugin_id, "cluster", "lease_renew", 0);
        let vtable_fn = self.lease_renew;
        let plugin_handle = SendHandle(self.plugin_handle);
        let lease_handle = self.lease_handle;
        let result =
            tokio::task::spawn_blocking(move || vtable_fn(plugin_handle.ptr(), lease_handle)).await;
        let raw = match result {
            Ok(r) => r,
            Err(_) => {
                call.end_err(0);
                return Err(ClusterError::BackendUnavailable {
                    reason: "native plugin panicked during lease_renew".into(),
                });
            }
        };
        let resp_bytes = raw.len();
        let raw_str = raw.as_str();
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Ok { ok: String },
            Err { err: ClusterError },
        }
        match serde_json::from_str::<Wire>(raw_str) {
            Ok(Wire::Ok { ok }) => {
                call.end_ok(resp_bytes);
                // Update cached expires_at.
                if let Ok(mut guard) = self.expires_at.lock() {
                    *guard = ok;
                }
                Ok(())
            }
            Ok(Wire::Err { err }) => {
                call.end_err(resp_bytes);
                Err(err)
            }
            Err(_) => {
                call.end_err(resp_bytes);
                Err(ClusterError::Internal {
                    reason: format!("native plugin returned malformed renew: {raw_str}"),
                })
            }
        }
    }

    async fn release(&self) -> Result<(), ClusterError> {
        let call =
            crate::ffi_metering::FfiCall::begin(&self.plugin_id, "cluster", "lease_release", 0);
        let vtable_fn = self.lease_release;
        let plugin_handle = SendHandle(self.plugin_handle);
        let lease_handle = self.lease_handle;
        let result =
            tokio::task::spawn_blocking(move || vtable_fn(plugin_handle.ptr(), lease_handle)).await;
        let raw = match result {
            Ok(r) => r,
            Err(_) => {
                call.end_err(0);
                return Err(ClusterError::BackendUnavailable {
                    reason: "native plugin panicked during lease_release".into(),
                });
            }
        };
        let resp_bytes = raw.len();
        // Result envelope: `{"ok": null}` /
        // `{"err": ClusterError}`.
        match mcpg_plugin_protocol::result_envelope::decode_result_envelope::<(), ClusterError>(
            raw.as_str(),
        ) {
            Ok(Ok(())) => {
                call.end_ok(resp_bytes);
                Ok(())
            }
            Ok(Err(e)) => {
                call.end_err(resp_bytes);
                Err(e)
            }
            Err(e) => {
                call.end_err(resp_bytes);
                Err(ClusterError::Internal {
                    reason: format!(
                        "native plugin returned undecodable lease_release envelope: {e}",
                    ),
                })
            }
        }
    }
}

impl Drop for NativeLeaseHandle {
    fn drop(&mut self) {
        // Best-effort cleanup — plugin can choose to ignore if
        // release already ran. The `library` Arc keeps the
        // cdylib alive until the drop completes.
        (self.lease_drop)(self.plugin_handle, self.lease_handle);
        let _ = &self.library;
    }
}

// No explicit `Drop` — freeing the plugin instance is delegated to
// the refcounted `instance: Arc<NativeClusterInstance>` field, whose own
// `Drop` runs `drop_instance` only once the adapter AND every outstanding
// `NativeLeaseHandle` (each holding an `Arc` clone) have dropped. A held
// lease therefore keeps the instance — and the cdylib — alive past the
// adapter, closing the latent use-after-free.

#[async_trait]
impl ClusterBackend for NativeClusterAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn key_value_store(&self) -> Option<Arc<dyn KeyValueStore>> {
        // Expose the FFI-backed KV only for coordinators that actually back
        // the `KeyValueStore` primitive. The manifest `kv` role is necessary
        // but not sufficient: a coordinator may advertise the `kv` slot for
        // routing yet ship no `KeyValueStore` impl (its default macro slots
        // return an `Unsupported` envelope). Probing the `kv_get` slot once
        // distinguishes the two, so a non-KV coordinator keeps the documented
        // per-capability `store:` override / MemoryKv fallback rather than
        // surfacing a KV that errors on every call.
        if !self.manifest.provides.iter().any(|r| r == "kv") {
            return None;
        }
        if !self.probe_kv_supported() {
            return None;
        }
        Some(Arc::new(NativeClusterKv {
            library: Arc::clone(&self.library),
            kv_get: self.vtable.kv_get,
            kv_put: self.vtable.kv_put,
            kv_put_if_absent: self.vtable.kv_put_if_absent,
            kv_delete: self.vtable.kv_delete,
            kv_list_prefix: self.vtable.kv_list_prefix,
            kv_expire: self.vtable.kv_expire,
            handle: self.handle,
            plugin_id: self.manifest.id.clone(),
            _instance: Arc::clone(&self.instance),
        }) as Arc<dyn KeyValueStore>)
    }

    fn pub_sub(&self) -> Option<Arc<dyn PubSub>> {
        // The PubSub primitive delegates to the coordinator-level
        // publish/subscribe FFI slots (which already cross the boundary and
        // work cluster-wide). This requires no new ABI surface — it routes
        // the resume-critical delivery / cancellation / approval buses
        // through the same path the credential-cache bus already uses.
        if !self.manifest.provides.iter().any(|r| r == "bus") {
            return None;
        }
        Some(Arc::new(NativeClusterPubSub {
            coordinator: self.ffi_pub_sub_handle(),
        }) as Arc<dyn PubSub>)
    }

    async fn node_info(&self) -> ClusterNodeInfo {
        let vt_fn = self.vtable.node_info;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        let result = tokio::time::timeout(
            self.library.ffi_limits.control_timeout,
            tokio::task::spawn_blocking(move || vt_fn(handle.ptr())),
        )
        .await;
        let raw = match result {
            Ok(Ok(r)) => r,
            _ => {
                return ClusterNodeInfo {
                    node_id: format!("error:{plugin_id}"),
                    address: String::new(),
                    version: String::new(),
                    started_at: String::new(),
                    roles: vec![],
                };
            }
        };
        serde_json::from_str(raw.as_str()).unwrap_or(ClusterNodeInfo {
            node_id: format!("malformed:{plugin_id}"),
            address: String::new(),
            version: String::new(),
            started_at: String::new(),
            roles: vec![],
        })
    }

    async fn list_peers(&self) -> Vec<ClusterPeer> {
        let vt_fn = self.vtable.list_peers;
        let handle = SendHandle(self.handle);
        let result = tokio::time::timeout(
            self.library.ffi_limits.control_timeout,
            tokio::task::spawn_blocking(move || vt_fn(handle.ptr())),
        )
        .await;
        let raw = match result {
            Ok(Ok(r)) => r,
            _ => return Vec::new(),
        };
        serde_json::from_str(raw.as_str()).unwrap_or_default()
    }

    async fn watch_peers(&self) -> BoxPeerEventStream {
        // Real streaming via the shared bridge. On any
        // failure we fall back to an empty terminating stream —
        // the `ClusterBackend::watch_peers` trait return is
        // `BoxPeerEventStream` (not `Result<_>`), so failures
        // surface as "no events ever arrive". Operators inspect
        // the plugin log + metrics to diagnose.
        let (bridge_ptr_raw, sink, rx) = make_stream_bridge(&self.manifest.id);
        let bridge_ptr = SendPtr(bridge_ptr_raw);
        let vtable_fn = self.vtable.watch_peers;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        let spawn_result = tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), sink)).await;
        let result = match spawn_result {
            Ok(r) => r,
            Err(_) => {
                unsafe {
                    drop(Box::from_raw(bridge_ptr.0));
                }
                tracing::error!(
                    plugin_id = %plugin_id,
                    "native cluster plugin panicked during watch_peers",
                );
                return empty_peer_event_stream();
            }
        };
        if result.handle == 0 {
            unsafe {
                drop(Box::from_raw(bridge_ptr.0));
            }
            tracing::error!(
                plugin_id = %plugin_id,
                error = %result.error_json,
                "native cluster plugin refused watch_peers",
            );
            return empty_peer_event_stream();
        }
        let guard = StreamCancelGuard {
            library: Arc::clone(&self.library),
            cancel_fn: self.vtable.cancel_stream,
            plugin_handle: self.handle,
            watch_handle: result.handle,
            bridge_ptr: bridge_ptr.0,
        };
        Box::pin(PeerEventStream { rx, _guard: guard })
    }

    async fn acquire_leadership(
        &self,
        role: &str,
        lease_ttl: std::time::Duration,
    ) -> Result<BoxActiveLease, ClusterError> {
        let args = serde_json::json!({
            "role": role,
            "ttl_ms": lease_ttl.as_millis().min(u64::MAX as u128) as u64,
        });
        self.acquire_lease_common(self.vtable.acquire_leadership, args, "acquire_leadership")
            .await
    }

    async fn acquire_lock(
        &self,
        key: &str,
        lease_ttl: std::time::Duration,
    ) -> Result<BoxActiveLease, ClusterError> {
        let args = serde_json::json!({
            "key": key,
            "ttl_ms": lease_ttl.as_millis().min(u64::MAX as u128) as u64,
        });
        self.acquire_lease_common(self.vtable.acquire_lock, args, "acquire_lock")
            .await
    }

    async fn try_acquire_leadership(
        &self,
        role: &str,
        lease_ttl: std::time::Duration,
    ) -> Result<Option<BoxActiveLease>, ClusterError> {
        let args = serde_json::json!({
            "role": role,
            "ttl_ms": lease_ttl.as_millis().min(u64::MAX as u128) as u64,
        });
        self.try_acquire_lease_common(
            self.vtable.try_acquire_leadership,
            args,
            "try_acquire_leadership",
        )
        .await
    }

    async fn try_acquire_lock(
        &self,
        key: &str,
        lease_ttl: std::time::Duration,
    ) -> Result<Option<BoxActiveLease>, ClusterError> {
        let args = serde_json::json!({
            "key": key,
            "ttl_ms": lease_ttl.as_millis().min(u64::MAX as u128) as u64,
        });
        self.try_acquire_lease_common(self.vtable.try_acquire_lock, args, "try_acquire_lock")
            .await
    }

    async fn publish(
        &self,
        topic: &str,
        routing_key: Option<&str>,
        payload: bytes::Bytes,
    ) -> Result<(), ClusterError> {
        let args = serde_json::json!({
            "topic": topic,
            "routing_key": routing_key,
            "payload": payload.to_vec(),
        });
        let args_str = serde_json::to_string(&args).unwrap_or_else(|_| "{}".into());
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "cluster",
            "publish",
            args_str.len(),
        );
        let args_json = abi_stable::std_types::RString::from(args_str);
        let vt_fn = self.vtable.publish;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        let result = tokio::time::timeout(
            self.library.ffi_limits.data_timeout,
            tokio::task::spawn_blocking(move || vt_fn(handle.ptr(), args_json)),
        )
        .await;
        let raw = match result {
            Ok(Ok(r)) => r,
            _ => {
                call.end_err(0);
                return Err(ClusterError::BackendUnavailable {
                    reason: format!("native plugin '{plugin_id}' timed out or panicked"),
                });
            }
        };
        let resp_bytes = raw.len();
        // Result envelope: `{"ok": null}` /
        // `{"err": ClusterError}`.
        match mcpg_plugin_protocol::result_envelope::decode_result_envelope::<(), ClusterError>(
            raw.as_str(),
        ) {
            Ok(Ok(())) => {
                call.end_ok(resp_bytes);
                Ok(())
            }
            Ok(Err(e)) => {
                call.end_err(resp_bytes);
                Err(e)
            }
            Err(e) => {
                call.end_err(resp_bytes);
                Err(ClusterError::Internal {
                    reason: format!(
                        "native plugin '{plugin_id}' returned undecodable publish envelope: {e}",
                    ),
                })
            }
        }
    }

    async fn subscribe(
        &self,
        topic: &str,
        group: Option<&str>,
        routing_key: Option<&str>,
    ) -> Result<BoxPublishedMessageStream, ClusterError> {
        let (bridge_ptr_raw, sink, rx) = make_stream_bridge(&self.manifest.id);
        let bridge_ptr = SendPtr(bridge_ptr_raw);
        let args = serde_json::json!({
            "topic": topic,
            "group": group,
            "routing_key": routing_key,
        });
        let args_str = serde_json::to_string(&args).unwrap_or_else(|_| "{}".into());
        // Instrument the host→plugin subscribe install only.
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "cluster",
            "subscribe",
            args_str.len(),
        );
        let args_json = abi_stable::std_types::RString::from(args_str);
        let vtable_fn = self.vtable.subscribe;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        let spawn_result =
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), args_json, sink)).await;
        let result = match spawn_result {
            Ok(r) => r,
            Err(_) => {
                call.end_err(0);
                unsafe {
                    drop(Box::from_raw(bridge_ptr.0));
                }
                return Err(ClusterError::BackendUnavailable {
                    reason: format!("native plugin '{plugin_id}' panicked during subscribe",),
                });
            }
        };
        let resp_bytes = result.error_json.len();
        if result.handle == 0 {
            call.end_err(resp_bytes);
            unsafe {
                drop(Box::from_raw(bridge_ptr.0));
            }
            let err = serde_json::from_str::<ClusterError>(result.error_json.as_str()).unwrap_or(
                ClusterError::Internal {
                    reason: format!(
                        "native plugin '{plugin_id}' returned undecodable subscribe error",
                    ),
                },
            );
            return Err(err);
        }
        call.end_ok(resp_bytes);
        let guard = StreamCancelGuard {
            library: Arc::clone(&self.library),
            cancel_fn: self.vtable.cancel_stream,
            plugin_handle: self.handle,
            watch_handle: result.handle,
            bridge_ptr: bridge_ptr.0,
        };
        Ok(Box::pin(PublishedMessageStream { rx, _guard: guard }))
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

fn empty_peer_event_stream() -> BoxPeerEventStream {
    use std::pin::Pin;
    use std::task::{Context, Poll};
    struct Empty;
    impl futures_core::Stream for Empty {
        type Item = PeerEvent;
        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(None)
        }
    }
    Box::pin(Empty)
}

struct PeerEventStream {
    rx: tokio::sync::mpsc::Receiver<String>,
    _guard: StreamCancelGuard,
}

impl futures_core::Stream for PeerEventStream {
    type Item = PeerEvent;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            match self.rx.poll_recv(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                std::task::Poll::Ready(Some(json)) => {
                    match serde_json::from_str::<PeerEvent>(&json) {
                        Ok(ev) => return std::task::Poll::Ready(Some(ev)),
                        Err(_) => continue,
                    }
                }
            }
        }
    }
}

struct PublishedMessageStream {
    rx: tokio::sync::mpsc::Receiver<String>,
    _guard: StreamCancelGuard,
}

impl futures_core::Stream for PublishedMessageStream {
    type Item = PublishedMessage;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            match self.rx.poll_recv(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                std::task::Poll::Ready(Some(json)) => {
                    match serde_json::from_str::<PublishedMessage>(&json) {
                        Ok(msg) => return std::task::Poll::Ready(Some(msg)),
                        Err(_) => continue,
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Transport adapter
// ---------------------------------------------------------------------------
//
// Bridges a host-provided `Arc<dyn MessageDispatcher>` onto the
// plugin's `DispatcherCallbackRef`. The plugin's accept loop runs
// on its own thread; per message it calls the FFI dispatch fn,
// which block_on's the host's async dispatch and returns bytes.
//
// Narrowings carried from the ABI design:
// - `DispatchResponse.stream` is not carried across. If the host
//   dispatcher returns a streaming reply, we surface
//   `DispatcherError::Internal { reason: "stream reply not
//   supported across FFI" }` to the plugin.
// - No SDK macro is shipped for transport (same narrowing pattern
//   as http_route). Plugin authors building transport cdylibs
//   hand-roll the extern "C" fns against the documented vtable.

fn clone_transport(vt: &TransportVTable) -> TransportVTable {
    TransportVTable {
        make: vt.make,
        manifest_json: vt.manifest_json,
        name: vt.name,
        start: vt.start,
        transport_handle_close: vt.transport_handle_close,
        transport_handle_drop: vt.transport_handle_drop,
        transport_handle_listen_address: vt.transport_handle_listen_address,
        shutdown: vt.shutdown,
        drop_instance: vt.drop_instance,
    }
}

/// Host-side bridge between the plugin's `DispatcherCallbackRef`
/// and the real `Arc<dyn MessageDispatcher>`. The plugin calls
/// the extern "C" fn; the fn block_on's the async dispatch.
struct DispatcherBridge {
    dispatcher: Arc<dyn MessageDispatcher>,
    rt: tokio::runtime::Handle,
}

extern "C" fn dispatcher_bridge_callback(
    ctx: usize,
    session_id: abi_stable::std_types::RString,
    message_json: abi_stable::std_types::RString,
) -> DispatcherCallbackResult {
    // SAFETY: `ctx` is a `*const DispatcherBridge` leaked by the
    // adapter's `start()`. Stays live until the transport
    // handle's Drop frees the box.
    let bridge = unsafe { &*(ctx as *const DispatcherBridge) };
    #[derive(serde::Deserialize)]
    struct MessageWire {
        bytes: Vec<u8>,
    }
    let message: MessageWire = match serde_json::from_str(message_json.as_str()) {
        Ok(m) => m,
        Err(e) => {
            let err = DispatcherError::InvalidMessage {
                reason: format!("malformed dispatch message_json: {e}"),
            };
            return DispatcherCallbackResult {
                reply_json: abi_stable::std_types::RString::from(
                    serde_json::to_string(&serde_json::json!({"err": err})).unwrap_or_default(),
                ),
            };
        }
    };
    let session = session_id.as_str().to_owned();
    let bytes = bytes::Bytes::from(message.bytes);
    // block_on the async dispatch. Plugin's thread blocks here
    // until the host's pipeline returns. The rt Handle was
    // captured at `start()` time; `block_on` works from any
    // thread the runtime is visible from.
    let dispatcher = Arc::clone(&bridge.dispatcher);
    let result = bridge
        .rt
        .block_on(async move { dispatcher.dispatch(&session, bytes).await });
    let reply_wire = match result {
        Ok(DispatchResponse {
            reply: Some(b),
            stream: None,
        }) => serde_json::json!({"ok": {"bytes": b.to_vec()}}),
        Ok(DispatchResponse {
            reply: None,
            stream: None,
        }) => serde_json::json!({"ok": {"bytes": Vec::<u8>::new()}}),
        Ok(DispatchResponse {
            stream: Some(_), ..
        }) => {
            let err = DispatcherError::Internal {
                reason: "streaming reply not supported across FFI".into(),
            };
            serde_json::json!({"err": err})
        }
        Err(err) => serde_json::json!({"err": err}),
    };
    DispatcherCallbackResult {
        reply_json: abi_stable::std_types::RString::from(
            serde_json::to_string(&reply_wire).unwrap_or_default(),
        ),
    }
}

pub struct NativeTransportAdapter {
    library: Arc<LoadedNativePlugin>,
    vtable: TransportVTable,
    handle: RPluginHandle,
    manifest: PluginManifest,
    name: String,
    #[allow(dead_code)]
    alias: String,
    _host_bridge: crate::host_bridge::HostBridge,
}

unsafe impl Send for NativeTransportAdapter {}
unsafe impl Sync for NativeTransportAdapter {}

impl NativeTransportAdapter {
    pub fn new(
        library: Arc<LoadedNativePlugin>,
        config: serde_json::Value,
        alias: String,
        services: Arc<dyn crate::host_services::HostServices>,
    ) -> Result<Self> {
        let vt = match library.registration.first_transport() {
            Some(vt) => clone_transport(vt),
            None => {
                return Err(anyhow!("plugin does not export a Transport vtable"));
            }
        };
        let cfg = abi_stable::std_types::RString::from(
            serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        );
        let host_bridge =
            crate::host_bridge::HostBridge::with_services(None, alias.clone(), services);
        let host_ref = host_bridge.as_ffi_ref();
        let inner_name = abi_stable::std_types::RString::new();
        let handle = guard_ffi_make(|| (vt.make)(host_ref, cfg, inner_name));
        if handle.is_null() {
            return Err(anyhow!("native transport plugin panicked during make"));
        }
        let manifest_json = guard_ffi_rstring("manifest_json", || (vt.manifest_json)(handle));
        if manifest_json.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!("native transport plugin returned empty manifest"));
        }
        let manifest: PluginManifest =
            serde_json::from_str(manifest_json.as_str()).map_err(|e| {
                guard_ffi_drop(|| (vt.drop_instance)(handle));
                anyhow::Error::from(e).context("invalid manifest from transport plugin")
            })?;
        let name_rstr = (vt.name)(handle);
        if name_rstr.as_str().is_empty() {
            guard_ffi_drop(|| (vt.drop_instance)(handle));
            return Err(anyhow!("native transport plugin returned empty name"));
        }
        let name = name_rstr.as_str().to_owned();
        Ok(Self {
            library,
            vtable: vt,
            handle,
            manifest,
            name,
            alias,
            _host_bridge: host_bridge,
        })
    }
}

impl Drop for NativeTransportAdapter {
    fn drop(&mut self) {
        guard_ffi_drop(|| (self.vtable.drop_instance)(self.handle));
        let _ = &self.library;
    }
}

#[async_trait]
impl Transport for NativeTransportAdapter {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn start(
        &self,
        listener_config: &serde_json::Value,
        dispatcher: Arc<dyn MessageDispatcher>,
    ) -> Result<Box<dyn TransportHandle>, TransportError> {
        let rt = tokio::runtime::Handle::current();
        let bridge = Box::new(DispatcherBridge { dispatcher, rt });
        let bridge_ptr_raw = Box::into_raw(bridge);
        let bridge_ptr = SendPtr(bridge_ptr_raw);
        let cb = DispatcherCallbackRef {
            ctx: bridge_ptr_raw as usize,
            dispatch: dispatcher_bridge_callback,
        };
        let config_str = serde_json::to_string(listener_config).unwrap_or_else(|_| "{}".into());
        let call = crate::ffi_metering::FfiCall::begin(
            &self.manifest.id,
            "transport",
            "start",
            config_str.len(),
        );
        let config_json = abi_stable::std_types::RString::from(config_str);
        let vtable_fn = self.vtable.start;
        let handle = SendHandle(self.handle);
        let plugin_id = self.manifest.id.clone();
        let spawn_result =
            tokio::task::spawn_blocking(move || vtable_fn(handle.ptr(), config_json, cb)).await;
        let result = match spawn_result {
            Ok(r) => r,
            Err(_) => {
                call.end_err(0);
                // SAFETY: bridge_ptr was Box::into_raw'd above; no
                // callback ever fired because start panicked.
                unsafe {
                    drop(Box::from_raw(bridge_ptr.0));
                }
                return Err(TransportError::Io {
                    reason: format!("native plugin '{plugin_id}' panicked during start"),
                });
            }
        };
        let resp_bytes = result.error_json.len() + result.metadata_json.len();
        if result.handle == 0 {
            call.end_err(resp_bytes);
            unsafe {
                drop(Box::from_raw(bridge_ptr.0));
            }
            let err = serde_json::from_str::<TransportError>(result.error_json.as_str()).unwrap_or(
                TransportError::Io {
                    reason: format!("native plugin '{plugin_id}' returned undecodable error"),
                },
            );
            return Err(err);
        }
        call.end_ok(resp_bytes);
        // `TransportVTable::start` returns a `StreamHandle`;
        // the listen address (when present) is
        // encoded into `metadata_json` as `{"listen_address": "..."}`.
        let listen_address = if result.metadata_json.as_str().is_empty() {
            None
        } else {
            #[derive(serde::Deserialize)]
            struct StartMeta {
                listen_address: Option<String>,
            }
            match serde_json::from_str::<StartMeta>(result.metadata_json.as_str()) {
                Ok(meta) => meta.listen_address.filter(|s| !s.is_empty()),
                Err(_) => None,
            }
        };
        Ok(Box::new(NativeTransportHandle {
            library: Arc::clone(&self.library),
            close_fn: self.vtable.transport_handle_close,
            drop_fn: self.vtable.transport_handle_drop,
            listen_address_fn: self.vtable.transport_handle_listen_address,
            plugin_handle: self.handle,
            transport_handle: result.handle,
            bridge_ptr: bridge_ptr.0,
            cached_listen_address: std::sync::Mutex::new(listen_address),
        }))
    }

    async fn shutdown(&self) {
        guard_ffi_drop(|| (self.vtable.shutdown)(self.handle));
    }
}

pub struct NativeTransportHandle {
    library: Arc<LoadedNativePlugin>,
    close_fn: extern "C" fn(RPluginHandle, usize),
    drop_fn: extern "C" fn(RPluginHandle, usize),
    listen_address_fn: extern "C" fn(RPluginHandle, usize) -> abi_stable::std_types::RString,
    plugin_handle: RPluginHandle,
    transport_handle: usize,
    bridge_ptr: *mut DispatcherBridge,
    cached_listen_address: std::sync::Mutex<Option<String>>,
}

unsafe impl Send for NativeTransportHandle {}
unsafe impl Sync for NativeTransportHandle {}

#[async_trait]
impl TransportHandle for NativeTransportHandle {
    async fn listen_address(&self) -> Option<String> {
        // Cheap path: use cached value populated at start(). If
        // caller wants fresh, we call into the plugin.
        if let Ok(guard) = self.cached_listen_address.lock()
            && guard.is_some()
        {
            return guard.clone();
        }
        let vt_fn = self.listen_address_fn;
        let plugin_handle = SendHandle(self.plugin_handle);
        let transport_handle = self.transport_handle;
        let result =
            tokio::task::spawn_blocking(move || vt_fn(plugin_handle.ptr(), transport_handle)).await;
        let raw = match result {
            Ok(r) => r,
            Err(_) => return None,
        };
        if raw.as_str().is_empty() {
            None
        } else {
            Some(raw.as_str().to_owned())
        }
    }

    async fn close(&self) {
        let vt_fn = self.close_fn;
        let plugin_handle = SendHandle(self.plugin_handle);
        let transport_handle = self.transport_handle;
        let _ =
            tokio::task::spawn_blocking(move || vt_fn(plugin_handle.ptr(), transport_handle)).await;
    }
}

impl Drop for NativeTransportHandle {
    fn drop(&mut self) {
        // Tell plugin to free its transport state.
        (self.drop_fn)(self.plugin_handle, self.transport_handle);
        // Plugin MUST NOT call the dispatcher after
        // transport_handle_drop returns — contract of the vtable.
        // Safe to free the bridge box now.
        // SAFETY: bridge_ptr was Box::into_raw'd in start().
        unsafe {
            drop(Box::from_raw(self.bridge_ptr));
        }
        let _ = &self.library;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi_stable::std_types::{ROption, RString, RVec};

    // A panic inside a foreign cdylib's lifecycle slot must be caught
    // host-side and mapped to the sentinel value the caller already checks,
    // never unwound across `extern "C"`.
    #[test]
    fn ffi_guards_catch_panic_into_sentinels() {
        let h = guard_ffi_make(|| panic!("boom in make"));
        assert!(h.is_null(), "panicking make must yield a null handle");

        let s = guard_ffi_rstring("manifest_json", || panic!("boom in manifest"));
        assert!(
            s.as_str().is_empty(),
            "panicking rstring slot must yield empty"
        );

        // Drop guard must swallow the panic (no unwind escapes).
        guard_ffi_drop(|| panic!("boom in drop"));

        // Non-panicking paths pass values through unchanged.
        let ok = guard_ffi_rstring("manifest_json", || RString::from("{\"id\":\"x\"}"));
        assert_eq!(ok.as_str(), "{\"id\":\"x\"}");
    }

    fn empty_registration(version: u32) -> PluginRegistration {
        PluginRegistration {
            abi_version: version,
            plugin_id: RString::from("test.plugin"),
            plugin_version: RString::from("0.0.1"),
            module_path_prefix: RString::from("dev.mcpg.builtin.test"),
            entities: RVec::new(),
            capabilities: RVec::new(),
            backend_profile_json: ROption::RNone,
            descriptor_yaml: Default::default(),
        }
    }

    #[test]
    fn validate_rejects_mismatched_abi_version() {
        let reg = empty_registration(MCPG_PLUGIN_ABI_VERSION + 1);
        let err = validate_registration(&reg).unwrap_err().to_string();
        assert!(err.contains("ABI version"), "got: {err}");
    }

    #[test]
    fn decode_backend_profile_none_yields_none() {
        let reg = empty_registration(MCPG_PLUGIN_ABI_VERSION);
        assert!(decode_backend_profile(&reg).unwrap().is_none());
    }

    #[test]
    fn decode_backend_profile_round_trips_declared_profile() {
        use mcpg_plugin_protocol::manifest::{BackendProfile, HealthProbeDecl};
        let profile = BackendProfile {
            health_probe: HealthProbeDecl::Http {
                path: "/healthz".to_owned(),
            },
            type_label: Some("acme".to_owned()),
            dynamic_list: true,
            pipeline_capable: true,
            transport_only_fields: vec!["/url".to_owned()],
        };
        let mut reg = empty_registration(MCPG_PLUGIN_ABI_VERSION);
        reg.backend_profile_json =
            ROption::RSome(RString::from(serde_json::to_string(&profile).unwrap()));
        let decoded = decode_backend_profile(&reg).unwrap().unwrap();
        assert_eq!(decoded, profile);
    }

    #[test]
    fn decode_backend_profile_rejects_malformed_json() {
        let mut reg = empty_registration(MCPG_PLUGIN_ABI_VERSION);
        reg.backend_profile_json = ROption::RSome(RString::from("{ not json"));
        assert!(decode_backend_profile(&reg).is_err());
    }

    #[test]
    fn validate_rejects_registration_with_no_entities() {
        let reg = empty_registration(MCPG_PLUGIN_ABI_VERSION);
        let err = validate_registration(&reg).unwrap_err().to_string();
        assert!(err.contains("no entities"), "got: {err}");
    }

    #[test]
    fn decode_capabilities_passes_through_known_kinds() {
        use mcpg_plugin_protocol::abi::TypedCapabilityDecl;
        use mcpg_plugin_protocol::capability::Capability;

        let mut reg = empty_registration(MCPG_PLUGIN_ABI_VERSION);
        reg.capabilities = RVec::from(vec![
            TypedCapabilityDecl::from_capability(&Capability::NetworkOutbound),
            TypedCapabilityDecl::from_capability(&Capability::FilesystemRead {
                paths: vec!["/etc/myapp".into()],
            }),
        ]);
        let caps = super::decode_capabilities(&reg).unwrap();
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0], Capability::NetworkOutbound);
        assert!(
            matches!(caps[1], Capability::FilesystemRead { ref paths } if paths == &["/etc/myapp".to_owned()])
        );
    }

    #[test]
    fn decode_capabilities_rejects_unknown_kind_with_plugin_id() {
        use mcpg_plugin_protocol::abi::TypedCapabilityDecl;

        let mut reg = empty_registration(MCPG_PLUGIN_ABI_VERSION);
        reg.capabilities = RVec::from(vec![TypedCapabilityDecl {
            kind: RString::from("future_capability"),
            args_json: RString::new(),
        }]);
        let err = super::decode_capabilities(&reg).unwrap_err().to_string();
        assert!(err.contains("test.plugin"), "missing plugin id: {err}");
        assert!(err.contains("future_capability"), "missing kind: {err}");
    }

    // ----- abi_stable layout/type-identity check -----

    #[test]
    fn abi_layout_check_accepts_identical_layout() {
        // The host comparing PluginRegistration's layout against itself must
        // pass — this is the in-tree case (plugin + host built from the same
        // mcpg_plugin_protocol). It also proves the host accessor + the
        // abi_checking call wire up correctly.
        use mcpg_plugin_protocol::abi::{PluginRegistration, plugin_registration_layout};
        let host = <PluginRegistration as abi_stable::StableAbi>::LAYOUT;
        let raw = plugin_registration_layout();
        assert!(!raw.is_null(), "layout accessor must not be null");
        let plugin: &'static abi_stable::type_layout::TypeLayout = unsafe { &*raw };
        assert!(
            abi_stable::abi_stability::abi_checking::check_layout_compatibility(host, plugin)
                .is_ok(),
            "identical PluginRegistration layout must be compatible"
        );
    }

    #[test]
    fn abi_layout_check_rejects_a_different_type_layout() {
        // A different type's layout must be REJECTED — proves the check
        // actually discriminates (not a no-op) and is wired correctly.
        //
        // NOTE on scope: `check_layout_compatibility` name-gates first, so
        // this (RString vs PluginRegistration) trips on the type-name
        // mismatch. Demonstrating the harder property — that a *same-named*
        // `PluginRegistration` built with reordered/added fields or a changed
        // nested vtable signature is caught — is not expressible in one
        // process (two differently-laid-out types can't share a name). That
        // detection rests on abi_stable's documented recursion (positional
        // field-name + size/alignment + field-count comparison, recursing into
        // nested StableAbi structs/enums incl. the per-class VTables) and is
        // exercised end-to-end by the cross-build `e2e/plugin-ffi` suite, where
        // a genuinely drifted cdylib is loaded against the host.
        use mcpg_plugin_protocol::abi::PluginRegistration;
        let host = <PluginRegistration as abi_stable::StableAbi>::LAYOUT;
        // RString is `#[repr(C)] StableAbi` but a wholly different type/shape.
        let other = <abi_stable::std_types::RString as abi_stable::StableAbi>::LAYOUT;
        assert!(
            abi_stable::abi_stability::abi_checking::check_layout_compatibility(host, other)
                .is_err(),
            "a different type's layout must be refused"
        );
    }

    // ----- load-time content re-hash (TOCTOU guard) -----

    fn toctou_tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mcpg-toctou-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn load_time_rehash_detects_same_length_inplace_swap() {
        // The verify→load guard re-hashes the artifact and compares to the
        // verified digest. A same-length in-place rewrite (the attack that
        // defeats an mtime/inode pin, since mtime is forgeable) changes the
        // content hash and is therefore detected.
        let dir = toctou_tempdir();
        let path = dir.join("plugin.so");
        std::fs::write(&path, b"verified-bytes-AAAA").unwrap();
        let verified = crate::verify::sha256_file(&path).unwrap();
        // Same byte length, different content (in place).
        std::fs::write(&path, b"swapped-bytes-BBBBB").unwrap();
        let reload = crate::verify::sha256_file(&path).unwrap();
        assert_ne!(
            verified, reload,
            "a same-length in-place rewrite must change the content hash"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_time_rehash_stable_when_unchanged() {
        let dir = toctou_tempdir();
        let path = dir.join("plugin.so");
        std::fs::write(&path, b"unchanged-artifact-bytes").unwrap();
        let a = crate::verify::sha256_file(&path).unwrap();
        let b = crate::verify::sha256_file(&path).unwrap();
        assert_eq!(
            a, b,
            "hash must be stable across reads of an unchanged file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod descriptor_manifest_tests {
    use super::*;
    use abi_stable::std_types::{ROption, RString, RVec};
    use mcpg_plugin_protocol::abi::MCPG_PLUGIN_ABI_VERSION;

    const SYSLOG_LIKE_DESCRIPTOR: &str = r#"
schema: mcpg.plugin/v1
id: dev.mcpg.log.syslog
name: Syslog Log Sink
license: Apache-2.0
description: Ships gateway logs to a syslog collector.
class: log_sink
runtime: native-cdylib-v1
protocol_version: "1.0"
tags: [logging]
provides: []
provides_schemes: []
"#;

    fn registration(descriptor: &str) -> PluginRegistration {
        PluginRegistration {
            abi_version: MCPG_PLUGIN_ABI_VERSION,
            plugin_id: RString::from("dev.mcpg.log.syslog"),
            plugin_version: RString::from("0.0.1-alpha.6"),
            module_path_prefix: RString::from("mcpg_plugin_log_syslog"),
            entities: RVec::new(),
            capabilities: RVec::new(),
            backend_profile_json: ROption::RNone,
            descriptor_yaml: RString::from(descriptor),
        }
    }

    /// The manifest must come off the descriptor without touching a vtable —
    /// the whole point, since a strict-config plugin cannot be constructed
    /// with the empty config the host has at manifest time. The registration
    /// here declares no entities at all, so any attempt to probe would fail.
    #[test]
    fn manifest_derives_from_descriptor_without_constructing_an_instance() {
        let manifest = derive_manifest(&registration(SYSLOG_LIKE_DESCRIPTOR))
            .expect("descriptor-derived manifest");

        assert_eq!(manifest.id, "dev.mcpg.log.syslog");
        assert_eq!(manifest.name, "Syslog Log Sink");
        assert_eq!(
            manifest.plugin_class,
            mcpg_plugin_protocol::manifest::PluginClass::LogSink
        );
        assert_eq!(manifest.protocol_version, "1.0");
        assert_eq!(manifest.license.as_deref(), Some("Apache-2.0"));
        // Off the registration, not the descriptor.
        assert_eq!(manifest.version, "0.0.1-alpha.6");
        assert_eq!(manifest.module_path_prefix, "mcpg_plugin_log_syslog");
        // Host-derived downstream; the descriptor never populates these.
        assert!(manifest.required_capabilities.is_empty());
        assert!(manifest.backend_profile.is_none());
    }

    #[test]
    fn malformed_descriptor_is_a_clear_load_error() {
        let err = derive_manifest(&registration("this: is: not: a: descriptor"))
            .expect_err("a broken descriptor must fail the load");
        let msg = format!("{err:#}");
        assert!(msg.contains("descriptor_yaml"), "got: {msg}");
    }

    /// Hand-built registrations (built-ins, fixtures) carry no descriptor and
    /// must still reach the probe path rather than erroring on the parse.
    #[test]
    fn empty_descriptor_falls_through_to_the_probe() {
        let err = derive_manifest(&registration(""))
            .expect_err("no entities to probe, so this errors — but not on parsing");
        let msg = format!("{err:#}");
        assert!(msg.contains("exports no entities"), "got: {msg}");
    }
}
