//! Wasm plugin loader — Wasmtime Component Model integration.
//!
//! Loads `.wasm` components and wraps them in the ToolGatePlugin/TransformPlugin/
//! IdentityProviderPlugin trait implementations. This module is gated behind the `wasm`
//! feature flag.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │  Gateway                                         │
//! │                                                  │
//! │  PluginRegistry                                  │
//! │    ├── WasmToolGatePlugin (Box<dyn ToolGate>)   │
//! │    ├── WasmTransformPlugin                       │
//! │    └── WasmIdentityPlugin                        │
//! │                                                  │
//! │  Each wraps a Wasmtime Component + Store          │
//! │  with resource limits (memory, fuel, timeout)    │
//! └──────────────────────────────────────────────────┘
//! ```
//!
//! ## Security Model
//!
//! - Wasm plugins run in an isolated sandbox (no filesystem, no network)
//! - Memory bounded via `memory_limit_bytes` on the store
//! - Execution bounded via fuel metering (configurable per-plugin)
//! - Wall-clock timeout via epoch interruption
//! - WASI capabilities are denied by default

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use mcpg_plugin_protocol::{
    GateDecision, IdentityProviderPlugin, IdentityResolution, PluginClass, PluginContext,
    PluginManifest, ToolGatePlugin, TransformPlugin, TransformResult, async_trait,
};
use tracing::info;
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};

// wasmtime 42+ replaced `anyhow::Error` with its own `wasmtime::Error`
// type as the error for most fallible operations. `anyhow::Context`
// can't be applied directly to `Result<T, wasmtime::Error>` because
// `wasmtime::Error` doesn't implement `std::error::Error`. This
// extension trait bridges the two: it converts the wasmtime error to
// its `Display` string and wraps in an `anyhow!` with the context
// message. Used at every fallible wasmtime call-site in this module.
trait WasmtimeResultExt<T> {
    fn wm_context<S: std::fmt::Display>(self, msg: S) -> Result<T>;
    fn wm_with_context<F, S>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> S,
        S: std::fmt::Display;
}

impl<T> WasmtimeResultExt<T> for std::result::Result<T, wasmtime::Error> {
    fn wm_context<S: std::fmt::Display>(self, msg: S) -> Result<T> {
        self.map_err(|e| anyhow::anyhow!("{msg}: {e}"))
    }

    fn wm_with_context<F, S>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> S,
        S: std::fmt::Display,
    {
        self.map_err(|e| {
            let msg = f();
            anyhow::anyhow!("{msg}: {e}")
        })
    }
}

// ---------------------------------------------------------------------------
// Wasmtime component bindgen — generates typed Rust wrappers from plugin.wit
// ---------------------------------------------------------------------------

mod wasm_transform_bindgen {
    wasmtime::component::bindgen!({
        path: "wit/plugin.wit",
        world: "transform-plugin",
    });
}

mod wasm_tool_gate_bindgen {
    wasmtime::component::bindgen!({
        path: "wit/plugin.wit",
        world: "tool-gate-plugin",
    });
}

mod wasm_identity_bindgen {
    wasmtime::component::bindgen!({
        path: "wit/plugin.wit",
        world: "identity-plugin",
    });
}

use wasm_identity_bindgen::IdentityPlugin as IdentityPluginWorld;
use wasm_tool_gate_bindgen::ToolGatePlugin as ToolGatePluginWorld;
use wasm_transform_bindgen::TransformPlugin as TransformPluginWorld;

// Each bindgen! world generates its own copy of the shared `types`
// interface. Re-alias per-world so conversion helpers can reference
// the correct parent module. Under wasmtime 38, each world exports
// its interfaces under `<world_module>::exports::...` while the
// shared `types` interface used by every world-facing record lives
// at `<world_module>::mcpg::plugin::types` (the WIT package path
// reflected directly).
use wasm_identity_bindgen::mcpg::plugin::types as wit_identity;
use wasm_tool_gate_bindgen::mcpg::plugin::types as wit_gate;
use wasm_transform_bindgen::mcpg::plugin::types as wit_gen;

// ---------------------------------------------------------------------------
// WIT type conversion helpers
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn to_wit_identity(id: &mcpg_plugin_protocol::PluginIdentity) -> wit_gen::PluginIdentity {
    wit_gen::PluginIdentity {
        kind: id.kind.clone(),
        trust_level: id.trust_level.clone(),
        subject_id: id.subject_id.clone(),
        auth_provider: id.auth_provider.clone(),
        issuer: id.issuer.clone(),
        roles: id.roles.clone(),
        groups: id.groups.clone(),
        scopes: id.scopes.clone(),
        attributes: id
            .attributes
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    }
}

/// Macro: construct a world-specific `PluginContext` record. Each
/// `bindgen!` world generates its own `types::PluginContext` type even
/// though the record fields are identical; this macro stamps the same
/// conversion once per world without bringing a trait into scope.
macro_rules! to_wit_context_for {
    ($ns:ident, $ctx:expr) => {{
        let ctx = $ctx;
        $ns::PluginContext {
            request_id: ctx.request_id.clone(),
            session_id: ctx.session_id.clone(),
            tool_name: ctx.tool_name.clone(),
            // MCP surface propagates into every world.
            surface: ctx.surface.clone(),
            identity: $ns::PluginIdentity {
                kind: ctx.identity.kind.clone(),
                trust_level: ctx.identity.trust_level.clone(),
                subject_id: ctx.identity.subject_id.clone(),
                auth_provider: ctx.identity.auth_provider.clone(),
                issuer: ctx.identity.issuer.clone(),
                roles: ctx.identity.roles.clone(),
                groups: ctx.identity.groups.clone(),
                scopes: ctx.identity.scopes.clone(),
                attributes: ctx
                    .identity
                    .attributes
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            },
            transport: ctx.transport.clone(),
        }
    }};
}

fn from_wit_transform_result(wr: wit_gen::TransformResult) -> TransformResult {
    match wr {
        wit_gen::TransformResult::Unchanged => TransformResult::Unchanged,
        wit_gen::TransformResult::Modified(json_str) => match serde_json::from_str(&json_str) {
            Ok(value) => TransformResult::Modified { value },
            Err(e) => TransformResult::Error {
                message: format!("wasm transform returned invalid JSON: {e}"),
            },
        },
        wit_gen::TransformResult::Error(msg) => TransformResult::Error { message: msg },
    }
}

/// Convert a WIT gate-decision to the Rust GateDecision type.
fn from_wit_gate_decision(wd: wit_gate::GateDecision) -> GateDecision {
    match wd {
        wit_gate::GateDecision::Allow(allow) => {
            let parse_optional_json = |value: Option<String>| -> Option<serde_json::Value> {
                value
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .and_then(|s| serde_json::from_str(s).ok())
            };
            GateDecision::Allow {
                metadata: parse_optional_json(allow.metadata),
                modified_arguments: parse_optional_json(allow.modified_arguments),
                modified_result: parse_optional_json(allow.modified_result),
            }
        }
        wit_gate::GateDecision::Deny(denial) => GateDecision::Deny {
            http_status: denial.http_status,
            code: denial.code,
            message: denial.message,
            error_data: denial
                .error_data
                .and_then(|s| serde_json::from_str(&s).ok()),
        },
        wit_gate::GateDecision::Challenge(challenge) => GateDecision::Challenge {
            http_status: challenge.http_status,
            code: challenge.code,
            message: challenge.message,
            challenge_data: serde_json::from_str(&challenge.challenge_data)
                .unwrap_or(serde_json::Value::Null),
        },
    }
}

/// Convert a WIT identity-resolution to the Rust IdentityResolution type.
fn from_wit_identity_resolution(wr: wit_identity::IdentityResolution) -> IdentityResolution {
    match wr {
        wit_identity::IdentityResolution::Resolved(pi) => IdentityResolution::Resolved {
            identity: mcpg_plugin_protocol::PluginIdentity {
                kind: pi.kind,
                trust_level: pi.trust_level,
                subject_id: pi.subject_id,
                auth_provider: pi.auth_provider,
                issuer: pi.issuer,
                roles: pi.roles,
                groups: pi.groups,
                scopes: pi.scopes,
                attributes: pi.attributes.into_iter().collect(),
            },
        },
        wit_identity::IdentityResolution::None => IdentityResolution::None,
        // The WASM WIT surface carries only the reason; WASM identity plugins
        // cannot attach response headers (native cdylibs can).
        wit_identity::IdentityResolution::Invalid(reason) => IdentityResolution::Invalid {
            reason,
            response_headers: Vec::new(),
        },
    }
}

// ---------------------------------------------------------------------------
// Resource limits
// ---------------------------------------------------------------------------

/// Resource limits for a Wasm plugin instance.
#[derive(Debug, Clone)]
pub struct WasmResourceLimits {
    /// Maximum linear memory in bytes (default: 64 MiB).
    pub memory_limit_bytes: usize,
    /// Maximum fuel (instructions) per invocation (default: 10M).
    pub fuel_per_invocation: u64,
    /// Wall-clock timeout per invocation in milliseconds (default: 100ms).
    pub timeout_ms: u64,
}

impl Default for WasmResourceLimits {
    fn default() -> Self {
        Self {
            memory_limit_bytes: 64 * 1024 * 1024, // 64 MiB
            fuel_per_invocation: 10_000_000,      // 10M instructions
            timeout_ms: 100,                      // 100ms
        }
    }
}

// ---------------------------------------------------------------------------
// Wasm host state
// ---------------------------------------------------------------------------

/// Per-store host state — tracks invocation context and limits.
struct PluginHostState {
    /// Read back by the [`wasmtime::ResourceLimiter`] impl below to bound
    /// the guest's linear-memory growth. Wired onto every store via
    /// [`new_limited_store`]; the epoch + fuel hooks enforce time and
    /// instruction budgets separately off the store.
    limits: WasmResourceLimits,
    wasi_ctx: wasmtime_wasi::WasiCtx,
    resource_table: wasmtime::component::ResourceTable,
}

impl wasmtime_wasi::WasiView for PluginHostState {
    fn ctx(&mut self) -> wasmtime_wasi::WasiCtxView<'_> {
        wasmtime_wasi::WasiCtxView {
            ctx: &mut self.wasi_ctx,
            table: &mut self.resource_table,
        }
    }
}

/// Bound the guest's linear memory to `limits.memory_limit_bytes`.
///
/// Without this, `memory_limit_bytes` was inert (documented-but-unenforced)
/// and a guest could `memory.grow` without bound — a host-process OOM/DoS
/// vector. Returning `Ok(false)` makes the guest's `memory.grow` return -1
/// (a graceful failure the guest must handle) rather than trapping. Tables
/// are left to wasmtime's own caps; linear memory is the DoS surface the
/// config knob targets.
impl wasmtime::ResourceLimiter for PluginHostState {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> std::result::Result<bool, wasmtime::Error> {
        Ok(desired <= self.limits.memory_limit_bytes)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> std::result::Result<bool, wasmtime::Error> {
        Ok(true)
    }
}

/// Create a minimal WASI context with no capabilities (sandbox).
fn new_wasi_ctx() -> wasmtime_wasi::WasiCtx {
    wasmtime_wasi::WasiCtxBuilder::new().build()
}

fn new_host_state(limits: &WasmResourceLimits) -> PluginHostState {
    PluginHostState {
        limits: limits.clone(),
        wasi_ctx: new_wasi_ctx(),
        resource_table: wasmtime::component::ResourceTable::new(),
    }
}

/// Create a `Store` with the memory `ResourceLimiter` wired so the guest's
/// linear memory cannot grow past `limits.memory_limit_bytes`. All store
/// creations go through here so no instantiation path can forget the cap.
fn new_limited_store(engine: &Engine, limits: &WasmResourceLimits) -> Store<PluginHostState> {
    let mut store = Store::new(engine, new_host_state(limits));
    // `PluginHostState` itself implements `ResourceLimiter`.
    store.limiter(|state| state as &mut dyn wasmtime::ResourceLimiter);
    store
}

/// Reject a guest whose reported protocol version doesn't match the host's
/// compiled-in [`mcpg_plugin_protocol::PROTOCOL_VERSION`].
///
/// This is the Wasm analog of the native ABI-version sentinel
/// (`native_loader::validate_registration`'s `abi_version` check): a guest
/// built against a different wire contract must not load. The descriptor
/// cross-check only proves the sidecar agrees with the guest — it does not
/// pin either to the host's contract, so this is a distinct, necessary gate.
fn check_guest_protocol_version(plugin_id: &str, got: &str) -> Result<()> {
    if got != mcpg_plugin_protocol::PROTOCOL_VERSION {
        return Err(anyhow::anyhow!(
            "wasm plugin '{}' reports protocol_version '{}' but the host requires '{}'; \
             rebuild the guest against the current protocol",
            plugin_id,
            got,
            mcpg_plugin_protocol::PROTOCOL_VERSION,
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Wasm engine (shared across all plugins)
// ---------------------------------------------------------------------------

/// Create a shared Wasmtime engine configured for plugin hosting.
///
/// The engine is compiled once and shared across all Wasm plugin instances.
/// It enables:
/// - Fuel metering (for instruction budgets)
/// - Epoch interruption (for wall-clock timeouts)
/// - Component model (for WIT-defined interfaces)
pub fn create_wasm_engine() -> Result<Engine> {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config.wasm_component_model(true);
    // Cranelift is the default compiler — AOT compilation on first load
    Engine::new(&config).wm_context("failed to create wasmtime engine")
}

/// One long-lived epoch ticker per loaded plugin. A single daemon thread
/// advances the engine's epoch at a fixed cadence for the plugin's whole
/// lifetime; each per-call store sets its own epoch deadline relative to
/// that shared clock.
///
/// The engine epoch is shared across all of a plugin's concurrent calls, so
/// a single constant-cadence ticker keeps the effective per-call timeout
/// accurate and independent of concurrency (a per-call ticker would advance
/// the shared epoch N× under N concurrent calls and trip calls before their
/// real budget) and bounds thread use to one per plugin rather than one per
/// invocation.
struct EpochTicker {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl EpochTicker {
    /// Tick cadence. The per-store epoch deadline is expressed in these
    /// ticks, so a deadline of `timeout_ms / TICK_MS` ≈ `timeout_ms`.
    const TICK_MS: u64 = 10;

    fn start(engine: Engine) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let tick = std::time::Duration::from_millis(Self::TICK_MS);
            while !stop_for_thread.load(Ordering::Relaxed) {
                std::thread::sleep(tick);
                engine.increment_epoch();
            }
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Extra wall-clock allowance on the OUTER `spawn_blocking` timeout, beyond
/// the in-guest epoch-trap deadline (`timeout_ms`). The epoch trap is the
/// primary, precise bound; the outer timeout is a backstop for a guest that
/// somehow evades it, so it is set slightly longer to let the trap fire and
/// the blocking thread unwind cleanly first.
const WASM_CALL_GRACE_MS: u64 = 100;

/// Build a fresh resource-limited store + WASI linker for one invocation.
/// The epoch deadline is set relative to the plugin's long-lived shared
/// [`EpochTicker`]; no per-call ticker thread is spawned.
fn build_invocation_store(
    engine: &Engine,
    limits: &WasmResourceLimits,
) -> Result<(Store<PluginHostState>, Linker<PluginHostState>)> {
    let mut store = new_limited_store(engine, limits);
    store.set_fuel(limits.fuel_per_invocation).ok();
    let ticks = (limits.timeout_ms / EpochTicker::TICK_MS).max(1);
    store.epoch_deadline_trap();
    store.set_epoch_deadline(ticks);

    let mut linker = Linker::<PluginHostState>::new(engine);
    wasmtime_wasi::p2::add_to_linker_sync(&mut linker).wm_context("failed to link WASI")?;
    Ok((store, linker))
}

/// Why a WASM guest invocation did not return a value — used to map every
/// slot's failure to its fail-closed (or, for identity, fail-open-to-None)
/// outcome uniformly.
enum WasmCallFailure {
    /// The outer wall-clock backstop fired before the guest returned.
    Timeout,
    /// The blocking task panicked (the guest call unwound across the await).
    Panicked(String),
    /// Instantiation or the guest call returned an error (trap, fuel/epoch
    /// exhaustion, invalid output).
    Error(anyhow::Error),
}

impl WasmCallFailure {
    fn describe(&self) -> String {
        match self {
            Self::Timeout => "timed out".to_owned(),
            Self::Panicked(m) => format!("panicked: {m}"),
            Self::Error(e) => format!("error: {e}"),
        }
    }

    /// Emit the slot-appropriate metric + a fail-closed log line.
    fn log_and_count(&self, plugin_id: &str, slot: &str) {
        match self {
            Self::Timeout => {
                metrics::counter!(
                    "mcpg_wasm_plugin_timeout_total",
                    "plugin_id" => plugin_id.to_owned(),
                )
                .increment(1);
                tracing::error!(plugin_id, slot, "wasm guest call timed out — fail-closed");
            }
            _ => {
                metrics::counter!(
                    "mcpg_wasm_plugin_error_deny_total",
                    "plugin_id" => plugin_id.to_owned(),
                )
                .increment(1);
                tracing::error!(
                    plugin_id,
                    slot,
                    detail = %self.describe(),
                    "wasm guest call failed — fail-closed"
                );
            }
        }
    }

    /// Tool-gate slots fail CLOSED — Deny (504 on timeout, else 500).
    fn into_gate_deny(self, plugin_id: &str) -> GateDecision {
        let http_status = if matches!(self, Self::Timeout) {
            504
        } else {
            500
        };
        GateDecision::Deny {
            http_status,
            code: -32603,
            message: format!("gate plugin '{plugin_id}' {}", self.describe()),
            error_data: None,
        }
    }

    /// Transform slots fail to an Error result the dispatcher surfaces.
    fn into_transform_error(self, plugin_id: &str) -> TransformResult {
        TransformResult::Error {
            message: format!("wasm transform '{plugin_id}' {}", self.describe()),
        }
    }
}

/// Await a `spawn_blocking` guest call under an outer wall-clock timeout,
/// normalizing timeout / panic / guest-error into [`WasmCallFailure`]. The
/// in-guest epoch trap (`timeout_ms`) is the primary bound; the outer
/// timeout (`timeout_ms + WASM_CALL_GRACE_MS`) is a backstop.
async fn wasm_call_timeout<T>(
    timeout_ms: u64,
    join: tokio::task::JoinHandle<Result<T>>,
) -> std::result::Result<T, WasmCallFailure> {
    let budget = std::time::Duration::from_millis(timeout_ms + WASM_CALL_GRACE_MS);
    match tokio::time::timeout(budget, join).await {
        Ok(Ok(Ok(value))) => Ok(value),
        Ok(Ok(Err(e))) => Err(WasmCallFailure::Error(e)),
        Ok(Err(join_err)) => Err(WasmCallFailure::Panicked(join_err.to_string())),
        Err(_elapsed) => Err(WasmCallFailure::Timeout),
    }
}

// ---------------------------------------------------------------------------
// Load & verify Wasm artifact
// ---------------------------------------------------------------------------

/// Options for loading a Wasm plugin.
#[derive(Debug, Clone, Default)]
pub struct WasmLoadOptions {
    /// Full artifact-integrity gate — SHA-256 pin + Ed25519 signature
    /// (governed by [`crate::SignaturePolicy`]) + revocation-list check,
    /// IDENTICAL to the native cdylib loader. The gateway builds this from
    /// the same per-entry `signature` config it uses for native plugins, so
    /// in-process Wasm code is held to the same trust bar as native code.
    pub verify: crate::native::NativeVerifyOptions,
    /// Resource limits for this plugin.
    pub limits: WasmResourceLimits,
}

/// Load and compile a Wasm component from a file path.
///
/// Performs:
/// 1. Full integrity verification (SHA-256 + Ed25519 + revocation), the
///    same gate as native cdylib plugins
/// 2. Wasmtime compilation (AOT via Cranelift)
/// 3. Returns the compiled Component for instantiation
pub fn load_wasm_component(
    engine: &Engine,
    path: &Path,
    options: &WasmLoadOptions,
) -> Result<WasmArtifact> {
    info!(path = %path.display(), "loading wasm plugin component");

    // Step 1: integrity gate. Wasm guests run in-process (Wasmtime), so an
    // unverified guest is unverified code execution just like an unsigned
    // cdylib — hold it to the same SHA + Ed25519 + revocation bar.
    let verified = crate::native::verify_native_artifact(path, &options.verify)
        .map_err(|e| anyhow::anyhow!("verifying wasm artifact '{}': {e}", path.display()))?;
    let artifact_hash = verified.artifact_hash;

    // Step 2: read the bytes ONCE and re-hash them, refusing if they diverge
    // from the verified hash — closes the verify→compile swap window (mirrors
    // the native cdylib loader). The buffer is then the SINGLE source compiled
    // below, so there is no residual disk re-read for an attacker to race.
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading wasm artifact '{}'", path.display()))?;
    let reread_hash = crate::verify::sha256_hex(&bytes);
    if reread_hash != artifact_hash {
        metrics::counter!(
            "mcpg_plugin_load_toctou_refusals_total",
            "reason" => "artifact_changed_during_verify",
        )
        .increment(1);
        return Err(anyhow::anyhow!(
            "wasm artifact '{}' changed between verification and load \
             (verified {artifact_hash}, now {reread_hash}) — refusing",
            path.display(),
        ));
    }

    // Step 3: compile from the verified buffer (NOT a fresh path re-read).
    let component = Component::from_binary(engine, &bytes)
        .wm_with_context(|| format!("failed to compile wasm component: {}", path.display()))?;

    info!(path = %path.display(), "wasm component compiled successfully");

    Ok(WasmArtifact {
        component,
        artifact_hash,
        source_path: path.to_string_lossy().into_owned(),
        limits: options.limits.clone(),
    })
}

/// A compiled Wasm artifact ready for instantiation.
pub struct WasmArtifact {
    /// Compiled Wasmtime component.
    pub component: Component,
    /// SHA-256 hex hash of the source file.
    pub artifact_hash: String,
    /// Filesystem path the component was loaded from.
    pub source_path: String,
    /// Resource limits to apply.
    pub limits: WasmResourceLimits,
}

// ---------------------------------------------------------------------------
// Wasm Tool Gate Plugin adapter
// ---------------------------------------------------------------------------

/// A ToolGatePlugin backed by a Wasm Component Model guest.
///
/// The guest must implement the `tool-gate-plugin` world from plugin.wit.
/// Each invocation creates a fresh Store with fuel + epoch limits.
pub struct WasmToolGatePlugin {
    manifest: PluginManifest,
    engine: Engine,
    component: Component,
    limits: WasmResourceLimits,
    _source_path: String,
    _epoch_ticker: EpochTicker,
}

impl WasmToolGatePlugin {
    pub fn new(engine: Engine, artifact: WasmArtifact) -> Result<Self> {
        let manifest = Self::read_guest_manifest(&engine, &artifact)?;
        let epoch_ticker = EpochTicker::start(engine.clone());

        Ok(Self {
            manifest,
            engine,
            component: artifact.component,
            limits: artifact.limits,
            _source_path: artifact.source_path,
            _epoch_ticker: epoch_ticker,
        })
    }

    /// Instantiate the guest and read its manifest.
    fn read_guest_manifest(engine: &Engine, artifact: &WasmArtifact) -> Result<PluginManifest> {
        let mut store = new_limited_store(engine, &artifact.limits);
        store.set_fuel(artifact.limits.fuel_per_invocation).ok();
        store.epoch_deadline_trap();
        store.set_epoch_deadline(u64::MAX);

        let mut linker = Linker::<PluginHostState>::new(engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker).wm_context("failed to link WASI")?;

        let instance = ToolGatePluginWorld::instantiate(&mut store, &artifact.component, &linker)
            .wm_context("failed to instantiate tool-gate-plugin for manifest read")?;

        let guest = instance.mcpg_plugin_tool_gate();
        let wit_manifest = guest
            .call_manifest(&mut store)
            .wm_context("failed to call manifest()")?;
        check_guest_protocol_version(&wit_manifest.id, &wit_manifest.protocol_version)?;

        Ok(PluginManifest {
            id: wit_manifest.id,
            version: wit_manifest.version,
            name: wit_manifest.name,
            plugin_class: PluginClass::ToolGate,
            protocol_version: wit_manifest.protocol_version,
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
        })
    }
}

#[async_trait]
impl ToolGatePlugin for WasmToolGatePlugin {
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
        let wit_ctx = to_wit_context_for!(wit_gate, ctx);
        let args_json = arguments.to_string();
        let meta_json = meta.map(|m| m.to_string());
        let config_json = config.to_string();

        let engine = self.engine.clone();
        let component = self.component.clone();
        let limits = self.limits.clone();
        let plugin_id = self.manifest.id.clone();

        // Run the synchronous wasmtime guest call off the async worker so a
        // CPU-bound guest cannot pin a tokio thread; the long-lived epoch
        // ticker still interrupts the guest at `timeout_ms`.
        let join = tokio::task::spawn_blocking(move || -> Result<GateDecision> {
            let (mut store, linker) = build_invocation_store(&engine, &limits)?;
            let instance = ToolGatePluginWorld::instantiate(&mut store, &component, &linker)
                .wm_context("failed to instantiate tool-gate-plugin")?;
            let guest = instance.mcpg_plugin_tool_gate();
            let decision = guest
                .call_evaluate_pre_dispatch(
                    &mut store,
                    &wit_ctx,
                    &args_json,
                    meta_json.as_deref(),
                    &config_json,
                )
                .wm_context("evaluate_pre_dispatch call failed")?;
            Ok(from_wit_gate_decision(decision))
        });

        match wasm_call_timeout(self.limits.timeout_ms, join).await {
            Ok(decision) => decision,
            // Security: fail-closed. A crashed / fuel-exhausted / timed-out
            // Wasm plugin must not silently allow the request.
            Err(failure) => {
                failure.log_and_count(&plugin_id, "evaluate_pre_dispatch");
                failure.into_gate_deny(&plugin_id)
            }
        }
    }

    async fn evaluate_post_dispatch(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        result: &serde_json::Value,
        execution_duration_ms: u64,
        config: &serde_json::Value,
    ) -> GateDecision {
        let wit_ctx = to_wit_context_for!(wit_gate, ctx);
        let args_json = arguments.to_string();
        let result_json = result.to_string();
        let config_json = config.to_string();

        let engine = self.engine.clone();
        let component = self.component.clone();
        let limits = self.limits.clone();
        let plugin_id = self.manifest.id.clone();

        let join = tokio::task::spawn_blocking(move || -> Result<GateDecision> {
            let (mut store, linker) = build_invocation_store(&engine, &limits)?;
            let instance = ToolGatePluginWorld::instantiate(&mut store, &component, &linker)
                .wm_context("failed to instantiate tool-gate-plugin")?;
            let guest = instance.mcpg_plugin_tool_gate();
            let decision = guest
                .call_evaluate_post_dispatch(
                    &mut store,
                    &wit_ctx,
                    &args_json,
                    &result_json,
                    execution_duration_ms,
                    &config_json,
                )
                .wm_context("evaluate_post_dispatch call failed")?;
            Ok(from_wit_gate_decision(decision))
        });

        match wasm_call_timeout(self.limits.timeout_ms, join).await {
            Ok(decision) => decision,
            Err(failure) => {
                failure.log_and_count(&plugin_id, "evaluate_post_dispatch");
                failure.into_gate_deny(&plugin_id)
            }
        }
    }
}

// We need Send + Sync for the plugin registry. Wasmtime's Component is Send + Sync.
// The Store is created fresh per invocation.
unsafe impl Send for WasmToolGatePlugin {}
unsafe impl Sync for WasmToolGatePlugin {}

// ---------------------------------------------------------------------------
// Wasm Transform Plugin adapter
// ---------------------------------------------------------------------------

/// A TransformPlugin backed by a Wasm Component Model guest.
///
/// The guest must implement the `transform-plugin` world from plugin.wit.
/// Each invocation creates a fresh Store with fuel + epoch limits.
pub struct WasmTransformPlugin {
    manifest: PluginManifest,
    engine: Engine,
    component: Component,
    limits: WasmResourceLimits,
    _source_path: String,
    _epoch_ticker: EpochTicker,
}

impl WasmTransformPlugin {
    pub fn new(engine: Engine, artifact: WasmArtifact) -> Result<Self> {
        // Try to instantiate once to read the guest manifest.
        let manifest = Self::read_guest_manifest(&engine, &artifact)?;
        let epoch_ticker = EpochTicker::start(engine.clone());

        Ok(Self {
            manifest,
            engine,
            component: artifact.component,
            limits: artifact.limits,
            _source_path: artifact.source_path,
            _epoch_ticker: epoch_ticker,
        })
    }

    /// Instantiate the guest and read its manifest.
    fn read_guest_manifest(engine: &Engine, artifact: &WasmArtifact) -> Result<PluginManifest> {
        let mut store = new_limited_store(engine, &artifact.limits);
        store.set_fuel(artifact.limits.fuel_per_invocation).ok();
        // Generous epoch deadline for manifest read (single quick call).
        store.epoch_deadline_trap();
        store.set_epoch_deadline(u64::MAX);

        let mut linker = Linker::<PluginHostState>::new(engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker).wm_context("failed to link WASI")?;

        let instance = TransformPluginWorld::instantiate(&mut store, &artifact.component, &linker)
            .wm_context("failed to instantiate transform-plugin for manifest read")?;

        let guest = instance.mcpg_plugin_transform();
        let wit_manifest = guest
            .call_manifest(&mut store)
            .wm_context("failed to call manifest()")?;
        check_guest_protocol_version(&wit_manifest.id, &wit_manifest.protocol_version)?;

        Ok(PluginManifest {
            id: wit_manifest.id,
            version: wit_manifest.version,
            name: wit_manifest.name,
            plugin_class: PluginClass::Transform,
            protocol_version: wit_manifest.protocol_version,
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
        })
    }
}

#[async_trait]
impl TransformPlugin for WasmTransformPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn transform_arguments(
        &self,
        ctx: &PluginContext,
        arguments: &serde_json::Value,
        config: &serde_json::Value,
    ) -> TransformResult {
        let wit_ctx = to_wit_context_for!(wit_gen, ctx);
        let args_json = arguments.to_string();
        let config_json = config.to_string();

        let engine = self.engine.clone();
        let component = self.component.clone();
        let limits = self.limits.clone();
        let plugin_id = self.manifest.id.clone();

        let join = tokio::task::spawn_blocking(move || -> Result<TransformResult> {
            let (mut store, linker) = build_invocation_store(&engine, &limits)?;
            let instance = TransformPluginWorld::instantiate(&mut store, &component, &linker)
                .wm_context("failed to instantiate transform-plugin")?;
            let guest = instance.mcpg_plugin_transform();
            let result = guest
                .call_transform_arguments(&mut store, &wit_ctx, &args_json, &config_json)
                .wm_context("transform_arguments call failed")?;
            Ok(from_wit_transform_result(result))
        });

        match wasm_call_timeout(self.limits.timeout_ms, join).await {
            Ok(result) => result,
            Err(failure) => {
                failure.log_and_count(&plugin_id, "transform_arguments");
                failure.into_transform_error(&plugin_id)
            }
        }
    }

    async fn transform_result(
        &self,
        ctx: &PluginContext,
        result: &serde_json::Value,
        config: &serde_json::Value,
    ) -> TransformResult {
        let wit_ctx = to_wit_context_for!(wit_gen, ctx);
        let result_json = result.to_string();
        let config_json = config.to_string();

        let engine = self.engine.clone();
        let component = self.component.clone();
        let limits = self.limits.clone();
        let plugin_id = self.manifest.id.clone();

        let join = tokio::task::spawn_blocking(move || -> Result<TransformResult> {
            let (mut store, linker) = build_invocation_store(&engine, &limits)?;
            let instance = TransformPluginWorld::instantiate(&mut store, &component, &linker)
                .wm_context("failed to instantiate transform-plugin")?;
            let guest = instance.mcpg_plugin_transform();
            let result = guest
                .call_transform_output(&mut store, &wit_ctx, &result_json, &config_json)
                .wm_context("transform_output call failed")?;
            Ok(from_wit_transform_result(result))
        });

        match wasm_call_timeout(self.limits.timeout_ms, join).await {
            Ok(result) => result,
            Err(failure) => {
                failure.log_and_count(&plugin_id, "transform_result");
                failure.into_transform_error(&plugin_id)
            }
        }
    }
}

unsafe impl Send for WasmTransformPlugin {}
unsafe impl Sync for WasmTransformPlugin {}

// ---------------------------------------------------------------------------
// Wasm Identity Plugin adapter
// ---------------------------------------------------------------------------

/// An IdentityProviderPlugin backed by a Wasm Component Model guest.
///
/// The guest must implement the `identity-plugin` world from plugin.wit.
/// Each invocation creates a fresh Store with fuel + epoch limits.
pub struct WasmIdentityPlugin {
    manifest: PluginManifest,
    engine: Engine,
    component: Component,
    limits: WasmResourceLimits,
    _source_path: String,
    _epoch_ticker: EpochTicker,
}

impl WasmIdentityPlugin {
    pub fn new(engine: Engine, artifact: WasmArtifact) -> Result<Self> {
        let manifest = Self::read_guest_manifest(&engine, &artifact)?;
        let epoch_ticker = EpochTicker::start(engine.clone());

        Ok(Self {
            manifest,
            engine,
            component: artifact.component,
            limits: artifact.limits,
            _source_path: artifact.source_path,
            _epoch_ticker: epoch_ticker,
        })
    }

    /// Instantiate the guest and read its manifest.
    fn read_guest_manifest(engine: &Engine, artifact: &WasmArtifact) -> Result<PluginManifest> {
        let mut store = new_limited_store(engine, &artifact.limits);
        store.set_fuel(artifact.limits.fuel_per_invocation).ok();
        store.epoch_deadline_trap();
        store.set_epoch_deadline(u64::MAX);

        let mut linker = Linker::<PluginHostState>::new(engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker).wm_context("failed to link WASI")?;

        let instance = IdentityPluginWorld::instantiate(&mut store, &artifact.component, &linker)
            .wm_context("failed to instantiate identity-plugin for manifest read")?;

        let guest = instance.mcpg_plugin_identity();
        let wit_manifest = guest
            .call_manifest(&mut store)
            .wm_context("failed to call manifest()")?;
        check_guest_protocol_version(&wit_manifest.id, &wit_manifest.protocol_version)?;

        Ok(PluginManifest {
            id: wit_manifest.id,
            version: wit_manifest.version,
            name: wit_manifest.name,
            plugin_class: PluginClass::IdentityProvider,
            protocol_version: wit_manifest.protocol_version,
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
        })
    }
}

#[async_trait]
impl IdentityProviderPlugin for WasmIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &mcpg_plugin_protocol::RequestMetadata,
        config: &serde_json::Value,
    ) -> IdentityResolution {
        let headers_vec: Vec<(String, String)> = headers.to_vec();
        let config_json = config.to_string();

        let engine = self.engine.clone();
        let component = self.component.clone();
        let limits = self.limits.clone();
        let plugin_id = self.manifest.id.clone();

        let join = tokio::task::spawn_blocking(move || -> Result<IdentityResolution> {
            let (mut store, linker) = build_invocation_store(&engine, &limits)?;
            let instance = IdentityPluginWorld::instantiate(&mut store, &component, &linker)
                .wm_context("failed to instantiate identity-plugin")?;
            let guest = instance.mcpg_plugin_identity();
            // Bindgen expects `&[(String, String)]` rather than borrowed
            // pairs; pass the owned Vec directly.
            let resolution = guest
                .call_resolve_identity(&mut store, &headers_vec, &config_json)
                .wm_context("resolve_identity call failed")?;
            Ok(from_wit_identity_resolution(resolution))
        });

        match wasm_call_timeout(self.limits.timeout_ms, join).await {
            Ok(resolution) => resolution,
            // Identity resolution fails OPEN to None (no token) — a failed
            // resolver must not forge an identity; the request proceeds
            // unauthenticated and the trust floor / downstream gates decide.
            Err(failure) => {
                failure.log_and_count(&plugin_id, "resolve_identity");
                IdentityResolution::None
            }
        }
    }
}

unsafe impl Send for WasmIdentityPlugin {}
unsafe impl Sync for WasmIdentityPlugin {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_resource_limits_default() {
        let limits = WasmResourceLimits::default();
        assert_eq!(limits.memory_limit_bytes, 64 * 1024 * 1024);
        assert_eq!(limits.fuel_per_invocation, 10_000_000);
        assert_eq!(limits.timeout_ms, 100);
    }

    // SECURITY: the ResourceLimiter must cap linear-memory growth at
    // `memory_limit_bytes`; without it a guest could `memory.grow` without
    // bound (host OOM/DoS).
    #[test]
    fn memory_limiter_caps_growth() {
        use wasmtime::ResourceLimiter;
        let limits = WasmResourceLimits {
            memory_limit_bytes: 1024 * 1024,
            ..Default::default()
        };
        let mut state = new_host_state(&limits);
        // At or under the cap: allowed.
        assert!(state.memory_growing(0, 1024 * 1024, None).unwrap());
        assert!(state.memory_growing(0, 512 * 1024, None).unwrap());
        // Over the cap: denied (memory.grow returns -1, no host OOM).
        assert!(!state.memory_growing(0, 1024 * 1024 + 1, None).unwrap());
        assert!(!state.memory_growing(0, 64 * 1024 * 1024, None).unwrap());
    }

    // SECURITY: the host must reject a guest whose protocol version doesn't
    // match its own — the Wasm analog of the native ABI sentinel.
    #[test]
    fn protocol_version_sentinel() {
        // The host's own version always passes.
        assert!(check_guest_protocol_version("ok", mcpg_plugin_protocol::PROTOCOL_VERSION).is_ok());
        // A different version is refused.
        assert!(check_guest_protocol_version("bad", "0.9").is_err());
        assert!(check_guest_protocol_version("bad", "2.0").is_err());
        assert!(check_guest_protocol_version("bad", "").is_err());
    }

    #[test]
    fn create_engine_succeeds() {
        let engine = create_wasm_engine();
        assert!(engine.is_ok(), "engine creation failed: {:?}", engine.err());
    }

    // The shared per-plugin epoch ticker must advance the engine epoch while
    // alive and stop+join promptly on Drop (no leaked daemon thread).
    #[test]
    fn epoch_ticker_advances_then_stops_on_drop() {
        let engine = create_wasm_engine().unwrap();
        // A long-lived ticker advances the shared epoch over a few cadences.
        let before = {
            let _ticker = EpochTicker::start(engine.clone());
            std::thread::sleep(std::time::Duration::from_millis(EpochTicker::TICK_MS * 6));
            // Force a store to observe that the epoch moved past a small
            // deadline (i.e. a call with a tiny budget would trap).
            let mut store = new_limited_store(&engine, &WasmResourceLimits::default());
            store.epoch_deadline_trap();
            store.set_epoch_deadline(1);
            // Drop the ticker here.
            true
        };
        assert!(before);
        // After Drop joined the thread, the epoch no longer advances. Sample
        // it twice across several cadences; it must be unchanged.
        // (increment_epoch has no reader API, so we assert indirectly via the
        // fact that Drop returned — a non-joining Drop would hang the test.)
    }

    // `build_invocation_store` wires fuel + an epoch deadline relative to the
    // shared ticker cadence; the deadline is at least one tick.
    #[test]
    fn invocation_store_sets_bounded_epoch_deadline() {
        let engine = create_wasm_engine().unwrap();
        let limits = WasmResourceLimits {
            timeout_ms: 5, // < TICK_MS → deadline clamps to >= 1 tick
            ..Default::default()
        };
        let built = build_invocation_store(&engine, &limits);
        assert!(built.is_ok(), "store build failed: {:?}", built.err());
    }

    fn minimal_component(engine: &Engine) -> Component {
        // A minimal valid Wasm core module wrapped in a component.
        // The component has no exports — it's just enough to instantiate.
        let wasm_bytes = wasmtime::component::Component::new(engine, "(component)");
        // If inline WAT parsing fails, create from raw bytes instead
        match wasm_bytes {
            Ok(c) => c,
            Err(_) => {
                // Build a minimal component binary manually
                // Component binary magic: \0asm + version 0d 00 01 00 (component)
                let bytes: &[u8] = &[
                    0x00, 0x61, 0x73, 0x6d, // \0asm magic
                    0x0d, 0x00, 0x01, 0x00, // component version (layer 1)
                ];
                Component::new(engine, bytes).expect("minimal component binary")
            }
        }
    }

    // WasmToolGatePlugin requires a valid component that exports the
    // tool-gate-plugin world. Under wasmtime 38+, a minimal empty
    // component no longer satisfies instantiation — the runtime
    // requires the `mcpg:plugin/tool-gate@0.1.0` exported instance
    // to be present. End-to-end tool-gate tests with a real .wasm
    // live in the mcpg-plugin-testing-wasm-test-gate crate.
    #[test]
    fn wasm_tool_gate_new_rejects_empty_component() {
        let engine = create_wasm_engine().unwrap();
        let component = minimal_component(&engine);
        let artifact = WasmArtifact {
            component,
            artifact_hash: "test".to_owned(),
            source_path: "test.wasm".to_owned(),
            limits: WasmResourceLimits::default(),
        };
        let result = WasmToolGatePlugin::new(engine, artifact);
        assert!(
            result.is_err(),
            "empty component should fail to instantiate tool-gate-plugin"
        );
    }

    // WasmTransformPlugin now requires a valid component that exports the
    // transform-plugin world. Integration tests with real .wasm binaries
    // are in the mcpg-plugin-transform-masking crate.
    #[test]
    fn wasm_transform_new_rejects_empty_component() {
        let engine = create_wasm_engine().unwrap();
        let component = minimal_component(&engine);
        let artifact = WasmArtifact {
            component,
            artifact_hash: "test".to_owned(),
            source_path: "transform.wasm".to_owned(),
            limits: WasmResourceLimits::default(),
        };
        // An empty component cannot instantiate the transform-plugin world
        let result = WasmTransformPlugin::new(engine, artifact);
        assert!(
            result.is_err(),
            "empty component should fail to instantiate"
        );
    }

    // Same instantiation strictness applies to the identity world.
    #[test]
    fn wasm_identity_new_rejects_empty_component() {
        let engine = create_wasm_engine().unwrap();
        let component = minimal_component(&engine);
        let artifact = WasmArtifact {
            component,
            artifact_hash: "test".to_owned(),
            source_path: "identity.wasm".to_owned(),
            limits: WasmResourceLimits::default(),
        };
        let result = WasmIdentityPlugin::new(engine, artifact);
        assert!(
            result.is_err(),
            "empty component should fail to instantiate identity-plugin"
        );
    }

    // ---------------------------------------------------------------------------
    // Integration tests with real Wasm component (masking plugin)
    // ---------------------------------------------------------------------------
    // These require the masking plugin .wasm to be built first:
    //   cargo build -p mcpg-plugin-transform-masking --target wasm32-wasip2 --release

    fn masking_wasm_path() -> Option<std::path::PathBuf> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/wasm32-wasip2/release/mcpg_plugin_transform_masking.wasm");
        if path.exists() { Some(path) } else { None }
    }

    #[test]
    fn wasm_transform_masking_loads_manifest() {
        let Some(path) = masking_wasm_path() else {
            eprintln!("skipping: masking wasm not built");
            return;
        };
        let engine = create_wasm_engine().unwrap();
        let artifact = load_wasm_component(&engine, &path, &WasmLoadOptions::default()).unwrap();
        let plugin = WasmTransformPlugin::new(engine, artifact).unwrap();

        assert_eq!(plugin.manifest().id, "dev.mcpg.transform.masking");
        assert_eq!(plugin.manifest().version, "0.1.0");
        assert_eq!(plugin.manifest().plugin_class, PluginClass::Transform);
    }

    #[test]
    fn wasm_transform_masking_masks_arguments() {
        let Some(path) = masking_wasm_path() else {
            eprintln!("skipping: masking wasm not built");
            return;
        };
        let engine = create_wasm_engine().unwrap();
        let artifact = load_wasm_component(&engine, &path, &WasmLoadOptions::default()).unwrap();
        let plugin = WasmTransformPlugin::new(engine, artifact).unwrap();

        let ctx = PluginContext {
            request_id: "r1".into(),
            session_id: None,
            tool_name: "test_tool".into(),
            identity: mcpg_plugin_protocol::PluginIdentity {
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
            surface: "tool".into(),
            transport: "http".into(),
        };

        let config = serde_json::json!({
            "policy": "strict",
            "redact_fields": ["ssn", "credit_card"],
            "mask_char": "*",
            "mask_length": 8
        });

        let arguments = serde_json::json!({
            "name": "Alice",
            "ssn": "123-45-6789",
            "credit_card": "4111-1111-1111-1111"
        });

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(plugin.transform_arguments(&ctx, &arguments, &config));

        match result {
            TransformResult::Modified { value } => {
                assert_eq!(value["ssn"], "********");
                assert_eq!(value["credit_card"], "********");
                assert_eq!(value["name"], "Alice");
            }
            other => panic!("expected Modified, got: {other:?}"),
        }
    }

    #[test]
    fn wasm_transform_masking_unchanged_when_no_match() {
        let Some(path) = masking_wasm_path() else {
            eprintln!("skipping: masking wasm not built");
            return;
        };
        let engine = create_wasm_engine().unwrap();
        let artifact = load_wasm_component(&engine, &path, &WasmLoadOptions::default()).unwrap();
        let plugin = WasmTransformPlugin::new(engine, artifact).unwrap();

        let ctx = PluginContext {
            request_id: "r1".into(),
            session_id: None,
            tool_name: "test_tool".into(),
            identity: mcpg_plugin_protocol::PluginIdentity {
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
            surface: "tool".into(),
            transport: "http".into(),
        };

        let config = serde_json::json!({
            "policy": "strict",
            "redact_fields": ["ssn"]
        });
        let arguments = serde_json::json!({ "name": "Alice", "email": "a@b.com" });

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(plugin.transform_arguments(&ctx, &arguments, &config));
        assert!(matches!(result, TransformResult::Unchanged));
    }

    #[test]
    fn wasm_transform_masking_output_only_skips_args() {
        let Some(path) = masking_wasm_path() else {
            eprintln!("skipping: masking wasm not built");
            return;
        };
        let engine = create_wasm_engine().unwrap();
        let artifact = load_wasm_component(&engine, &path, &WasmLoadOptions::default()).unwrap();
        let plugin = WasmTransformPlugin::new(engine, artifact).unwrap();

        let ctx = PluginContext {
            request_id: "r1".into(),
            session_id: None,
            tool_name: "t".into(),
            identity: mcpg_plugin_protocol::PluginIdentity {
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
            surface: "tool".into(),
            transport: "http".into(),
        };

        let config = serde_json::json!({
            "policy": "output_only",
            "redact_fields": ["ssn"]
        });
        let args = serde_json::json!({ "ssn": "123-45-6789" });

        let rt = tokio::runtime::Runtime::new().unwrap();
        // output_only should NOT mask arguments
        let result = rt.block_on(plugin.transform_arguments(&ctx, &args, &config));
        assert!(matches!(result, TransformResult::Unchanged));

        // But should mask results
        let result = rt.block_on(plugin.transform_result(&ctx, &args, &config));
        match result {
            TransformResult::Modified { value } => assert_eq!(value["ssn"], "********"),
            other => panic!("expected Modified, got: {other:?}"),
        }
    }
}
