//! Host→plugin FFI call instrumentation.
//!
//! Each adapter in `native_loader.rs` calls the plugin via its vtable
//! function pointers — JSON in, JSON out. This module wraps those
//! sites with two histograms:
//!
//! - `mcpg_plugin_ffi_call_duration_seconds{plugin_id, kind, slot, outcome}`
//!   — host→plugin call latency (vtable dispatch + JSON encode/decode +
//!   plugin execution). Mirrors `mcpg_plugin_host_call_duration_seconds`
//!   (the plugin→host direction in `host_bridge.rs`).
//! - `mcpg_plugin_payload_bytes{plugin_id, kind, slot, direction}`
//!   — payload size for both request (host→plugin) and response
//!   (plugin→host) so operators can spot oversized payloads before they
//!   trip [`enforce_ffi_payload_cap`](crate::native_loader::enforce_ffi_payload_cap).
//!
//! # Labels
//!
//! - `plugin_id` — `PluginManifest.id` (bounded; set at boot)
//! - `kind` — the entity kind (`"backend"`, `"tool_gate"`, `"store"`, …)
//! - `slot` — the vtable slot name (`"execute"`, `"evaluate_pre_dispatch"`,
//!   `"get"`, `"put"`, …) — closed enum per kind
//! - `outcome` — `"ok"` or `"err"`
//! - `direction` — `"request"` or `"response"`
//!
//! All labels are bounded enums; no cardinality risk.
//!
//! # Usage
//!
//! Adapters use the [`FfiCall`] RAII guard so the duration covers
//! request encoding + dispatch + response decoding consistently
//! across kinds:
//!
//! ```ignore
//! let call = FfiCall::begin(&self.manifest.id, "backend", "execute", req_json.len());
//! let out = (self.vtable.execute)(self.handle, req_json);
//! let resp_bytes = out.len();
//! match decode(out) {
//!     Ok(v) => { call.end_ok(resp_bytes); Ok(v) }
//!     Err(e) => { call.end_err(resp_bytes); Err(e) }
//! }
//! ```

use std::time::Instant;

/// RAII-style guard that records the request payload size at
/// construction and the response payload size + outcome at
/// completion. Ends are explicit because the call's success /
/// failure outcome is only known after decoding the response.
pub(crate) struct FfiCall {
    plugin_id: String,
    kind: &'static str,
    slot: &'static str,
    start: Instant,
}

impl FfiCall {
    /// Start timing a host→plugin call. Records the request payload
    /// size immediately so it's captured even if the call panics or
    /// the guard is dropped without an end_*() call.
    pub(crate) fn begin(
        plugin_id: &str,
        kind: &'static str,
        slot: &'static str,
        request_bytes: usize,
    ) -> Self {
        record_payload_bytes(plugin_id, kind, slot, "request", request_bytes);
        Self {
            plugin_id: plugin_id.to_owned(),
            kind,
            slot,
            start: Instant::now(),
        }
    }

    /// Record the response size + duration + outcome="ok".
    pub(crate) fn end_ok(self, response_bytes: usize) {
        record_payload_bytes(
            &self.plugin_id,
            self.kind,
            self.slot,
            "response",
            response_bytes,
        );
        record_duration(&self.plugin_id, self.kind, self.slot, "ok", self.start);
    }

    /// Record the response size + duration + outcome="err".
    pub(crate) fn end_err(self, response_bytes: usize) {
        record_payload_bytes(
            &self.plugin_id,
            self.kind,
            self.slot,
            "response",
            response_bytes,
        );
        record_duration(&self.plugin_id, self.kind, self.slot, "err", self.start);
    }

    /// Start timing **before** the request is JSON-encoded, deferring the
    /// request-size record to [`record_request`](Self::record_request).
    ///
    /// Use this where the request encode is itself a non-trivial part of the
    /// FFI boundary cost — notably `backend.execute`, where the request
    /// `payload: Vec<u8>` serialises as a JSON number-array (a large payload
    /// can spend milliseconds in the encode alone; see the `ffi_matrix`
    /// payload-scaling bench). The plain [`begin`](Self::begin) records the
    /// size up front but only starts the clock after the caller has already
    /// encoded, so it under-reports the boundary by the encode cost. This
    /// variant captures the full host-side boundary: encode → vtable → decode.
    pub(crate) fn begin_no_request(
        plugin_id: &str,
        kind: &'static str,
        slot: &'static str,
    ) -> Self {
        Self {
            plugin_id: plugin_id.to_owned(),
            kind,
            slot,
            start: Instant::now(),
        }
    }

    /// Record the request payload size for a call started via
    /// [`begin_no_request`](Self::begin_no_request) (after encoding).
    pub(crate) fn record_request(&self, request_bytes: usize) {
        record_payload_bytes(
            &self.plugin_id,
            self.kind,
            self.slot,
            "request",
            request_bytes,
        );
    }
}

fn record_duration(
    plugin_id: &str,
    kind: &'static str,
    slot: &'static str,
    outcome: &'static str,
    start: Instant,
) {
    metrics::histogram!(
        "mcpg_plugin_ffi_call_duration_seconds",
        "plugin_id" => plugin_id.to_owned(),
        "kind" => kind,
        "slot" => slot,
        "outcome" => outcome,
    )
    .record(start.elapsed().as_secs_f64());
}

fn record_payload_bytes(
    plugin_id: &str,
    kind: &'static str,
    slot: &'static str,
    direction: &'static str,
    bytes: usize,
) {
    metrics::histogram!(
        "mcpg_plugin_payload_bytes",
        "plugin_id" => plugin_id.to_owned(),
        "kind" => kind,
        "slot" => slot,
        "direction" => direction,
    )
    .record(bytes as f64);
}
