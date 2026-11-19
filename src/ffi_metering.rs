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

use metrics::{Key, Label, Level, Metadata};

const CALL_DURATION: &str = "mcpg_plugin_ffi_call_duration_seconds";
const PAYLOAD_BYTES: &str = "mcpg_plugin_payload_bytes";

/// The metadata `metrics::histogram!` attaches from this module.
static METADATA: Metadata<'static> =
    Metadata::new(module_path!(), Level::INFO, Some(module_path!()));

/// The four series of one plugin slot, keyed once when the adapter is
/// built, so a call on a hot slot records without building labels.
pub(crate) struct FfiMeter {
    request: Key,
    response: Key,
    ok: Key,
    err: Key,
}

impl FfiMeter {
    pub(crate) fn new(plugin_id: &str, kind: &'static str, slot: &'static str) -> Self {
        let key = |name: &'static str, label: &'static str, value: &'static str| {
            Key::from_parts(
                name,
                vec![
                    Label::new("plugin_id", plugin_id.to_owned()),
                    Label::new("kind", kind),
                    Label::new("slot", slot),
                    Label::new(label, value),
                ],
            )
        };
        Self {
            request: key(PAYLOAD_BYTES, "direction", "request"),
            response: key(PAYLOAD_BYTES, "direction", "response"),
            ok: key(CALL_DURATION, "outcome", "ok"),
            err: key(CALL_DURATION, "outcome", "err"),
        }
    }

    /// [`FfiCall::begin`] on this slot's series.
    pub(crate) fn begin(&self, request_bytes: usize) -> FfiCall<'_> {
        record(&self.request, request_bytes as f64);
        FfiCall {
            labels: CallLabels::Keyed(self),
            start: Instant::now(),
        }
    }

    /// Start timing **before** the request is JSON-encoded, deferring the
    /// request-size record to [`record_request`](FfiCall::record_request).
    ///
    /// Use this where the request encode is itself a non-trivial part of the
    /// FFI boundary cost — notably `backend.execute`, where the request
    /// `payload: Vec<u8>` serialises as a JSON number-array (a large payload
    /// can spend milliseconds in the encode alone; see the `ffi_matrix`
    /// payload-scaling bench). The plain [`begin`](Self::begin) records the
    /// size up front but only starts the clock after the caller has already
    /// encoded, so it under-reports the boundary by the encode cost. This
    /// variant captures the full host-side boundary: encode → vtable → decode.
    pub(crate) fn begin_no_request(&self) -> FfiCall<'_> {
        FfiCall {
            labels: CallLabels::Keyed(self),
            start: Instant::now(),
        }
    }
}

enum CallLabels<'a> {
    Keyed(&'a FfiMeter),
    PerCall {
        plugin_id: String,
        kind: &'static str,
        slot: &'static str,
    },
}

/// RAII-style guard that records the request payload size at
/// construction and the response payload size + outcome at
/// completion. Ends are explicit because the call's success /
/// failure outcome is only known after decoding the response.
pub(crate) struct FfiCall<'a> {
    labels: CallLabels<'a>,
    start: Instant,
}

impl FfiCall<'static> {
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
            labels: CallLabels::PerCall {
                plugin_id: plugin_id.to_owned(),
                kind,
                slot,
            },
            start: Instant::now(),
        }
    }
}

impl FfiCall<'_> {
    /// Record the response size + duration + outcome="ok".
    pub(crate) fn end_ok(self, response_bytes: usize) {
        self.end(response_bytes, true);
    }

    /// Record the response size + duration + outcome="err".
    pub(crate) fn end_err(self, response_bytes: usize) {
        self.end(response_bytes, false);
    }

    /// Record the request payload size for a call started via
    /// [`begin_no_request`](FfiMeter::begin_no_request) (after encoding).
    pub(crate) fn record_request(&self, request_bytes: usize) {
        match &self.labels {
            CallLabels::Keyed(meter) => record(&meter.request, request_bytes as f64),
            CallLabels::PerCall {
                plugin_id,
                kind,
                slot,
            } => record_payload_bytes(plugin_id, kind, slot, "request", request_bytes),
        }
    }

    fn end(self, response_bytes: usize, ok: bool) {
        match &self.labels {
            CallLabels::Keyed(meter) => {
                record(&meter.response, response_bytes as f64);
                let outcome = if ok { &meter.ok } else { &meter.err };
                record(outcome, self.start.elapsed().as_secs_f64());
            }
            CallLabels::PerCall {
                plugin_id,
                kind,
                slot,
            } => {
                record_payload_bytes(plugin_id, kind, slot, "response", response_bytes);
                let outcome = if ok { "ok" } else { "err" };
                record_duration(plugin_id, kind, slot, outcome, self.start);
            }
        }
    }
}

fn record(key: &Key, value: f64) {
    metrics::with_recorder(|recorder| recorder.register_histogram(key, &METADATA).record(value));
}

fn record_duration(
    plugin_id: &str,
    kind: &'static str,
    slot: &'static str,
    outcome: &'static str,
    start: Instant,
) {
    metrics::histogram!(
        CALL_DURATION,
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
        PAYLOAD_BYTES,
        "plugin_id" => plugin_id.to_owned(),
        "kind" => kind,
        "slot" => slot,
        "direction" => direction,
    )
    .record(bytes as f64);
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex;

    use metrics::{
        Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
    };

    use super::{FfiCall, FfiMeter};

    /// A metric registration: the handle kind, the key, and the target,
    /// level and module path of the metadata.
    pub(crate) type Registration = (&'static str, Key, String);

    #[derive(Default)]
    struct Registrations(Mutex<Vec<Registration>>);

    impl Registrations {
        fn push(&self, kind: &'static str, key: &Key, metadata: &Metadata<'_>) {
            let meta = format!(
                "{} {:?} {:?}",
                metadata.target(),
                metadata.level(),
                metadata.module_path()
            );
            self.0.lock().unwrap().push((kind, key.clone(), meta));
        }
    }

    impl Recorder for Registrations {
        fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn register_counter(&self, key: &Key, metadata: &Metadata<'_>) -> Counter {
            self.push("counter", key, metadata);
            Counter::noop()
        }
        fn register_gauge(&self, key: &Key, metadata: &Metadata<'_>) -> Gauge {
            self.push("gauge", key, metadata);
            Gauge::noop()
        }
        fn register_histogram(&self, key: &Key, metadata: &Metadata<'_>) -> Histogram {
            self.push("histogram", key, metadata);
            Histogram::noop()
        }
    }

    /// Every metric registration `calls` makes on this thread, in order.
    pub(crate) fn registrations(calls: impl FnOnce()) -> Vec<Registration> {
        let recorder = Registrations::default();
        metrics::with_local_recorder(&recorder, calls);
        recorder.0.into_inner().unwrap()
    }

    #[test]
    fn a_keyed_call_records_the_series_a_per_call_one_does() {
        let meter = FfiMeter::new("dev.example.plugin", "backend", "execute");
        let keyed = registrations(|| {
            meter.begin(10).end_ok(20);
            let call = meter.begin_no_request();
            call.record_request(30);
            call.end_err(40);
        });
        let per_call = registrations(|| {
            FfiCall::begin("dev.example.plugin", "backend", "execute", 10).end_ok(20);
            FfiCall::begin("dev.example.plugin", "backend", "execute", 30).end_err(40);
        });
        assert_eq!(keyed.len(), 6);
        assert_eq!(keyed, per_call);
    }
}
