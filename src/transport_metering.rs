//! Metrics wrapper around `Arc<dyn Transport>`. Transparent —
//! callers on the startup path see `Arc<dyn Transport>` and never
//! know about this type.
//!
//! Unlike the secret / config decorators (which meter every
//! dispatch), transport lifecycle events are rare — typically one
//! `start` per transport at gateway boot + one `shutdown` at
//! drain. We meter the start call only:
//!
//!   - `mcpg_transport_starts_total{plugin_id, transport_name}`
//!     — counter, Ok arm only.
//!   - `mcpg_transport_start_latency_seconds{plugin_id,
//!     transport_name}` — histogram, sampled both arms.
//!   - `mcpg_transport_errors_total{plugin_id, transport_name,
//!     kind}` — counter, Err arm only. `kind` =
//!     `TransportError::kind_label()`.
//!
//! Per-message metrics belong on the `MessageDispatcher` side —
//! they're the per-request hot path, not the transport's.

use std::sync::Arc;
use std::time::Instant;

use mcpg_plugin_protocol::PluginManifest;
use mcpg_plugin_protocol::transport::{
    MessageDispatcher, Transport, TransportError, TransportHandle,
};
use tracing::Instrument;

pub(crate) struct MeteredTransport {
    plugin_id: String,
    transport_name: String,
    inner: Arc<dyn Transport>,
}

impl MeteredTransport {
    pub(crate) fn wrap(inner: Arc<dyn Transport>) -> Arc<dyn Transport> {
        let plugin_id = inner.manifest().id.clone();
        let transport_name = inner.name().to_owned();
        Arc::new(Self {
            plugin_id,
            transport_name,
            inner,
        })
    }
}

fn record_start_success(plugin_id: &str, transport_name: &str, elapsed: std::time::Duration) {
    metrics::histogram!(
        "mcpg_transport_start_latency_seconds",
        "plugin_id" => plugin_id.to_owned(),
        "transport_name" => transport_name.to_owned(),
    )
    .record(elapsed.as_secs_f64());
    metrics::counter!(
        "mcpg_transport_starts_total",
        "plugin_id" => plugin_id.to_owned(),
        "transport_name" => transport_name.to_owned(),
    )
    .increment(1);
}

fn record_start_error(
    plugin_id: &str,
    transport_name: &str,
    kind: &'static str,
    elapsed: std::time::Duration,
) {
    metrics::histogram!(
        "mcpg_transport_start_latency_seconds",
        "plugin_id" => plugin_id.to_owned(),
        "transport_name" => transport_name.to_owned(),
    )
    .record(elapsed.as_secs_f64());
    metrics::counter!(
        "mcpg_transport_errors_total",
        "plugin_id" => plugin_id.to_owned(),
        "transport_name" => transport_name.to_owned(),
        "kind" => kind,
    )
    .increment(1);
}

#[mcpg_plugin_protocol::async_trait]
impl Transport for MeteredTransport {
    fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn start(
        &self,
        listener_config: &serde_json::Value,
        dispatcher: Arc<dyn MessageDispatcher>,
    ) -> Result<Box<dyn TransportHandle>, TransportError> {
        // Plugin-attributed span so transport-start
        // traces resolve back to the transport plugin id.
        let span = crate::sampled_info_span!(
            "transport_start",
            plugin_id = %self.plugin_id,
            transport_name = %self.transport_name,
        );
        let started = Instant::now();
        let result = self
            .inner
            .start(listener_config, dispatcher)
            .instrument(span)
            .await;
        match &result {
            Ok(_) => record_start_success(&self.plugin_id, &self.transport_name, started.elapsed()),
            Err(e) => record_start_error(
                &self.plugin_id,
                &self.transport_name,
                e.kind_label(),
                started.elapsed(),
            ),
        }
        result
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}
