//! Metrics wrapper around `Arc<dyn ConfigProvider>`. Transparent —
//! callers on the reconciliation path see `Arc<dyn ConfigProvider>`
//! and never know about this type.
//!
//! Mirrors `secret_metering::MeteredSecretProvider`. Three metrics
//! per dispatch:
//!
//!   - `mcpg_config_ops_total{plugin_id, scheme, op}` — counter,
//!     Ok arm only.
//!   - `mcpg_config_op_latency_seconds{plugin_id, scheme, op}` —
//!     histogram, sampled regardless of outcome.
//!   - `mcpg_config_errors_total{plugin_id, scheme, kind}` —
//!     Err arm only. `kind` = `ConfigError::kind_label()`.

use std::sync::Arc;
use std::time::Instant;

use mcpg_plugin_protocol::PluginManifest;
use mcpg_plugin_protocol::config::{
    BoxConfigDeltaStream, ConfigError, ConfigProvider, ConfigSnapshot,
};
use tracing::Instrument;

pub(crate) struct MeteredConfigProvider {
    plugin_id: String,
    scheme_label: String,
    inner: Arc<dyn ConfigProvider>,
}

impl MeteredConfigProvider {
    pub(crate) fn wrap(
        scheme: impl Into<String>,
        inner: Arc<dyn ConfigProvider>,
    ) -> Arc<dyn ConfigProvider> {
        let plugin_id = inner.manifest().id.clone();
        Arc::new(Self {
            plugin_id,
            scheme_label: scheme.into(),
            inner,
        })
    }
}

fn record_success(plugin_id: &str, scheme: &str, op: &'static str, elapsed: std::time::Duration) {
    metrics::histogram!(
        "mcpg_config_op_latency_seconds",
        "plugin_id" => plugin_id.to_owned(),
        "scheme" => scheme.to_owned(),
        "op" => op,
    )
    .record(elapsed.as_secs_f64());
    metrics::counter!(
        "mcpg_config_ops_total",
        "plugin_id" => plugin_id.to_owned(),
        "scheme" => scheme.to_owned(),
        "op" => op,
    )
    .increment(1);
}

fn record_error(
    plugin_id: &str,
    scheme: &str,
    op: &'static str,
    kind: &'static str,
    elapsed: std::time::Duration,
) {
    metrics::histogram!(
        "mcpg_config_op_latency_seconds",
        "plugin_id" => plugin_id.to_owned(),
        "scheme" => scheme.to_owned(),
        "op" => op,
    )
    .record(elapsed.as_secs_f64());
    metrics::counter!(
        "mcpg_config_errors_total",
        "plugin_id" => plugin_id.to_owned(),
        "scheme" => scheme.to_owned(),
        "kind" => kind,
    )
    .increment(1);
}

#[mcpg_plugin_protocol::async_trait]
impl ConfigProvider for MeteredConfigProvider {
    fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }

    fn supported_schemes(&self) -> Vec<String> {
        self.inner.supported_schemes()
    }

    async fn snapshot(&self, reference: &str) -> Result<ConfigSnapshot, ConfigError> {
        // Plugin-attributed span so config snapshot
        // traces resolve to the config-provider plugin id.
        let span = crate::sampled_info_span!(
            "config_snapshot",
            plugin_id = %self.plugin_id,
            scheme = %self.scheme_label,
        );
        let start = Instant::now();
        let result = self.inner.snapshot(reference).instrument(span).await;
        match &result {
            Ok(_) => record_success(
                &self.plugin_id,
                &self.scheme_label,
                "snapshot",
                start.elapsed(),
            ),
            Err(e) => record_error(
                &self.plugin_id,
                &self.scheme_label,
                "snapshot",
                e.kind_label(),
                start.elapsed(),
            ),
        }
        result
    }

    async fn watch(&self, reference: &str) -> Result<BoxConfigDeltaStream, ConfigError> {
        let span = crate::sampled_info_span!(
            "config_watch",
            plugin_id = %self.plugin_id,
            scheme = %self.scheme_label,
        );
        let start = Instant::now();
        let result = self.inner.watch(reference).instrument(span).await;
        match &result {
            Ok(_) => record_success(
                &self.plugin_id,
                &self.scheme_label,
                "watch",
                start.elapsed(),
            ),
            Err(e) => record_error(
                &self.plugin_id,
                &self.scheme_label,
                "watch",
                e.kind_label(),
                start.elapsed(),
            ),
        }
        result
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}
