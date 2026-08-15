//! Metrics wrapper around `Arc<dyn SecretProvider>`. Transparent —
//! callers on the hot path see `Arc<dyn SecretProvider>` and never
//! know about this type.
//!
//! Mirrors `store_metering::MeteredStore` + `cache_metering::
//! MeteredCache`. Three metrics per dispatch:
//!
//!   - `mcpg_secret_ops_total{plugin_id, scheme, op}` — counter,
//!     Ok arm only.
//!   - `mcpg_secret_op_latency_seconds{plugin_id, scheme, op}` —
//!     histogram, sampled regardless of outcome.
//!   - `mcpg_secret_errors_total{plugin_id, scheme, kind}` —
//!     Err arm only. `kind` = `SecretError::kind_label()`.

use std::sync::Arc;
use std::time::Instant;

use mcpg_plugin_protocol::PluginManifest;
use mcpg_plugin_protocol::secret::{
    BoxSecretRotationStream, SecretError, SecretProvider, SecretValue,
};
use tracing::Instrument;

pub(crate) struct MeteredSecretProvider {
    plugin_id: String,
    scheme_label: String,
    inner: Arc<dyn SecretProvider>,
}

impl MeteredSecretProvider {
    pub(crate) fn wrap(
        scheme: impl Into<String>,
        inner: Arc<dyn SecretProvider>,
    ) -> Arc<dyn SecretProvider> {
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
        "mcpg_secret_op_latency_seconds",
        "plugin_id" => plugin_id.to_owned(),
        "scheme" => scheme.to_owned(),
        "op" => op,
    )
    .record(elapsed.as_secs_f64());
    metrics::counter!(
        "mcpg_secret_ops_total",
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
        "mcpg_secret_op_latency_seconds",
        "plugin_id" => plugin_id.to_owned(),
        "scheme" => scheme.to_owned(),
        "op" => op,
    )
    .record(elapsed.as_secs_f64());
    metrics::counter!(
        "mcpg_secret_errors_total",
        "plugin_id" => plugin_id.to_owned(),
        "scheme" => scheme.to_owned(),
        "kind" => kind,
    )
    .increment(1);
}

#[mcpg_plugin_protocol::async_trait]
impl SecretProvider for MeteredSecretProvider {
    fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }

    fn supported_schemes(&self) -> Vec<String> {
        self.inner.supported_schemes()
    }

    async fn get(&self, secret_ref: &str) -> Result<SecretValue, SecretError> {
        // Plugin-attributed span so traces resolve back
        // to the secret-provider plugin id for per-plugin override.
        let span = crate::sampled_info_span!(
            "secret_get",
            plugin_id = %self.plugin_id,
            scheme = %self.scheme_label,
        );
        let start = Instant::now();
        let result = self.inner.get(secret_ref).instrument(span).await;
        match &result {
            Ok(_) => record_success(&self.plugin_id, &self.scheme_label, "get", start.elapsed()),
            Err(e) => record_error(
                &self.plugin_id,
                &self.scheme_label,
                "get",
                e.kind_label(),
                start.elapsed(),
            ),
        }
        result
    }

    async fn has(&self, secret_ref: &str) -> bool {
        let span = crate::sampled_info_span!(
            "secret_has",
            plugin_id = %self.plugin_id,
            scheme = %self.scheme_label,
        );
        let start = Instant::now();
        let result = self.inner.has(secret_ref).instrument(span).await;
        record_success(&self.plugin_id, &self.scheme_label, "has", start.elapsed());
        result
    }

    async fn watch(&self, secret_ref: &str) -> Result<BoxSecretRotationStream, SecretError> {
        let span = crate::sampled_info_span!(
            "secret_watch",
            plugin_id = %self.plugin_id,
            scheme = %self.scheme_label,
        );
        let start = Instant::now();
        let result = self.inner.watch(secret_ref).instrument(span).await;
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
