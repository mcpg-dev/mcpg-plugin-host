//! Metrics wrapper around `Arc<dyn Cache>` — mirrors
//! `store_metering::MeteredStore`.
//!
//! Three metrics per dispatch:
//!
//!   - `mcpg_cache_ops_total{plugin_id, namespace, op, outcome}`
//!     — `outcome` is `hit` / `miss` for `get`, `ok` otherwise;
//!     callers who care about hit rate read this metric.
//!   - `mcpg_cache_op_latency_seconds{plugin_id, namespace, op}`
//!     — histogram, sampled regardless of outcome.
//!   - `mcpg_cache_errors_total{plugin_id, namespace, kind}` —
//!     Err arm only. `kind` is `CacheError::kind_label()`.
//!
//! Wrapping is transparent; callers on the hot path see
//! `Arc<dyn Cache>` and never know about this type.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mcpg_plugin_protocol::PluginManifest;
use mcpg_plugin_protocol::cache::{Cache, CacheError};

pub(crate) struct MeteredCache {
    plugin_id: String,
    namespace_label: String,
    inner: Arc<dyn Cache>,
}

impl MeteredCache {
    /// Wrap `inner` with metrics labelled to `namespace`. The
    /// caller (the registry's `bind_cache_namespace`) knows the
    /// namespace at bind time; wrapping once per-binding avoids
    /// re-deriving the label on every dispatch.
    pub(crate) fn wrap(namespace: impl Into<String>, inner: Arc<dyn Cache>) -> Arc<dyn Cache> {
        let plugin_id = inner.manifest().id.clone();
        Arc::new(Self {
            plugin_id,
            namespace_label: namespace.into(),
            inner,
        })
    }
}

fn record_success(
    plugin_id: &str,
    namespace: &str,
    op: &'static str,
    outcome: &'static str,
    elapsed: Duration,
) {
    metrics::histogram!(
        "mcpg_cache_op_latency_seconds",
        "plugin_id" => plugin_id.to_owned(),
        "namespace" => namespace.to_owned(),
        "op" => op,
    )
    .record(elapsed.as_secs_f64());
    metrics::counter!(
        "mcpg_cache_ops_total",
        "plugin_id" => plugin_id.to_owned(),
        "namespace" => namespace.to_owned(),
        "op" => op,
        "outcome" => outcome,
    )
    .increment(1);
}

fn record_error(
    plugin_id: &str,
    namespace: &str,
    op: &'static str,
    kind: &'static str,
    elapsed: Duration,
) {
    metrics::histogram!(
        "mcpg_cache_op_latency_seconds",
        "plugin_id" => plugin_id.to_owned(),
        "namespace" => namespace.to_owned(),
        "op" => op,
    )
    .record(elapsed.as_secs_f64());
    metrics::counter!(
        "mcpg_cache_errors_total",
        "plugin_id" => plugin_id.to_owned(),
        "namespace" => namespace.to_owned(),
        "kind" => kind,
    )
    .increment(1);
}

#[mcpg_plugin_protocol::async_trait]
impl Cache for MeteredCache {
    fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }

    fn supported_namespaces(&self) -> Vec<String> {
        self.inner.supported_namespaces()
    }

    fn serves_any_namespace(&self) -> bool {
        self.inner.serves_any_namespace()
    }

    async fn get(&self, ns: &str, key: &str) -> Option<bytes::Bytes> {
        // Plugin-attributed span so traces from cache
        // ops resolve back to the cache plugin id for per-plugin
        // observability override.
        use tracing::Instrument;
        let span = crate::sampled_info_span!(
            "cache_get",
            plugin_id = %self.plugin_id,
            namespace = %self.namespace_label,
        );
        let start = Instant::now();
        let result = self.inner.get(ns, key).instrument(span).await;
        let outcome = if result.is_some() { "hit" } else { "miss" };
        record_success(
            &self.plugin_id,
            &self.namespace_label,
            "get",
            outcome,
            start.elapsed(),
        );
        result
    }

    async fn put(
        &self,
        ns: &str,
        key: &str,
        value: bytes::Bytes,
        ttl: Duration,
    ) -> Result<(), CacheError> {
        use tracing::Instrument;
        let span = crate::sampled_info_span!(
            "cache_put",
            plugin_id = %self.plugin_id,
            namespace = %self.namespace_label,
        );
        let start = Instant::now();
        let result = self.inner.put(ns, key, value, ttl).instrument(span).await;
        match &result {
            Ok(()) => record_success(
                &self.plugin_id,
                &self.namespace_label,
                "put",
                "ok",
                start.elapsed(),
            ),
            Err(e) => record_error(
                &self.plugin_id,
                &self.namespace_label,
                "put",
                e.kind_label(),
                start.elapsed(),
            ),
        }
        result
    }

    async fn delete(&self, ns: &str, key: &str) {
        use tracing::Instrument;
        let span = crate::sampled_info_span!(
            "cache_delete",
            plugin_id = %self.plugin_id,
            namespace = %self.namespace_label,
        );
        let start = Instant::now();
        self.inner.delete(ns, key).instrument(span).await;
        record_success(
            &self.plugin_id,
            &self.namespace_label,
            "delete",
            "ok",
            start.elapsed(),
        );
    }

    async fn clear(&self, ns: &str) -> Result<(), CacheError> {
        let start = Instant::now();
        let result = self.inner.clear(ns).await;
        match &result {
            Ok(()) => record_success(
                &self.plugin_id,
                &self.namespace_label,
                "clear",
                "ok",
                start.elapsed(),
            ),
            Err(e) => record_error(
                &self.plugin_id,
                &self.namespace_label,
                "clear",
                e.kind_label(),
                start.elapsed(),
            ),
        }
        result
    }

    async fn incr(&self, ns: &str, key: &str, by: i64, ttl: Duration) -> Result<i64, CacheError> {
        let start = Instant::now();
        let result = self.inner.incr(ns, key, by, ttl).await;
        match &result {
            Ok(_) => record_success(
                &self.plugin_id,
                &self.namespace_label,
                "incr",
                "ok",
                start.elapsed(),
            ),
            Err(e) => record_error(
                &self.plugin_id,
                &self.namespace_label,
                "incr",
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
