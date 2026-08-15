//! Metrics wrapper around `Arc<dyn Store>` — emits three
//! operational metrics on every dispatch:
//!
//!   - `mcpg_store_ops_total{plugin_id, role, op}` — successful op
//!     count, bumped in the `Ok(_)` arm of every trait method.
//!   - `mcpg_store_op_latency_seconds{plugin_id, role, op}` —
//!     histogram sampled regardless of outcome (failure latency is
//!     still useful — a slow `NotFound` is slow).
//!   - `mcpg_store_errors_total{plugin_id, role, kind}` — bumped
//!     in the `Err(_)` arm. `kind` uses `StoreError::kind_label()`
//!     so free-form `reason` strings never inflate Prometheus
//!     cardinality.
//!
//! Wrapping is transparent — callers on the hot path go through
//! `Arc<dyn Store>` + never see this type.

use std::sync::Arc;
use std::time::Instant;

use mcpg_plugin_protocol::PluginManifest;
use mcpg_plugin_protocol::store::{
    AppendResult, BoxStoreEventStream, Store, StoreError, StorePage, StoreRole, StoreValue,
};
use tracing::Instrument;

/// Decorator that records metrics around every `Store` method call
/// on the wrapped plugin.
pub(crate) struct MeteredStore {
    plugin_id: String,
    inner: Arc<dyn Store>,
}

impl MeteredStore {
    pub(crate) fn wrap(inner: Arc<dyn Store>) -> Arc<dyn Store> {
        let plugin_id = inner.manifest().id.clone();
        Arc::new(Self { plugin_id, inner })
    }
}

/// Emit the three metrics for one dispatch outcome. Centralised so
/// every trait method gets the same label discipline.
fn record(
    plugin_id: &str,
    role: &StoreRole,
    op: &'static str,
    elapsed: std::time::Duration,
    err_kind: Option<&'static str>,
) {
    metrics::histogram!(
        "mcpg_store_op_latency_seconds",
        "plugin_id" => plugin_id.to_owned(),
        "role" => role.as_label(),
        "op" => op,
    )
    .record(elapsed.as_secs_f64());
    match err_kind {
        None => {
            metrics::counter!(
                "mcpg_store_ops_total",
                "plugin_id" => plugin_id.to_owned(),
                "role" => role.as_label(),
                "op" => op,
            )
            .increment(1);
        }
        Some(kind) => {
            metrics::counter!(
                "mcpg_store_errors_total",
                "plugin_id" => plugin_id.to_owned(),
                "role" => role.as_label(),
                "kind" => kind,
            )
            .increment(1);
        }
    }
}

#[mcpg_plugin_protocol::async_trait]
impl Store for MeteredStore {
    fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }

    fn supported_roles(&self) -> Vec<StoreRole> {
        self.inner.supported_roles()
    }

    async fn get(&self, role: StoreRole, key: &str) -> Result<Option<StoreValue>, StoreError> {
        // Plugin-attributed span so traces resolve back
        // to the store plugin id for per-plugin observability override.
        let span = crate::sampled_info_span!(
            "store_get",
            plugin_id = %self.plugin_id,
            role = role.as_label(),
        );
        let start = Instant::now();
        let result = self.inner.get(role.clone(), key).instrument(span).await;
        record(
            &self.plugin_id,
            &role,
            "get",
            start.elapsed(),
            result.as_ref().err().map(StoreError::kind_label),
        );
        result
    }

    async fn put(&self, role: StoreRole, key: &str, value: StoreValue) -> Result<(), StoreError> {
        let span = crate::sampled_info_span!(
            "store_put",
            plugin_id = %self.plugin_id,
            role = role.as_label(),
        );
        let start = Instant::now();
        let result = self
            .inner
            .put(role.clone(), key, value)
            .instrument(span)
            .await;
        record(
            &self.plugin_id,
            &role,
            "put",
            start.elapsed(),
            result.as_ref().err().map(StoreError::kind_label),
        );
        result
    }

    async fn delete(&self, role: StoreRole, key: &str) -> Result<(), StoreError> {
        let span = crate::sampled_info_span!(
            "store_delete",
            plugin_id = %self.plugin_id,
            role = role.as_label(),
        );
        let start = Instant::now();
        let result = self.inner.delete(role.clone(), key).instrument(span).await;
        record(
            &self.plugin_id,
            &role,
            "delete",
            start.elapsed(),
            result.as_ref().err().map(StoreError::kind_label),
        );
        result
    }

    async fn list(
        &self,
        role: StoreRole,
        prefix: &str,
        cursor: Option<String>,
    ) -> Result<StorePage, StoreError> {
        let span = crate::sampled_info_span!(
            "store_list",
            plugin_id = %self.plugin_id,
            role = role.as_label(),
        );
        let start = Instant::now();
        let result = self
            .inner
            .list(role.clone(), prefix, cursor)
            .instrument(span)
            .await;
        record(
            &self.plugin_id,
            &role,
            "list",
            start.elapsed(),
            result.as_ref().err().map(StoreError::kind_label),
        );
        result
    }

    async fn compare_and_swap(
        &self,
        role: StoreRole,
        key: &str,
        expected: Option<StoreValue>,
        new: StoreValue,
    ) -> Result<bool, StoreError> {
        let span = crate::sampled_info_span!(
            "store_compare_and_swap",
            plugin_id = %self.plugin_id,
            role = role.as_label(),
        );
        let start = Instant::now();
        let result = self
            .inner
            .compare_and_swap(role.clone(), key, expected, new)
            .instrument(span)
            .await;
        record(
            &self.plugin_id,
            &role,
            "compare_and_swap",
            start.elapsed(),
            result.as_ref().err().map(StoreError::kind_label),
        );
        result
    }

    async fn append(
        &self,
        role: StoreRole,
        key: &str,
        value: StoreValue,
    ) -> Result<AppendResult, StoreError> {
        let span = crate::sampled_info_span!(
            "store_append",
            plugin_id = %self.plugin_id,
            role = role.as_label(),
        );
        let start = Instant::now();
        let result = self
            .inner
            .append(role.clone(), key, value)
            .instrument(span)
            .await;
        record(
            &self.plugin_id,
            &role,
            "append",
            start.elapsed(),
            result.as_ref().err().map(StoreError::kind_label),
        );
        result
    }

    async fn watch(&self, role: StoreRole, key: &str) -> Result<BoxStoreEventStream, StoreError> {
        let span = crate::sampled_info_span!(
            "store_watch",
            plugin_id = %self.plugin_id,
            role = role.as_label(),
        );
        let start = Instant::now();
        let result = self.inner.watch(role.clone(), key).instrument(span).await;
        record(
            &self.plugin_id,
            &role,
            "watch",
            start.elapsed(),
            result.as_ref().err().map(StoreError::kind_label),
        );
        result
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}
