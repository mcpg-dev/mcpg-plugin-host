//! Metrics wrapper around `Box<dyn CatalogProvider>`. Transparent —
//! callers see `Box<dyn CatalogProvider>` and never know about this
//! type. Mirrors `identity_metering::MeteredIdentityProvider` etc.
//!
//! Three metrics per chain pass:
//!
//!   - `mcpg_catalog_op_total{plugin_id, op, result}` — counter,
//!     one row per `filter_and_enrich` / `describe` /
//!     `list_catalog` invocation. `result` is `ok` | `panic`
//!     (panic on the plugin side surfaces as `ok` here — the
//!     plugin's macro returns an empty list / null on panic; we
//!     don't see the panic from the metering layer).
//!   - `mcpg_catalog_op_latency_seconds{plugin_id, op}` —
//!     histogram, sampled on every call.
//!   - `mcpg_catalog_tools_filtered_total{plugin_id, direction}` —
//!     counter. `direction` is `dropped` (input had it; this
//!     provider's output omits it) or `enriched` (input had it
//!     unenriched; output gained catalog metadata).

use std::time::Instant;

use mcpg_plugin_protocol::PluginManifest;
use mcpg_plugin_protocol::async_trait;
use mcpg_plugin_protocol::catalog::{CatalogEntry, CatalogProvider, EnrichedToolDescriptor};
use mcpg_plugin_protocol::types::PluginContext;
use tracing::Instrument;

pub(crate) struct MeteredCatalogProvider {
    plugin_id: String,
    inner: Box<dyn CatalogProvider>,
}

impl MeteredCatalogProvider {
    pub(crate) fn wrap(inner: Box<dyn CatalogProvider>) -> Box<dyn CatalogProvider> {
        let plugin_id = inner.manifest().id.clone();
        Box::new(Self { plugin_id, inner })
    }
}

fn record_op(plugin_id: &str, op: &'static str, elapsed: std::time::Duration) {
    metrics::histogram!(
        "mcpg_catalog_op_latency_seconds",
        "plugin_id" => plugin_id.to_owned(),
        "op" => op,
    )
    .record(elapsed.as_secs_f64());
    metrics::counter!(
        "mcpg_catalog_op_total",
        "plugin_id" => plugin_id.to_owned(),
        "op" => op,
        "result" => "ok",
    )
    .increment(1);
}

fn record_filter_delta(
    plugin_id: &str,
    input: &[EnrichedToolDescriptor],
    output: &[EnrichedToolDescriptor],
) {
    let dropped = input.len().saturating_sub(output.len()) as u64;
    if dropped > 0 {
        metrics::counter!(
            "mcpg_catalog_tools_filtered_total",
            "plugin_id" => plugin_id.to_owned(),
            "direction" => "dropped",
        )
        .increment(dropped);
    }
    let mut enriched = 0u64;
    for tool in output {
        let was_enriched_before = input
            .iter()
            .find(|t| t.base.name == tool.base.name)
            .and_then(|t| t.catalog.as_ref())
            .is_some();
        let is_enriched_now = tool.catalog.as_ref().is_some_and(|c| !c.is_empty());
        if !was_enriched_before && is_enriched_now {
            enriched += 1;
        }
    }
    if enriched > 0 {
        metrics::counter!(
            "mcpg_catalog_tools_filtered_total",
            "plugin_id" => plugin_id.to_owned(),
            "direction" => "enriched",
        )
        .increment(enriched);
    }
}

#[async_trait]
impl CatalogProvider for MeteredCatalogProvider {
    fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }

    async fn filter_and_enrich(
        &self,
        ctx: &PluginContext,
        in_progress: &[EnrichedToolDescriptor],
    ) -> Vec<EnrichedToolDescriptor> {
        // Plugin-attributed span so traces resolve back
        // to the catalog-provider plugin id for per-plugin override.
        let span = crate::sampled_info_span!(
            "catalog_filter_and_enrich",
            plugin_id = %self.plugin_id,
        );
        let started = Instant::now();
        let refined = self
            .inner
            .filter_and_enrich(ctx, in_progress)
            .instrument(span)
            .await;
        record_op(&self.plugin_id, "filter_and_enrich", started.elapsed());
        record_filter_delta(&self.plugin_id, in_progress, &refined);
        refined
    }

    async fn describe(&self, tool_id: &str) -> Option<CatalogEntry> {
        let span = crate::sampled_info_span!(
            "catalog_describe",
            plugin_id = %self.plugin_id,
        );
        let started = Instant::now();
        let entry = self.inner.describe(tool_id).instrument(span).await;
        record_op(&self.plugin_id, "describe", started.elapsed());
        entry
    }

    async fn list_catalog(&self) -> Vec<CatalogEntry> {
        let span = crate::sampled_info_span!(
            "catalog_list",
            plugin_id = %self.plugin_id,
        );
        let started = Instant::now();
        let entries = self.inner.list_catalog().instrument(span).await;
        record_op(&self.plugin_id, "list_catalog", started.elapsed());
        entries
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::catalog::{
        CatalogMetadata, EnrichedToolDescriptor, ProtocolToolDescriptor,
    };
    use mcpg_plugin_protocol::manifest::{PluginClass, PluginManifest};
    use serde_json::json;

    struct StubCatalog {
        manifest: PluginManifest,
        out: Vec<EnrichedToolDescriptor>,
    }

    #[async_trait]
    impl CatalogProvider for StubCatalog {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn filter_and_enrich(
            &self,
            _: &PluginContext,
            _: &[EnrichedToolDescriptor],
        ) -> Vec<EnrichedToolDescriptor> {
            self.out.clone()
        }
        async fn describe(&self, _: &str) -> Option<CatalogEntry> {
            None
        }
        async fn list_catalog(&self) -> Vec<CatalogEntry> {
            Vec::new()
        }
    }

    fn manifest() -> PluginManifest {
        PluginManifest {
            id: "test.catalog".into(),
            version: "0.0.1".into(),
            name: "test".into(),
            plugin_class: PluginClass::CatalogProvider,
            protocol_version: "1.0".into(),
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
        }
    }

    fn identity() -> mcpg_plugin_protocol::types::PluginIdentity {
        mcpg_plugin_protocol::types::PluginIdentity {
            kind: "anonymous".into(),
            trust_level: "anonymous".into(),
            subject_id: None,
            auth_provider: None,
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: Default::default(),
        }
    }

    fn descriptor(name: &str, enriched: bool) -> EnrichedToolDescriptor {
        EnrichedToolDescriptor {
            base: ProtocolToolDescriptor {
                name: name.into(),
                title: None,
                description: "x".into(),
                input_schema: json!({}),
                output_schema: None,
            },
            catalog: if enriched {
                Some(CatalogMetadata {
                    owner: Some("a".into()),
                    ..CatalogMetadata::default()
                })
            } else {
                None
            },
        }
    }

    #[tokio::test]
    async fn metering_wrapper_delegates_filter_and_enrich() {
        let stub = StubCatalog {
            manifest: manifest(),
            out: vec![descriptor("a", true)],
        };
        let wrapped = MeteredCatalogProvider::wrap(Box::new(stub));
        let ctx = PluginContext {
            request_id: "r1".into(),
            session_id: None,
            tool_name: "tools.list".into(),
            surface: "tool".into(),
            identity: identity(),
            transport: "http".into(),
        };
        let input = vec![descriptor("a", false), descriptor("b", false)];
        let out = wrapped.filter_and_enrich(&ctx, &input).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].base.name, "a");
    }
}
