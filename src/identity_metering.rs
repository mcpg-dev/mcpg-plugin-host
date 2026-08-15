//! Metrics wrapper around `Box<dyn IdentityProviderPlugin>`. Transparent —
//! callers see `Box<dyn IdentityProviderPlugin>` and never know about this
//! type. Mirrors `secret_metering::MeteredSecretProvider` and the
//! rest of the entity-kind metering-wrapper matrix.
//!
//! Two metrics per `resolve_identity` call:
//!
//!   - `mcpg_identity_resolutions_total{plugin_id, outcome}` —
//!     counter, one of {`resolved`, `none`, `invalid`}.
//!   - `mcpg_identity_resolution_latency_seconds{plugin_id}` —
//!     histogram, sampled regardless of outcome.
//!
//! Outcome cardinality stays at 3 (one label) so per-plugin
//! per-outcome series is bounded; no `key_id` / `subject_id`
//! ever land in metric labels — those are PII and would explode
//! the cardinality.

use std::time::Instant;

use mcpg_plugin_protocol::{
    IdentityProviderPlugin, IdentityResolution, PluginManifest, async_trait,
};
use tracing::Instrument;

pub(crate) struct MeteredIdentityProvider {
    plugin_id: String,
    inner: Box<dyn IdentityProviderPlugin>,
}

impl MeteredIdentityProvider {
    pub(crate) fn wrap(inner: Box<dyn IdentityProviderPlugin>) -> Box<dyn IdentityProviderPlugin> {
        let plugin_id = inner.manifest().id.clone();
        Box::new(Self { plugin_id, inner })
    }
}

fn record(plugin_id: &str, outcome: &'static str, elapsed: std::time::Duration) {
    metrics::histogram!(
        "mcpg_identity_resolution_latency_seconds",
        "plugin_id" => plugin_id.to_owned(),
    )
    .record(elapsed.as_secs_f64());
    metrics::counter!(
        "mcpg_identity_resolutions_total",
        "plugin_id" => plugin_id.to_owned(),
        "outcome" => outcome,
    )
    .increment(1);
}

#[async_trait]
impl IdentityProviderPlugin for MeteredIdentityProvider {
    fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }

    async fn resolve_identity(
        &self,
        headers: &[(String, String)],
        metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        config: &serde_json::Value,
    ) -> IdentityResolution {
        // Plugin-attributed span so identity traces
        // resolve to the identity-provider plugin id (host-side
        // wrapper for plugins not yet self-instrumenting).
        let span = crate::sampled_info_span!(
            "identity_resolve",
            plugin_id = %self.plugin_id,
        );
        let start = Instant::now();
        let result = self
            .inner
            .resolve_identity(headers, metadata, config)
            .instrument(span)
            .await;
        let outcome = match &result {
            IdentityResolution::Resolved { .. } => "resolved",
            IdentityResolution::None => "none",
            IdentityResolution::Invalid { .. } => "invalid",
        };
        record(&self.plugin_id, outcome, start.elapsed());
        result
    }
}
