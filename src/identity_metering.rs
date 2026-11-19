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

use std::time::{Duration, Instant};

use mcpg_plugin_protocol::{
    IdentityProviderPlugin, IdentityResolution, PluginManifest, async_trait,
};
use metrics::{Key, Label, Level, Metadata};
use tracing::Instrument;

/// The metadata `metrics::histogram!` and `metrics::counter!` attach from
/// this module.
static METADATA: Metadata<'static> =
    Metadata::new(module_path!(), Level::INFO, Some(module_path!()));

pub(crate) struct MeteredIdentityProvider {
    plugin_id: String,
    series: Series,
    inner: Box<dyn IdentityProviderPlugin>,
}

impl MeteredIdentityProvider {
    pub(crate) fn wrap(inner: Box<dyn IdentityProviderPlugin>) -> Box<dyn IdentityProviderPlugin> {
        let plugin_id = inner.manifest().id.clone();
        let series = Series::new(&plugin_id);
        Box::new(Self {
            plugin_id,
            series,
            inner,
        })
    }
}

/// The series of one plugin, keyed once at wrap time so a resolution
/// records without building labels.
struct Series {
    latency: Key,
    resolved: Key,
    none: Key,
    invalid: Key,
}

impl Series {
    fn new(plugin_id: &str) -> Self {
        let outcome = |outcome: &'static str| {
            Key::from_parts(
                "mcpg_identity_resolutions_total",
                vec![
                    Label::new("plugin_id", plugin_id.to_owned()),
                    Label::new("outcome", outcome),
                ],
            )
        };
        Self {
            latency: Key::from_parts(
                "mcpg_identity_resolution_latency_seconds",
                vec![Label::new("plugin_id", plugin_id.to_owned())],
            ),
            resolved: outcome("resolved"),
            none: outcome("none"),
            invalid: outcome("invalid"),
        }
    }

    fn record(&self, result: &IdentityResolution, elapsed: Duration) {
        let outcome = match result {
            IdentityResolution::Resolved { .. } => &self.resolved,
            IdentityResolution::None => &self.none,
            IdentityResolution::Invalid { .. } => &self.invalid,
        };
        metrics::with_recorder(|recorder| {
            recorder
                .register_histogram(&self.latency, &METADATA)
                .record(elapsed.as_secs_f64());
            recorder.register_counter(outcome, &METADATA).increment(1);
        });
    }
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
        self.series.record(&result, start.elapsed());
        result
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use mcpg_plugin_protocol::{IdentityResolution, PluginIdentity};

    use super::Series;
    use crate::ffi_metering::tests::registrations;

    #[test]
    fn a_resolution_records_the_series_the_macros_name() {
        let identity = PluginIdentity {
            kind: "verified".to_owned(),
            trust_level: "verified".to_owned(),
            subject_id: Some("alice".to_owned()),
            auth_provider: None,
            issuer: None,
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes: Default::default(),
        };
        let results = [
            ("resolved", IdentityResolution::Resolved { identity }),
            ("none", IdentityResolution::None),
            (
                "invalid",
                IdentityResolution::Invalid {
                    reason: "expired".to_owned(),
                    response_headers: Vec::new(),
                },
            ),
        ];
        let series = Series::new("dev.example.identity");
        for (outcome, result) in results {
            let keyed = registrations(|| series.record(&result, Duration::from_millis(3)));
            let named = registrations(|| {
                metrics::histogram!(
                    "mcpg_identity_resolution_latency_seconds",
                    "plugin_id" => "dev.example.identity".to_owned(),
                )
                .record(0.003);
                metrics::counter!(
                    "mcpg_identity_resolutions_total",
                    "plugin_id" => "dev.example.identity".to_owned(),
                    "outcome" => outcome,
                )
                .increment(1);
            });
            // The macros here run one module below the wrapper.
            let named: Vec<_> = named
                .into_iter()
                .map(|(kind, key, meta)| (kind, key, meta.replace("::tests", "")))
                .collect();
            assert_eq!(keyed.len(), 2);
            assert_eq!(keyed, named, "{outcome}");
        }
    }
}
