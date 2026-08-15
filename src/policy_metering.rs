//! Metrics wrapper around `Arc<dyn PolicyEngine>`. Transparent —
//! callers on the evaluate path see `Arc<dyn PolicyEngine>` and
//! never know about this type.
//!
//! Mirrors `secret_metering::MeteredSecretProvider`. Metrics:
//!
//!   - `mcpg_policy_evaluations_total{plugin_id, engine_name,
//!     decision_point, effect}` — counter, incremented on every
//!     evaluate call. `effect` is the bounded
//!     `PolicyEffect::label()` (`allow` / `deny` /
//!     `not_applicable`).
//!   - `mcpg_policy_evaluation_latency_seconds{plugin_id,
//!     engine_name, decision_point}` — histogram, sampled on
//!     every call.
//!
//! # Label cardinality note
//!
//! `decision_point` is a free-form string — the spec reserves the
//! canonical set (§9.14.1) but operators + plugins MAY define
//! custom points with plugin-owned prefixes. This adds label
//! cardinality proportional to the number of distinct points the
//! operator uses. At canonical-only cardinality (~10 points)
//! that's fine; operators rolling out hundreds of custom points
//! should either rewrite with a bounded suffix or drop the label
//! at the Prometheus scrape layer.

use std::sync::Arc;
use std::time::Instant;

use mcpg_plugin_protocol::PluginManifest;
use mcpg_plugin_protocol::policy::{PolicyDecision, PolicyEngine, PolicyVersion};
use tracing::Instrument;

pub(crate) struct MeteredPolicyEngine {
    plugin_id: String,
    engine_name: String,
    inner: Arc<dyn PolicyEngine>,
}

impl MeteredPolicyEngine {
    pub(crate) fn wrap(inner: Arc<dyn PolicyEngine>) -> Arc<dyn PolicyEngine> {
        let plugin_id = inner.manifest().id.clone();
        let engine_name = inner.name().to_owned();
        Arc::new(Self {
            plugin_id,
            engine_name,
            inner,
        })
    }
}

#[mcpg_plugin_protocol::async_trait]
impl PolicyEngine for MeteredPolicyEngine {
    fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn evaluate(
        &self,
        decision_point: &str,
        input: &serde_json::Value,
        context: &mcpg_plugin_protocol::PluginContext,
    ) -> PolicyDecision {
        // Plugin-attributed span so policy traces
        // resolve to the policy-engine plugin id.
        let span = crate::sampled_info_span!(
            "policy_evaluate",
            plugin_id = %self.plugin_id,
            engine = %self.engine_name,
            decision_point = %decision_point,
        );
        let started = Instant::now();
        let decision = self
            .inner
            .evaluate(decision_point, input, context)
            .instrument(span)
            .await;
        let elapsed = started.elapsed();
        metrics::histogram!(
            "mcpg_policy_evaluation_latency_seconds",
            "plugin_id" => self.plugin_id.clone(),
            "engine_name" => self.engine_name.clone(),
            "decision_point" => decision_point.to_owned(),
        )
        .record(elapsed.as_secs_f64());
        metrics::counter!(
            "mcpg_policy_evaluations_total",
            "plugin_id" => self.plugin_id.clone(),
            "engine_name" => self.engine_name.clone(),
            "decision_point" => decision_point.to_owned(),
            "effect" => decision.effect.label(),
        )
        .increment(1);
        decision
    }

    async fn policy_version(&self) -> PolicyVersion {
        self.inner.policy_version().await
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}
