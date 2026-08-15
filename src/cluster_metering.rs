//! Metrics wrapper around `Arc<dyn ClusterBackend>`.
//! Transparent — callers see `Arc<dyn ClusterBackend>`.
//!
//! Cluster ops are rare compared to request traffic; the metric
//! story is centred on lease + pub/sub lifecycle events, which
//! correlate directly with operator concerns (who's leader,
//! which lock has churn, pub/sub backlog shape).
//!
//! # Metrics
//!
//! - `mcpg_cluster_lease_acquires_total{plugin_id, kind, target}`
//!   — counter, increments on every successful `acquire_leadership`
//!   or `acquire_lock`. `kind` is `leadership` or `lock`; `target`
//!   is the role name / lock key. (Label cardinality proportional
//!   to the number of distinct roles + locks the gateway uses —
//!   typically a handful.)
//! - `mcpg_cluster_lease_errors_total{plugin_id, op, kind}` —
//!   counter, Err arm of acquire_leadership / acquire_lock. `op`
//!   is `leadership` / `lock`; `kind` is
//!   `ClusterError::kind_label()`.
//! - `mcpg_cluster_publish_total{plugin_id, topic}` — counter,
//!   Ok arm of `publish`. `topic` is free-form — operators using
//!   many topics pay proportional cardinality.
//! - `mcpg_cluster_subscribe_total{plugin_id, topic}` — counter,
//!   Ok arm of `subscribe`.
//! - `mcpg_cluster_op_latency_seconds{plugin_id, op}` — histogram,
//!   tracks `acquire_leadership` / `acquire_lock` / `publish` /
//!   `subscribe` / `node_info` / `list_peers` call durations.
//!   `op` is a bounded label set (6 values).

use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use mcpg_cluster_api::{
    BoxActiveLease, BoxPeerEventStream, BoxPublishedMessageStream, ClusterBackend, ClusterError,
    ClusterNodeInfo, ClusterPeer, KeyValueStore, Lease, PubSub, Watch,
};
use mcpg_plugin_protocol::PluginManifest;
use tracing::Instrument;

/// Global audit emitter handle for the cluster metering wrapper.
/// Set once at gateway boot via [`set_audit_emitter`]
/// to a `Weak<PluginRegistry>`; the wrapper upgrades on each
/// `acquire_leadership` Ok / Err to fire `mcpg.cluster.leader_*`
/// audit events. Weak is intentional — registry rebuilds on hot
/// reload set a fresh weak via the same setter; the old handle
/// then upgrades to None and the wrapper silently no-ops.
static AUDIT_EMITTER: OnceLock<std::sync::Mutex<Weak<crate::PluginRegistry>>> = OnceLock::new();

/// Wire the cluster-metering wrapper to a `PluginRegistry` so its
/// `acquire_leadership` events can emit `mcpg.cluster.leader_*`
/// audit events. Idempotent — subsequent calls replace the
/// handle, supporting hot-reload registry rebuilds.
pub fn set_audit_emitter(weak: Weak<crate::PluginRegistry>) {
    let cell = AUDIT_EMITTER.get_or_init(|| std::sync::Mutex::new(Weak::new()));
    if let Ok(mut guard) = cell.lock() {
        *guard = weak;
    }
}

fn current_audit_registry() -> Option<Arc<crate::PluginRegistry>> {
    let cell = AUDIT_EMITTER.get()?;
    let guard = cell.lock().ok()?;
    guard.upgrade()
}

pub(crate) struct MeteredClusterBackend {
    plugin_id: String,
    inner: Arc<dyn ClusterBackend>,
}

impl MeteredClusterBackend {
    pub(crate) fn wrap(inner: Arc<dyn ClusterBackend>) -> Arc<dyn ClusterBackend> {
        let plugin_id = inner.manifest().id.clone();
        Arc::new(Self { plugin_id, inner })
    }
}

fn record_latency(plugin_id: &str, op: &'static str, elapsed: Duration) {
    metrics::histogram!(
        "mcpg_cluster_op_latency_seconds",
        "plugin_id" => plugin_id.to_owned(),
        "op" => op,
    )
    .record(elapsed.as_secs_f64());
}

#[mcpg_plugin_protocol::async_trait]
impl ClusterBackend for MeteredClusterBackend {
    // `cluster_provides()` is intentionally NOT overridden: the default
    // derives the role-set from `self.manifest().provides`, and our
    // `manifest()` delegates to the wrapped coordinator — so the decorator
    // surfaces the inner coordinator's role-set with no second copy.
    fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }

    // Primitive accessors MUST delegate to the wrapped coordinator — the trait
    // defaults return `None`, which would make the metering decorator silently
    // hide a coordinator's KeyValueStore / PubSub / Lease / Watch from the
    // gateway (the boot reachability probe then fails closed, or capability
    // state silently de-clusters to per-replica Memory* primitives). The
    // inner primitives are already FFI-attributed; metering happens at the
    // coordinator-op layer (node_info / locks / leases), not per KV/bus op.
    fn key_value_store(&self) -> Option<Arc<dyn KeyValueStore>> {
        self.inner.key_value_store()
    }

    fn pub_sub(&self) -> Option<Arc<dyn PubSub>> {
        self.inner.pub_sub()
    }

    fn lease(&self) -> Option<Arc<dyn Lease>> {
        self.inner.lease()
    }

    fn watch(&self) -> Option<Arc<dyn Watch>> {
        self.inner.watch()
    }

    async fn node_info(&self) -> ClusterNodeInfo {
        // Plugin-attributed span so cluster ops resolve
        // back to the cluster plugin id for per-plugin override.
        let span = crate::sampled_info_span!(
            "cluster_node_info",
            plugin_id = %self.plugin_id,
        );
        let started = Instant::now();
        let info = self.inner.node_info().instrument(span).await;
        record_latency(&self.plugin_id, "node_info", started.elapsed());
        info
    }

    async fn list_peers(&self) -> Vec<ClusterPeer> {
        let span = crate::sampled_info_span!(
            "cluster_list_peers",
            plugin_id = %self.plugin_id,
        );
        let started = Instant::now();
        let peers = self.inner.list_peers().instrument(span).await;
        record_latency(&self.plugin_id, "list_peers", started.elapsed());
        peers
    }

    async fn watch_peers(&self) -> BoxPeerEventStream {
        // No latency record — streams are long-lived. Span still
        // attributes the subscribe call itself.
        let span = crate::sampled_info_span!(
            "cluster_watch_peers",
            plugin_id = %self.plugin_id,
        );
        self.inner.watch_peers().instrument(span).await
    }

    async fn acquire_leadership(
        &self,
        role: &str,
        lease_ttl: Duration,
    ) -> Result<BoxActiveLease, ClusterError> {
        let span = crate::sampled_info_span!(
            "cluster_acquire_leadership",
            plugin_id = %self.plugin_id,
            role = %role,
        );
        let started = Instant::now();
        let result = self
            .inner
            .acquire_leadership(role, lease_ttl)
            .instrument(span)
            .await;
        let elapsed = started.elapsed();
        record_latency(&self.plugin_id, "acquire_leadership", elapsed);
        match &result {
            Ok(_) => {
                metrics::counter!(
                    "mcpg_cluster_lease_acquires_total",
                    "plugin_id" => self.plugin_id.clone(),
                    "kind" => "leadership",
                    "target" => role.to_owned(),
                )
                .increment(1);
                // Audit the leader change. SREs ask "when
                // did the leader flip the night the alert fired?"
                // The acquire_leadership Ok arm is the deterministic
                // local signal that this gateway took the role.
                if let Some(registry) = current_audit_registry() {
                    let event = crate::audit_events::cluster_leader_event(
                        &self.plugin_id,
                        role,
                        true,
                        None,
                    );
                    let _ = registry.emit_audit_event(&event).await;
                }
            }
            Err(e) => {
                metrics::counter!(
                    "mcpg_cluster_lease_errors_total",
                    "plugin_id" => self.plugin_id.clone(),
                    "op" => "leadership",
                    "kind" => e.kind_label(),
                )
                .increment(1);
                // A failed leadership acquire is
                // also informative: contention spikes show up here.
                if let Some(registry) = current_audit_registry() {
                    let err_msg = e.to_string();
                    let event = crate::audit_events::cluster_leader_event(
                        &self.plugin_id,
                        role,
                        false,
                        Some(&err_msg),
                    );
                    let _ = registry.emit_audit_event(&event).await;
                }
            }
        }
        result
    }

    async fn acquire_lock(
        &self,
        key: &str,
        lease_ttl: Duration,
    ) -> Result<BoxActiveLease, ClusterError> {
        let span = crate::sampled_info_span!(
            "cluster_acquire_lock",
            plugin_id = %self.plugin_id,
            key = %key,
        );
        let started = Instant::now();
        let result = self
            .inner
            .acquire_lock(key, lease_ttl)
            .instrument(span)
            .await;
        let elapsed = started.elapsed();
        record_latency(&self.plugin_id, "acquire_lock", elapsed);
        match &result {
            Ok(_) => {
                metrics::counter!(
                    "mcpg_cluster_lease_acquires_total",
                    "plugin_id" => self.plugin_id.clone(),
                    "kind" => "lock",
                    "target" => key.to_owned(),
                )
                .increment(1);
            }
            Err(e) => {
                metrics::counter!(
                    "mcpg_cluster_lease_errors_total",
                    "plugin_id" => self.plugin_id.clone(),
                    "op" => "lock",
                    "kind" => e.kind_label(),
                )
                .increment(1);
            }
        }
        result
    }

    // v21 — try-variants. Same metering shape; extra `outcome`
    // dimension distinguishes acquired / declined / error so ops
    // can spot a runaway lock-contention rate that the blocking
    // variant would have hidden as a long latency tail.
    async fn try_acquire_leadership(
        &self,
        role: &str,
        lease_ttl: Duration,
    ) -> Result<Option<BoxActiveLease>, ClusterError> {
        let span = crate::sampled_info_span!(
            "cluster_try_acquire_leadership",
            plugin_id = %self.plugin_id,
            role = %role,
        );
        let started = Instant::now();
        let result = self
            .inner
            .try_acquire_leadership(role, lease_ttl)
            .instrument(span)
            .await;
        let elapsed = started.elapsed();
        record_latency(&self.plugin_id, "try_acquire_leadership", elapsed);
        let outcome = match &result {
            Ok(Some(_)) => "acquired",
            Ok(None) => "declined",
            Err(_) => "error",
        };
        metrics::counter!(
            "mcpg_cluster_try_acquires_total",
            "plugin_id" => self.plugin_id.clone(),
            "kind" => "leadership",
            "target" => role.to_owned(),
            "outcome" => outcome,
        )
        .increment(1);
        if let Err(e) = &result {
            metrics::counter!(
                "mcpg_cluster_lease_errors_total",
                "plugin_id" => self.plugin_id.clone(),
                "op" => "try_leadership",
                "kind" => e.kind_label(),
            )
            .increment(1);
        }
        result
    }

    async fn try_acquire_lock(
        &self,
        key: &str,
        lease_ttl: Duration,
    ) -> Result<Option<BoxActiveLease>, ClusterError> {
        let span = crate::sampled_info_span!(
            "cluster_try_acquire_lock",
            plugin_id = %self.plugin_id,
            key = %key,
        );
        let started = Instant::now();
        let result = self
            .inner
            .try_acquire_lock(key, lease_ttl)
            .instrument(span)
            .await;
        let elapsed = started.elapsed();
        record_latency(&self.plugin_id, "try_acquire_lock", elapsed);
        let outcome = match &result {
            Ok(Some(_)) => "acquired",
            Ok(None) => "declined",
            Err(_) => "error",
        };
        metrics::counter!(
            "mcpg_cluster_try_acquires_total",
            "plugin_id" => self.plugin_id.clone(),
            "kind" => "lock",
            "target" => key.to_owned(),
            "outcome" => outcome,
        )
        .increment(1);
        if let Err(e) = &result {
            metrics::counter!(
                "mcpg_cluster_lease_errors_total",
                "plugin_id" => self.plugin_id.clone(),
                "op" => "try_lock",
                "kind" => e.kind_label(),
            )
            .increment(1);
        }
        result
    }

    async fn publish(
        &self,
        topic: &str,
        routing_key: Option<&str>,
        payload: Bytes,
    ) -> Result<(), ClusterError> {
        let span = crate::sampled_info_span!(
            "cluster_publish",
            plugin_id = %self.plugin_id,
            topic = %topic,
        );
        let started = Instant::now();
        let result = self
            .inner
            .publish(topic, routing_key, payload)
            .instrument(span)
            .await;
        record_latency(&self.plugin_id, "publish", started.elapsed());
        if result.is_ok() {
            metrics::counter!(
                "mcpg_cluster_publish_total",
                "plugin_id" => self.plugin_id.clone(),
                "topic" => topic.to_owned(),
            )
            .increment(1);
        }
        result
    }

    async fn subscribe(
        &self,
        topic: &str,
        group: Option<&str>,
        routing_key: Option<&str>,
    ) -> Result<BoxPublishedMessageStream, ClusterError> {
        let span = crate::sampled_info_span!(
            "cluster_subscribe",
            plugin_id = %self.plugin_id,
            topic = %topic,
        );
        let started = Instant::now();
        let result = self
            .inner
            .subscribe(topic, group, routing_key)
            .instrument(span)
            .await;
        record_latency(&self.plugin_id, "subscribe", started.elapsed());
        if result.is_ok() {
            metrics::counter!(
                "mcpg_cluster_subscribe_total",
                "plugin_id" => self.plugin_id.clone(),
                "topic" => topic.to_owned(),
            )
            .increment(1);
        }
        result
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}
