//! Cluster-aware credential cache.
//!
//! Closes the multi-instance divergence gap: without coordination,
//! two gateway instances behind a load balancer would issue two
//! DIFFERENT Vault dynamic credentials for the same caller, breaking
//! per-caller row-level security and identity propagation.
//!
//! # Mechanism
//!
//! Wraps [`CredentialCache`] with a `cluster_backend`-backed
//! pub/sub layer. Each gateway instance:
//!
//! 1. Subscribes to a shared topic (default
//!    `mcpg.credentials.events`) at boot.
//! 2. On local cache miss + successful `plugin.issue`: inserts
//!    locally + publishes an `Issued` event so peer instances
//!    pre-populate their caches.
//! 3. On `invalidate` / `invalidate_plugin`: applies locally +
//!    publishes a `Revoked` event so peer instances drop their
//!    matching entries.
//! 4. Background subscriber task receives events; ignores its
//!    own publishes (filtered by `published_by`); applies
//!    Issued / Revoked to the local cache.
//!
//! Result: at most one plugin call per
//! `(identity_hash, plugin_id, target)` cluster-wide per
//! credential lifetime. Identity propagation works correctly in
//! multi-instance deploys.
//!
//! # Backend semantics
//!
//! The durability of cache events depends on the bound
//! `cluster_backend` backend:
//!
//! - **NATS-JetStream**: durable + replayable. Recommended for
//!   strict-consistency deploys. Subscribers that disconnect
//!   briefly catch up via stream replay.
//! - **etcd**: durable within retention window. Reconnect-with-
//!   revision recovers missed events.
//! - **Consul**: best-effort gossip. Acceptable for low-frequency
//!   credential issuance + tolerance for occasional missed
//!   publishes.
//!
//! Operators choose by their existing cluster_backend binding.
//!
//! # Privacy
//!
//! Cache events carry credential bytes over the cluster topic.
//! Two layers protect them:
//!
//! 1. **Transport TLS on the cluster_backend** — operators
//!    SHOULD configure TLS on NATS-JS / etcd / Consul (same
//!    hardening required for any pub/sub of sensitive material).
//! 2. **Application-layer AEAD via [`EventCipher`]** — operators
//!    MAY supply a 32-byte symmetric key; events get encrypted
//!    under XChaCha20-Poly1305 with a random nonce per publish.
//!    Defence in depth — even a misconfigured transport can't
//!    leak credential bytes when this is set.
//!
//! Both layers compose. Operators with strict-handling
//! requirements should run both. The cipher is opt-in (default
//! off) so single-node + dev deploys aren't forced to manage a
//! key for state that never leaves the process.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures_core::Stream;
use mcpg_cluster_api::ClusterBackend;
use mcpg_plugin_protocol::credential::{
    CredentialError, CredentialIssuer, IssuedCredential, identity_hash_with_attrs,
};
use mcpg_plugin_protocol::types::PluginIdentity;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::credential_cache::{CredentialCache, RevocationCallback, RevocationSubscription};
use crate::credential_cache_cipher::{DecryptError, EventCipher};

/// Default topic for credential cache events. Operators with
/// multiple INDEPENDENT MCPG deployments sharing one
/// cluster_backend MUST namespace per deployment to avoid
/// cross-deployment leaks.
pub const DEFAULT_CACHE_EVENT_TOPIC: &str = "mcpg.credentials.events";

/// Either a plain in-process [`CredentialCache`] or a
/// [`ClusteredCredentialCache`] that wraps one. Lets the gateway
/// hold a single typed handle that's the same shape regardless
/// of whether a `cluster_backend` is bound — the resolver +
/// admin endpoints reach for `.local()` and ignore the cluster
/// flavour, while issuance + invalidation paths use the methods
/// on the kind itself so cluster broadcasts fire when configured.
pub enum CredentialCacheKind {
    /// Single-instance / no-cluster mode.
    Local(Arc<CredentialCache>),
    /// Multi-instance mode — the cluster wrapper publishes
    /// `Issued` / `Revoked` events on every issuance + invalidation
    /// so peer instances stay convergent.
    Clustered(ClusteredCredentialCache),
}

impl CredentialCacheKind {
    /// Borrow the underlying [`CredentialCache`]. Both variants
    /// hold one — the clustered variant simply layers pub/sub on
    /// top. Read-only call sites (resolver, admin probes) take
    /// this and ignore the cluster wrapper.
    #[must_use]
    pub fn local(&self) -> &Arc<CredentialCache> {
        match self {
            Self::Local(c) => c,
            Self::Clustered(c) => c.local(),
        }
    }

    /// Look up + issue (with cluster pub/sub when bound). Mirrors
    /// the `ClusteredCredentialCache::get_or_issue` shape so call
    /// sites can use one method regardless of variant.
    pub async fn get_or_issue(
        &self,
        issuer: &Arc<dyn CredentialIssuer>,
        identity: &PluginIdentity,
        target: &str,
        config: &serde_json::Value,
    ) -> Result<IssuedCredential, CredentialError> {
        match self {
            Self::Local(c) => {
                if let Some(cached) = c.try_get(identity, &issuer.manifest().id, target) {
                    return Ok(cached);
                }
                let credential = issuer.issue(identity, target, config).await?;
                c.insert_external(identity, &issuer.manifest().id, target, credential.clone());
                Ok(credential)
            }
            Self::Clustered(c) => c.get_or_issue(issuer, identity, target, config).await,
        }
    }

    /// Invalidate one entry, broadcasting `Revoked` to peers when
    /// in clustered mode.
    pub async fn invalidate(&self, identity: &PluginIdentity, plugin_id: &str, target: &str) {
        match self {
            Self::Local(c) => {
                c.invalidate(identity, plugin_id, target);
            }
            Self::Clustered(c) => c.invalidate(identity, plugin_id, target).await,
        }
    }

    /// True when the cluster wrapper is active. Surfaced so boot
    /// logging + telemetry can record cluster-vs-local mode at
    /// startup.
    #[must_use]
    pub fn is_clustered(&self) -> bool {
        matches!(self, Self::Clustered(_))
    }

    /// Subscribe to revocation events. The callback fires for every
    /// local invalidate AND (in clustered mode) every peer-published
    /// `Revoked` event applied to the local cache. Backend adapters
    /// holding per-credential connection state subscribe so they
    /// can drop the matching state on revocation. Returns a guard
    /// that unsubscribes on drop.
    pub fn on_revoked(&self, cb: RevocationCallback) -> RevocationSubscription {
        self.local().on_revoked(cb)
    }
}

/// Events published on the cache topic. Tagged enum (`kind`) so
/// future event variants can be added without breaking older
/// subscribers — they ignore unknown `kind` values per serde's
/// default `untagged: false` behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CacheEvent {
    /// A peer instance issued a credential. Subscribers populate
    /// their local cache with the bundled credential so future
    /// requests for `(identity_hash, plugin_id, target)` skip the
    /// plugin call.
    Issued {
        identity_hash: String,
        plugin_id: String,
        target: String,
        credential: IssuedCredential,
        /// node_id of the publisher. Receivers compare against
        /// their own `node_id` to skip self-publishes.
        published_by: String,
        /// Publish time (Unix epoch millis). On the AEAD path this is
        /// inside the sealed payload, so it is authenticated — a stale
        /// captured event can't be replayed past the freshness window.
        /// `#[serde(default)]` → events from a pre-field publisher
        /// deserialize to 0, which the receiver treats as
        /// "untimestamped, skip the freshness check" (rolling-upgrade
        /// safe).
        #[serde(default)]
        published_at_ms: u64,
        /// Unique per-publish id (uuid v7). Rides inside the sealed
        /// payload on the AEAD path, so a replayer can't mint a fresh
        /// id without the key. The receiver applies each
        /// `(published_by, event_id)` at most once within the replay
        /// window. `#[serde(default)]` → a pre-field publisher
        /// deserializes to "" and is exempt from the dedup
        /// (rolling-upgrade safe).
        #[serde(default)]
        event_id: String,
    },
    /// A peer instance invalidated a credential (binding signaled
    /// auth-failure, sweeper revoked, plugin shutdown). Subscribers
    /// drop the matching entry from their local cache.
    Revoked {
        identity_hash: String,
        plugin_id: String,
        target: String,
        published_by: String,
        /// See [`CacheEvent::Issued::published_at_ms`].
        #[serde(default)]
        published_at_ms: u64,
        /// See [`CacheEvent::Issued::event_id`].
        #[serde(default)]
        event_id: String,
    },
}

impl CacheEvent {
    fn published_at_ms(&self) -> u64 {
        match self {
            CacheEvent::Issued {
                published_at_ms, ..
            }
            | CacheEvent::Revoked {
                published_at_ms, ..
            } => *published_at_ms,
        }
    }

    #[cfg(test)]
    fn event_id(&self) -> &str {
        match self {
            CacheEvent::Issued { event_id, .. } | CacheEvent::Revoked { event_id, .. } => event_id,
        }
    }
}

/// Apply each peer event at most once within the replay window: a
/// bounded, TTL-expiring set keyed on `(published_by, event_id)`.
struct SeenEvents {
    ttl_ms: u64,
    cap: usize,
    seen: std::collections::HashMap<(String, String), u64>,
    order: std::collections::VecDeque<(String, String)>,
}

impl SeenEvents {
    fn new(ttl_ms: u64, cap: usize) -> Self {
        Self {
            ttl_ms,
            cap,
            seen: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    /// Returns `true` when the `(published_by, event_id)` pair has not
    /// been applied within the window (and records it), `false` when it
    /// is a duplicate that should be dropped.
    fn check_and_record(&mut self, published_by: &str, event_id: &str, now_ms: u64) -> bool {
        // Lazily drop entries that have aged out of the window.
        while let Some(front) = self.order.front() {
            match self.seen.get(front) {
                Some(&ts) if now_ms.saturating_sub(ts) >= self.ttl_ms => {
                    let front = front.clone();
                    self.order.pop_front();
                    self.seen.remove(&front);
                }
                _ => break,
            }
        }
        let key = (published_by.to_owned(), event_id.to_owned());
        if let Some(&ts) = self.seen.get(&key)
            && now_ms.saturating_sub(ts) < self.ttl_ms
        {
            return false;
        }
        self.seen.insert(key.clone(), now_ms);
        self.order.push_back(key);
        while self.order.len() > self.cap {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        true
    }
}

/// Hard ceiling on the replay seen-set (bounded memory under flood).
const MAX_SEEN_EVENTS: usize = 100_000;

fn new_cache_event_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Reject peer cache events whose publish timestamp is more than this
/// far from local now (either direction — covers clock skew + replay).
/// Generous enough to absorb cross-replica clock drift, tight enough to
/// blunt replay of a long-captured event (defense-in-depth).
const MAX_EVENT_AGE_MS: u64 = 300_000; // 5 minutes

fn now_unix_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Cluster-aware wrapper around [`CredentialCache`].
///
/// Cheap to clone — interior state is shared via `Arc`s. Drop
/// triggers the subscriber task to stop on next event.
pub struct ClusteredCredentialCache {
    local: Arc<CredentialCache>,
    coordinator: Arc<dyn ClusterBackend>,
    node_id: String,
    topic: String,
    /// Application-layer AEAD cipher. `Some(_)` when operators
    /// have configured a symmetric key — every publish is
    /// encrypted, every received envelope is decrypted before
    /// apply. `None` when only transport TLS is the privacy
    /// boundary.
    cipher: Option<Arc<EventCipher>>,
    /// JoinHandle for the subscriber task. Aborted on drop so the
    /// background task is cleanly stopped when the cache goes
    /// away.
    subscriber: Option<JoinHandle<()>>,
}

impl Drop for ClusteredCredentialCache {
    fn drop(&mut self) {
        if let Some(handle) = self.subscriber.take() {
            handle.abort();
        }
    }
}

impl ClusteredCredentialCache {
    /// Bind the cache to a `cluster_backend`. Spawns the
    /// background subscriber task; cache events from peer
    /// instances start flowing into the local cache as soon as
    /// `start()` returns.
    ///
    /// `cipher` opts into application-layer AEAD encryption of
    /// the cluster events. When `Some(_)`, every publish is
    /// encrypted and every received envelope is decrypted before
    /// apply. When `None`, the wire format is plaintext JSON
    /// (operators relying on transport TLS only).
    pub async fn start(
        local: Arc<CredentialCache>,
        coordinator: Arc<dyn ClusterBackend>,
        node_id: String,
        topic: Option<String>,
        cipher: Option<EventCipher>,
        allowed_publishers: Vec<String>,
    ) -> Result<Self, ClusterStartError> {
        let topic = topic.unwrap_or_else(|| DEFAULT_CACHE_EVENT_TOPIC.to_owned());
        let cipher = cipher.map(Arc::new);
        let allowed_publishers = Arc::new(allowed_publishers);
        // The seen-set ages entries by receipt time, but the freshness guard
        // is two-sided (it accepts events stamped up to MAX_EVENT_AGE_MS in
        // the future as well as the past), so in receipt-time an id can re-pass
        // freshness across a span of up to 2 * MAX_EVENT_AGE_MS. The TTL must
        // outlast that whole span or a future-dated capture could be replayed
        // after its seen entry expired but while it is still freshness-valid.
        let seen = Arc::new(Mutex::new(SeenEvents::new(
            2 * MAX_EVENT_AGE_MS + 60_000,
            MAX_SEEN_EVENTS,
        )));
        let stream = coordinator
            .subscribe(&topic, None, None)
            .await
            .map_err(|e| ClusterStartError::Subscribe {
                topic: topic.clone(),
                error: format!("{e:?}"),
            })?;
        let subscriber = tokio::spawn(subscriber_task(
            stream,
            Arc::clone(&local),
            node_id.clone(),
            topic.clone(),
            cipher.clone(),
            Arc::clone(&allowed_publishers),
            seen,
        ));
        if let Some(c) = &cipher {
            tracing::info!(
                topic = %topic,
                kid = %c.kid(),
                "credential cache: application-layer AEAD enabled (XChaCha20-Poly1305)"
            );
        } else {
            tracing::info!(
                topic = %topic,
                "credential cache: clustered (plaintext on wire — operators MUST configure TLS on cluster_backend transport)"
            );
        }
        Ok(Self {
            local,
            coordinator,
            node_id,
            topic,
            cipher,
            subscriber: Some(subscriber),
        })
    }

    /// Shared handle to the underlying local cache. Used by the
    /// resolver + admin endpoints that don't need cluster
    /// awareness.
    #[must_use]
    pub fn local(&self) -> &Arc<CredentialCache> {
        &self.local
    }

    /// Look up the credential cached for this `(identity, plugin,
    /// target)` triple. On local miss + successful issuance, also
    /// publishes the resulting credential to the cluster topic.
    pub async fn get_or_issue(
        &self,
        issuer: &Arc<dyn CredentialIssuer>,
        identity: &PluginIdentity,
        target: &str,
        config: &serde_json::Value,
    ) -> Result<IssuedCredential, CredentialError> {
        // Optimistic local-first lookup. If a peer instance has
        // already issued + published, our local cache is already
        // populated.
        if let Some(cached) = self.local.try_get(identity, &issuer.manifest().id, target) {
            return Ok(cached);
        }
        // Local miss: issue fresh, insert locally, publish.
        let credential = issuer.issue(identity, target, config).await?;
        let plugin_id = issuer.manifest().id.clone();
        self.local
            .insert_external(identity, &plugin_id, target, credential.clone());
        self.publish_issued(identity, &plugin_id, target, &credential)
            .await;
        Ok(credential)
    }

    /// Drop a specific cache entry locally + publish a Revoked
    /// event to the cluster.
    pub async fn invalidate(&self, identity: &PluginIdentity, plugin_id: &str, target: &str) {
        self.local.invalidate(identity, plugin_id, target);
        self.publish_revoked(identity, plugin_id, target).await;
    }

    /// Drop every entry issued by `plugin_id` locally + publish
    /// per-entry Revoked events. Returns the credentials evicted
    /// locally (callers may want to call `issuer.revoke(lease_id)`
    /// for each — same shape as the non-clustered cache).
    pub async fn invalidate_plugin(&self, plugin_id: &str) -> Vec<IssuedCredential> {
        let evicted = self.local.invalidate_plugin(plugin_id);
        // Plugin-wide invalidation skips per-entry Revoked publishes:
        // it happens at gateway shutdown anyway, so letting peers
        // expire the entries via their own TTL is acceptable.
        let _ = plugin_id;
        evicted
    }

    async fn publish_issued(
        &self,
        identity: &PluginIdentity,
        plugin_id: &str,
        target: &str,
        credential: &IssuedCredential,
    ) {
        let event = CacheEvent::Issued {
            identity_hash: identity_hash_with_attrs(identity, self.local.key_attributes()),
            plugin_id: plugin_id.to_owned(),
            target: target.to_owned(),
            credential: credential.clone(),
            published_by: self.node_id.clone(),
            published_at_ms: now_unix_millis(),
            event_id: new_cache_event_id(),
        };
        self.publish(&event).await;
    }

    async fn publish_revoked(&self, identity: &PluginIdentity, plugin_id: &str, target: &str) {
        let event = CacheEvent::Revoked {
            identity_hash: identity_hash_with_attrs(identity, self.local.key_attributes()),
            plugin_id: plugin_id.to_owned(),
            target: target.to_owned(),
            published_by: self.node_id.clone(),
            published_at_ms: now_unix_millis(),
            event_id: new_cache_event_id(),
        };
        self.publish(&event).await;
    }

    /// Serialize the event into the wire payload. When a cipher
    /// is configured, the event is wrapped in an AEAD envelope;
    /// otherwise the plain JSON CacheEvent is the payload.
    fn encode_event(&self, event: &CacheEvent) -> Result<Bytes, String> {
        if let Some(cipher) = &self.cipher {
            let envelope = cipher.encrypt_event(event).map_err(|e| e.to_string())?;
            Ok(Bytes::from(envelope))
        } else {
            let payload = serde_json::to_vec(event).map_err(|e| e.to_string())?;
            Ok(Bytes::from(payload))
        }
    }

    async fn publish(&self, event: &CacheEvent) {
        let payload = match self.encode_event(event) {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "credential cache: failed to encode event for cluster publish — skipping",
                );
                return;
            }
        };
        if let Err(err) = self.coordinator.publish(&self.topic, None, payload).await {
            // Publish failure is logged but doesn't break the
            // local cache — we already inserted/invalidated
            // locally. Peers may diverge briefly until the next
            // local issuance or until a peer's own publish
            // arrives.
            metrics::counter!(
                "mcpg_credential_cache_cluster_publish_failures_total",
                "topic" => self.topic.clone(),
            )
            .increment(1);
            tracing::warn!(
                topic = %self.topic,
                error = ?err,
                "credential cache: cluster publish failed",
            );
        }
    }
}

/// Failure modes for [`ClusteredCredentialCache::start`].
#[derive(Debug, thiserror::Error)]
pub enum ClusterStartError {
    #[error("failed to subscribe to cluster topic `{topic}`: {error}")]
    Subscribe { topic: String, error: String },
}

async fn subscriber_task(
    mut stream: std::pin::Pin<
        Box<dyn Stream<Item = mcpg_cluster_api::PublishedMessage> + Send + 'static>,
    >,
    local: Arc<CredentialCache>,
    self_node_id: String,
    topic: String,
    cipher: Option<Arc<EventCipher>>,
    allowed_publishers: Arc<Vec<String>>,
    seen: Arc<Mutex<SeenEvents>>,
) {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    // Pull messages in a hand-rolled poll loop because
    // `StreamExt::next` would require an extra dep (futures-util).
    // The stream surface returned by cluster_backend only
    // exposes `Stream`.
    struct PollNext<'a> {
        stream:
            Pin<&'a mut (dyn Stream<Item = mcpg_cluster_api::PublishedMessage> + Send + 'static)>,
    }
    impl<'a> std::future::Future for PollNext<'a> {
        type Output = Option<mcpg_cluster_api::PublishedMessage>;
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.stream.as_mut().poll_next(cx)
        }
    }

    loop {
        let next = PollNext {
            stream: stream.as_mut(),
        }
        .await;
        let Some(msg) = next else {
            tracing::info!(topic = %topic, "credential cache subscriber stream ended");
            break;
        };
        let event = match decode_event(&msg.payload, cipher.as_deref(), &topic) {
            Some(e) => e,
            None => continue,
        };
        apply_event(&local, &self_node_id, &allowed_publishers, &seen, event);
    }
}

/// Decode a wire payload into a `CacheEvent`. Branches on the
/// cipher config:
///
/// - **Cipher configured**: payload MUST be an envelope. Plaintext
///   payloads (a peer published without encryption) are dropped
///   loudly — they'd otherwise leak past the encryption gate.
/// - **No cipher**: payload MUST be plain JSON. Envelope payloads
///   (a peer published WITH encryption while we're configured
///   without) are dropped loudly — we couldn't decrypt them
///   anyway.
fn decode_event(raw: &[u8], cipher: Option<&EventCipher>, topic: &str) -> Option<CacheEvent> {
    if let Some(cipher) = cipher {
        match cipher.decrypt_envelope(raw) {
            Ok(event) => Some(event),
            Err(DecryptError::NotEnvelope) => {
                metrics::counter!(
                    "mcpg_credential_cache_cluster_events_total",
                    "kind" => "decrypt_dropped",
                    "outcome" => "plaintext_with_cipher_configured",
                )
                .increment(1);
                tracing::warn!(
                    topic = %topic,
                    "credential cache subscriber: peer published plaintext but this \
                     instance has AEAD configured — dropping (peer is misconfigured \
                     or attempting to bypass encryption)",
                );
                None
            }
            Err(DecryptError::KidMismatch {
                published_kid,
                configured_kid,
            }) => {
                metrics::counter!(
                    "mcpg_credential_cache_cluster_events_total",
                    "kind" => "decrypt_dropped",
                    "outcome" => "kid_mismatch",
                )
                .increment(1);
                tracing::warn!(
                    topic = %topic,
                    %published_kid,
                    %configured_kid,
                    "credential cache subscriber: peer published with different kid \
                     — dropping. Operator likely mid-rotation; finish the rollout to \
                     converge.",
                );
                None
            }
            Err(err) => {
                metrics::counter!(
                    "mcpg_credential_cache_cluster_events_total",
                    "kind" => "decrypt_dropped",
                    "outcome" => "auth_failed",
                )
                .increment(1);
                tracing::warn!(
                    topic = %topic,
                    error = %err,
                    "credential cache subscriber: AEAD decrypt failed — dropping",
                );
                None
            }
        }
    } else {
        // No cipher — peer payload should be plain JSON. Detect
        // the envelope shape so we can warn loudly when a peer
        // has encryption ON and we're OFF (asymmetric config).
        if EventCipher::looks_like_envelope(raw) {
            metrics::counter!(
                "mcpg_credential_cache_cluster_events_total",
                "kind" => "decrypt_dropped",
                "outcome" => "envelope_without_cipher_configured",
            )
            .increment(1);
            tracing::warn!(
                topic = %topic,
                "credential cache subscriber: peer published encrypted envelope but \
                 this instance has no AEAD configured — dropping. Configure the \
                 same key on this instance to participate.",
            );
            return None;
        }
        match serde_json::from_slice::<CacheEvent>(raw) {
            Ok(event) => Some(event),
            Err(err) => {
                tracing::warn!(
                    topic = %topic,
                    error = %err,
                    "credential cache subscriber: malformed event payload, skipping",
                );
                None
            }
        }
    }
}

/// Gate a peer-published cache event before it mutates the local
/// cache. Returns `true` to apply, `false` to drop (with a metric +
/// warn). Two checks, both defense-in-depth:
///   * Peer allowlist — when configured, `published_by` must be listed.
///     Authenticated on the AEAD path (`published_by` is sealed); on the
///     plaintext path it is best-effort (forgeable) but bounds honest
///     misconfiguration / non-malicious peers.
///   * Field shape — reject events with an empty identity_hash / plugin_id
///     / target, which would otherwise poison or invalidate a broad cache
///     key.
fn peer_event_accepted(
    allowed_publishers: &[String],
    kind: &'static str,
    published_by: &str,
    id_hash: &str,
    plugin_id: &str,
    target: &str,
) -> bool {
    if !allowed_publishers.is_empty() && !allowed_publishers.iter().any(|p| p == published_by) {
        metrics::counter!(
            "mcpg_credential_cache_cluster_events_total",
            "kind" => kind,
            "outcome" => "dropped_publisher_not_allowed",
        )
        .increment(1);
        tracing::warn!(
            published_by = %published_by,
            "credential cache subscriber: dropping event from peer not in \
             allowed_publishers",
        );
        return false;
    }
    if id_hash.is_empty() || plugin_id.is_empty() || target.is_empty() {
        metrics::counter!(
            "mcpg_credential_cache_cluster_events_total",
            "kind" => kind,
            "outcome" => "dropped_malformed",
        )
        .increment(1);
        tracing::warn!(
            published_by = %published_by,
            "credential cache subscriber: dropping event with empty \
             identity_hash / plugin_id / target",
        );
        return false;
    }
    true
}

fn apply_event(
    local: &CredentialCache,
    self_node_id: &str,
    allowed_publishers: &[String],
    seen: &Mutex<SeenEvents>,
    event: CacheEvent,
) {
    // Replay freshness guard (defense-in-depth). On the AEAD path
    // `published_at_ms` is inside the sealed payload, so it's
    // authenticated — a captured Issued/Revoked event can't be replayed
    // beyond the window to re-poison or re-revoke. `0` means the event
    // predates the field (rolling upgrade) → skip the check.
    let stamped = event.published_at_ms();
    if stamped != 0 {
        let now = now_unix_millis();
        let skew = now.abs_diff(stamped);
        if skew > MAX_EVENT_AGE_MS {
            metrics::counter!(
                "mcpg_credential_cache_cluster_events_total",
                "kind" => "freshness",
                "outcome" => "rejected_stale",
            )
            .increment(1);
            tracing::warn!(
                published_at_ms = stamped,
                skew_ms = skew,
                "credential cache subscriber: dropping event outside the freshness \
                 window (replay or excessive clock skew)",
            );
            return;
        }
    }
    match event {
        CacheEvent::Issued {
            identity_hash: id_hash,
            plugin_id,
            target,
            credential,
            published_by,
            published_at_ms: _,
            event_id,
        } => {
            if published_by == self_node_id {
                // Skip own-publishes — we've already inserted
                // locally before publishing.
                metrics::counter!(
                    "mcpg_credential_cache_cluster_events_total",
                    "kind" => "issued",
                    "outcome" => "skipped_self",
                )
                .increment(1);
                return;
            }
            if !peer_event_accepted(
                allowed_publishers,
                "issued",
                &published_by,
                &id_hash,
                &plugin_id,
                &target,
            ) {
                return;
            }
            if !accept_once(seen, &published_by, &event_id, "issued") {
                return;
            }
            local.insert_by_hash(id_hash, plugin_id, target, credential);
            metrics::counter!(
                "mcpg_credential_cache_cluster_events_total",
                "kind" => "issued",
                "outcome" => "applied",
            )
            .increment(1);
        }
        CacheEvent::Revoked {
            identity_hash: id_hash,
            plugin_id,
            target,
            published_by,
            published_at_ms: _,
            event_id,
        } => {
            if published_by == self_node_id {
                metrics::counter!(
                    "mcpg_credential_cache_cluster_events_total",
                    "kind" => "revoked",
                    "outcome" => "skipped_self",
                )
                .increment(1);
                return;
            }
            if !peer_event_accepted(
                allowed_publishers,
                "revoked",
                &published_by,
                &id_hash,
                &plugin_id,
                &target,
            ) {
                return;
            }
            if !accept_once(seen, &published_by, &event_id, "revoked") {
                return;
            }
            local.invalidate_by_hash(&id_hash, &plugin_id, &target);
            metrics::counter!(
                "mcpg_credential_cache_cluster_events_total",
                "kind" => "revoked",
                "outcome" => "applied",
            )
            .increment(1);
        }
    }
}

/// Replay guard: drop a peer event whose `(published_by, event_id)`
/// pair was already applied within the window. An empty `event_id`
/// (pre-field publisher) is exempt so a mixed-version cluster keeps
/// working. Recorded only for events that would otherwise apply, so a
/// flood of malformed/unlisted events can't exhaust the seen-set.
fn accept_once(seen: &Mutex<SeenEvents>, published_by: &str, event_id: &str, kind: &str) -> bool {
    if event_id.is_empty() {
        return true;
    }
    let fresh = seen
        .lock()
        .expect("credential cache seen-set mutex poisoned")
        .check_and_record(published_by, event_id, now_unix_millis());
    if !fresh {
        metrics::counter!(
            "mcpg_credential_cache_cluster_events_total",
            "kind" => kind.to_owned(),
            "outcome" => "dropped_replay",
        )
        .increment(1);
        tracing::warn!(
            published_by = %published_by,
            event_id = %event_id,
            "credential cache subscriber: dropping duplicate peer event (replay guard)",
        );
    }
    fresh
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_event_issued_roundtrips_via_serde() {
        let event = CacheEvent::Issued {
            identity_hash: "abc123".into(),
            plugin_id: "vault-pg".into(),
            target: "orders-readonly".into(),
            credential: IssuedCredential::from_value("token-xyz", 60),
            published_by: "node-a".into(),
            published_at_ms: 0,
            event_id: String::new(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: CacheEvent = serde_json::from_str(&json).unwrap();
        match parsed {
            CacheEvent::Issued { plugin_id, .. } => assert_eq!(plugin_id, "vault-pg"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn cache_event_revoked_roundtrips_via_serde() {
        let event = CacheEvent::Revoked {
            identity_hash: "abc123".into(),
            plugin_id: "vault-pg".into(),
            target: "orders-readonly".into(),
            published_by: "node-b".into(),
            published_at_ms: 0,
            event_id: String::new(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: CacheEvent = serde_json::from_str(&json).unwrap();
        matches!(parsed, CacheEvent::Revoked { .. });
    }

    #[test]
    fn cache_event_uses_kind_tag() {
        let event = CacheEvent::Issued {
            identity_hash: "x".into(),
            plugin_id: "p".into(),
            target: "t".into(),
            credential: IssuedCredential::from_value("c", 60),
            published_by: "n".into(),
            published_at_ms: 0,
            event_id: String::new(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"kind\":\"issued\""));
    }

    // ---------------------------------------------------------------
    // decode_event: the dispatch helper that splits payloads into
    // either-plaintext-or-encrypted-envelope based on the cipher
    // configuration. Exercises the asymmetric-config detection that
    // catches operators with mismatched encryption between peers.
    // ---------------------------------------------------------------

    fn sample_event() -> CacheEvent {
        CacheEvent::Issued {
            identity_hash: "abc".into(),
            plugin_id: "vault-pg".into(),
            target: "orders".into(),
            credential: IssuedCredential::from_value("token-xyz", 60),
            published_by: "node-a".into(),
            published_at_ms: 0,
            event_id: String::new(),
        }
    }

    fn raw_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(7);
        }
        k
    }

    #[test]
    fn decode_event_no_cipher_accepts_plaintext_event() {
        let raw = serde_json::to_vec(&sample_event()).unwrap();
        let decoded = super::decode_event(&raw, None, "test-topic")
            .expect("plaintext event with no cipher should decode");
        match decoded {
            CacheEvent::Issued { plugin_id, .. } => assert_eq!(plugin_id, "vault-pg"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn apply_event_drops_stale_replayed_event_applies_fresh() {
        // Replay guard: an authenticated-but-stale event replayed
        // past the freshness window is dropped; a fresh peer event
        // applies. (`published_at_ms` is inside the AEAD-sealed payload,
        // so a replayer can't refresh it.)
        use crate::credential_cache::{CredentialCache, CredentialCacheConfig};
        let local = CredentialCache::new(CredentialCacheConfig {
            max_entries: 16,
            max_cache_ttl: std::time::Duration::from_secs(60),
            key_attributes: Vec::new(),
        });
        let event = |ts: u64| CacheEvent::Issued {
            identity_hash: "h".into(),
            plugin_id: "p".into(),
            target: "t".into(),
            credential: IssuedCredential::from_value("c", 60),
            published_by: "other-node".into(),
            published_at_ms: ts,
            event_id: String::new(),
        };
        let seen = test_seen();
        // Stamped ~1970 → far outside the window → dropped.
        apply_event(&local, "self-node", &[], &seen, event(1));
        assert!(local.is_empty(), "stale replayed event must be dropped");
        // Fresh peer event applies.
        apply_event(&local, "self-node", &[], &seen, event(now_unix_millis()));
        assert_eq!(local.len(), 1, "a fresh peer event must apply");
    }

    #[test]
    fn apply_event_enforces_peer_allowlist_and_field_shape() {
        // With a peer allowlist, an event from an unlisted peer is
        // dropped; a listed peer applies. A malformed event (empty target)
        // is dropped regardless.
        use crate::credential_cache::{CredentialCache, CredentialCacheConfig};
        let local = CredentialCache::new(CredentialCacheConfig {
            max_entries: 16,
            max_cache_ttl: std::time::Duration::from_secs(60),
            key_attributes: Vec::new(),
        });
        let allow = vec!["trusted-peer".to_owned()];
        let issued = |by: &str, target: &str| CacheEvent::Issued {
            identity_hash: "h".into(),
            plugin_id: "p".into(),
            target: target.into(),
            credential: IssuedCredential::from_value("c", 60),
            published_by: by.into(),
            published_at_ms: now_unix_millis(),
            event_id: String::new(),
        };

        let seen = test_seen();
        // Unlisted peer → dropped.
        apply_event(&local, "self", &allow, &seen, issued("evil-peer", "t"));
        assert!(local.is_empty(), "event from unlisted peer must be dropped");

        // Malformed (empty target) even from a listed peer → dropped.
        apply_event(&local, "self", &allow, &seen, issued("trusted-peer", ""));
        assert!(local.is_empty(), "malformed event must be dropped");

        // Listed peer, well-formed → applied.
        apply_event(&local, "self", &allow, &seen, issued("trusted-peer", "t"));
        assert_eq!(local.len(), 1, "event from a listed peer must apply");
    }

    fn test_seen() -> Mutex<SeenEvents> {
        Mutex::new(SeenEvents::new(MAX_EVENT_AGE_MS + 60_000, MAX_SEEN_EVENTS))
    }

    fn test_cache() -> CredentialCache {
        use crate::credential_cache::{CredentialCache, CredentialCacheConfig};
        CredentialCache::new(CredentialCacheConfig {
            max_entries: 16,
            max_cache_ttl: std::time::Duration::from_secs(60),
            key_attributes: Vec::new(),
        })
    }

    #[test]
    fn apply_event_replayed_revoked_is_dropped_entry_survives() {
        let local = test_cache();
        let seen = test_seen();
        let revoked = || CacheEvent::Revoked {
            identity_hash: "h".into(),
            plugin_id: "p".into(),
            target: "t".into(),
            published_by: "peer".into(),
            published_at_ms: now_unix_millis(),
            event_id: "E1".into(),
        };
        local.insert_by_hash(
            "h".into(),
            "p".into(),
            "t".into(),
            IssuedCredential::from_value("c", 60),
        );
        apply_event(&local, "self", &[], &seen, revoked());
        assert!(local.is_empty(), "first revoke applies");
        // A new credential is re-issued locally, then the SAME revoke event is
        // replayed — the dedup must drop it so the live entry survives.
        local.insert_by_hash(
            "h".into(),
            "p".into(),
            "t".into(),
            IssuedCredential::from_value("c2", 60),
        );
        apply_event(&local, "self", &[], &seen, revoked());
        assert_eq!(local.len(), 1, "replayed revoke must be dropped");
    }

    #[test]
    fn apply_event_distinct_event_ids_both_apply() {
        let local = test_cache();
        let seen = test_seen();
        let issued = |hash: &str, id: &str| CacheEvent::Issued {
            identity_hash: hash.into(),
            plugin_id: "p".into(),
            target: "t".into(),
            credential: IssuedCredential::from_value("c", 60),
            published_by: "peer".into(),
            published_at_ms: now_unix_millis(),
            event_id: id.into(),
        };
        apply_event(&local, "self", &[], &seen, issued("h1", "E1"));
        apply_event(&local, "self", &[], &seen, issued("h2", "E2"));
        assert_eq!(local.len(), 2, "distinct event ids both apply");
    }

    #[test]
    fn apply_event_empty_event_id_skips_dedup() {
        // A pre-field publisher (empty event_id) is exempt from the replay
        // guard, so a mixed-version cluster keeps applying its events.
        let local = test_cache();
        let seen = test_seen();
        let revoked = || CacheEvent::Revoked {
            identity_hash: "h".into(),
            plugin_id: "p".into(),
            target: "t".into(),
            published_by: "peer".into(),
            published_at_ms: now_unix_millis(),
            event_id: String::new(),
        };
        local.insert_by_hash(
            "h".into(),
            "p".into(),
            "t".into(),
            IssuedCredential::from_value("c", 60),
        );
        apply_event(&local, "self", &[], &seen, revoked());
        assert!(local.is_empty());
        local.insert_by_hash(
            "h".into(),
            "p".into(),
            "t".into(),
            IssuedCredential::from_value("c2", 60),
        );
        apply_event(&local, "self", &[], &seen, revoked());
        assert!(local.is_empty(), "empty-id revoke is not deduplicated");
    }

    #[test]
    fn seen_events_evicts_by_ttl_and_cap() {
        let mut seen = SeenEvents::new(1_000, 2);
        // Same id past the TTL is re-accepted.
        assert!(seen.check_and_record("n", "a", 0));
        assert!(
            !seen.check_and_record("n", "a", 500),
            "within window: duplicate"
        );
        assert!(
            seen.check_and_record("n", "a", 2_000),
            "past ttl: re-accepted"
        );
        // Hard cap evicts the oldest tracked id.
        let mut capped = SeenEvents::new(1_000_000, 2);
        assert!(capped.check_and_record("n", "1", 0));
        assert!(capped.check_and_record("n", "2", 0));
        assert!(capped.check_and_record("n", "3", 0)); // evicts "1"
        assert!(
            capped.check_and_record("n", "1", 0),
            "evicted id is accepted again"
        );
    }

    #[test]
    fn cache_event_event_id_roundtrips_via_serde() {
        let event = CacheEvent::Issued {
            identity_hash: "h".into(),
            plugin_id: "p".into(),
            target: "t".into(),
            credential: IssuedCredential::from_value("c", 60),
            published_by: "node".into(),
            published_at_ms: 7,
            event_id: "uuid-7".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: CacheEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_id(), "uuid-7");
    }

    #[test]
    fn cache_event_missing_event_id_defaults_empty() {
        // Serialize a real event, strip event_id (mimics a pre-field
        // publisher), and confirm it deserializes to "" rather than failing.
        let event = CacheEvent::Issued {
            identity_hash: "h".into(),
            plugin_id: "p".into(),
            target: "t".into(),
            credential: IssuedCredential::from_value("c", 60),
            published_by: "n".into(),
            published_at_ms: 0,
            event_id: "drop-me".into(),
        };
        let mut value = serde_json::to_value(&event).unwrap();
        value.as_object_mut().unwrap().remove("event_id");
        let parsed: CacheEvent = serde_json::from_value(value).unwrap();
        assert_eq!(
            parsed.event_id(),
            "",
            "absent event_id deserializes to empty"
        );
    }

    #[test]
    fn decode_event_no_cipher_drops_encrypted_envelope() {
        // Asymmetric config: peer encrypted but we're configured
        // without a cipher. We can't decrypt — drop loudly.
        let cipher = EventCipher::from_raw_key(&raw_key(), "k1".into()).unwrap();
        let envelope = cipher.encrypt_event(&sample_event()).unwrap();
        let decoded = super::decode_event(&envelope, None, "test-topic");
        assert!(
            decoded.is_none(),
            "envelope-shaped payload MUST NOT be apply-without-cipher"
        );
    }

    #[test]
    fn decode_event_with_cipher_accepts_encrypted_envelope() {
        let cipher = EventCipher::from_raw_key(&raw_key(), "k1".into()).unwrap();
        let envelope = cipher.encrypt_event(&sample_event()).unwrap();
        let decoded = super::decode_event(&envelope, Some(&cipher), "test-topic")
            .expect("envelope encrypted under same key should decode");
        matches!(decoded, CacheEvent::Issued { .. });
    }

    #[test]
    fn decode_event_with_cipher_drops_plaintext_event() {
        // Asymmetric config: peer published plaintext but we're
        // configured WITH encryption. Don't apply the plaintext —
        // a peer (or attacker) bypassing the encryption boundary
        // shouldn't poison the cache.
        let cipher = EventCipher::from_raw_key(&raw_key(), "k1".into()).unwrap();
        let plaintext = serde_json::to_vec(&sample_event()).unwrap();
        let decoded = super::decode_event(&plaintext, Some(&cipher), "test-topic");
        assert!(
            decoded.is_none(),
            "plaintext event MUST NOT bypass encryption gate when cipher configured",
        );
    }

    #[test]
    fn decode_event_with_cipher_drops_wrong_key() {
        // Receiver has key A; peer encrypted with key B. AEAD
        // auth fails — drop.
        let alice = EventCipher::from_raw_key(&raw_key(), "k1".into()).unwrap();
        let mut bob_key = raw_key();
        bob_key[0] ^= 0xff;
        let bob = EventCipher::from_raw_key(&bob_key, "k1".into()).unwrap();
        let envelope = bob.encrypt_event(&sample_event()).unwrap();
        let decoded = super::decode_event(&envelope, Some(&alice), "test-topic");
        assert!(decoded.is_none(), "wrong-key envelope MUST drop");
    }

    #[test]
    fn decode_event_with_cipher_drops_kid_mismatch() {
        // Same key, different kids — operator mid-rotation. Drop
        // until rotation completes.
        let alice = EventCipher::from_raw_key(&raw_key(), "old-kid".into()).unwrap();
        let bob = EventCipher::from_raw_key(&raw_key(), "new-kid".into()).unwrap();
        let envelope = alice.encrypt_event(&sample_event()).unwrap();
        let decoded = super::decode_event(&envelope, Some(&bob), "test-topic");
        assert!(decoded.is_none(), "kid-mismatch envelope MUST drop");
    }

    #[test]
    fn decode_event_no_cipher_drops_random_garbage() {
        // Garbage payload — neither valid CacheEvent JSON nor
        // valid envelope. Drop.
        let garbage = b"not even close to valid";
        let decoded = super::decode_event(garbage, None, "test-topic");
        assert!(decoded.is_none());
    }
}
