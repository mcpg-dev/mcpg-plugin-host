//! Per-`(identity_hash, plugin_id, target)` credential cache.
//!
//! Caches `IssuedCredential` values returned by `credential_issuer`
//! plugins. Vault dynamic-DB issuance takes ~50-200ms; AWS STS
//! AssumeRole takes ~50-100ms. Without caching, every MCP request
//! adds that latency to every backend call. The cache keeps
//! steady-state cost at one issuance per (caller, target) pair per
//! credential lifetime.
//!
//! # Eviction
//!
//! Two layers:
//!
//! - **TTL** — entries expire at `issued_at + min(plugin_ttl,
//!   max_cache_ttl)`. The plugin-supplied TTL is honored unless
//!   the operator-configured cap is shorter. Expired entries are
//!   removed lazily on the next `get_or_issue` call (no
//!   background sweeper in v0.1; LRU + per-call expiry checks
//!   keep memory bounded).
//! - **LRU** — when `entries.len() >= max_entries`, the
//!   least-recently-issued entry is evicted to make room. This
//!   defends against unbounded cardinality growth from
//!   identity providers that emit too many distinct callers.
//!
//! # Multi-instance
//!
//! v0.1 ships an in-process cache per gateway instance. The
//! multi-instance divergence gap is closed by cluster_backend
//! pub/sub invalidation events.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mcpg_plugin_protocol::credential::{
    CredentialError, CredentialIssuer, IssuedCredential, identity_hash_with_attrs,
};
use mcpg_plugin_protocol::types::PluginIdentity;

/// Cache key dimension. `identity_hash` is the deterministic hash
/// of stable identity fields (subject_id, roles, scopes, etc.) —
/// excludes `attributes` to bound cardinality. `plugin_id` is the
/// `credential_issuer` manifest id. `target` is the operator-
/// supplied target string from the `cred://` URI.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CacheKey {
    identity_hash: String,
    plugin_id: String,
    target: String,
}

#[derive(Debug, Clone)]
struct CachedEntry {
    credential: IssuedCredential,
    expires_at: Instant,
    /// Track recency so we can evict the LRU entry on overflow.
    /// Updated to `Instant::now()` on every cache hit.
    last_access: Instant,
}

/// Operator-supplied cache config. All fields have safe defaults.
#[derive(Debug, Clone)]
pub struct CredentialCacheConfig {
    /// Maximum number of (identity, plugin, target) entries. When
    /// the cache is full, the LRU entry is evicted. Default 10000
    /// — at ~500 bytes per entry that's ~5MB worst case.
    pub max_entries: usize,
    /// Operator-side cap on per-entry TTL. Even if a plugin
    /// returns a 24-hour TTL, the cache evicts at this cap to
    /// limit blast radius from leaked / compromised credentials.
    /// Default 3600 (1 hour).
    pub max_cache_ttl: Duration,
    /// Stable, low-cardinality identity attribute names (e.g. the
    /// tenant claim) folded into the cache key so callers differing
    /// only by these claims do NOT share a cached credential. Empty
    /// (default) excludes attributes from the key — set this to your
    /// tenant claim name(s) when the `credential_issuer` derives its
    /// principal from an attribute claim, otherwise those callers
    /// share one credential.
    pub key_attributes: Vec<String>,
}

impl Default for CredentialCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_cache_ttl: Duration::from_secs(3600),
            key_attributes: Vec::new(),
        }
    }
}

/// Subscriber callback for revocation events. Called every time a
/// `(plugin_id, target)` cache entry is invalidated — either via a
/// direct [`CredentialCache::invalidate`] / [`invalidate_plugin`]
/// call OR (in the clustered wrapper) when a peer publishes a
/// `Revoked` event the local cache applies. Backend adapters
/// holding per-credential pools subscribe so they can drop the
/// matching pool on revocation.
///
/// The closure runs synchronously inside the lock guard. Keep it
/// short — long work belongs in a spawned task driven by a channel
/// the closure pushes to.
pub type RevocationCallback = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// Guard returned by [`CredentialCache::on_revoked`]. The cache
/// removes the subscription from its dispatch list when this guard
/// drops. Holding the guard for the lifetime of the subscriber
/// (typically a backend's `ProfileRuntime`) is the correct usage.
#[must_use = "RevocationSubscription unsubscribes when dropped"]
pub struct RevocationSubscription {
    cache: Arc<Mutex<Inner>>,
    id: u64,
}

impl Drop for RevocationSubscription {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.cache.lock() {
            guard.subscribers.retain(|(sid, _)| *sid != self.id);
        }
    }
}

/// In-process credential cache. Cheap to clone — interior state
/// lives behind an `Arc<Mutex>`.
#[derive(Clone)]
pub struct CredentialCache {
    inner: Arc<Mutex<Inner>>,
    config: CredentialCacheConfig,
}

struct Inner {
    entries: BTreeMap<CacheKey, CachedEntry>,
    /// Revocation subscribers — fired on every local invalidate
    /// call. Each entry is `(subscription_id, callback)`.
    subscribers: Vec<(u64, RevocationCallback)>,
    /// Monotonic id source for [`RevocationSubscription`].
    next_subscriber_id: u64,
}

impl Default for CredentialCache {
    fn default() -> Self {
        Self::new(CredentialCacheConfig::default())
    }
}

impl CredentialCache {
    #[must_use]
    pub fn new(config: CredentialCacheConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                entries: BTreeMap::new(),
                subscribers: Vec::new(),
                next_subscriber_id: 0,
            })),
            config,
        }
    }

    /// Cache-key identity hash for this cache, folding in the
    /// operator-configured [`CredentialCacheConfig::key_attributes`].
    fn identity_hash(&self, identity: &PluginIdentity) -> String {
        identity_hash_with_attrs(identity, &self.config.key_attributes)
    }

    /// The operator-configured attribute names folded into the cache
    /// key. The clustered wrapper reads this so the hash it publishes
    /// matches the local key.
    #[must_use]
    pub fn key_attributes(&self) -> &[String] {
        &self.config.key_attributes
    }

    /// Subscribe to revocation events. The callback is invoked with
    /// `(plugin_id, target)` whenever a cached credential for that
    /// pair is invalidated locally. The returned guard unsubscribes
    /// on drop — hold it for the lifetime of the consumer.
    ///
    /// Used by backend adapters with per-credential connection pools
    /// (SQL, NATS, Kafka) so they can evict the matching pool on
    /// revocation. The clustered wrapper additionally fires the
    /// callback when a peer publishes a `Revoked` event we apply
    /// locally — see [`crate::credential_cache_clustered`].
    ///
    /// Contract: the callback runs **while the cache lock is held** (so
    /// that `unsubscribe` cannot race the FFI plugin freeing the
    /// callback context mid-fire — see the `invalidate*` methods).
    /// It MUST be short and MUST NOT call back into this cache (doing so
    /// re-enters the non-reentrant lock and deadlocks); offload real
    /// work to a channel/task.
    pub fn on_revoked(&self, cb: RevocationCallback) -> RevocationSubscription {
        let mut guard = self.inner.lock().expect("credential cache mutex poisoned");
        let id = guard.next_subscriber_id;
        guard.next_subscriber_id = id.wrapping_add(1);
        guard.subscribers.push((id, cb));
        RevocationSubscription {
            cache: Arc::clone(&self.inner),
            id,
        }
    }

    /// Fire every registered subscriber. Called by the `invalidate*`
    /// methods **while the cache lock is held** — keeping the fire and
    /// the subscriber-list mutation (subscribe/unsubscribe) mutually
    /// exclusive is what guarantees the FFI callback context is not
    /// freed by a concurrent `host_unsubscribe` mid-fire.
    fn notify_revoked(subscribers: &[(u64, RevocationCallback)], plugin_id: &str, target: &str) {
        for (_, cb) in subscribers {
            cb(plugin_id, target);
        }
    }

    /// Look up the credential cached for this `(identity, plugin,
    /// target)` triple. Cache miss / expired → calls `issuer.issue`
    /// and stores the fresh credential before returning.
    pub async fn get_or_issue(
        &self,
        issuer: &Arc<dyn CredentialIssuer>,
        identity: &PluginIdentity,
        target: &str,
        config: &serde_json::Value,
    ) -> Result<IssuedCredential, CredentialError> {
        let key = CacheKey {
            identity_hash: self.identity_hash(identity),
            plugin_id: issuer.manifest().id.clone(),
            target: target.to_owned(),
        };
        let now = Instant::now();

        // Fast path: cache hit + not expired.
        if let Some(cached) = self.lookup(&key, now) {
            metrics::counter!(
                "mcpg_credential_cache_total",
                "plugin_id" => key.plugin_id.clone(),
                "outcome" => "hit",
            )
            .increment(1);
            return Ok(cached);
        }

        // Slow path: issue fresh + insert.
        metrics::counter!(
            "mcpg_credential_cache_total",
            "plugin_id" => key.plugin_id.clone(),
            "outcome" => "miss",
        )
        .increment(1);
        let credential = issuer.issue(identity, target, config).await?;
        self.insert(key, credential.clone(), now);
        Ok(credential)
    }

    /// Drop a specific cache entry. Used when the binding signals
    /// "this credential is invalid" (e.g. Postgres returned
    /// auth-failed) — the gateway invalidates so the next request
    /// re-issues. If the entry has a `lease_id`, the caller may
    /// also want to call `issuer.revoke(lease_id)` separately.
    pub fn invalidate(&self, identity: &PluginIdentity, plugin_id: &str, target: &str) {
        let key = CacheKey {
            identity_hash: self.identity_hash(identity),
            plugin_id: plugin_id.to_owned(),
            target: target.to_owned(),
        };
        // Fire subscribers WHILE holding the lock: a concurrent
        // `host_unsubscribe` (RevocationSubscription::drop) needs this same
        // lock to deregister, so it cannot return — and the plugin cannot
        // free the FFI callback context — until any in-flight fire here has
        // finished. Callbacks must be short and non-reentrant.
        let mut guard = self.inner.lock().expect("credential cache mutex poisoned");
        guard.entries.remove(&key);
        Self::notify_revoked(&guard.subscribers, plugin_id, target);
    }

    /// Drop every entry issued by `plugin_id`. Used at plugin
    /// shutdown so leases don't outlive the issuer's ability to
    /// revoke them.
    pub fn invalidate_plugin(&self, plugin_id: &str) -> Vec<IssuedCredential> {
        // Hold the lock across eviction + the subscriber fan-out (see the
        // note on `invalidate`).
        let mut guard = self.inner.lock().expect("credential cache mutex poisoned");
        let evicted: Vec<_> = guard
            .entries
            .iter()
            .filter(|(k, _)| k.plugin_id == plugin_id)
            .map(|(_, v)| v.credential.clone())
            .collect();
        let evicted_targets: Vec<String> = guard
            .entries
            .iter()
            .filter(|(k, _)| k.plugin_id == plugin_id)
            .map(|(k, _)| k.target.clone())
            .collect();
        guard.entries.retain(|k, _| k.plugin_id != plugin_id);
        for target in &evicted_targets {
            Self::notify_revoked(&guard.subscribers, plugin_id, target);
        }
        evicted
    }

    /// Direct insert — used by the cluster-aware wrapper when a
    /// peer instance publishes an Issued event to the cluster
    /// topic. Bypasses the plugin call; the credential was issued
    /// by some other instance and is already alive.
    ///
    /// The TTL applied is `min(credential.ttl_seconds,
    /// max_cache_ttl)` — same shape as the local-issue path so
    /// peer-issued and local-issued credentials behave
    /// identically.
    pub fn insert_external(
        &self,
        identity: &PluginIdentity,
        plugin_id: &str,
        target: &str,
        credential: IssuedCredential,
    ) {
        let key = CacheKey {
            identity_hash: self.identity_hash(identity),
            plugin_id: plugin_id.to_owned(),
            target: target.to_owned(),
        };
        self.insert(key, credential, Instant::now());
    }

    /// Insert a credential by pre-computed identity_hash. Used by
    /// the cluster-aware wrapper applying peer-published Issued
    /// events — the publisher already serialised the
    /// identity_hash, so we don't reconstruct a PluginIdentity to
    /// recompute it.
    pub fn insert_by_hash(
        &self,
        identity_hash: String,
        plugin_id: String,
        target: String,
        credential: IssuedCredential,
    ) {
        let key = CacheKey {
            identity_hash,
            plugin_id,
            target,
        };
        self.insert(key, credential, Instant::now());
    }

    /// Invalidate a cache entry by pre-computed identity_hash.
    /// Counterpart to [`Self::insert_by_hash`] — used by the
    /// cluster-aware wrapper applying peer-published Revoked
    /// events.
    pub fn invalidate_by_hash(&self, identity_hash: &str, plugin_id: &str, target: &str) {
        let key = CacheKey {
            identity_hash: identity_hash.to_owned(),
            plugin_id: plugin_id.to_owned(),
            target: target.to_owned(),
        };
        // Fire under the lock — see the note on `invalidate`.
        let mut guard = self.inner.lock().expect("credential cache mutex poisoned");
        guard.entries.remove(&key);
        Self::notify_revoked(&guard.subscribers, plugin_id, target);
    }

    /// Local-only lookup — used by the cluster-aware wrapper to
    /// decide whether to publish an Issued event after a fresh
    /// local issuance. Returns the cached credential if present
    /// and not expired; touches `last_access` like a normal
    /// lookup. Does NOT call the plugin.
    pub fn try_get(
        &self,
        identity: &PluginIdentity,
        plugin_id: &str,
        target: &str,
    ) -> Option<IssuedCredential> {
        let key = CacheKey {
            identity_hash: self.identity_hash(identity),
            plugin_id: plugin_id.to_owned(),
            target: target.to_owned(),
        };
        self.lookup(&key, Instant::now())
    }

    /// Number of entries currently in the cache (used by tests +
    /// the admin/inspect surface).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("credential cache mutex poisoned")
            .entries
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lookup(&self, key: &CacheKey, now: Instant) -> Option<IssuedCredential> {
        let mut guard = self.inner.lock().expect("credential cache mutex poisoned");
        let entry = guard.entries.get_mut(key)?;
        if entry.expires_at <= now {
            guard.entries.remove(key);
            return None;
        }
        entry.last_access = now;
        Some(entry.credential.clone())
    }

    fn insert(&self, key: CacheKey, credential: IssuedCredential, now: Instant) {
        let plugin_ttl = Duration::from_secs(credential.ttl_seconds);
        let ttl = plugin_ttl.min(self.config.max_cache_ttl);
        let expires_at = now + ttl;
        let entry = CachedEntry {
            credential,
            expires_at,
            last_access: now,
        };
        let mut guard = self.inner.lock().expect("credential cache mutex poisoned");
        // Evict LRU entries if we'd overflow on insertion.
        while guard.entries.len() >= self.config.max_entries {
            // BTreeMap ordering doesn't reflect access recency, so
            // walk and find the actual LRU.
            let lru_key = guard
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| k.clone());
            if let Some(k) = lru_key {
                guard.entries.remove(&k);
                metrics::counter!("mcpg_credential_cache_evictions_total").increment(1);
            } else {
                break;
            }
        }
        guard.entries.insert(key, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use mcpg_plugin_protocol::credential::identity_hash;
    use mcpg_plugin_protocol::manifest::{PluginClass, PluginManifest};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct StubIssuer {
        manifest: PluginManifest,
        issue_count: AtomicUsize,
        ttl_seconds: u64,
    }

    impl StubIssuer {
        fn new(id: &str, ttl_seconds: u64) -> Self {
            Self {
                manifest: PluginManifest {
                    id: id.into(),
                    version: "0.0.1".into(),
                    name: "stub".into(),
                    plugin_class: PluginClass::CredentialIssuer,
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
                },
                issue_count: AtomicUsize::new(0),
                ttl_seconds,
            }
        }
    }

    #[async_trait]
    impl CredentialIssuer for StubIssuer {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn issue(
            &self,
            _: &PluginIdentity,
            target: &str,
            _: &serde_json::Value,
        ) -> Result<IssuedCredential, CredentialError> {
            self.issue_count.fetch_add(1, Ordering::SeqCst);
            Ok(IssuedCredential::from_value(
                format!("token-for-{target}"),
                self.ttl_seconds,
            ))
        }
    }

    fn identity(subject: &str) -> PluginIdentity {
        PluginIdentity {
            kind: "verified".into(),
            trust_level: "verified".into(),
            subject_id: Some(subject.into()),
            auth_provider: None,
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn cache_miss_then_hit_reuses_credential() {
        let cache = CredentialCache::default();
        let issuer: Arc<dyn CredentialIssuer> = Arc::new(StubIssuer::new("p1", 60));
        let id = identity("alice");
        let cfg = serde_json::json!({});

        let a = cache
            .get_or_issue(&issuer, &id, "tgt-1", &cfg)
            .await
            .unwrap();
        let b = cache
            .get_or_issue(&issuer, &id, "tgt-1", &cfg)
            .await
            .unwrap();
        assert_eq!(a.value, b.value);
        // Single cache entry — the second call hit the cache, didn't
        // re-issue.
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn different_targets_are_separate_entries() {
        let cache = CredentialCache::default();
        let issuer: Arc<dyn CredentialIssuer> = Arc::new(StubIssuer::new("p1", 60));
        let id = identity("alice");
        let cfg = serde_json::json!({});

        cache
            .get_or_issue(&issuer, &id, "tgt-1", &cfg)
            .await
            .unwrap();
        cache
            .get_or_issue(&issuer, &id, "tgt-2", &cfg)
            .await
            .unwrap();
        assert_eq!(cache.len(), 2);
    }

    #[tokio::test]
    async fn different_identities_are_separate_entries() {
        let cache = CredentialCache::default();
        let issuer: Arc<dyn CredentialIssuer> = Arc::new(StubIssuer::new("p1", 60));
        let cfg = serde_json::json!({});

        cache
            .get_or_issue(&issuer, &identity("alice"), "tgt", &cfg)
            .await
            .unwrap();
        cache
            .get_or_issue(&issuer, &identity("bob"), "tgt", &cfg)
            .await
            .unwrap();
        assert_eq!(cache.len(), 2);
    }

    #[tokio::test]
    async fn expired_entry_evicted_on_lookup() {
        let cache = CredentialCache::new(CredentialCacheConfig {
            max_entries: 100,
            // Cap force-shrinks plugin_ttl to ~1ms for the test.
            max_cache_ttl: Duration::from_millis(1),
            key_attributes: Vec::new(),
        });
        let issuer: Arc<dyn CredentialIssuer> = Arc::new(StubIssuer::new("p1", 60));
        let id = identity("alice");
        let cfg = serde_json::json!({});

        cache.get_or_issue(&issuer, &id, "tgt", &cfg).await.unwrap();
        assert_eq!(cache.len(), 1);
        // Wait past TTL.
        tokio::time::sleep(Duration::from_millis(5)).await;
        cache.get_or_issue(&issuer, &id, "tgt", &cfg).await.unwrap();
        // Re-issued — but cache still holds the new entry.
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn invalidate_removes_specific_entry() {
        let cache = CredentialCache::default();
        let issuer: Arc<dyn CredentialIssuer> = Arc::new(StubIssuer::new("p1", 60));
        let id = identity("alice");
        let cfg = serde_json::json!({});

        cache
            .get_or_issue(&issuer, &id, "tgt-1", &cfg)
            .await
            .unwrap();
        cache
            .get_or_issue(&issuer, &id, "tgt-2", &cfg)
            .await
            .unwrap();
        cache.invalidate(&id, "p1", "tgt-1");
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn invalidate_plugin_removes_all_plugin_entries() {
        let cache = CredentialCache::default();
        let p1: Arc<dyn CredentialIssuer> = Arc::new(StubIssuer::new("p1", 60));
        let p2: Arc<dyn CredentialIssuer> = Arc::new(StubIssuer::new("p2", 60));
        let id = identity("alice");
        let cfg = serde_json::json!({});

        cache.get_or_issue(&p1, &id, "tgt", &cfg).await.unwrap();
        cache.get_or_issue(&p2, &id, "tgt", &cfg).await.unwrap();
        let evicted = cache.invalidate_plugin("p1");
        assert_eq!(evicted.len(), 1);
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn insert_by_hash_populates_and_lookups_by_hash_invalidates() {
        let cache = CredentialCache::default();
        let id = identity("alice");
        let cred = IssuedCredential::from_value("token", 60);

        cache.insert_by_hash(identity_hash(&id), "p1".into(), "tgt".into(), cred.clone());
        assert_eq!(cache.len(), 1);
        let got = cache.try_get(&id, "p1", "tgt");
        assert_eq!(got.unwrap().value, cred.value);
        cache.invalidate_by_hash(&identity_hash(&id), "p1", "tgt");
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test]
    async fn on_revoked_fires_for_invalidate() {
        use std::sync::atomic::AtomicUsize;
        let cache = CredentialCache::default();
        let issuer: Arc<dyn CredentialIssuer> = Arc::new(StubIssuer::new("p1", 60));
        let id = identity("alice");
        let cfg = serde_json::json!({});
        let calls = Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
        let calls_clone = Arc::clone(&calls);
        let _sub = cache.on_revoked(Arc::new(move |plugin_id, target| {
            calls_clone
                .lock()
                .unwrap()
                .push((plugin_id.to_owned(), target.to_owned()));
        }));

        cache
            .get_or_issue(&issuer, &id, "tgt-1", &cfg)
            .await
            .unwrap();
        cache.invalidate(&id, "p1", "tgt-1");

        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded, vec![("p1".to_owned(), "tgt-1".to_owned())]);
        // unused suppression
        let _ = AtomicUsize::new(0);
    }

    #[tokio::test]
    async fn on_revoked_fires_for_invalidate_plugin_per_target() {
        let cache = CredentialCache::default();
        let issuer: Arc<dyn CredentialIssuer> = Arc::new(StubIssuer::new("p1", 60));
        let id = identity("alice");
        let cfg = serde_json::json!({});
        let calls = Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
        let calls_clone = Arc::clone(&calls);
        let _sub = cache.on_revoked(Arc::new(move |plugin_id, target| {
            calls_clone
                .lock()
                .unwrap()
                .push((plugin_id.to_owned(), target.to_owned()));
        }));

        cache
            .get_or_issue(&issuer, &id, "tgt-a", &cfg)
            .await
            .unwrap();
        cache
            .get_or_issue(&issuer, &id, "tgt-b", &cfg)
            .await
            .unwrap();
        cache.invalidate_plugin("p1");

        let recorded = calls.lock().unwrap().clone();
        let mut targets: Vec<String> = recorded.iter().map(|(_, t)| t.clone()).collect();
        targets.sort();
        assert_eq!(targets, vec!["tgt-a".to_owned(), "tgt-b".to_owned()]);
    }

    #[tokio::test]
    async fn on_revoked_unsubscribes_on_drop() {
        let cache = CredentialCache::default();
        let issuer: Arc<dyn CredentialIssuer> = Arc::new(StubIssuer::new("p1", 60));
        let id = identity("alice");
        let cfg = serde_json::json!({});
        let calls = Arc::new(std::sync::Mutex::new(0usize));
        let calls_clone = Arc::clone(&calls);
        {
            let _sub = cache.on_revoked(Arc::new(move |_, _| {
                *calls_clone.lock().unwrap() += 1;
            }));
            cache.get_or_issue(&issuer, &id, "tgt", &cfg).await.unwrap();
            cache.invalidate(&id, "p1", "tgt");
        } // _sub drops here

        cache.get_or_issue(&issuer, &id, "tgt", &cfg).await.unwrap();
        cache.invalidate(&id, "p1", "tgt");
        assert_eq!(
            *calls.lock().unwrap(),
            1,
            "post-drop invalidate must not fire callback"
        );
    }

    /// Regression: unsubscribe must not race a concurrent revocation
    /// fire. The FFI plugin frees its callback context right after
    /// `host_unsubscribe` returns; if a fire is still in flight at that point
    /// it dereferences freed memory (UAF). The fix fires callbacks while
    /// holding the cache lock, so `RevocationSubscription::drop` (which needs
    /// that lock) cannot return until the in-flight callback completes.
    ///
    /// This test proves the ordering guarantee: while a callback is executing,
    /// dropping the subscription from another thread BLOCKS until the callback
    /// returns. Before the fix (snapshot + fire outside the lock) the drop
    /// returned immediately.
    #[test]
    fn unsubscribe_blocks_until_in_flight_revocation_callback_completes() {
        use std::sync::Condvar;
        use std::time::{Duration, Instant};

        let cache = CredentialCache::default();
        let entered = Arc::new((std::sync::Mutex::new(false), Condvar::new()));
        let release = Arc::new((std::sync::Mutex::new(false), Condvar::new()));
        let entered_cb = Arc::clone(&entered);
        let release_cb = Arc::clone(&release);

        let sub = cache.on_revoked(Arc::new(move |_pid: &str, _tgt: &str| {
            // Signal we're inside the callback (cache lock is held here).
            {
                let (m, c) = &*entered_cb;
                *m.lock().unwrap() = true;
                c.notify_all();
            }
            // Block until the test releases us.
            let (m, c) = &*release_cb;
            let mut g = m.lock().unwrap();
            while !*g {
                g = c.wait(g).unwrap();
            }
        }));

        // Fire the callback from another thread (holds the cache lock for the
        // duration of the callback).
        let cache2 = cache.clone();
        let fire = std::thread::spawn(move || {
            cache2.invalidate(&identity("alice"), "p1", "tgt");
        });

        // Wait until the callback is executing.
        {
            let (m, c) = &*entered;
            let mut g = m.lock().unwrap();
            while !*g {
                g = c.wait(g).unwrap();
            }
        }

        // Drop the subscription on a separate thread; it must block on the
        // cache lock held by the in-flight callback.
        let dropper = std::thread::spawn(move || {
            let start = Instant::now();
            drop(sub);
            start.elapsed()
        });

        // The dropper should still be blocked after this nap.
        std::thread::sleep(Duration::from_millis(150));
        // Release the callback → invalidate returns → lock frees → drop proceeds.
        {
            let (m, c) = &*release;
            *m.lock().unwrap() = true;
            c.notify_all();
        }

        let waited = dropper.join().unwrap();
        fire.join().unwrap();
        assert!(
            waited >= Duration::from_millis(100),
            "unsubscribe must block until the in-flight callback completes; waited {waited:?}"
        );
    }

    #[tokio::test]
    async fn on_revoked_fires_for_invalidate_by_hash() {
        let cache = CredentialCache::default();
        let id = identity("alice");
        let cred = IssuedCredential::from_value("token", 60);
        let calls = Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
        let calls_clone = Arc::clone(&calls);
        let _sub = cache.on_revoked(Arc::new(move |plugin_id, target| {
            calls_clone
                .lock()
                .unwrap()
                .push((plugin_id.to_owned(), target.to_owned()));
        }));

        cache.insert_by_hash(identity_hash(&id), "p1".into(), "tgt".into(), cred);
        cache.invalidate_by_hash(&identity_hash(&id), "p1", "tgt");

        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded, vec![("p1".to_owned(), "tgt".to_owned())]);
    }

    #[tokio::test]
    async fn lru_eviction_when_over_capacity() {
        let cache = CredentialCache::new(CredentialCacheConfig {
            max_entries: 2,
            max_cache_ttl: Duration::from_secs(60),
            key_attributes: Vec::new(),
        });
        let issuer: Arc<dyn CredentialIssuer> = Arc::new(StubIssuer::new("p1", 60));
        let cfg = serde_json::json!({});

        cache
            .get_or_issue(&issuer, &identity("a"), "t", &cfg)
            .await
            .unwrap();
        // Sleep to advance access times so LRU ordering is
        // deterministic.
        tokio::time::sleep(Duration::from_millis(2)).await;
        cache
            .get_or_issue(&issuer, &identity("b"), "t", &cfg)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
        cache
            .get_or_issue(&issuer, &identity("c"), "t", &cfg)
            .await
            .unwrap();
        // First entry (alice) was LRU, should be evicted.
        assert_eq!(cache.len(), 2);
    }
}
