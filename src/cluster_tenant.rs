//! Optional per-deployment tenant segment on cluster capability
//! KV keys + bus topics, so a single coordinator namespace can be fenced
//! per-tenant by broker-native ACLs (NATS subject perms, redis
//! key-pattern ACLs, consul/etcd path ACLs).
//!
//! These decorators wrap an `Arc<dyn KeyValueStore>` / `Arc<dyn PubSub>`
//! and prefix the KEY / TOPIC (not the value) with a stable head:
//! - KV:    `t.<segment>/<original-key>`   (slash-delimited head)
//! - topic: `t.<segment>.<original-topic>` (dot-delimited head — a NATS
//!   subject token, so `t.<segment>.>` subject perms fence it)
//!
//! Applied at the same boot/reload chokepoints as the encryption
//! decorators, but **outermost** (`wrap_tenant_kv(wrap_state_kv(kv,…),…)`)
//! so the cipher's AAD binds the FULL tenant-prefixed key/topic —
//! a value sealed in tenant `acme`'s `session:s1` cannot be opened (even
//! by a coordinator operator who bypasses ACLs) after being moved to
//! tenant `bob`'s slot (cross-tenant swap-resistance, for free).
//!
//! ## Scope (honest)
//! This is a **deployment-level** label — one tenant segment per gateway
//! process, matching mcpg's interim "one coordinator namespace == one
//! trust domain" model, now made ACL-segmentable. It is NOT per-request
//! multi-tenancy: the runtime carries no per-request tenant at
//! key/topic-formation time, so per-request segmentation remains future
//! work. Unset = today's flat, un-prefixed keys/topics.
//!
//! Turning the segment on is a key-namespace cutover (old flat keys
//! become invisible) — same class as changing a coordinator `key_prefix`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use mcpg_cluster_api::{ClusterError, Entry, KeyValueStore, Message, PubSub, Subscription};

// ---------------------------------------------------------------------------
// KeyValueStore decorator
// ---------------------------------------------------------------------------

/// Prefixes every KV key with `t.<segment>/`. Transparent to callers and
/// to each store's hardcoded key/scan literals (`session:`, `task:`, …):
/// the prefix is applied at the KV-Arc boundary, so point reads, writes,
/// and `list_prefix` scans all stay within the tenant by construction.
/// `list_prefix` strips the head back off returned keys so callers see
/// the original key shape (the subscription store + boot-hydrate parse it).
#[derive(Debug)]
pub struct TenantPrefixKeyValueStore {
    inner: Arc<dyn KeyValueStore>,
    prefix: String,
}

impl TenantPrefixKeyValueStore {
    pub fn new(inner: Arc<dyn KeyValueStore>, segment: &str) -> Self {
        Self {
            inner,
            prefix: format!("t.{segment}/"),
        }
    }
    fn full(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }
    fn strip(&self, key: String) -> String {
        key.strip_prefix(&self.prefix)
            .map(str::to_owned)
            .unwrap_or(key)
    }
}

#[async_trait]
impl KeyValueStore for TenantPrefixKeyValueStore {
    async fn get(&self, key: &str) -> Result<Option<Entry>, ClusterError> {
        self.inner.get(&self.full(key)).await
    }
    async fn put(
        &self,
        key: &str,
        value: Bytes,
        ttl: Option<Duration>,
    ) -> Result<(), ClusterError> {
        self.inner.put(&self.full(key), value, ttl).await
    }
    async fn put_if_absent(
        &self,
        key: &str,
        value: Bytes,
        ttl: Option<Duration>,
    ) -> Result<bool, ClusterError> {
        self.inner.put_if_absent(&self.full(key), value, ttl).await
    }
    async fn delete(&self, key: &str) -> Result<bool, ClusterError> {
        self.inner.delete(&self.full(key)).await
    }
    async fn list_prefix(
        &self,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<(String, Entry)>, ClusterError> {
        let raw = self.inner.list_prefix(&self.full(prefix), limit).await?;
        Ok(raw.into_iter().map(|(k, e)| (self.strip(k), e)).collect())
    }
    async fn expire(&self, key: &str, ttl: Option<Duration>) -> Result<bool, ClusterError> {
        self.inner.expire(&self.full(key), ttl).await
    }
}

// ---------------------------------------------------------------------------
// PubSub decorator
// ---------------------------------------------------------------------------

/// Prefixes every topic with `t.<segment>.`; strips it back off delivered
/// `Message.topic` so consumers see the original topic. Payload untouched.
#[derive(Debug)]
pub struct TenantPrefixPubSub {
    inner: Arc<dyn PubSub>,
    prefix: String,
}

impl TenantPrefixPubSub {
    pub fn new(inner: Arc<dyn PubSub>, segment: &str) -> Self {
        Self {
            inner,
            prefix: format!("t.{segment}."),
        }
    }
    fn full(&self, topic: &str) -> String {
        format!("{}{topic}", self.prefix)
    }
}

#[async_trait]
impl PubSub for TenantPrefixPubSub {
    async fn publish(&self, topic: &str, payload: Bytes) -> Result<(), ClusterError> {
        self.inner.publish(&self.full(topic), payload).await
    }
    async fn subscribe(
        &self,
        pattern: &str,
        queue_group: Option<&str>,
    ) -> Result<Subscription, ClusterError> {
        let prefix = self.prefix.clone();
        let inner = self
            .inner
            .subscribe(&self.full(pattern), queue_group)
            .await?;
        Ok(inner
            .map(move |item| {
                item.map(|mut m: Message| {
                    if let Some(stripped) = m.topic.strip_prefix(&prefix) {
                        m.topic = stripped.to_owned();
                    }
                    m
                })
            })
            .boxed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct MemKv {
        map: Mutex<HashMap<String, Bytes>>,
    }
    #[async_trait]
    impl KeyValueStore for MemKv {
        async fn get(&self, key: &str) -> Result<Option<Entry>, ClusterError> {
            Ok(self.map.lock().unwrap().get(key).map(|b| Entry {
                bytes: b.clone(),
                expires_at: None,
            }))
        }
        async fn put(&self, key: &str, v: Bytes, _t: Option<Duration>) -> Result<(), ClusterError> {
            self.map.lock().unwrap().insert(key.to_owned(), v);
            Ok(())
        }
        async fn put_if_absent(
            &self,
            key: &str,
            v: Bytes,
            _t: Option<Duration>,
        ) -> Result<bool, ClusterError> {
            let mut m = self.map.lock().unwrap();
            if m.contains_key(key) {
                Ok(false)
            } else {
                m.insert(key.to_owned(), v);
                Ok(true)
            }
        }
        async fn delete(&self, key: &str) -> Result<bool, ClusterError> {
            Ok(self.map.lock().unwrap().remove(key).is_some())
        }
        async fn list_prefix(
            &self,
            prefix: &str,
            limit: usize,
        ) -> Result<Vec<(String, Entry)>, ClusterError> {
            Ok(self
                .map
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .take(limit)
                .map(|(k, v)| {
                    (
                        k.clone(),
                        Entry {
                            bytes: v.clone(),
                            expires_at: None,
                        },
                    )
                })
                .collect())
        }
        async fn expire(&self, _k: &str, _t: Option<Duration>) -> Result<bool, ClusterError> {
            Ok(true)
        }
    }

    #[derive(Debug, Default)]
    struct MemBus {
        subs: Mutex<HashMap<String, Vec<futures::channel::mpsc::UnboundedSender<Message>>>>,
    }
    #[async_trait]
    impl PubSub for MemBus {
        async fn publish(&self, topic: &str, payload: Bytes) -> Result<(), ClusterError> {
            if let Some(v) = self.subs.lock().unwrap().get(topic) {
                for tx in v {
                    let _ = tx.unbounded_send(Message {
                        topic: topic.to_owned(),
                        payload: payload.clone(),
                    });
                }
            }
            Ok(())
        }
        async fn subscribe(
            &self,
            pattern: &str,
            _qg: Option<&str>,
        ) -> Result<Subscription, ClusterError> {
            let (tx, rx) = futures::channel::mpsc::unbounded::<Message>();
            self.subs
                .lock()
                .unwrap()
                .entry(pattern.to_owned())
                .or_default()
                .push(tx);
            Ok(rx.map(Ok).boxed())
        }
    }

    #[tokio::test]
    async fn kv_prefixes_inner_and_round_trips() {
        let inner = Arc::new(MemKv::default());
        let kv = TenantPrefixKeyValueStore::new(inner.clone(), "acme");
        kv.put("session:s1", Bytes::from_static(b"v"), None)
            .await
            .unwrap();
        // Caller sees the original key.
        assert_eq!(
            kv.get("session:s1").await.unwrap().unwrap().bytes.as_ref(),
            b"v"
        );
        // Inner store holds the tenant-prefixed key.
        assert!(inner.get("t.acme/session:s1").await.unwrap().is_some());
        assert!(inner.get("session:s1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_prefix_stays_in_tenant_and_strips_head() {
        let inner = Arc::new(MemKv::default());
        let kv = TenantPrefixKeyValueStore::new(inner.clone(), "acme");
        kv.put("session:a", Bytes::from_static(b"1"), None)
            .await
            .unwrap();
        kv.put("session:b", Bytes::from_static(b"2"), None)
            .await
            .unwrap();
        // A foreign tenant's key sitting in the same coordinator namespace.
        inner
            .put("t.other/session:c", Bytes::from_static(b"x"), None)
            .await
            .unwrap();
        let mut keys: Vec<String> = kv
            .list_prefix("session:", 10)
            .await
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        keys.sort();
        // Only this tenant's entries, with the head stripped back off.
        assert_eq!(keys, vec!["session:a".to_owned(), "session:b".to_owned()]);
    }

    #[tokio::test]
    async fn bus_prefixes_topic_and_strips_on_delivery() {
        let inner = Arc::new(MemBus::default());
        let bus = TenantPrefixPubSub::new(inner.clone(), "acme");
        let mut rx = bus.subscribe("mcpg.cancel", None).await.unwrap();
        // Inner subscription registered under the prefixed topic.
        inner
            .publish("t.acme.mcpg.cancel", Bytes::from_static(b"evt"))
            .await
            .unwrap();
        let msg = tokio::time::timeout(Duration::from_secs(1), rx.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        // Consumer sees the ORIGINAL topic + payload.
        assert_eq!(msg.topic, "mcpg.cancel");
        assert_eq!(msg.payload.as_ref(), b"evt");
    }

    #[tokio::test]
    async fn cross_tenant_swap_rejected_when_stacked_with_w12() {
        // Tenant OUTER, cipher INNER: the cipher's AAD binds the full
        // `t.<seg>/key`, so a value sealed for acme cannot be opened as bob
        // even after a coordinator operator moves the bytes between slots.
        use crate::cluster_encryption::EncryptingKeyValueStore;
        use crate::credential_cache_cipher::EventCipher;
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(11);
        }
        let cipher = Arc::new(EventCipher::from_raw_key(&k, "k1".into()).unwrap());
        let raw = Arc::new(MemKv::default());

        // acme = tenant(acme) over cipher over raw.
        let acme: Arc<dyn KeyValueStore> = Arc::new(TenantPrefixKeyValueStore::new(
            Arc::new(EncryptingKeyValueStore::new(raw.clone(), cipher.clone())),
            "acme",
        ));
        acme.put("session:s1", Bytes::from_static(b"secret"), None)
            .await
            .unwrap();
        assert_eq!(
            acme.get("session:s1")
                .await
                .unwrap()
                .unwrap()
                .bytes
                .as_ref(),
            b"secret"
        );

        // Operator copies acme's sealed bytes into bob's slot in the raw store.
        let sealed = raw.get("t.acme/session:s1").await.unwrap().unwrap().bytes;
        raw.put("t.bob/session:s1", sealed, None).await.unwrap();

        // bob (same cipher key) must NOT be able to open it — AAD mismatch.
        let bob: Arc<dyn KeyValueStore> = Arc::new(TenantPrefixKeyValueStore::new(
            Arc::new(EncryptingKeyValueStore::new(raw.clone(), cipher.clone())),
            "bob",
        ));
        assert!(bob.get("session:s1").await.is_err());
    }
}
