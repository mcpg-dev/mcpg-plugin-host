//! Opt-in application-layer AEAD envelope encryption for the
//! cluster *capability* state (sessions, delivery, cancellation, tasks,
//! pipelines, idempotency, request-state, subscriptions, quota, + the
//! approvals backstop).
//!
//! These decorators wrap an `Arc<dyn KeyValueStore>` / `Arc<dyn PubSub>`
//! resolved from the coordinator and transparently seal every VALUE (KV)
//! or PAYLOAD (bus) with [`EventCipher`] — the same XChaCha20-Poly1305
//! envelope the credential cache uses — while leaving KEYS and TOPICS in
//! cleartext (they drive routing, `list_prefix`, and wildcard matching).
//!
//! The KV key / bus topic is bound into the AEAD as **associated data**,
//! so a value sealed for key `A` cannot be replayed into key `B` even
//! under the same cluster key (swap-resistance).
//!
//! Opt-in: only inserted when `cluster.state_encryption_key_env` is set.
//! When absent, capability state stays plaintext serde (today's
//! behaviour; confidentiality then rests on the transport guard).
//! The credential cache is NOT wrapped here — it has its own cipher.
//!
//! ## Plaintext posture (fail-closed by default)
//! Once a key is configured, a keyed reader fails closed on a NON-envelope
//! value: an unencrypted, unauthenticated write (a forged session blob,
//! idempotency record, approval-backstop entry, …) is rejected, not served.
//! `get`/`put_if_absent` follow-up reads return an error; `list_prefix` /
//! bus delivery count + drop the single bad entry. A value that **is** an
//! envelope but fails to open (wrong key / tamper / AAD mismatch) is
//! likewise rejected.
//!
//! For a bounded migration window where unkeyed peers may still be writing
//! plaintext, the operator can opt into tolerating (passing through)
//! plaintext reads via `cluster.state_encryption_allow_plaintext_reads`.
//! That mode warns once and is intended to be turned off once every replica
//! is keyed.
//!
//! ## Out of scope (v1)
//! The cluster `Watch` primitive is not wrapped — no in-scope capability
//! consumes coordinator `watch()` values today (the MCP resource-watch
//! engine uses the protocol-level `WatchEvent`, a different type). If a
//! Watch-value consumer is added, an `EncryptingWatch` decorator following
//! this same pattern is the natural extension.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use mcpg_cluster_api::{ClusterError, Entry, KeyValueStore, Message, PubSub, Subscription};

use crate::credential_cache_cipher::{DecryptError, EventCipher};

/// Map a seal failure (essentially impossible for valid input) to a
/// cluster error so callers see it rather than silently writing plaintext.
fn seal_or_err(cipher: &EventCipher, plaintext: &[u8], aad: &[u8]) -> Result<Bytes, ClusterError> {
    cipher
        .seal(plaintext, aad)
        .map(Bytes::from)
        .map_err(|e| ClusterError::Internal {
            reason: format!("cluster state-encryption: seal failed: {e}"),
        })
}

// ---------------------------------------------------------------------------
// KeyValueStore decorator
// ---------------------------------------------------------------------------

/// Value-encrypting wrapper over any [`KeyValueStore`]. Seals values on
/// write (AAD = the KV key), opens them on read; keys, TTLs, and the
/// `delete`/`expire` ops pass through untouched.
#[derive(Debug)]
pub struct EncryptingKeyValueStore {
    inner: Arc<dyn KeyValueStore>,
    cipher: Arc<EventCipher>,
    /// When true, a plaintext (non-envelope) value is passed through
    /// rather than rejected — a bounded, operator-acknowledged migration
    /// window. Default false (fail closed).
    allow_plaintext: bool,
    /// Warn at most once when a tolerated plaintext value is read.
    plaintext_warned: AtomicBool,
}

impl EncryptingKeyValueStore {
    pub fn new(inner: Arc<dyn KeyValueStore>, cipher: Arc<EventCipher>) -> Self {
        Self {
            inner,
            cipher,
            allow_plaintext: false,
            plaintext_warned: AtomicBool::new(false),
        }
    }

    /// Opt into tolerating plaintext (non-envelope) reads for a bounded
    /// migration window. Off by default — fail closed.
    pub fn allow_plaintext_reads(mut self, allow: bool) -> Self {
        self.allow_plaintext = allow;
        self
    }

    /// Open a stored value under `key` AAD. `Ok(None)` is returned only
    /// when the value is plaintext (not an envelope) AND plaintext reads
    /// are tolerated — the caller passes the raw bytes through. Otherwise
    /// `Err`: a plaintext value under a configured key is rejected
    /// (fail closed), as is an envelope that fails to open (corruption /
    /// wrong key / AAD mismatch).
    fn open_value(&self, key: &str, raw: &Bytes) -> Result<Option<Vec<u8>>, ClusterError> {
        match self.cipher.open(raw, key.as_bytes()) {
            Ok(pt) => Ok(Some(pt)),
            Err(DecryptError::NotEnvelope) => {
                if self.allow_plaintext {
                    if !self.plaintext_warned.swap(true, Ordering::Relaxed) {
                        tracing::warn!(
                            "cluster state-encryption: read a plaintext (non-envelope) value — \
                             tolerating it under state_encryption_allow_plaintext_reads (migration \
                             window); turn this off once every replica is keyed"
                        );
                    }
                    return Ok(None);
                }
                metrics::counter!(
                    "mcpg_cluster_state_decrypt_failures_total",
                    "surface" => "kv",
                    "reason" => "plaintext_rejected",
                )
                .increment(1);
                Err(ClusterError::Internal {
                    reason:
                        "cluster state-encryption: refusing a plaintext (non-envelope) value under \
                         a configured key — fail closed (set state_encryption_allow_plaintext_reads \
                         only for a bounded migration window)"
                            .to_owned(),
                })
            }
            Err(e) => {
                metrics::counter!(
                    "mcpg_cluster_state_decrypt_failures_total",
                    "surface" => "kv",
                    "reason" => "open_failed",
                )
                .increment(1);
                Err(ClusterError::Internal {
                    reason: format!(
                        "cluster state-encryption: failed to open value for a key (corruption, \
                         wrong key, or AAD mismatch): {e}"
                    ),
                })
            }
        }
    }
}

#[async_trait]
impl KeyValueStore for EncryptingKeyValueStore {
    async fn get(&self, key: &str) -> Result<Option<Entry>, ClusterError> {
        let Some(entry) = self.inner.get(key).await? else {
            return Ok(None);
        };
        let expires_at = entry.expires_at;
        match self.open_value(key, &entry.bytes)? {
            Some(pt) => Ok(Some(Entry {
                bytes: Bytes::from(pt),
                expires_at,
            })),
            None => Ok(Some(entry)), // plaintext passthrough (rollout)
        }
    }

    async fn put(
        &self,
        key: &str,
        value: Bytes,
        ttl: Option<Duration>,
    ) -> Result<(), ClusterError> {
        let sealed = seal_or_err(&self.cipher, &value, key.as_bytes())?;
        self.inner.put(key, sealed, ttl).await
    }

    async fn put_if_absent(
        &self,
        key: &str,
        value: Bytes,
        ttl: Option<Duration>,
    ) -> Result<bool, ClusterError> {
        // Atomicity is on key presence, not value content — sealing the
        // value (fresh nonce per call) is transparent to the single-winner
        // contract. The loser reads the winner's sealed record via `get`
        // and opens it (same key AAD, same cluster key).
        let sealed = seal_or_err(&self.cipher, &value, key.as_bytes())?;
        self.inner.put_if_absent(key, sealed, ttl).await
    }

    async fn delete(&self, key: &str) -> Result<bool, ClusterError> {
        self.inner.delete(key).await
    }

    async fn list_prefix(
        &self,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<(String, Entry)>, ClusterError> {
        let raw = self.inner.list_prefix(prefix, limit).await?;
        let mut out = Vec::with_capacity(raw.len());
        for (key, entry) in raw {
            let expires_at = entry.expires_at;
            // Each entry is sealed under its OWN key as AAD.
            match self.open_value(&key, &entry.bytes) {
                Ok(Some(pt)) => out.push((
                    key,
                    Entry {
                        bytes: Bytes::from(pt),
                        expires_at,
                    },
                )),
                Ok(None) => out.push((key, entry)), // tolerated plaintext passthrough
                // A rejected (fail-closed plaintext or corrupt) entry must not
                // poison the whole list: open_value already logged + counted;
                // drop just this one.
                Err(_) => continue,
            }
        }
        Ok(out)
    }

    async fn expire(&self, key: &str, ttl: Option<Duration>) -> Result<bool, ClusterError> {
        self.inner.expire(key, ttl).await
    }
}

// ---------------------------------------------------------------------------
// PubSub decorator
// ---------------------------------------------------------------------------

/// Payload-encrypting wrapper over any [`PubSub`]. Seals the payload on
/// publish (AAD = topic), opens each delivered message (AAD = the
/// message's concrete topic, so wildcard subscriptions still
/// authenticate). Topics stay cleartext for routing.
#[derive(Debug)]
pub struct EncryptingPubSub {
    inner: Arc<dyn PubSub>,
    cipher: Arc<EventCipher>,
    /// When true, a plaintext (non-envelope) payload is delivered rather
    /// than dropped — a bounded migration window. Default false.
    allow_plaintext: bool,
}

impl EncryptingPubSub {
    pub fn new(inner: Arc<dyn PubSub>, cipher: Arc<EventCipher>) -> Self {
        Self {
            inner,
            cipher,
            allow_plaintext: false,
        }
    }

    /// Opt into tolerating plaintext (non-envelope) payloads for a bounded
    /// migration window. Off by default — fail closed (drop + count).
    pub fn allow_plaintext_reads(mut self, allow: bool) -> Self {
        self.allow_plaintext = allow;
        self
    }
}

#[async_trait]
impl PubSub for EncryptingPubSub {
    async fn publish(&self, topic: &str, payload: Bytes) -> Result<(), ClusterError> {
        let sealed = seal_or_err(&self.cipher, &payload, topic.as_bytes())?;
        self.inner.publish(topic, sealed).await
    }

    async fn subscribe(
        &self,
        pattern: &str,
        queue_group: Option<&str>,
    ) -> Result<Subscription, ClusterError> {
        let cipher = Arc::clone(&self.cipher);
        let allow_plaintext = self.allow_plaintext;
        let inner = self.inner.subscribe(pattern, queue_group).await?;
        let decrypted = inner.filter_map(move |item| {
            let cipher = Arc::clone(&cipher);
            async move {
                match item {
                    Ok(Message { topic, payload }) => match cipher.open(&payload, topic.as_bytes())
                    {
                        Ok(pt) => Some(Ok(Message {
                            topic,
                            payload: Bytes::from(pt),
                        })),
                        // Plaintext payload under a configured key. Deliver only
                        // when the operator opted into the migration window;
                        // otherwise fail closed — drop + count.
                        Err(DecryptError::NotEnvelope) => {
                            if allow_plaintext {
                                Some(Ok(Message { topic, payload }))
                            } else {
                                metrics::counter!(
                                    "mcpg_cluster_state_decrypt_failures_total",
                                    "surface" => "bus",
                                    "reason" => "plaintext_rejected",
                                )
                                .increment(1);
                                tracing::error!(
                                    topic = %topic,
                                    "cluster state-encryption: dropping a plaintext (non-envelope) \
                                     bus message under a configured key — fail closed"
                                );
                                None
                            }
                        }
                        // Corruption / wrong key / AAD mismatch: drop this one
                        // message (don't kill the subscription) + surface it.
                        Err(e) => {
                            metrics::counter!(
                                "mcpg_cluster_state_decrypt_failures_total",
                                "surface" => "bus",
                                "reason" => "open_failed",
                            )
                            .increment(1);
                            tracing::error!(
                                error = %e,
                                topic = %topic,
                                "cluster state-encryption: dropping a bus message that failed to \
                                 decrypt"
                            );
                            None
                        }
                    },
                    Err(e) => Some(Err(e)),
                }
            }
        });
        Ok(decrypted.boxed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // Minimal in-memory KV/PubSub so the decorators can be tested inside
    // plugin-host without depending on the gateway's builtins.
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
        async fn put(
            &self,
            key: &str,
            value: Bytes,
            _ttl: Option<Duration>,
        ) -> Result<(), ClusterError> {
            self.map.lock().unwrap().insert(key.to_owned(), value);
            Ok(())
        }
        async fn put_if_absent(
            &self,
            key: &str,
            value: Bytes,
            _ttl: Option<Duration>,
        ) -> Result<bool, ClusterError> {
            let mut m = self.map.lock().unwrap();
            if m.contains_key(key) {
                Ok(false)
            } else {
                m.insert(key.to_owned(), value);
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
        async fn expire(&self, _key: &str, _ttl: Option<Duration>) -> Result<bool, ClusterError> {
            Ok(true)
        }
    }

    fn cipher(kid: &str) -> Arc<EventCipher> {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(11);
        }
        Arc::new(EventCipher::from_raw_key(&k, kid.into()).unwrap())
    }

    fn cipher_alt() -> Arc<EventCipher> {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(3);
        }
        Arc::new(EventCipher::from_raw_key(&k, "k1".into()).unwrap())
    }

    #[tokio::test]
    async fn kv_roundtrip_and_inner_is_sealed() {
        let inner = Arc::new(MemKv::default());
        let kv = EncryptingKeyValueStore::new(inner.clone(), cipher("k1"));
        kv.put("sess/s1", Bytes::from_static(b"plaintext-blob"), None)
            .await
            .unwrap();
        // The decorator returns the original bytes.
        let got = kv.get("sess/s1").await.unwrap().unwrap();
        assert_eq!(got.bytes.as_ref(), b"plaintext-blob");
        // ...but the INNER store holds an envelope, not the plaintext.
        let raw = inner.get("sess/s1").await.unwrap().unwrap();
        assert!(EventCipher::looks_like_envelope(&raw.bytes));
        assert_ne!(raw.bytes.as_ref(), b"plaintext-blob");
    }

    #[tokio::test]
    async fn kv_wrong_key_fails_closed() {
        let inner = Arc::new(MemKv::default());
        EncryptingKeyValueStore::new(inner.clone(), cipher("k1"))
            .put("k", Bytes::from_static(b"v"), None)
            .await
            .unwrap();
        // A decorator with a DIFFERENT key must not silently return garbage.
        let other = EncryptingKeyValueStore::new(inner.clone(), cipher_alt());
        let err = other.get("k").await.unwrap_err();
        assert!(matches!(err, ClusterError::Internal { .. }));
    }

    #[tokio::test]
    async fn kv_cross_key_swap_rejected() {
        // Move an envelope sealed under key "A" to slot "B"; reading "B"
        // must fail because the AAD (the key) no longer matches.
        let inner = Arc::new(MemKv::default());
        let kv = EncryptingKeyValueStore::new(inner.clone(), cipher("k1"));
        kv.put("A", Bytes::from_static(b"secret"), None)
            .await
            .unwrap();
        let sealed_for_a = inner.get("A").await.unwrap().unwrap().bytes;
        inner.put("B", sealed_for_a, None).await.unwrap();
        let err = kv.get("B").await.unwrap_err();
        assert!(matches!(err, ClusterError::Internal { .. }));
    }

    #[tokio::test]
    async fn kv_plaintext_passthrough_only_in_migration_mode() {
        // An unkeyed peer wrote plaintext. The opt-in migration window
        // tolerates it; the default posture fails closed.
        let inner = Arc::new(MemKv::default());
        inner
            .put("legacy", Bytes::from_static(b"not-an-envelope"), None)
            .await
            .unwrap();

        let tolerant =
            EncryptingKeyValueStore::new(inner.clone(), cipher("k1")).allow_plaintext_reads(true);
        let got = tolerant.get("legacy").await.unwrap().unwrap();
        assert_eq!(got.bytes.as_ref(), b"not-an-envelope");
    }

    #[tokio::test]
    async fn kv_plaintext_rejected_by_default() {
        // A keyed reader must NOT serve unauthenticated plaintext (forged
        // capability state) once a key is configured — fail closed.
        let inner = Arc::new(MemKv::default());
        inner
            .put("legacy", Bytes::from_static(b"not-an-envelope"), None)
            .await
            .unwrap();
        let kv = EncryptingKeyValueStore::new(inner.clone(), cipher("k1"));
        let err = kv.get("legacy").await.unwrap_err();
        assert!(matches!(err, ClusterError::Internal { .. }));
    }

    #[tokio::test]
    async fn kv_list_prefix_drops_plaintext_when_fail_closed() {
        // list_prefix must not surface a fail-closed plaintext entry; it is
        // counted + dropped, the rest of the list is unaffected.
        let inner = Arc::new(MemKv::default());
        let kv = EncryptingKeyValueStore::new(inner.clone(), cipher("k1"));
        kv.put("p/sealed", Bytes::from_static(b"v"), None)
            .await
            .unwrap();
        inner
            .put("p/plain", Bytes::from_static(b"not-an-envelope"), None)
            .await
            .unwrap();
        let got = kv.list_prefix("p/", 10).await.unwrap();
        assert_eq!(got.len(), 1, "plaintext entry must be dropped");
        assert_eq!(got[0].0, "p/sealed");
    }

    #[tokio::test]
    async fn kv_list_prefix_opens_each_under_its_own_key() {
        let inner = Arc::new(MemKv::default());
        let kv = EncryptingKeyValueStore::new(inner.clone(), cipher("k1"));
        kv.put("p/a", Bytes::from_static(b"va"), None)
            .await
            .unwrap();
        kv.put("p/b", Bytes::from_static(b"vb"), None)
            .await
            .unwrap();
        let mut got: Vec<(String, Vec<u8>)> = kv
            .list_prefix("p/", 10)
            .await
            .unwrap()
            .into_iter()
            .map(|(k, e)| (k, e.bytes.to_vec()))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("p/a".to_owned(), b"va".to_vec()),
                ("p/b".to_owned(), b"vb".to_vec()),
            ]
        );
    }

    #[tokio::test]
    async fn kv_put_if_absent_single_winner_preserved() {
        let inner = Arc::new(MemKv::default());
        let kv = EncryptingKeyValueStore::new(inner.clone(), cipher("k1"));
        assert!(
            kv.put_if_absent("claim", Bytes::from_static(b"first"), None)
                .await
                .unwrap()
        );
        assert!(
            !kv.put_if_absent("claim", Bytes::from_static(b"second"), None)
                .await
                .unwrap()
        );
        // Winner's value is readable (decrypts).
        assert_eq!(
            kv.get("claim").await.unwrap().unwrap().bytes.as_ref(),
            b"first"
        );
    }
}
