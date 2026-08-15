//! Application-layer AEAD encryption for the cluster credential
//! cache events.
//!
//! Closes the privacy gap documented in
//! [`crate::credential_cache_clustered`]: cache events carry
//! credential bytes (Vault dynamic-DB usernames + passwords,
//! KMS-issued tokens, etc.) over the cluster topic. Without
//! transport-level TLS on the operator's cluster_backend,
//! peers — and anyone with topic-read access — would see those
//! credentials in the wire.
//!
//! Operators supply a 32-byte symmetric key (URL-safe-base64 in
//! config). Each event gets serialised, encrypted under
//! XChaCha20-Poly1305 with a random nonce, and wrapped in a JSON
//! envelope:
//!
//! ```json
//! { "v": 1, "kid": "my-key", "n": "<base64-nonce>", "c": "<base64-ciphertext-tag>" }
//! ```
//!
//! Receivers decrypt with the same key + apply the inner event.
//! Tampering / wrong-key / version-mismatch all decode-fail and
//! the message is dropped (logged + counted).
//!
//! # Why XChaCha20-Poly1305
//!
//! - 24-byte nonce → random nonces are safe at cluster cache
//!   event volumes (the birthday-bound collision risk is
//!   negligible — operators would need ~2^96 events before
//!   reuse becomes statistically meaningful).
//! - AEAD: integrity + confidentiality in one primitive. A
//!   tampered ciphertext fails decryption with no recovery.
//! - Stream cipher: no padding, no oracle attacks.
//! - RustCrypto pure-Rust implementation: no link-time
//!   dependency on aws-lc-rs / openssl, keeps the host crate's
//!   binary surface small.
//!
//! # Why not just rely on transport TLS?
//!
//! Operator hygiene varies. NATS-JetStream / Consul / etcd all
//! support TLS but not all operators turn it on (especially in
//! private-network deploys where the perception is "the network
//! is the perimeter"). Application-layer encryption is defence
//! in depth — even a misconfigured TLS endpoint can't leak
//! credentials.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload, generic_array::GenericArray},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::credential_cache_clustered::CacheEvent;

const ENVELOPE_VERSION: u8 = 1;
/// XChaCha20-Poly1305 key size (NIST SP 800-38D).
pub const KEY_BYTES: usize = 32;
/// XChaCha20-Poly1305 nonce size — 24 bytes is the "X" extension
/// over plain ChaCha20-Poly1305's 12-byte nonce. Random nonces
/// are safe at this width.
pub const NONCE_BYTES: usize = 24;

#[derive(Debug, thiserror::Error)]
pub enum EventCipherError {
    #[error("event cipher: key must decode to {KEY_BYTES} bytes (got {got})")]
    InvalidKeyLength { got: usize },
    #[error("event cipher: key base64 decode failed: {0}")]
    InvalidKeyBase64(String),
    #[error("event cipher: kid is empty (operators must label keys for rotation safety)")]
    EmptyKid,
    #[error("event cipher: serialise event before encryption: {0}")]
    SerialiseEvent(String),
    #[error("event cipher: encrypt failed (cipher returned error)")]
    EncryptFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    /// Payload didn't parse as the envelope shape; the publisher
    /// likely isn't running with encryption configured. When the
    /// receiver IS configured for encryption this is loud — peer
    /// is misconfigured (or someone is publishing plaintext).
    #[error("event cipher: payload is not an encrypted envelope (likely unencrypted publisher)")]
    NotEnvelope,
    /// Envelope `v` field doesn't match the supported version.
    #[error("event cipher: unsupported envelope version {got} (this build supports {supported})")]
    UnsupportedVersion { got: u8, supported: u8 },
    /// Envelope `kid` doesn't match the receiver's configured kid.
    /// Operators may have rotated keys but missed an instance —
    /// log the mismatch loudly so they notice.
    #[error(
        "event cipher: kid mismatch — peer published with `{published_kid}`, this instance configured for `{configured_kid}`"
    )]
    KidMismatch {
        published_kid: String,
        configured_kid: String,
    },
    #[error("event cipher: envelope nonce/ciphertext base64 decode failed: {0}")]
    InvalidBase64(String),
    #[error("event cipher: nonce must decode to {NONCE_BYTES} bytes (got {got})")]
    InvalidNonceLength { got: usize },
    /// AEAD authentication failed. Either: wrong key (the receiver
    /// has key A, the publisher used key B); or the ciphertext was
    /// tampered with in transit. Indistinguishable.
    #[error("event cipher: decrypt+authenticate failed (wrong key or tampered ciphertext)")]
    AuthFailed,
    #[error("event cipher: inner event JSON decode failed after decrypt: {0}")]
    InvalidPlaintext(String),
}

/// AEAD cipher for cache events. Holds the operator-supplied key
/// plus a `kid` label; both publishes and decryptions use the
/// same instance.
///
/// The key bytes are zeroized on drop to limit memory exposure.
/// XChaCha20-Poly1305 itself derives subkeys per nonce so a
/// single instance is safely reusable for many events.
#[derive(ZeroizeOnDrop)]
pub struct EventCipher {
    cipher: XChaCha20Poly1305,
    /// Operator-defined key identifier. Surfaced in the encrypted
    /// envelope so receivers can detect cross-instance key drift
    /// (rotated key A on instance 1 but instance 2 still on key
    /// B → kid mismatch on first peer event).
    #[zeroize(skip)]
    kid: String,
}

impl std::fmt::Debug for EventCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Elide the cipher key — Debug output lands in logs +
        // panic messages; printing a 32-byte symmetric key there
        // is exactly the leak this module exists to prevent.
        f.debug_struct("EventCipher")
            .field("kid", &self.kid)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl EventCipher {
    /// Build a cipher from a URL-safe-base64-encoded 32-byte key
    /// and an operator-supplied kid label.
    pub fn from_base64_key(key_b64: &str, kid: String) -> Result<Self, EventCipherError> {
        let kid_trimmed = kid.trim();
        if kid_trimmed.is_empty() {
            return Err(EventCipherError::EmptyKid);
        }
        // Accept padded OR unpadded URL-safe base64 — operators
        // pasting from CLI key generators get either form.
        let raw = B64URL
            .decode(key_b64.trim().trim_end_matches('='))
            .map_err(|e| EventCipherError::InvalidKeyBase64(e.to_string()))?;
        if raw.len() != KEY_BYTES {
            return Err(EventCipherError::InvalidKeyLength { got: raw.len() });
        }
        let key = GenericArray::from_slice(&raw);
        let cipher = XChaCha20Poly1305::new(key);
        Ok(Self {
            cipher,
            kid: kid_trimmed.to_owned(),
        })
    }

    /// Build a cipher from raw 32-byte key material. Useful for
    /// tests + cases where the key is already binary (loaded from
    /// a KMS, etc.).
    pub fn from_raw_key(
        key_bytes: &[u8; KEY_BYTES],
        kid: String,
    ) -> Result<Self, EventCipherError> {
        let kid_trimmed = kid.trim();
        if kid_trimmed.is_empty() {
            return Err(EventCipherError::EmptyKid);
        }
        let key = GenericArray::from_slice(key_bytes);
        let cipher = XChaCha20Poly1305::new(key);
        Ok(Self {
            cipher,
            kid: kid_trimmed.to_owned(),
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Seal arbitrary plaintext into the wire envelope, binding
    /// `aad` (associated data — e.g. the cluster KV key or pub/sub
    /// topic) into the AEAD tag. A value sealed with `aad = X`
    /// authenticates ONLY when opened with the same `aad`, so a
    /// ciphertext sealed for key `A` cannot be replayed into key
    /// `B` (it fails `AuthFailed`) even under the same key —
    /// swap-resistance for the per-key/per-topic state encryption.
    /// `aad = &[]` reproduces the AAD-less credential-cache
    /// envelope byte-for-byte (the slice form `encrypt(n, msg)` is
    /// definitionally `Payload { msg, aad: &[] }`).
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, EventCipherError> {
        let mut nonce_bytes = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| EventCipherError::EncryptFailed)?;
        let envelope = Envelope {
            v: ENVELOPE_VERSION,
            kid: self.kid.clone(),
            n: B64URL.encode(nonce_bytes),
            c: B64URL.encode(&ciphertext),
        };
        // Envelope serialises infallibly (the only String fields
        // are operator-supplied and finite).
        serde_json::to_vec(&envelope).map_err(|e| EventCipherError::SerialiseEvent(e.to_string()))
    }

    /// Open a wire envelope, requiring the same `aad` that sealed
    /// it. Returns raw plaintext bytes. Validation order matches the
    /// legacy path: NotEnvelope → version → kid → base64 → nonce-len
    /// → AEAD (`AuthFailed` on wrong key / tamper / AAD mismatch).
    pub fn open(&self, raw: &[u8], aad: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let envelope: Envelope =
            serde_json::from_slice(raw).map_err(|_| DecryptError::NotEnvelope)?;
        if envelope.v != ENVELOPE_VERSION {
            return Err(DecryptError::UnsupportedVersion {
                got: envelope.v,
                supported: ENVELOPE_VERSION,
            });
        }
        if envelope.kid != self.kid {
            return Err(DecryptError::KidMismatch {
                published_kid: envelope.kid,
                configured_kid: self.kid.clone(),
            });
        }
        let nonce_raw = B64URL
            .decode(envelope.n.as_bytes())
            .map_err(|e| DecryptError::InvalidBase64(e.to_string()))?;
        if nonce_raw.len() != NONCE_BYTES {
            return Err(DecryptError::InvalidNonceLength {
                got: nonce_raw.len(),
            });
        }
        let ciphertext = B64URL
            .decode(envelope.c.as_bytes())
            .map_err(|e| DecryptError::InvalidBase64(e.to_string()))?;
        let nonce = XNonce::from_slice(&nonce_raw);
        self.cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext.as_slice(),
                    aad,
                },
            )
            .map_err(|_| DecryptError::AuthFailed)
    }

    /// Encrypt a `CacheEvent` into the wire envelope. Generates a
    /// random 24-byte nonce per call. Thin wrapper over [`Self::seal`]
    /// with no AAD — preserves the credential-cache wire format.
    pub fn encrypt_event(&self, event: &CacheEvent) -> Result<Vec<u8>, EventCipherError> {
        let plaintext = serde_json::to_vec(event)
            .map_err(|e| EventCipherError::SerialiseEvent(e.to_string()))?;
        self.seal(&plaintext, &[])
    }

    /// Decrypt a payload received from the cluster topic into a
    /// `CacheEvent`. Returns `Err(DecryptError::NotEnvelope)` when
    /// the payload isn't envelope-shaped — callers may surface
    /// that as a misconfiguration warning + drop the event. Thin
    /// wrapper over [`Self::open`] with no AAD.
    pub fn decrypt_envelope(&self, raw: &[u8]) -> Result<CacheEvent, DecryptError> {
        let plaintext = self.open(raw, &[])?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| DecryptError::InvalidPlaintext(e.to_string()))
    }

    /// True for raw payloads that look like our envelope shape.
    /// Lets callers distinguish "publisher used encryption" from
    /// "publisher published plaintext" without a full decrypt
    /// attempt.
    pub fn looks_like_envelope(raw: &[u8]) -> bool {
        // Cheap check — peek into the JSON for the `v` field
        // before committing to a full parse. Real envelopes will
        // have all four fields; non-envelope payloads (a plain
        // `CacheEvent` JSON, or random bytes) won't.
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(raw) else {
            return false;
        };
        let Some(obj) = value.as_object() else {
            return false;
        };
        obj.contains_key("v")
            && obj.contains_key("kid")
            && obj.contains_key("n")
            && obj.contains_key("c")
    }
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    v: u8,
    kid: String,
    n: String,
    c: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::credential::IssuedCredential;

    fn sample_key() -> [u8; KEY_BYTES] {
        // Deterministic key for tests; production operators MUST
        // generate via CSPRNG (the operator runbook documents the
        // recommended `openssl rand -base64 32` command).
        let mut k = [0u8; KEY_BYTES];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(11);
        }
        k
    }

    fn sample_event() -> CacheEvent {
        CacheEvent::Issued {
            identity_hash: "abc123".into(),
            plugin_id: "vault-pg".into(),
            target: "orders-readonly".into(),
            credential: IssuedCredential::from_value("token-xyz", 60),
            published_by: "node-a".into(),
            published_at_ms: 0,
            event_id: "evt-1".into(),
        }
    }

    #[test]
    fn roundtrip_event_via_cipher() {
        let cipher = EventCipher::from_raw_key(&sample_key(), "k1".into()).unwrap();
        let event = sample_event();
        let envelope = cipher.encrypt_event(&event).unwrap();
        // Envelope MUST be parseable as our wire shape.
        assert!(EventCipher::looks_like_envelope(&envelope));
        // And MUST NOT contain plaintext credential bytes — the
        // smoke test that proves encryption actually fired.
        let envelope_str = std::str::from_utf8(&envelope).unwrap();
        assert!(
            !envelope_str.contains("token-xyz"),
            "encrypted envelope leaks plaintext credential: {envelope_str}",
        );
        assert!(
            !envelope_str.contains("orders-readonly"),
            "encrypted envelope leaks plaintext target: {envelope_str}",
        );
        let decoded = cipher.decrypt_envelope(&envelope).unwrap();
        match decoded {
            CacheEvent::Issued {
                credential, target, ..
            } => {
                assert_eq!(target, "orders-readonly");
                assert_eq!(credential.value.as_deref(), Some("token-xyz"));
            }
            other => panic!("expected Issued, got {other:?}"),
        }
    }

    #[test]
    fn from_base64_key_accepts_padded_and_unpadded() {
        let raw = sample_key();
        let padded = base64::engine::general_purpose::URL_SAFE.encode(raw);
        let unpadded = B64URL.encode(raw);
        EventCipher::from_base64_key(&padded, "k1".into()).unwrap();
        EventCipher::from_base64_key(&unpadded, "k1".into()).unwrap();
    }

    #[test]
    fn from_base64_key_rejects_short_key() {
        // 16-byte key (too short for XChaCha20).
        let short = B64URL.encode([0u8; 16]);
        let err = EventCipher::from_base64_key(&short, "k1".into()).unwrap_err();
        match err {
            EventCipherError::InvalidKeyLength { got } => assert_eq!(got, 16),
            other => panic!("expected InvalidKeyLength, got {other}"),
        }
    }

    #[test]
    fn from_base64_key_rejects_empty_kid() {
        let raw = B64URL.encode(sample_key());
        let err = EventCipher::from_base64_key(&raw, "  ".into()).unwrap_err();
        assert!(matches!(err, EventCipherError::EmptyKid));
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let alice = EventCipher::from_raw_key(&sample_key(), "k1".into()).unwrap();
        let mut bob_key = sample_key();
        bob_key[0] ^= 0xff;
        let bob = EventCipher::from_raw_key(&bob_key, "k1".into()).unwrap();
        let envelope = alice.encrypt_event(&sample_event()).unwrap();
        let err = bob.decrypt_envelope(&envelope).unwrap_err();
        assert!(matches!(err, DecryptError::AuthFailed), "got {err:?}");
    }

    #[test]
    fn decrypt_rejects_kid_mismatch() {
        // Same key bytes, different kids — operator mid-rotation.
        let alice = EventCipher::from_raw_key(&sample_key(), "key-2026-Q1".into()).unwrap();
        let bob = EventCipher::from_raw_key(&sample_key(), "key-2026-Q2".into()).unwrap();
        let envelope = alice.encrypt_event(&sample_event()).unwrap();
        let err = bob.decrypt_envelope(&envelope).unwrap_err();
        match err {
            DecryptError::KidMismatch {
                published_kid,
                configured_kid,
            } => {
                assert_eq!(published_kid, "key-2026-Q1");
                assert_eq!(configured_kid, "key-2026-Q2");
            }
            other => panic!("expected KidMismatch, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let cipher = EventCipher::from_raw_key(&sample_key(), "k1".into()).unwrap();
        let mut envelope = cipher.encrypt_event(&sample_event()).unwrap();
        // Flip a byte deep in the envelope (one of the
        // ciphertext characters). AEAD authentication tag must
        // catch the tamper.
        let len = envelope.len();
        envelope[len - 5] ^= 0x01;
        let err = cipher.decrypt_envelope(&envelope).unwrap_err();
        // Could be AuthFailed (most likely) or InvalidBase64 if
        // we flipped a base64 char that lands outside the
        // alphabet. Both prove the tamper was detected.
        assert!(
            matches!(
                err,
                DecryptError::AuthFailed | DecryptError::InvalidBase64(_)
            ),
            "expected tamper detection, got {err:?}",
        );
    }

    #[test]
    fn decrypt_distinguishes_plaintext_event_from_envelope() {
        // A peer publishing without encryption produces a
        // plaintext `CacheEvent` JSON. The receiver must not
        // confuse that with an envelope.
        let plaintext = serde_json::to_vec(&sample_event()).unwrap();
        assert!(!EventCipher::looks_like_envelope(&plaintext));
        let cipher = EventCipher::from_raw_key(&sample_key(), "k1".into()).unwrap();
        let err = cipher.decrypt_envelope(&plaintext).unwrap_err();
        assert!(matches!(err, DecryptError::NotEnvelope), "got {err:?}",);
    }

    #[test]
    fn random_nonces_diverge_per_publish() {
        // Two encryptions of the same event MUST produce
        // different envelopes (random nonces). Otherwise an
        // attacker observing the wire could correlate which
        // events recur.
        let cipher = EventCipher::from_raw_key(&sample_key(), "k1".into()).unwrap();
        let e1 = cipher.encrypt_event(&sample_event()).unwrap();
        let e2 = cipher.encrypt_event(&sample_event()).unwrap();
        assert_ne!(
            e1, e2,
            "same plaintext + same key MUST produce different ciphertexts (random nonces)",
        );
    }

    #[test]
    fn seal_open_roundtrip_with_aad() {
        // seal/open round-trips arbitrary bytes under a bound AAD.
        let cipher = EventCipher::from_raw_key(&sample_key(), "k1".into()).unwrap();
        let sealed = cipher.seal(b"session-blob", b"mcpg.session.s1").unwrap();
        assert!(EventCipher::looks_like_envelope(&sealed));
        let opened = cipher.open(&sealed, b"mcpg.session.s1").unwrap();
        assert_eq!(opened, b"session-blob");
    }

    #[test]
    fn open_rejects_aad_mismatch_swap_resistance() {
        // A value sealed for key A cannot be opened as key B,
        // even with the same cipher key — the AAD binding is what
        // makes the per-key seal swap-resistant.
        let cipher = EventCipher::from_raw_key(&sample_key(), "k1".into()).unwrap();
        let sealed = cipher.seal(b"value-for-A", b"key-A").unwrap();
        let err = cipher.open(&sealed, b"key-B").unwrap_err();
        assert!(matches!(err, DecryptError::AuthFailed), "got {err:?}");
        // Same AAD still opens fine.
        assert_eq!(cipher.open(&sealed, b"key-A").unwrap(), b"value-for-A");
    }

    #[test]
    fn seal_empty_aad_is_legacy_wire_format() {
        // `seal(pt, &[])` must produce the exact AAD-less envelope the
        // credential cache emits — so the two paths share one format.
        let cipher = EventCipher::from_raw_key(&sample_key(), "k1".into()).unwrap();
        let event = sample_event();
        // Round-trip through the high-level event API (which delegates
        // to seal/open with aad=&[]) proves the wrapper is intact.
        let envelope = cipher.encrypt_event(&event).unwrap();
        let opened_raw = cipher.open(&envelope, &[]).unwrap();
        let reparsed: CacheEvent = serde_json::from_slice(&opened_raw).unwrap();
        match reparsed {
            CacheEvent::Issued { target, .. } => assert_eq!(target, "orders-readonly"),
            other => panic!("expected Issued, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_envelope_version_rejected() {
        let cipher = EventCipher::from_raw_key(&sample_key(), "k1".into()).unwrap();
        // Hand-craft an envelope with `v: 99` — future format
        // bump that this build doesn't support.
        let envelope = serde_json::json!({
            "v": 99,
            "kid": "k1",
            "n": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "c": "AAAA",
        });
        let raw = serde_json::to_vec(&envelope).unwrap();
        let err = cipher.decrypt_envelope(&raw).unwrap_err();
        match err {
            DecryptError::UnsupportedVersion { got, supported } => {
                assert_eq!(got, 99);
                assert_eq!(supported, ENVELOPE_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }
}
