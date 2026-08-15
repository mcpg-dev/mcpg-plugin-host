//! Plugin artifact integrity verification.
//!
//! Provides:
//! - **SHA-256 hash verification** — validates plugin artifact integrity
//! - **Ed25519 signature verification** — validates that native plugins
//!   were signed by a trusted key (mandatory for native tier, optional for Wasm)

use std::io::Read;

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey, pkcs8::DecodePublicKey};
use sha2::{Digest, Sha256};

/// Compute a hex-encoded SHA-256 hash of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

/// Compute a hex-encoded SHA-256 hash of a file.
pub fn sha256_file(path: &std::path::Path) -> Result<String> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("failed to open artifact: {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Verify that a file at `path` has the expected SHA-256 hex digest.
pub fn verify_file_hash(path: &std::path::Path, expected_hex: &str) -> Result<bool> {
    let actual = sha256_file(path)?;
    Ok(constant_time_eq(&actual, expected_hex))
}

/// Verify an Ed25519 detached signature over raw data.
///
/// - `public_key_bytes`: 32-byte Ed25519 public key
/// - `data`: the artifact bytes that were signed
/// - `signature_bytes`: 64-byte Ed25519 signature
pub fn verify_ed25519_signature(
    public_key_bytes: &[u8; 32],
    data: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<bool> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key_bytes).context("invalid Ed25519 public key")?;
    let signature = Signature::from_bytes(signature_bytes);
    Ok(verifying_key.verify(data, &signature).is_ok())
}

/// Derive the co-located `.sig` path for an artifact (`foo.so` →
/// `foo.so.sig`).
pub fn sig_path_for(artifact_path: &std::path::Path) -> std::path::PathBuf {
    artifact_path.with_extension(format!(
        "{}.sig",
        artifact_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("bin")
    ))
}

/// Verify an Ed25519 detached signature over ALREADY-READ artifact bytes.
///
/// Reads only the co-located `.sig` file — the artifact bytes are supplied
/// by the caller so the hash check and the signature check operate over the
/// identical buffer (no independent re-open between them).
pub fn verify_signature_over_bytes(
    artifact_path: &std::path::Path,
    artifact_bytes: &[u8],
    public_key_bytes: &[u8; 32],
) -> Result<bool> {
    let sig_path = sig_path_for(artifact_path);

    if !sig_path.exists() {
        return Err(anyhow::anyhow!(
            "signature file not found: {}",
            sig_path.display()
        ));
    }

    let sig_data = std::fs::read(&sig_path)
        .with_context(|| format!("failed to read signature: {}", sig_path.display()))?;

    if sig_data.len() != 64 {
        return Err(anyhow::anyhow!(
            "signature file has invalid length: expected 64 bytes, got {}",
            sig_data.len()
        ));
    }

    let sig_array: [u8; 64] = sig_data.try_into().unwrap();
    verify_ed25519_signature(public_key_bytes, artifact_bytes, &sig_array)
}

/// Verify an Ed25519 detached signature over a file.
///
/// Reads both the artifact and its `.sig` co-located file. Prefer
/// [`verify_signature_over_bytes`] when the artifact bytes are already in
/// hand (e.g. read once for the hash check).
pub fn verify_file_signature(
    artifact_path: &std::path::Path,
    public_key_bytes: &[u8; 32],
) -> Result<bool> {
    let mut artifact_data = Vec::new();
    std::fs::File::open(artifact_path)
        .with_context(|| format!("failed to open artifact: {}", artifact_path.display()))?
        .read_to_end(&mut artifact_data)?;
    verify_signature_over_bytes(artifact_path, &artifact_data, public_key_bytes)
}

/// Decode a PEM-encoded Ed25519 SubjectPublicKeyInfo into the raw
/// 32-byte verifying key. Accepts the standard PKCS#8 wrapping that
/// `openssl genpkey -algorithm Ed25519 -out priv.pem` and `openssl
/// pkey -in priv.pem -pubout` emit (BEGIN PUBLIC KEY / END PUBLIC
/// KEY). Operators paste this PEM directly into per-entry
/// `signature.trusted_keys[].pem`.
pub fn decode_pem_ed25519_public_key(pem: &str) -> Result<[u8; 32]> {
    let key = VerifyingKey::from_public_key_pem(pem.trim())
        .context("not a valid PEM-encoded Ed25519 public key")?;
    Ok(*key.as_bytes())
}

/// Constant-time string comparison to prevent timing side-channels on hash comparisons.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // echo -n "hello world" | sha256sum
        let hash = sha256_hex(b"hello world");
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn sha256_empty() {
        let hash = sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_file_works() {
        let dir = tempdir();
        let path = dir.join("test.bin");
        std::fs::write(&path, b"hello world").unwrap();
        let hash = sha256_file(&path).unwrap();
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn verify_hash_matches() {
        let dir = tempdir();
        let path = dir.join("test.bin");
        std::fs::write(&path, b"hello world").unwrap();
        assert!(
            verify_file_hash(
                &path,
                "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            )
            .unwrap()
        );
    }

    #[test]
    fn verify_hash_rejects_mismatch() {
        let dir = tempdir();
        let path = dir.join("test.bin");
        std::fs::write(&path, b"hello world").unwrap();
        assert!(
            !verify_file_hash(
                &path,
                "0000000000000000000000000000000000000000000000000000000000000000"
            )
            .unwrap()
        );
    }

    #[test]
    fn ed25519_sign_and_verify() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let public_key = signing_key.verifying_key();
        let message = b"plugin artifact bytes";
        let signature = signing_key.sign(message);

        let result =
            verify_ed25519_signature(public_key.as_bytes(), message, &signature.to_bytes())
                .unwrap();
        assert!(result, "valid signature should verify");
    }

    #[test]
    fn ed25519_rejects_wrong_data() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let public_key = signing_key.verifying_key();
        let message = b"plugin artifact bytes";
        let signature = signing_key.sign(message);

        let result = verify_ed25519_signature(
            public_key.as_bytes(),
            b"tampered data",
            &signature.to_bytes(),
        )
        .unwrap();
        assert!(!result, "tampered data should fail verification");
    }

    #[test]
    fn ed25519_rejects_wrong_key() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let wrong_key = SigningKey::from_bytes(&[99u8; 32]);
        let message = b"plugin artifact bytes";
        let signature = signing_key.sign(message);

        let result = verify_ed25519_signature(
            wrong_key.verifying_key().as_bytes(),
            message,
            &signature.to_bytes(),
        )
        .unwrap();
        assert!(!result, "wrong public key should fail verification");
    }

    #[test]
    fn verify_file_signature_end_to_end() {
        use ed25519_dalek::{Signer, SigningKey};

        let dir = tempdir();
        let artifact_path = dir.join("plugin.so");
        let sig_path = dir.join("plugin.so.sig");

        let content = b"fake plugin binary content";
        std::fs::write(&artifact_path, content).unwrap();

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let public_key = signing_key.verifying_key();
        let signature = signing_key.sign(content.as_ref());
        std::fs::write(&sig_path, signature.to_bytes()).unwrap();

        let result = verify_file_signature(&artifact_path, public_key.as_bytes()).unwrap();
        assert!(result);
    }

    #[test]
    fn verify_file_signature_missing_sig_file() {
        let dir = tempdir();
        let path = dir.join("plugin.so");
        std::fs::write(&path, b"data").unwrap();

        let key = [0u8; 32];
        let err = verify_file_signature(&path, &key).unwrap_err();
        assert!(
            err.to_string().contains("signature file not found"),
            "got: {err}"
        );
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
    }

    #[test]
    fn decode_pem_extracts_known_raw_key() {
        // Known PEM: the standard PKCS#8 SubjectPublicKeyInfo
        // wrapping for an Ed25519 raw key of all-zeros (RFC 8410
        // §10.1 test vector with the Curve25519 identity-equivalent
        // key). The 12-byte prefix
        // `30 2a 30 05 06 03 2b 65 70 03 21 00` is the SPKI envelope
        // for `id-Ed25519` (1.3.101.112), then the 32 raw bytes.
        // Operators paste exactly this shape from
        // `openssl pkey -in priv.pem -pubout -outform PEM`.
        let pem = "-----BEGIN PUBLIC KEY-----\n\
                   MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
                   -----END PUBLIC KEY-----";
        let decoded = decode_pem_ed25519_public_key(pem).unwrap();
        assert_eq!(decoded, [0u8; 32]);
    }

    #[test]
    fn decode_pem_rejects_garbage() {
        let err = decode_pem_ed25519_public_key("not a pem").unwrap_err();
        assert!(
            err.to_string().contains("PEM-encoded Ed25519 public key"),
            "got: {err}"
        );
    }

    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mcpg-plugin-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
