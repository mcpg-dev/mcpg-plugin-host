//! Native plugin loader.
//!
//! Loads native Rust dylib plugins at runtime. Native plugins are either:
//!
//! 1. **Built-in** — registered programmatically by the gateway (e.g. payment
//!    plugin extracted into a separate crate, linked at compile time)
//! 2. **External** — loaded from `.so`/`.dylib` files with mandatory Ed25519
//!    signature verification and optional SHA-256 hash pinning
//!
//! ## Security Model
//!
//! Native plugins run in the same process as the gateway. They are
//! cryptographically signed by a trusted Ed25519 key. The trust
//! posture is per-entry: each plugin's
//! `plugins[*].signature.{policy, sha256, trusted_keys}` declares
//! its own posture, with a gateway-wide default at
//! `gateway.plugin_registry.default_signature_policy`. Loading an
//! unsigned or tampered plugin under `policy: enforce` is a hard
//! error — fail-closed.

use std::path::Path;

use anyhow::{Context, Result};
use mcpg_plugin_protocol::PluginManifest;
use tracing::{info, warn};

use crate::revocation::RevocationList;
use crate::signature::SignaturePolicy;
use crate::verify;

/// Metadata for a natively loaded plugin.
#[derive(Debug, Clone)]
pub struct NativePluginMeta {
    /// The manifest extracted from the plugin instance.
    pub manifest: PluginManifest,
    /// Filesystem path the plugin was loaded from (if applicable).
    pub source_path: Option<String>,
    /// Whether the plugin's signature was verified.
    pub signature_verified: bool,
    /// SHA-256 hex digest of the artifact (if computed).
    pub artifact_hash: Option<String>,
}

/// Options for verifying a native plugin before loading.
#[derive(Debug, Clone, Default)]
pub struct NativeVerifyOptions {
    /// Expected SHA-256 hex digest (checked if present).
    pub expected_sha256: Option<String>,
    /// Trusted Ed25519 public keys (32 bytes each).
    /// At least one must verify the signature if the list is non-empty.
    pub trusted_public_keys: Vec<[u8; 32]>,
    /// Per-plugin signature verification policy. `Disabled` skips
    /// the Ed25519 step entirely; `Warn` attempts verification and
    /// logs failures but still loads the plugin; `Enforce` refuses
    /// to load on any failure (missing key, bad sig, no `.sig`
    /// when one is required). Defaults to `Warn` (the safest
    /// first-rollout posture — operators see noisy logs instead
    /// of refused boots while they wire up trusted keys).
    pub policy: SignaturePolicy,
    /// Operator-supplied revocation list. Checked AFTER the
    /// Ed25519 signature passes; an artefact whose SHA-256
    /// matches a revoked entry fails to load with a distinct
    /// error referencing the revocation reason. `None` means
    /// "no revocation list configured" — equivalent to an empty
    /// list (every signed artefact is allowed).
    pub revocation_list: Option<RevocationList>,
}

/// Verify a native plugin artifact before loading.
///
/// Returns the verified `NativePluginMeta` or an error if verification fails.
pub fn verify_native_artifact(
    artifact_path: &Path,
    options: &NativeVerifyOptions,
) -> Result<NativeVerifyResult> {
    info!(
        path = %artifact_path.display(),
        "verifying native plugin artifact"
    );

    // Read the artifact ONCE; the hash check and the Ed25519 signature
    // check then operate over the identical buffer (no independent re-open
    // between them, so they cannot observe different bytes).
    let artifact_bytes = std::fs::read(artifact_path)
        .with_context(|| format!("failed to read artifact: {}", artifact_path.display()))?;

    // Step 1: SHA-256 hash check (if expected hash is provided)
    let artifact_hash = verify::sha256_hex(&artifact_bytes);
    if let Some(expected) = &options.expected_sha256 {
        if artifact_hash != *expected {
            warn!(
                path = %artifact_path.display(),
                expected_hash = %expected,
                actual_hash = %artifact_hash,
                "native plugin artifact hash mismatch"
            );
            return Err(anyhow::anyhow!(
                "artifact hash mismatch for '{}': expected {}, got {}",
                artifact_path.display(),
                expected,
                artifact_hash,
            ));
        }
        info!(
            path = %artifact_path.display(),
            hash = %artifact_hash,
            "SHA-256 hash verified"
        );
    }

    // Step 2: Ed25519 signature check, governed by `options.policy`.
    //
    // - `Disabled` — skip the step entirely. Caller (the gateway)
    //   is responsible for emitting an audit event when any entry
    //   resolves to this policy; the host just respects the
    //   posture without further commentary beyond a `warn!` log.
    // - `Warn` — attempt verification; on ANY failure (no keys
    //   configured, no `.sig`, signature didn't match) log a
    //   warning and proceed. `signature_verified` stays `false`
    //   so the plugin metadata reflects the actual state.
    // - `Enforce` — return `Err` on any failure (today's
    //   behaviour). The strictest posture; recommended for
    //   production.
    let signature_verified = if options.policy.skips_verification() {
        warn!(
            path = %artifact_path.display(),
            "SIGNATURE VERIFICATION SKIPPED — policy is `disabled` (development only)"
        );
        false
    } else {
        match try_verify_signature(artifact_path, &artifact_bytes, &options.trusted_public_keys) {
            Ok(()) => true,
            Err(failure) => {
                // Enforce-when-keyed: configuring trusted keys is an
                // explicit intent to verify, so a failure MUST block even
                // under `warn` — otherwise an unsigned/tampered plugin loads
                // in-process with only a log line. Only a genuinely keyless
                // `warn` (first rollout, nothing to verify against) proceeds.
                let keyed = !options.trusted_public_keys.is_empty();
                if options.policy.refuses_on_failure() || keyed {
                    return Err(anyhow::anyhow!(
                        "native plugin '{}': signature verification failed under policy `{}`{}: \
                         {failure}",
                        artifact_path.display(),
                        options.policy.as_label(),
                        if keyed && !options.policy.refuses_on_failure() {
                            " (trusted keys configured — treated as enforce)"
                        } else {
                            ""
                        },
                    ));
                }
                // Keyless warn: loud log + metric so the unverified-load count
                // is observable, not silent.
                metrics::counter!(
                    "mcpg_plugin_unverified_load_total",
                    "reason" => "warn_no_trusted_keys",
                )
                .increment(1);
                warn!(
                    path = %artifact_path.display(),
                    error = %failure,
                    "signature verification failed under policy `warn` with NO trusted keys \
                     configured — loading UNVERIFIED native code; configure trusted keys to enforce"
                );
                false
            }
        }
    };

    // Step 3: revocation-list check, keyed on the artifact hash
    // (independent of signature outcome). Under `Enforce` a bad
    // signature already returned above, so this only sees signed
    // artefacts; under `Warn`/`Disabled` it still runs and can
    // refuse a revoked artefact even when the signature step was
    // skipped or merely warned. Distinct error message from the
    // "no valid signature" failure so operators can tell the two
    // failure modes apart.
    if let Some(list) = options.revocation_list.as_ref()
        && let Some(entry) = list.lookup(&artifact_hash)
    {
        warn!(
            path = %artifact_path.display(),
            artifact_sha256 = %artifact_hash,
            reason = %entry.reason,
            revoked_at = ?entry.revoked_at,
            "native plugin REVOKED — refusing to load"
        );
        return Err(anyhow::anyhow!(
            "native plugin '{}' is revoked: {} (artifact_sha256 {}{})",
            artifact_path.display(),
            entry.reason,
            artifact_hash,
            entry
                .revoked_at
                .as_deref()
                .map(|ts| format!(", revoked_at {ts}"))
                .unwrap_or_default(),
        ));
    }

    Ok(NativeVerifyResult {
        artifact_hash,
        signature_verified,
        source_path: artifact_path.to_string_lossy().into_owned(),
    })
}

/// Result of native artifact verification.
#[derive(Debug, Clone)]
pub struct NativeVerifyResult {
    /// SHA-256 hex digest of the artifact.
    pub artifact_hash: String,
    /// Whether the signature was successfully verified.
    pub signature_verified: bool,
    /// Filesystem path of the verified artifact.
    pub source_path: String,
}

impl NativeVerifyResult {
    /// Build a `NativePluginMeta` from this verification result and a manifest.
    pub fn into_meta(self, manifest: PluginManifest) -> NativePluginMeta {
        NativePluginMeta {
            manifest,
            source_path: Some(self.source_path),
            signature_verified: self.signature_verified,
            artifact_hash: Some(self.artifact_hash),
        }
    }
}

/// Try to verify the artefact's `.sig` against any of the
/// trusted keys. Returns `Ok(())` when one key matches; `Err`
/// with a category-specific message when no key matches or no
/// keys are configured. The caller decides whether to bail or
/// log based on its policy.
fn try_verify_signature(
    artifact_path: &Path,
    artifact_bytes: &[u8],
    trusted_public_keys: &[[u8; 32]],
) -> Result<()> {
    if trusted_public_keys.is_empty() {
        return Err(anyhow::anyhow!(
            "no trusted_public_keys configured for '{}'; \
             configure at least one Ed25519 public key on the \
             entry's `signature.trusted_keys[]` or set \
             `signature.policy: disabled`",
            artifact_path.display(),
        ));
    }
    for key in trusted_public_keys {
        match verify::verify_signature_over_bytes(artifact_path, artifact_bytes, key) {
            Ok(true) => {
                info!(
                    path = %artifact_path.display(),
                    "Ed25519 signature verified"
                );
                return Ok(());
            }
            Ok(false) => continue,
            Err(e) => {
                tracing::debug!(
                    path = %artifact_path.display(),
                    error = %e,
                    "signature check failed with this key, trying next"
                );
                continue;
            }
        }
    }
    Err(anyhow::anyhow!(
        "no valid signature for '{}' from any trusted key",
        artifact_path.display(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mcpg-native-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn verify_artifact_with_correct_hash() {
        let dir = tempdir();
        let path = dir.join("plugin.so");
        std::fs::write(&path, b"fake plugin").unwrap();

        let expected_hash = verify::sha256_hex(b"fake plugin");
        let options = NativeVerifyOptions {
            expected_sha256: Some(expected_hash),
            policy: SignaturePolicy::Disabled,
            ..Default::default()
        };

        let result = verify_native_artifact(&path, &options).unwrap();
        assert!(!result.signature_verified);
        assert!(!result.artifact_hash.is_empty());
    }

    #[test]
    fn verify_artifact_with_wrong_hash_fails() {
        let dir = tempdir();
        let path = dir.join("plugin.so");
        std::fs::write(&path, b"fake plugin").unwrap();

        let options = NativeVerifyOptions {
            expected_sha256: Some("0".repeat(64)),
            policy: SignaturePolicy::Disabled,
            ..Default::default()
        };

        let err = verify_native_artifact(&path, &options).unwrap_err();
        assert!(err.to_string().contains("hash mismatch"), "got: {err}");
    }

    #[test]
    fn verify_artifact_with_signature() {
        let dir = tempdir();
        let artifact_path = dir.join("plugin.so");
        let sig_path = dir.join("plugin.so.sig");

        let content = b"signed plugin content";
        std::fs::write(&artifact_path, content).unwrap();

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let public_key = signing_key.verifying_key();
        let signature = signing_key.sign(content.as_ref());
        std::fs::write(&sig_path, signature.to_bytes()).unwrap();

        let options = NativeVerifyOptions {
            trusted_public_keys: vec![*public_key.as_bytes()],
            policy: SignaturePolicy::Enforce,
            ..Default::default()
        };

        let result = verify_native_artifact(&artifact_path, &options).unwrap();
        assert!(result.signature_verified);
    }

    /// Regression: under `warn`, a configured trusted key means the
    /// operator intends to verify — a bad/missing signature MUST block the
    /// load (enforce-when-keyed), not just log.
    #[test]
    fn warn_with_trusted_keys_blocks_bad_signature() {
        let dir = tempdir();
        let artifact_path = dir.join("plugin.so");
        let sig_path = dir.join("plugin.so.sig");
        std::fs::write(&artifact_path, b"plugin content").unwrap();

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let wrong_key = SigningKey::from_bytes(&[99u8; 32]);
        let signature = signing_key.sign(b"plugin content");
        std::fs::write(&sig_path, signature.to_bytes()).unwrap();

        let options = NativeVerifyOptions {
            trusted_public_keys: vec![*wrong_key.verifying_key().as_bytes()],
            policy: SignaturePolicy::Warn,
            ..Default::default()
        };

        let err = verify_native_artifact(&artifact_path, &options).unwrap_err();
        assert!(
            err.to_string().contains("treated as enforce"),
            "warn+keyed must escalate to enforce: {err}"
        );
    }

    #[test]
    fn verify_artifact_fails_with_wrong_signing_key_under_enforce() {
        let dir = tempdir();
        let artifact_path = dir.join("plugin.so");
        let sig_path = dir.join("plugin.so.sig");

        let content = b"plugin content";
        std::fs::write(&artifact_path, content).unwrap();

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let wrong_key = SigningKey::from_bytes(&[99u8; 32]);
        let signature = signing_key.sign(content.as_ref());
        std::fs::write(&sig_path, signature.to_bytes()).unwrap();

        let options = NativeVerifyOptions {
            trusted_public_keys: vec![*wrong_key.verifying_key().as_bytes()],
            policy: SignaturePolicy::Enforce,
            ..Default::default()
        };

        let err = verify_native_artifact(&artifact_path, &options).unwrap_err();
        assert!(err.to_string().contains("no valid signature"), "got: {err}");
        assert!(
            err.to_string().contains("enforce"),
            "policy mentioned: {err}"
        );
    }

    #[test]
    fn verify_artifact_fails_when_no_sig_file_under_enforce() {
        let dir = tempdir();
        let path = dir.join("plugin.so");
        std::fs::write(&path, b"unsigned plugin").unwrap();

        let options = NativeVerifyOptions {
            trusted_public_keys: vec![[0u8; 32]],
            policy: SignaturePolicy::Enforce,
            ..Default::default()
        };

        let err = verify_native_artifact(&path, &options).unwrap_err();
        assert!(err.to_string().contains("no valid signature"), "got: {err}");
    }

    #[test]
    fn verify_artifact_proceeds_under_warn_when_signature_invalid() {
        // Warn policy (the default) is the safety net during
        // first-rollout: an operator who hasn't yet wired
        // trusted keys gets a noisy log instead of a refused
        // boot. Returns Ok with `signature_verified: false` so
        // downstream code can still tell that the artefact was
        // not cryptographically attested.
        let dir = tempdir();
        let path = dir.join("plugin.so");
        std::fs::write(&path, b"unsigned plugin").unwrap();

        // Keyless warn: no trusted keys means nothing to enforce
        // against, so the load proceeds unverified. (With keys configured,
        // warn escalates to enforce — see warn_with_trusted_keys_blocks_*.)
        let options = NativeVerifyOptions {
            trusted_public_keys: vec![],
            policy: SignaturePolicy::Warn,
            ..Default::default()
        };

        let result = verify_native_artifact(&path, &options).unwrap();
        assert!(!result.signature_verified);
    }

    #[test]
    fn verify_artifact_under_enforce_with_no_keys_refuses() {
        let dir = tempdir();
        let path = dir.join("plugin.so");
        std::fs::write(&path, b"unsigned plugin").unwrap();

        let options = NativeVerifyOptions {
            trusted_public_keys: Vec::new(),
            policy: SignaturePolicy::Enforce,
            ..Default::default()
        };

        let err = verify_native_artifact(&path, &options).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no trusted_public_keys configured"),
            "got: {msg}"
        );
        assert!(msg.contains("enforce"), "policy mentioned: {msg}");
    }

    #[test]
    fn into_meta_builds_correct_metadata() {
        let result = NativeVerifyResult {
            artifact_hash: "abc123".into(),
            signature_verified: true,
            source_path: "/opt/plugins/payment.so".into(),
        };
        let manifest = PluginManifest {
            id: "com.test".into(),
            version: "1.0".into(),
            name: "Test".into(),
            plugin_class: mcpg_plugin_protocol::PluginClass::ToolGate,
            protocol_version: mcpg_plugin_protocol::PROTOCOL_VERSION.to_owned(),
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
        };
        let meta = result.into_meta(manifest);
        assert!(meta.signature_verified);
        assert_eq!(meta.artifact_hash.as_deref(), Some("abc123"));
        assert_eq!(meta.source_path.as_deref(), Some("/opt/plugins/payment.so"));
    }

    /// Build a NativeVerifyOptions whose `revocation_list`
    /// contains a single entry covering `target_sha256`.
    fn options_with_revocation(target_sha256: &str) -> NativeVerifyOptions {
        let file = crate::revocation::RevocationListFile {
            version: 1,
            issued_at: Some("2026-04-27T00:00:00Z".into()),
            revocations: vec![crate::revocation::RevocationEntry {
                artifact_sha256: target_sha256.to_owned(),
                reason: "compromised key — rotated".into(),
                revoked_at: Some("2026-04-27T00:00:00Z".into()),
            }],
        };
        NativeVerifyOptions {
            policy: SignaturePolicy::Disabled,
            revocation_list: Some(crate::revocation::RevocationList::from_file(file).unwrap()),
            ..Default::default()
        }
    }

    #[test]
    fn revocation_list_blocks_revoked_artifact() {
        let dir = tempdir();
        let path = dir.join("plugin.so");
        let content = b"compromised plugin bytes";
        std::fs::write(&path, content).unwrap();

        let sha = verify::sha256_hex(content);
        let options = options_with_revocation(&sha);

        let err = verify_native_artifact(&path, &options).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("is revoked"), "got: {s}");
        assert!(s.contains("compromised key"), "reason surfaced: {s}");
        assert!(
            s.contains("revoked_at 2026-04-27T00:00:00Z"),
            "timestamp surfaced: {s}"
        );
    }

    #[test]
    fn revocation_list_passes_unrevoked_artifact() {
        let dir = tempdir();
        let path = dir.join("plugin.so");
        std::fs::write(&path, b"clean plugin bytes").unwrap();

        // Revocation list contains a different artifact's hash.
        let options = options_with_revocation(&"a".repeat(64));
        let result = verify_native_artifact(&path, &options).unwrap();
        assert!(!result.signature_verified); // policy: Disabled
        assert_eq!(
            result.artifact_hash,
            verify::sha256_hex(b"clean plugin bytes")
        );
    }

    #[test]
    fn revocation_list_check_runs_after_signature_verification() {
        // Even an artefact carrying a *valid* signature is
        // refused when its hash is in the revocation list.
        // Distinct error message from the "no valid signature"
        // path so audit consumers can pattern-match the cause.
        let dir = tempdir();
        let artifact_path = dir.join("plugin.so");
        let sig_path = dir.join("plugin.so.sig");
        let content = b"properly-signed-but-revoked plugin";
        std::fs::write(&artifact_path, content).unwrap();

        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let public_key = signing_key.verifying_key();
        let signature = signing_key.sign(content.as_ref());
        std::fs::write(&sig_path, signature.to_bytes()).unwrap();

        let sha = verify::sha256_hex(content);
        let file = crate::revocation::RevocationListFile {
            version: 1,
            issued_at: None,
            revocations: vec![crate::revocation::RevocationEntry {
                artifact_sha256: sha.clone(),
                reason: "supply-chain incident".into(),
                revoked_at: None,
            }],
        };
        let options = NativeVerifyOptions {
            trusted_public_keys: vec![*public_key.as_bytes()],
            policy: SignaturePolicy::Enforce,
            revocation_list: Some(crate::revocation::RevocationList::from_file(file).unwrap()),
            ..Default::default()
        };

        let err = verify_native_artifact(&artifact_path, &options).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("is revoked"), "got: {s}");
        // The "no valid signature" message MUST NOT appear —
        // signature was good; revocation is the reason.
        assert!(
            !s.contains("no valid signature"),
            "wrong error category: {s}"
        );
    }

    #[test]
    fn revocation_list_ignores_artifact_with_no_match() {
        // Revocation list has 5 entries, none matching this
        // artefact. Verification proceeds normally.
        let dir = tempdir();
        let path = dir.join("plugin.so");
        std::fs::write(&path, b"some plugin").unwrap();

        let unrelated_hashes: Vec<String> = (0..5)
            .map(|i| format!("{:0>64}", format!("{i:x}")))
            .collect();
        let file = crate::revocation::RevocationListFile {
            version: 1,
            issued_at: None,
            revocations: unrelated_hashes
                .into_iter()
                .map(|h| crate::revocation::RevocationEntry {
                    artifact_sha256: h,
                    reason: "test".into(),
                    revoked_at: None,
                })
                .collect(),
        };
        let options = NativeVerifyOptions {
            policy: SignaturePolicy::Disabled,
            revocation_list: Some(crate::revocation::RevocationList::from_file(file).unwrap()),
            ..Default::default()
        };

        verify_native_artifact(&path, &options).unwrap();
    }
}
