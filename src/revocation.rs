//! Plugin-artefact revocation list.
//!
//! Operators ship a JSON list of artefact SHA-256s that the host
//! refuses to load even when the Ed25519 signature is valid.
//! This covers operators with mirrored / pre-pulled artefacts,
//! for whom "delete the OCI release" is not enough. The list is
//! checked AFTER `verify_native_artifact`'s Ed25519 step passes,
//! so a revoked artefact fails with a distinct error kind that
//! audit consumers can pattern-match on.
//!
//! ## File format
//!
//! ```json
//! {
//!   "version": 1,
//!   "issued_at": "2026-04-27T00:00:00Z",
//!   "revocations": [
//!     {
//!       "artifact_sha256": "abc123...",
//!       "reason": "compromised release; rotated signing key",
//!       "revoked_at": "2026-04-27T00:00:00Z"
//!     }
//!   ]
//! }
//! ```
//!
//! `version` is required and MUST equal `1`. `issued_at` and
//! per-entry `revoked_at` are RFC3339 strings used by audit
//! emitters; the host doesn't enforce ordering on them.
//!
//! Artefact SHA-256s are stored hex-encoded (lowercase), without
//! a `sha256:` prefix. Lookup is constant-time via a `BTreeSet`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Wire-format envelope for the revocation list. Operators
/// hand-author or generate this from their release toolchain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationListFile {
    /// Schema version. Currently `1`. Bumping is a hard cut-over;
    /// the host refuses unknown versions.
    pub version: u32,
    /// RFC3339 timestamp the operator generated the list. Audit-
    /// only — the host doesn't gate on freshness.
    #[serde(default)]
    pub issued_at: Option<String>,
    /// Revoked-artefact entries. Order is significant only for
    /// human review; the host indexes these into a set on load.
    #[serde(default)]
    pub revocations: Vec<RevocationEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationEntry {
    /// Lower-case hex SHA-256 of the artefact (cdylib bytes).
    /// MUST match the host's `verify::sha256_file` output for
    /// the entry to apply.
    pub artifact_sha256: String,
    /// Free-form reason surfaced to operators in the host's
    /// failure message + audit event. Required.
    pub reason: String,
    /// RFC3339 timestamp the entry was added. Optional.
    #[serde(default)]
    pub revoked_at: Option<String>,
}

/// Parsed + indexed revocation list. Owned by [`crate::PluginRegistry`]
/// for the lifetime of the gateway; the verifier consults it on
/// every plugin-load attempt.
#[derive(Debug, Clone, Default)]
pub struct RevocationList {
    by_sha256: BTreeMap<String, RevocationEntry>,
}

impl RevocationList {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Number of entries indexed.
    pub fn len(&self) -> usize {
        self.by_sha256.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_sha256.is_empty()
    }

    /// Look up an artefact's revocation entry. Hash MUST be
    /// lower-case hex; callers can normalise via
    /// `crate::verify::sha256_file` (which already emits lower
    /// case) before lookup.
    pub fn lookup(&self, sha256_hex: &str) -> Option<&RevocationEntry> {
        self.by_sha256.get(sha256_hex)
    }

    /// Build a RevocationList from a parsed [`RevocationListFile`].
    /// Validates per-entry shape; rejects duplicate SHA-256s
    /// (operator typo, often pasting the same revocation twice).
    pub fn from_file(file: RevocationListFile) -> Result<Self> {
        if file.version != SCHEMA_VERSION {
            return Err(anyhow::anyhow!(
                "revocation-list schema version {} not supported (this host \
                 understands version {})",
                file.version,
                SCHEMA_VERSION,
            ));
        }
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut by_sha256: BTreeMap<String, RevocationEntry> = BTreeMap::new();
        for entry in file.revocations {
            let normalised = entry.artifact_sha256.trim().to_ascii_lowercase();
            if normalised.len() != 64 || !normalised.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(anyhow::anyhow!(
                    "revocation-list entry has invalid artifact_sha256 '{}' \
                     (must be 64 lowercase hex chars)",
                    entry.artifact_sha256
                ));
            }
            if entry.reason.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "revocation-list entry for {normalised} is missing a reason \
                     (every revocation must explain *why* for audit)"
                ));
            }
            if !seen.insert(normalised.clone()) {
                return Err(anyhow::anyhow!(
                    "revocation-list has a duplicate entry for {normalised} — \
                     consolidate the two entries into one"
                ));
            }
            by_sha256.insert(
                normalised.clone(),
                RevocationEntry {
                    artifact_sha256: normalised,
                    reason: entry.reason,
                    revoked_at: entry.revoked_at,
                },
            );
        }
        Ok(Self { by_sha256 })
    }

    /// Read a revocation list from disk. Empty files / files
    /// containing `{"version":1,"revocations":[]}` are valid and
    /// produce an empty list. Operators initialising a deploy
    /// can ship an empty list and add entries via config-mgmt.
    pub fn from_file_path(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read revocation list at '{}'", path.display()))?;
        let parsed: RevocationListFile = serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "failed to parse revocation list at '{}' as JSON",
                path.display()
            )
        })?;
        Self::from_file(parsed)
    }
}

const SCHEMA_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(sha: &str, reason: &str) -> RevocationEntry {
        RevocationEntry {
            artifact_sha256: sha.to_owned(),
            reason: reason.to_owned(),
            revoked_at: None,
        }
    }

    #[test]
    fn empty_list_loads_cleanly() {
        let f = RevocationListFile {
            version: 1,
            issued_at: None,
            revocations: Vec::new(),
        };
        let list = RevocationList::from_file(f).unwrap();
        assert!(list.is_empty());
        assert!(list.lookup(&"a".repeat(64)).is_none());
    }

    #[test]
    fn happy_path_lookup_finds_revoked() {
        let sha = "a".repeat(64);
        let f = RevocationListFile {
            version: 1,
            issued_at: Some("2026-04-27T00:00:00Z".into()),
            revocations: vec![entry(&sha, "compromised key")],
        };
        let list = RevocationList::from_file(f).unwrap();
        let hit = list.lookup(&sha).expect("entry indexed");
        assert_eq!(hit.reason, "compromised key");
    }

    #[test]
    fn lookup_is_lowercase_only() {
        let sha = "a".repeat(64);
        let f = RevocationListFile {
            version: 1,
            issued_at: None,
            revocations: vec![entry(&sha, "x")],
        };
        let list = RevocationList::from_file(f).unwrap();
        // Caller-supplied uppercase doesn't match by design —
        // canonical form is lowercase; verify::sha256_file emits
        // lowercase too. Documented in the type-level rustdoc.
        assert!(list.lookup(&"A".repeat(64)).is_none());
        assert!(list.lookup(&sha).is_some());
    }

    #[test]
    fn entries_normalise_uppercase_to_lowercase() {
        // The list-author may paste an uppercase SHA-256; we
        // normalise on load so lookup with lowercase hashes (what
        // sha256_file produces) matches.
        let sha = "B".repeat(64);
        let f = RevocationListFile {
            version: 1,
            issued_at: None,
            revocations: vec![entry(&sha, "rotated key")],
        };
        let list = RevocationList::from_file(f).unwrap();
        assert!(list.lookup(&"b".repeat(64)).is_some());
    }

    #[test]
    fn rejects_unsupported_version() {
        let f = RevocationListFile {
            version: 2,
            issued_at: None,
            revocations: Vec::new(),
        };
        let err = RevocationList::from_file(f).unwrap_err().to_string();
        assert!(err.contains("schema version 2 not supported"), "{err}");
    }

    #[test]
    fn rejects_short_hex() {
        let f = RevocationListFile {
            version: 1,
            issued_at: None,
            revocations: vec![entry("deadbeef", "bug")],
        };
        let err = RevocationList::from_file(f).unwrap_err().to_string();
        assert!(err.contains("invalid artifact_sha256"), "{err}");
    }

    #[test]
    fn rejects_non_hex() {
        let f = RevocationListFile {
            version: 1,
            issued_at: None,
            revocations: vec![entry(&"z".repeat(64), "bug")],
        };
        let err = RevocationList::from_file(f).unwrap_err().to_string();
        assert!(err.contains("invalid artifact_sha256"), "{err}");
    }

    #[test]
    fn rejects_empty_reason() {
        let sha = "a".repeat(64);
        let f = RevocationListFile {
            version: 1,
            issued_at: None,
            revocations: vec![entry(&sha, "   ")],
        };
        let err = RevocationList::from_file(f).unwrap_err().to_string();
        assert!(err.contains("missing a reason"), "{err}");
    }

    #[test]
    fn rejects_duplicate_entry() {
        let sha = "a".repeat(64);
        let f = RevocationListFile {
            version: 1,
            issued_at: None,
            revocations: vec![entry(&sha, "first"), entry(&sha, "second")],
        };
        let err = RevocationList::from_file(f).unwrap_err().to_string();
        assert!(err.contains("duplicate entry"), "{err}");
    }

    #[test]
    fn from_file_path_reads_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revocations.json");
        let sha = "a".repeat(64);
        let body = serde_json::json!({
            "version": 1,
            "issued_at": "2026-04-27T00:00:00Z",
            "revocations": [
                {
                    "artifact_sha256": sha,
                    "reason": "compromised",
                    "revoked_at": "2026-04-27T00:00:00Z",
                }
            ]
        });
        std::fs::write(&path, body.to_string()).unwrap();
        let list = RevocationList::from_file_path(&path).unwrap();
        assert_eq!(list.len(), 1);
        let entry = list.lookup(&sha).unwrap();
        assert_eq!(entry.reason, "compromised");
        assert_eq!(entry.revoked_at.as_deref(), Some("2026-04-27T00:00:00Z"));
    }

    #[test]
    fn from_file_path_surfaces_io_error() {
        let err = RevocationList::from_file_path(Path::new("/no/such/file"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed to read"), "{err}");
    }

    #[test]
    fn from_file_path_surfaces_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revocations.json");
        std::fs::write(&path, b"not valid json").unwrap();
        let err = RevocationList::from_file_path(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed to parse"), "{err}");
    }
}
