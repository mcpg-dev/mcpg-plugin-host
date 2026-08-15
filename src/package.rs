//! Packaged plugin artifact — the distributable form of an MCPG
//! plugin.
//!
//! A packaged plugin is a zip archive bundling the files an
//! operator needs to load a single plugin:
//!
//! ```text
//! plugin.yaml         — descriptor (required; schema mcpg.dev/plugin/v1)
//! plugin.so           — native cdylib artifact (mutually exclusive with plugin.wasm)
//! plugin.wasm         — wasm component artifact (mutually exclusive with plugin.so)
//! plugin.sig          — Ed25519 detached signature over the artifact (optional)
//! LICENSE             — full license text of the plugin's source license (optional)
//! ```
//!
//! Exactly one of `plugin.so` / `plugin.wasm` must be present.
//! Zip is the on-wire container because it is universally
//! supported across Linux / macOS / Windows tooling, including
//! standard GUI file managers — operators can inspect a package
//! without any MCPG-specific utility.
//!
//! # Canonical filename
//!
//! ```text
//! mcpg-plugin-<NAME>_<VERSION>_<OS>_<ARCH>.zip
//! ```
//!
//! where:
//!
//! * `<NAME>` is the last `.`-separated segment of the plugin's
//!   descriptor id (e.g. `circuit-breaker` from
//!   `dev.mcpg.circuit-breaker`).
//! * `<VERSION>` is the plugin crate's semver (from `Cargo.toml`,
//!   passed to the packager at build time — the descriptor does
//!   not carry version).
//! * `<OS>` / `<ARCH>` are the target platform triplet halves,
//!   e.g. `linux` / `amd64`, `darwin` / `arm64`. WASI artifacts
//!   use `wasi` / `wasm` because wasm components are not tied to
//!   a host platform.
//!
//! Use [`canonical_filename`] to construct this string from its
//! parts. The file's internal layout is authoritative; the
//! filename is a convention for distribution channels (HTTP
//! downloads, GitHub releases, OCI tags).
//!
//! # Boundaries
//!
//! This module deals only with the *packaging* of files on disk.
//! Verifying signatures, cross-checking descriptors against the
//! runtime manifest, and actually loading the artifact live in
//! [`crate::verify`], [`crate::descriptor`], and the native / wasm
//! loaders respectively. A typical load flow is:
//!
//! 1. `Package::unpack_to(&path, &tmp_dir)` — extract the archive.
//! 2. `crate::load_descriptor(&tmp_dir.join("plugin.yaml"))`.
//! 3. Verify the artifact with [`crate::verify`] using the
//!    embedded `plugin.sig` and trusted public keys.
//! 4. Load via the appropriate loader (native / wasm) and register
//!    via [`crate::FirstPartyRegistrar::register_with_descriptor`].

use std::fs;
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::descriptor::DescriptorError;
use mcpg_plugin_protocol::PluginDescriptor;

/// Canonical entry names inside a packaged plugin archive.
pub mod entry {
    pub const DESCRIPTOR: &str = "plugin.yaml";
    pub const NATIVE_ARTIFACT: &str = "plugin.so";
    pub const WASM_ARTIFACT: &str = "plugin.wasm";
    pub const SIGNATURE: &str = "plugin.sig";
    pub const LICENSE: &str = "LICENSE";
}

/// Errors returned by [`Package::pack`] / [`Package::unpack_to`].
#[derive(Debug, Error)]
pub enum PackageError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid descriptor in package: {0}")]
    Descriptor(#[from] DescriptorError),
    #[error("zip error in {path}: {source}")]
    Zip {
        path: PathBuf,
        #[source]
        source: zip::result::ZipError,
    },
    #[error(
        "packaged plugin must contain exactly one of plugin.so or plugin.wasm; found {found:?}"
    )]
    AmbiguousArtifact { found: Vec<String> },
    #[error("packaged plugin is missing its artifact (neither plugin.so nor plugin.wasm)")]
    MissingArtifact,
    #[error("packaged plugin is missing plugin.yaml")]
    MissingDescriptor,
    #[error("unexpected entry in package: {0}")]
    UnexpectedEntry(String),
}

/// Classification of the artifact a package carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    /// Native cdylib — unpacks to `plugin.so`.
    Native,
    /// Wasi Component Model module — unpacks to `plugin.wasm`.
    Wasm,
}

impl ArtifactKind {
    /// Filename the artifact takes inside the archive.
    #[must_use]
    pub const fn archive_entry(self) -> &'static str {
        match self {
            Self::Native => entry::NATIVE_ARTIFACT,
            Self::Wasm => entry::WASM_ARTIFACT,
        }
    }
}

/// Source material to pack into a new archive. The paths are
/// resolved at [`Package::pack`] time, not stored.
pub struct PackInputs<'a> {
    pub descriptor_path: &'a Path,
    pub artifact_path: &'a Path,
    pub artifact_kind: ArtifactKind,
    /// Optional Ed25519 detached signature over the artifact
    /// bytes. Signing itself is done outside this module
    /// (`mcpg-plugin sign` or an external signer); this just
    /// passes the bytes through.
    pub signature_path: Option<&'a Path>,
    /// Optional full license text of the plugin's source license,
    /// stored as the `LICENSE` entry so distributed artifacts carry
    /// their license terms.
    pub license_path: Option<&'a Path>,
}

/// The in-memory contents of an unpacked package. Returned by
/// [`Package::unpack_to`] so callers can hand the individual
/// file paths to downstream loaders without re-reading the zip.
#[derive(Debug)]
pub struct UnpackedPackage {
    /// Descriptor parsed and schema-validated.
    pub descriptor: PluginDescriptor,
    /// Path to `plugin.yaml` on disk (inside the target directory).
    pub descriptor_path: PathBuf,
    /// Which kind of artifact the package carried.
    pub artifact_kind: ArtifactKind,
    /// Path to `plugin.so` or `plugin.wasm` on disk.
    pub artifact_path: PathBuf,
    /// Path to `plugin.sig` if the archive included one, else
    /// `None`. Signature verification is not performed here.
    pub signature_path: Option<PathBuf>,
    /// Path to `LICENSE` if the archive included one, else `None`.
    pub license_path: Option<PathBuf>,
}

/// Build the canonical distribution filename for a packaged
/// plugin.
///
/// Format: `mcpg-plugin-<name>_<version>_<os>_<arch>.zip`.
///
/// `name` is the last `.`-separated segment of the descriptor id
/// (see module docs). Callers typically use
/// [`short_name_from_id`] to derive it.
#[must_use]
pub fn canonical_filename(name: &str, version: &str, os: &str, arch: &str) -> String {
    format!("mcpg-plugin-{name}_{version}_{os}_{arch}.zip")
}

/// Derive the short plugin name used in the canonical filename
/// from a reverse-DNS plugin id.
///
/// Returns the last `.`-separated segment. Examples:
///
/// * `dev.mcpg.circuit-breaker` → `circuit-breaker`
/// * `org.mcpg.backend.kafka`   → `kafka`
/// * `acme`                     → `acme`
#[must_use]
pub fn short_name_from_id(id: &str) -> &str {
    id.rsplit('.').next().unwrap_or(id)
}

/// Pack / unpack entry points. All methods are stateless; there
/// is no `Package` struct to hold.
pub struct Package;

impl Package {
    /// Build a zip archive from the given inputs and write it to
    /// `output_path`.
    pub fn pack(inputs: &PackInputs<'_>, output_path: &Path) -> Result<(), PackageError> {
        let out_file = fs::File::create(output_path).map_err(|e| PackageError::Io {
            path: output_path.to_path_buf(),
            source: e,
        })?;
        let mut zipw = zip::ZipWriter::new(out_file);
        let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o644);

        append_file(
            &mut zipw,
            inputs.descriptor_path,
            entry::DESCRIPTOR,
            options,
            output_path,
        )?;
        // Artifact keeps the executable bit; the gateway doesn't
        // execute cdylibs directly but consumers may stash them
        // in other tools.
        let artifact_options: zip::write::SimpleFileOptions = options.unix_permissions(0o755);
        append_file(
            &mut zipw,
            inputs.artifact_path,
            inputs.artifact_kind.archive_entry(),
            artifact_options,
            output_path,
        )?;
        if let Some(sig) = inputs.signature_path {
            append_file(&mut zipw, sig, entry::SIGNATURE, options, output_path)?;
        }
        if let Some(license) = inputs.license_path {
            append_file(&mut zipw, license, entry::LICENSE, options, output_path)?;
        }

        zipw.finish().map_err(|e| PackageError::Zip {
            path: output_path.to_path_buf(),
            source: e,
        })?;
        Ok(())
    }

    /// Unpack a zip archive into `target_dir` — but skip the
    /// extraction work if `target_dir` already holds files whose
    /// sha256 fingerprint matches the archive's.
    ///
    /// Unlike [`Self::unpack_to`], which always re-extracts, this
    /// method is safe to call on every gateway boot. The cache
    /// key is the archive's sha256; callers typically pass a
    /// `base_cache_dir` of the form `<OS temp>/mcpg-plugin-cache/<id>/`
    /// so multiple versions of the same plugin coexist under the
    /// same parent.
    ///
    /// Semantics:
    ///
    /// * The effective target directory is
    ///   `base_cache_dir.join(<first 16 hex chars of the zip's sha256>)`.
    /// * If that directory already contains a valid `plugin.yaml`
    ///   and one of `plugin.so` / `plugin.wasm`, the archive is
    ///   assumed to have been unpacked previously and the method
    ///   short-circuits without touching the zip beyond the hash
    ///   computation.
    /// * Otherwise the archive is unpacked into that directory,
    ///   overwriting any partially-extracted remnants.
    ///
    /// Callers get the same [`UnpackedPackage`] shape either way,
    /// so the cached and fresh paths are interchangeable.
    pub fn unpack_cached_to(
        archive_path: &Path,
        base_cache_dir: &Path,
    ) -> Result<UnpackedPackage, PackageError> {
        let hash = crate::verify::sha256_file(archive_path).map_err(|e| PackageError::Io {
            path: archive_path.to_path_buf(),
            source: std::io::Error::other(e),
        })?;
        let cache_key: String = hash.chars().take(16).collect();
        let target_dir = base_cache_dir.join(&cache_key);

        if let Some(existing) = inspect_cache_hit(&target_dir)? {
            return Ok(existing);
        }

        Self::unpack_to(archive_path, &target_dir)
    }

    /// Unpack a zip archive into `target_dir` and return a
    /// description of what was found. The target directory is
    /// created if it does not exist. Any pre-existing files in
    /// the target with colliding names are overwritten.
    ///
    /// The descriptor is parsed + schema-checked inline; the
    /// artifact and optional signature are only extracted to disk
    /// — verification / loading is the caller's job.
    pub fn unpack_to(
        archive_path: &Path,
        target_dir: &Path,
    ) -> Result<UnpackedPackage, PackageError> {
        fs::create_dir_all(target_dir).map_err(|e| PackageError::Io {
            path: target_dir.to_path_buf(),
            source: e,
        })?;

        let file = fs::File::open(archive_path).map_err(|e| PackageError::Io {
            path: archive_path.to_path_buf(),
            source: e,
        })?;
        let mut zipa = zip::ZipArchive::new(file).map_err(|e| PackageError::Zip {
            path: archive_path.to_path_buf(),
            source: e,
        })?;

        let mut seen_native = false;
        let mut seen_wasm = false;
        let mut seen_descriptor = false;
        let mut seen_signature = false;
        let mut seen_license = false;

        for idx in 0..zipa.len() {
            let mut entry = zipa.by_index(idx).map_err(|e| PackageError::Zip {
                path: archive_path.to_path_buf(),
                source: e,
            })?;
            if entry.is_dir() {
                return Err(PackageError::UnexpectedEntry(entry.name().to_owned()));
            }
            // `enclosed_name` rejects absolute paths and `..`
            // components; None means the entry escapes the archive
            // root.
            let Some(enclosed) = entry.enclosed_name() else {
                return Err(PackageError::UnexpectedEntry(entry.name().to_owned()));
            };
            // Defense in depth: also reject nested paths — every
            // expected entry lives at the archive root.
            if enclosed.components().count() != 1 {
                return Err(PackageError::UnexpectedEntry(entry.name().to_owned()));
            }
            let name = enclosed
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_owned();

            let dest = target_dir.join(&name);
            match name.as_str() {
                entry::DESCRIPTOR => {
                    seen_descriptor = true;
                    extract_entry(&mut entry, &dest)?;
                }
                entry::NATIVE_ARTIFACT => {
                    seen_native = true;
                    extract_entry(&mut entry, &dest)?;
                }
                entry::WASM_ARTIFACT => {
                    seen_wasm = true;
                    extract_entry(&mut entry, &dest)?;
                }
                entry::SIGNATURE => {
                    seen_signature = true;
                    extract_entry(&mut entry, &dest)?;
                }
                entry::LICENSE => {
                    seen_license = true;
                    extract_entry(&mut entry, &dest)?;
                }
                other => {
                    return Err(PackageError::UnexpectedEntry(other.to_owned()));
                }
            }
        }

        if !seen_descriptor {
            return Err(PackageError::MissingDescriptor);
        }
        match (seen_native, seen_wasm) {
            (false, false) => return Err(PackageError::MissingArtifact),
            (true, true) => {
                return Err(PackageError::AmbiguousArtifact {
                    found: vec![
                        entry::NATIVE_ARTIFACT.to_owned(),
                        entry::WASM_ARTIFACT.to_owned(),
                    ],
                });
            }
            _ => {}
        }

        let descriptor_path = target_dir.join(entry::DESCRIPTOR);
        let descriptor = crate::load_descriptor(&descriptor_path)?;

        let (artifact_kind, artifact_path) = if seen_native {
            (
                ArtifactKind::Native,
                target_dir.join(entry::NATIVE_ARTIFACT),
            )
        } else {
            (ArtifactKind::Wasm, target_dir.join(entry::WASM_ARTIFACT))
        };

        let signature_path = if seen_signature {
            Some(target_dir.join(entry::SIGNATURE))
        } else {
            None
        };

        let license_path = if seen_license {
            Some(target_dir.join(entry::LICENSE))
        } else {
            None
        };

        Ok(UnpackedPackage {
            descriptor,
            descriptor_path,
            artifact_kind,
            artifact_path,
            signature_path,
            license_path,
        })
    }
}

/// Return `Some(UnpackedPackage)` if `target_dir` already holds
/// a coherent unpacked package from a previous run; `None`
/// otherwise. Used by [`Package::unpack_cached_to`] to skip
/// re-extraction on subsequent gateway boots.
///
/// A directory is considered a cache hit when:
///
/// * `plugin.yaml` exists AND parses (+ passes schema check);
/// * exactly one of `plugin.so` / `plugin.wasm` exists.
///
/// Any other shape (missing descriptor, both artifacts,
/// artifact missing, unparseable yaml) is treated as a miss, in
/// which case the caller re-extracts from scratch.
fn inspect_cache_hit(target_dir: &Path) -> Result<Option<UnpackedPackage>, PackageError> {
    if !target_dir.is_dir() {
        return Ok(None);
    }
    let descriptor_path = target_dir.join(entry::DESCRIPTOR);
    if !descriptor_path.is_file() {
        return Ok(None);
    }

    let native_path = target_dir.join(entry::NATIVE_ARTIFACT);
    let wasm_path = target_dir.join(entry::WASM_ARTIFACT);
    let (artifact_kind, artifact_path) = match (native_path.is_file(), wasm_path.is_file()) {
        (true, false) => (ArtifactKind::Native, native_path),
        (false, true) => (ArtifactKind::Wasm, wasm_path),
        _ => return Ok(None),
    };

    // Parse descriptor. A parse failure treats the cache dir as
    // corrupt and falls back to re-extraction.
    let descriptor = match crate::load_descriptor(&descriptor_path) {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };

    let sig_candidate = target_dir.join(entry::SIGNATURE);
    let signature_path = sig_candidate.is_file().then_some(sig_candidate);

    let license_candidate = target_dir.join(entry::LICENSE);
    let license_path = license_candidate.is_file().then_some(license_candidate);

    Ok(Some(UnpackedPackage {
        descriptor,
        descriptor_path,
        artifact_kind,
        artifact_path,
        signature_path,
        license_path,
    }))
}

fn append_file<W: Write + Seek>(
    writer: &mut zip::ZipWriter<W>,
    src: &Path,
    name_in_archive: &str,
    options: zip::write::SimpleFileOptions,
    archive_path_for_err: &Path,
) -> Result<(), PackageError> {
    let mut f = fs::File::open(src).map_err(|e| PackageError::Io {
        path: src.to_path_buf(),
        source: e,
    })?;
    writer
        .start_file(name_in_archive, options)
        .map_err(|e| PackageError::Zip {
            path: archive_path_for_err.to_path_buf(),
            source: e,
        })?;
    io::copy(&mut f, writer).map_err(|e| PackageError::Io {
        path: src.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

fn extract_entry<R: Read>(entry: &mut R, dest: &Path) -> Result<(), PackageError> {
    let mut out = fs::File::create(dest).map_err(|e| PackageError::Io {
        path: dest.to_path_buf(),
        source: e,
    })?;
    io::copy(entry, &mut out).map_err(|e| PackageError::Io {
        path: dest.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_descriptor_yaml() -> &'static str {
        "\
schema: mcpg.dev/plugin/v1
id: dev.mcpg.pkg.example
name: Packaging Example
description: Test plugin for packaging
class: tool_gate
runtime: static-firstparty-v1
protocol_version: \"1.0\"
required_capabilities: []
"
    }

    fn staging_dir() -> TempDir {
        TempDir::new().expect("create tempdir")
    }

    fn write_file(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn pack_and_unpack_native_roundtrip() {
        let src = staging_dir();
        let descriptor = write_file(
            src.path(),
            "plugin.yaml",
            sample_descriptor_yaml().as_bytes(),
        );
        let artifact = write_file(src.path(), "plugin.so", b"not-really-a-dylib");
        let signature = write_file(src.path(), "plugin.sig", b"sig-bytes");

        let out_dir = staging_dir();
        let archive = out_dir
            .path()
            .join(canonical_filename("example", "1.0.0", "linux", "amd64"));
        Package::pack(
            &PackInputs {
                descriptor_path: &descriptor,
                artifact_path: &artifact,
                artifact_kind: ArtifactKind::Native,
                signature_path: Some(&signature),
                license_path: None,
            },
            &archive,
        )
        .unwrap();
        assert!(archive.exists());

        let unpack_dir = staging_dir();
        let unpacked = Package::unpack_to(&archive, unpack_dir.path()).unwrap();

        assert_eq!(unpacked.artifact_kind, ArtifactKind::Native);
        assert_eq!(unpacked.descriptor.id, "dev.mcpg.pkg.example");
        assert_eq!(
            fs::read(&unpacked.artifact_path).unwrap(),
            b"not-really-a-dylib"
        );
        assert!(unpacked.signature_path.is_some());
        assert_eq!(
            fs::read(unpacked.signature_path.unwrap()).unwrap(),
            b"sig-bytes"
        );
    }

    #[test]
    fn pack_and_unpack_wasm_without_signature() {
        let src = staging_dir();
        let descriptor = write_file(
            src.path(),
            "plugin.yaml",
            sample_descriptor_yaml().as_bytes(),
        );
        let artifact = write_file(src.path(), "plugin.wasm", &[0, 0x61, 0x73, 0x6d]);

        let out_dir = staging_dir();
        let archive = out_dir
            .path()
            .join(canonical_filename("example", "1.0.0", "wasi", "wasm"));
        Package::pack(
            &PackInputs {
                descriptor_path: &descriptor,
                artifact_path: &artifact,
                artifact_kind: ArtifactKind::Wasm,
                signature_path: None,
                license_path: None,
            },
            &archive,
        )
        .unwrap();

        let unpack_dir = staging_dir();
        let unpacked = Package::unpack_to(&archive, unpack_dir.path()).unwrap();
        assert_eq!(unpacked.artifact_kind, ArtifactKind::Wasm);
        assert!(unpacked.signature_path.is_none());
    }

    #[test]
    fn pack_and_unpack_with_license_roundtrip() {
        let src = staging_dir();
        let descriptor = write_file(
            src.path(),
            "plugin.yaml",
            sample_descriptor_yaml().as_bytes(),
        );
        let artifact = write_file(src.path(), "plugin.so", b"bytes");
        let license = write_file(src.path(), "LICENSE", b"Apache License 2.0 full text");

        let out_dir = staging_dir();
        let archive = out_dir
            .path()
            .join(canonical_filename("example", "1.0.0", "linux", "amd64"));
        Package::pack(
            &PackInputs {
                descriptor_path: &descriptor,
                artifact_path: &artifact,
                artifact_kind: ArtifactKind::Native,
                signature_path: None,
                license_path: Some(&license),
            },
            &archive,
        )
        .unwrap();

        let unpack_dir = staging_dir();
        let unpacked = Package::unpack_to(&archive, unpack_dir.path()).unwrap();
        let license_path = unpacked.license_path.expect("archive carried a LICENSE");
        assert_eq!(
            fs::read(&license_path).unwrap(),
            b"Apache License 2.0 full text"
        );
        assert_eq!(
            license_path.file_name().and_then(|s| s.to_str()),
            Some(entry::LICENSE)
        );
    }

    #[test]
    fn cached_unpack_returns_license_on_hit() {
        // Both the fresh extraction and the cache-hit path surface
        // the LICENSE entry.
        let src = staging_dir();
        let descriptor = write_file(
            src.path(),
            "plugin.yaml",
            sample_descriptor_yaml().as_bytes(),
        );
        let artifact = write_file(src.path(), "plugin.so", b"bytes");
        let license = write_file(src.path(), "LICENSE", b"license text");
        let pkg = src.path().join("pkg.zip");
        Package::pack(
            &PackInputs {
                descriptor_path: &descriptor,
                artifact_path: &artifact,
                artifact_kind: ArtifactKind::Native,
                signature_path: None,
                license_path: Some(&license),
            },
            &pkg,
        )
        .unwrap();

        let cache_base = staging_dir();
        let fresh = Package::unpack_cached_to(&pkg, cache_base.path()).unwrap();
        assert!(fresh.license_path.is_some(), "fresh extraction has LICENSE");
        let hit = Package::unpack_cached_to(&pkg, cache_base.path()).unwrap();
        assert_eq!(fresh.license_path, hit.license_path);
    }

    #[test]
    fn canonical_filename_format_matches_spec() {
        assert_eq!(
            canonical_filename("circuit-breaker", "1.0.0", "linux", "amd64"),
            "mcpg-plugin-circuit-breaker_1.0.0_linux_amd64.zip"
        );
        assert_eq!(
            canonical_filename("masking", "0.2.3", "wasi", "wasm"),
            "mcpg-plugin-masking_0.2.3_wasi_wasm.zip"
        );
    }

    #[test]
    fn short_name_extracts_last_segment() {
        assert_eq!(
            short_name_from_id("dev.mcpg.circuit-breaker"),
            "circuit-breaker"
        );
        assert_eq!(short_name_from_id("dev.mcpg.backend.kafka"), "kafka");
        assert_eq!(short_name_from_id("simple"), "simple");
    }

    fn build_zip_with_entries(archive: &Path, entries: &[(&str, &[u8])]) {
        let file = fs::File::create(archive).unwrap();
        let mut w = zip::ZipWriter::new(file);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, body) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(body).unwrap();
        }
        w.finish().unwrap();
    }

    #[test]
    fn unpack_rejects_missing_descriptor() {
        let out_dir = staging_dir();
        let archive = out_dir.path().join("pkg.zip");
        build_zip_with_entries(&archive, &[("plugin.so", b"x")]);

        let unpack_dir = staging_dir();
        let err = Package::unpack_to(&archive, unpack_dir.path()).unwrap_err();
        assert!(matches!(err, PackageError::MissingDescriptor));
    }

    #[test]
    fn unpack_rejects_ambiguous_artifact() {
        let out_dir = staging_dir();
        let archive = out_dir.path().join("pkg.zip");
        build_zip_with_entries(
            &archive,
            &[
                ("plugin.yaml", sample_descriptor_yaml().as_bytes()),
                ("plugin.so", b"n"),
                ("plugin.wasm", b"w"),
            ],
        );

        let unpack_dir = staging_dir();
        let err = Package::unpack_to(&archive, unpack_dir.path()).unwrap_err();
        assert!(matches!(err, PackageError::AmbiguousArtifact { .. }));
    }

    #[test]
    fn unpack_rejects_unexpected_entry() {
        let out_dir = staging_dir();
        let archive = out_dir.path().join("pkg.zip");
        build_zip_with_entries(
            &archive,
            &[
                ("plugin.yaml", sample_descriptor_yaml().as_bytes()),
                ("plugin.so", b"n"),
                ("readme.txt", b"hi"),
            ],
        );

        let unpack_dir = staging_dir();
        let err = Package::unpack_to(&archive, unpack_dir.path()).unwrap_err();
        assert!(matches!(err, PackageError::UnexpectedEntry(ref n) if n == "readme.txt"));
    }

    #[test]
    fn unpack_rejects_nested_path_entries() {
        // Defense-in-depth: anything other than a bare filename at
        // the archive root is rejected, so a malicious archive with
        // `subdir/plugin.yaml` cannot slip files past the allowlist
        // of expected names. `enclosed_name` also rejects `..` and
        // absolute paths so directory traversal is caught earlier.
        let out_dir = staging_dir();
        let archive = out_dir.path().join("pkg.zip");
        build_zip_with_entries(
            &archive,
            &[("evil/plugin.yaml", sample_descriptor_yaml().as_bytes())],
        );

        let unpack_dir = staging_dir();
        let err = Package::unpack_to(&archive, unpack_dir.path()).unwrap_err();
        assert!(matches!(err, PackageError::UnexpectedEntry(_)));
    }

    // -- unpack_cached_to --------------------------------------------------

    fn valid_package(dir: &Path) -> PathBuf {
        let descriptor = write_file(dir, "plugin.yaml", sample_descriptor_yaml().as_bytes());
        let artifact = write_file(dir, "plugin.so", b"bytes");
        let out = dir.join("pkg.zip");
        Package::pack(
            &PackInputs {
                descriptor_path: &descriptor,
                artifact_path: &artifact,
                artifact_kind: ArtifactKind::Native,
                signature_path: None,
                license_path: None,
            },
            &out,
        )
        .unwrap();
        out
    }

    #[test]
    fn cached_unpack_populates_fresh_cache() {
        let src = staging_dir();
        let pkg = valid_package(src.path());
        let cache_base = staging_dir();
        let unpacked = Package::unpack_cached_to(&pkg, cache_base.path()).unwrap();
        assert_eq!(unpacked.descriptor.id, "dev.mcpg.pkg.example");
        assert!(unpacked.artifact_path.starts_with(cache_base.path()));
        // Cache dir uses the 16-char hash prefix as its name.
        let cache_key_dir = unpacked.artifact_path.parent().unwrap();
        assert_eq!(
            cache_key_dir
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap()
                .len(),
            16
        );
    }

    #[test]
    fn cached_unpack_reuses_existing_extraction() {
        // Second call on the same archive should return the same
        // paths without touching the cache again. We verify this
        // by mutating the cached artifact between calls and
        // observing the mutation on the second call — if the
        // second call re-extracted it would overwrite our edit.
        let src = staging_dir();
        let pkg = valid_package(src.path());
        let cache_base = staging_dir();
        let first = Package::unpack_cached_to(&pkg, cache_base.path()).unwrap();
        fs::write(&first.artifact_path, b"mutated").unwrap();
        let second = Package::unpack_cached_to(&pkg, cache_base.path()).unwrap();
        assert_eq!(first.artifact_path, second.artifact_path);
        assert_eq!(fs::read(&second.artifact_path).unwrap(), b"mutated");
    }

    #[test]
    fn cached_unpack_repopulates_corrupt_cache() {
        // If the cache dir is missing a required entry (e.g.
        // someone deleted the descriptor manually), the fallback
        // re-extraction runs and fixes it.
        let src = staging_dir();
        let pkg = valid_package(src.path());
        let cache_base = staging_dir();
        let first = Package::unpack_cached_to(&pkg, cache_base.path()).unwrap();
        // Corrupt the cache.
        fs::remove_file(&first.descriptor_path).unwrap();
        let second = Package::unpack_cached_to(&pkg, cache_base.path()).unwrap();
        assert!(second.descriptor_path.exists());
        assert_eq!(second.descriptor.id, "dev.mcpg.pkg.example");
    }

    #[test]
    fn cached_unpack_keys_on_sha256() {
        // Two different zips with the same descriptor but
        // different artifact bytes must end up in different
        // cache dirs.
        let src_a = staging_dir();
        let pkg_a = valid_package(src_a.path());
        let src_b = staging_dir();
        let desc_b = write_file(
            src_b.path(),
            "plugin.yaml",
            sample_descriptor_yaml().as_bytes(),
        );
        let artifact_b = write_file(src_b.path(), "plugin.so", b"DIFFERENT-BYTES");
        let pkg_b = src_b.path().join("pkg.zip");
        Package::pack(
            &PackInputs {
                descriptor_path: &desc_b,
                artifact_path: &artifact_b,
                artifact_kind: ArtifactKind::Native,
                signature_path: None,
                license_path: None,
            },
            &pkg_b,
        )
        .unwrap();

        let cache_base = staging_dir();
        let a = Package::unpack_cached_to(&pkg_a, cache_base.path()).unwrap();
        let b = Package::unpack_cached_to(&pkg_b, cache_base.path()).unwrap();
        assert_ne!(
            a.artifact_path.parent().unwrap(),
            b.artifact_path.parent().unwrap(),
            "different archive bytes must map to different cache dirs"
        );
    }
}
