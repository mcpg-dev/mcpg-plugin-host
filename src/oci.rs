//! OCI distribution for packaged plugins.
//!
//! Pushes a packaged `.zip` plugin archive to an OCI registry
//! as an OCI 1.1 Artifact — not a container image. Registries
//! that understand the artifact spec (GHCR, Docker Hub, Harbor,
//! ECR, Artifactory 7.6+, Zot, …) can store and serve these
//! blobs; `docker pull` will reject them because the config
//! media type is not `application/vnd.oci.image.config.v1+json`.
//!
//! # Artefact shape
//!
//! For a plugin published as `ghcr.io/org/circuit-breaker:1.0.0`
//! the pushed bytes are:
//!
//! ```text
//! manifest  application/vnd.oci.image.manifest.v1+json
//!   config    application/vnd.mcpg.plugin.config.v1+json   (tiny JSON, see below)
//!   layers[0] application/vnd.mcpg.plugin.package.v1+zip   (the zip archive bytes verbatim)
//! ```
//!
//! Config JSON carries the descriptor fields that downstream
//! tooling (registry UIs, catalog crawlers) might want without
//! having to unzip the layer:
//!
//! ```json
//! {
//!     "id": "dev.mcpg.circuit-breaker",
//!     "name": "Circuit Breaker",
//!     "class": "tool_gate",
//!     "runtime": "native-cdylib-v1",
//!     "protocol_version": "1.0",
//!     "schema": "mcpg.dev/plugin/v1",
//!     "has_signature": true
//! }
//! ```
//!
//! # Boundaries
//!
//! This module deals only with the wire format and the push /
//! pull round trip. The bytes pushed are produced by
//! [`crate::Package::pack`]; the bytes pulled are handed back to
//! [`crate::Package::unpack_to`]. No verification, caching, or
//! trust-config logic lives here — that is upstream concern.

use std::path::{Path, PathBuf};

use oci_client::{
    Reference,
    client::{Client, ClientConfig, ClientProtocol, Config, ImageLayer},
    manifest::OciImageManifest,
    secrets::RegistryAuth,
};
use thiserror::Error;

use crate::Package;
use crate::PackageError;

/// Host forms that are always treated as plain-HTTP unless the caller
/// explicitly overrides. Mirrors Docker's "insecure registries"
/// heuristic so local development against a `registry:2` container on
/// `localhost:5000` works without configuration.
///
/// The match is on the EXACT host component (port stripped) — a public
/// host that merely begins with one of these (`localhost.example.com`,
/// `127.0.0.1.evil.com`) is a remote registry and must stay on HTTPS.
const LOCALHOST_HOSTS: &[&str] = &["localhost", "127.0.0.1", "[::1]", "::1"];

/// True when `registry` (a `host` or `host:port`, possibly bracketed
/// IPv6) names a loopback host exactly. The host component is compared
/// against [`LOCALHOST_HOSTS`] after stripping any `:port`, so
/// `localhost:5000` and `[::1]:5002` match but `localhost.attacker.io`
/// does not.
fn is_localhost_registry(registry: &str) -> bool {
    // Bracketed IPv6: `[::1]` or `[::1]:port` — the host is the text
    // inside the brackets.
    if let Some(rest) = registry.strip_prefix('[') {
        return rest
            .split_once(']')
            .is_some_and(|(host, _port)| LOCALHOST_HOSTS.contains(&host));
    }
    // `host` or `host:port`. A bare unbracketed IPv6 (`::1`) carries more
    // than one colon and no port, so only strip a trailing `:port` when
    // the remaining host part has no further colon.
    let host = match registry.rsplit_once(':') {
        Some((host, _port)) if !host.contains(':') => host,
        _ => registry,
    };
    LOCALHOST_HOSTS.contains(&host)
}

/// Transport options for [`push`] and [`pull`].
///
/// `insecure_registries` lists hostnames (optionally `host:port`) that
/// the client should talk to over plain HTTP instead of HTTPS.
/// Localhost variants (`localhost`, `127.0.0.1`, `::1`) — regardless of
/// port — are always implicitly plain-HTTP, matching Docker's
/// `--insecure-registry` default.
#[derive(Debug, Clone, Default)]
pub struct OciClientOptions {
    /// Extra hostnames (optionally `host:port`) to serve over HTTP.
    /// Localhost variants are always implicitly included.
    pub insecure_registries: Vec<String>,
}

impl OciClientOptions {
    /// Build a `ClientConfig` whose `HttpsExcept` list includes every
    /// caller-provided insecure registry PLUS any localhost-prefixed
    /// form of `reference_registry` (`localhost`, `localhost:5000`,
    /// etc.), so the caller doesn't have to know the port in advance.
    fn client_config_for(&self, reference_registry: &str) -> ClientConfig {
        let mut insecure: Vec<String> = self.insecure_registries.clone();
        if is_localhost_registry(reference_registry)
            && !insecure.iter().any(|h| h == reference_registry)
        {
            insecure.push(reference_registry.to_owned());
        }
        ClientConfig {
            protocol: ClientProtocol::HttpsExcept(insecure),
            ..ClientConfig::default()
        }
    }
}

/// Media type for the OCI artifact's config blob.
pub const CONFIG_MEDIA_TYPE: &str = "application/vnd.mcpg.plugin.config.v1+json";

/// Media type for the OCI artifact's single layer (the zip
/// produced by [`crate::Package::pack`]).
pub const LAYER_MEDIA_TYPE: &str = "application/vnd.mcpg.plugin.package.v1+zip";

/// The `artifactType` annotation set at the image-index level so
/// registries' type filters can find MCPG plugins without having
/// to inspect the manifest.
pub const ARTIFACT_TYPE: &str = "application/vnd.mcpg.plugin.v1";

/// Errors returned by [`push`] / [`pull`].
#[derive(Debug, Error)]
pub enum OciError {
    #[error("invalid reference {reference:?}: {source}")]
    InvalidReference {
        reference: String,
        #[source]
        source: oci_client::ParseError,
    },
    #[error("package I/O error: {0}")]
    Package(#[from] PackageError),
    #[error("OCI distribution error: {0}")]
    Distribution(#[from] oci_client::errors::OciDistributionError),
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "pulled artefact has no MCPG plugin layer (expected mediaType {expected:?}, \
         manifest declared {found:?})"
    )]
    WrongLayer {
        expected: String,
        found: Vec<String>,
    },
    #[error("pulled manifest digest {got:?} does not match the pinned digest {expected:?}")]
    DigestMismatch { expected: String, got: String },
}

/// Credential strategy for talking to a registry.
#[derive(Debug, Clone)]
pub enum OciAuth {
    /// Anonymous — for public registries or pull-through proxies.
    Anonymous,
    /// Username + password / bearer token.
    Basic { username: String, password: String },
}

impl OciAuth {
    fn into_registry_auth(self) -> RegistryAuth {
        match self {
            Self::Anonymous => RegistryAuth::Anonymous,
            Self::Basic { username, password } => RegistryAuth::Basic(username, password),
        }
    }
}

/// Minimal metadata embedded in the config blob so registry
/// tooling can render it without pulling the layer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginArtifactConfig {
    pub id: String,
    pub name: String,
    pub class: String,
    pub runtime: String,
    pub protocol_version: String,
    pub schema: String,
    pub has_signature: bool,
}

/// Successful result of [`push`].
#[derive(Debug, Clone)]
pub struct PushOutcome {
    /// The `<sha256>@<hex>` digest of the published manifest.
    pub manifest_digest: String,
    /// Pullable URL the registry returned.
    pub manifest_url: String,
}

/// Push a packaged plugin (`.zip`) to an OCI registry under the
/// given reference (e.g. `ghcr.io/mcpg-dev/circuit-breaker:1.0.0`).
///
/// The archive is unpacked into an ephemeral temp directory only
/// to derive the config-blob fields from the descriptor; the
/// layer body is the zip bytes verbatim, not the unpacked files.
pub async fn push(
    archive_path: &Path,
    reference_str: &str,
    auth: OciAuth,
    options: OciClientOptions,
) -> Result<PushOutcome, OciError> {
    let reference: Reference =
        reference_str
            .parse()
            .map_err(|e: oci_client::ParseError| OciError::InvalidReference {
                reference: reference_str.to_owned(),
                source: e,
            })?;

    // Read the zip bytes for the layer.
    let layer_bytes = std::fs::read(archive_path).map_err(|e| OciError::Io {
        path: archive_path.to_path_buf(),
        source: e,
    })?;

    // Unpack just to parse the descriptor for config-blob
    // metadata. The layer body is the ORIGINAL zip.
    let tmp = tempfile::TempDir::new().map_err(|e| OciError::Io {
        path: std::env::temp_dir(),
        source: e,
    })?;
    let unpacked = Package::unpack_to(archive_path, tmp.path())?;
    let artifact_config = PluginArtifactConfig {
        id: unpacked.descriptor.id.clone(),
        name: unpacked.descriptor.name.clone(),
        class: unpacked.descriptor.class.to_string(),
        runtime: unpacked.descriptor.runtime.to_string(),
        protocol_version: unpacked.descriptor.protocol_version.clone(),
        schema: unpacked.descriptor.schema.clone(),
        has_signature: unpacked.signature_path.is_some(),
    };
    drop(unpacked);

    let config_json = serde_json::to_vec(&artifact_config).map_err(|e| OciError::Io {
        path: archive_path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
    })?;

    let layer = ImageLayer::new(layer_bytes, LAYER_MEDIA_TYPE.to_owned(), None);
    let config = Config::new(config_json, CONFIG_MEDIA_TYPE.to_owned(), None);

    let mut manifest = OciImageManifest::build(std::slice::from_ref(&layer), &config, None);
    // OCI 1.1 artifactType hint at the manifest level — registries
    // surface this in their list / filter UIs.
    manifest.artifact_type = Some(ARTIFACT_TYPE.to_owned());

    let client = Client::new(options.client_config_for(reference.registry()));
    let auth = auth.into_registry_auth();
    let resp = client
        .push(&reference, &[layer], config, &auth, Some(manifest))
        .await?;

    Ok(PushOutcome {
        manifest_digest: resp
            .manifest_url
            .split('/')
            .next_back()
            .unwrap_or("")
            .to_owned(),
        manifest_url: resp.manifest_url,
    })
}

/// Successful result of [`pull`].
#[derive(Debug, Clone)]
pub struct PullOutcome {
    /// The `sha256:<hex>` digest of the pulled manifest.
    pub manifest_digest: String,
    /// The `sha256:<hex>` digest of the MCPG plugin layer (the `.zip`
    /// bytes written to `output_path`), computed from the bytes
    /// actually received. This is the layer-content domain — the same
    /// domain as `signature.sha256`/`integrity.sha256` — so the caller
    /// can verify a cached copy against it.
    pub layer_digest: String,
    /// Path the `.zip` was written to (= the caller's requested
    /// `output_path`).
    pub output_path: PathBuf,
    /// Parsed config blob, if the manifest carried one with the
    /// MCPG media type. Useful for tooling that wants the
    /// descriptor fields without unzipping.
    pub config: Option<PluginArtifactConfig>,
}

/// Pull a packaged plugin from an OCI registry and write the
/// layer bytes to `output_path` as a `.zip` file. The caller is
/// expected to verify the result via
/// [`crate::Package::unpack_to`] and any further trust checks.
///
/// When `expected_digest` is `Some` (the caller pinned the manifest
/// via `@sha256:<hex>`), the resolved manifest digest is re-asserted
/// against it BEFORE the layer is persisted; a mismatch is rejected
/// without writing a (potentially substituted) cache file. The
/// argument is the bare hex, with or without a leading `sha256:`.
pub async fn pull(
    reference_str: &str,
    output_path: &Path,
    auth: OciAuth,
    options: OciClientOptions,
    expected_digest: Option<&str>,
) -> Result<PullOutcome, OciError> {
    let reference: Reference =
        reference_str
            .parse()
            .map_err(|e: oci_client::ParseError| OciError::InvalidReference {
                reference: reference_str.to_owned(),
                source: e,
            })?;

    let client = Client::new(options.client_config_for(reference.registry()));
    let auth = auth.into_registry_auth();

    let image_data = client
        .pull(&reference, &auth, vec![LAYER_MEDIA_TYPE])
        .await?;

    // Locate the one layer carrying the MCPG plugin zip.
    let Some(layer) = image_data
        .layers
        .iter()
        .find(|l| l.media_type == LAYER_MEDIA_TYPE)
    else {
        return Err(OciError::WrongLayer {
            expected: LAYER_MEDIA_TYPE.to_owned(),
            found: image_data
                .layers
                .iter()
                .map(|l| l.media_type.clone())
                .collect(),
        });
    };

    let manifest_digest = image_data.digest.unwrap_or_default();

    // Re-assert a caller-pinned manifest digest before persisting the
    // layer, so a substituted artefact never reaches the cache file the
    // downstream loader will trust. Compare hex-to-hex, case-insensitive,
    // tolerating an optional `sha256:` prefix on either side.
    if let Some(expected) = expected_digest {
        let strip = |s: &str| s.strip_prefix("sha256:").unwrap_or(s).to_owned();
        let got = strip(&manifest_digest);
        let want = strip(expected);
        if !got.eq_ignore_ascii_case(&want) {
            return Err(OciError::DigestMismatch {
                expected: expected.to_owned(),
                got: manifest_digest,
            });
        }
    }

    // Layer-content digest from the exact bytes received — the same
    // domain as the operator's `signature.sha256`/`integrity.sha256`
    // pin, so a cached copy can be checked against it.
    let layer_digest = layer.sha256_digest();

    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| OciError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    std::fs::write(output_path, &layer.data).map_err(|e| OciError::Io {
        path: output_path.to_path_buf(),
        source: e,
    })?;

    let config = if image_data.config.media_type == CONFIG_MEDIA_TYPE {
        serde_json::from_slice::<PluginArtifactConfig>(&image_data.config.data).ok()
    } else {
        None
    };

    Ok(PullOutcome {
        manifest_digest,
        layer_digest,
        output_path: output_path.to_path_buf(),
        config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_types_are_stable() {
        // These strings are part of the wire protocol — changing
        // them invalidates every published artefact. Lock them
        // into a test so accidental edits are caught.
        assert_eq!(
            CONFIG_MEDIA_TYPE,
            "application/vnd.mcpg.plugin.config.v1+json"
        );
        assert_eq!(
            LAYER_MEDIA_TYPE,
            "application/vnd.mcpg.plugin.package.v1+zip"
        );
        assert_eq!(ARTIFACT_TYPE, "application/vnd.mcpg.plugin.v1");
    }

    /// `client_config_for` must force plain-HTTP whenever the target
    /// registry's host looks like a localhost variant, regardless of
    /// the port chosen by the operator.
    #[test]
    fn client_config_plain_http_for_localhost_variants() {
        let opts = OciClientOptions::default();
        for registry in [
            "localhost",
            "localhost:5000",
            "localhost:18080",
            "127.0.0.1",
            "127.0.0.1:5001",
            "::1",
            "[::1]:5002",
        ] {
            let cfg = opts.client_config_for(registry);
            match cfg.protocol {
                ClientProtocol::HttpsExcept(ref hosts) => assert!(
                    hosts.iter().any(|h| h == registry),
                    "{registry} should be in insecure list, got {hosts:?}"
                ),
                other => panic!("expected HttpsExcept, got {other:?}"),
            }
        }
    }

    /// Non-localhost registries must NOT be silently demoted to HTTP.
    /// This is the important half of the test — a bug here would
    /// downgrade a real production push.
    #[test]
    fn client_config_keeps_https_for_public_registries() {
        let opts = OciClientOptions::default();
        for registry in ["ghcr.io", "harbor.internal", "registry-1.docker.io"] {
            let cfg = opts.client_config_for(registry);
            match cfg.protocol {
                ClientProtocol::HttpsExcept(ref hosts) => assert!(
                    !hosts.iter().any(|h| h == registry),
                    "{registry} must not be in insecure list, got {hosts:?}"
                ),
                other => panic!("expected HttpsExcept, got {other:?}"),
            }
        }
    }

    /// A public host that merely begins with a localhost token must NOT
    /// be demoted to plain HTTP — the match is on the exact host
    /// component, not a prefix.
    #[test]
    fn client_config_keeps_https_for_localhost_lookalikes() {
        let opts = OciClientOptions::default();
        for registry in [
            "localhost.attacker.example",
            "localhost.attacker.example:443",
            "127.0.0.1.evil.com",
            "localhostregistry.corp",
            "127.0.0.1evil:5000",
        ] {
            let cfg = opts.client_config_for(registry);
            match cfg.protocol {
                ClientProtocol::HttpsExcept(ref hosts) => assert!(
                    !hosts.iter().any(|h| h == registry),
                    "{registry} is not loopback and must stay HTTPS, got {hosts:?}"
                ),
                other => panic!("expected HttpsExcept, got {other:?}"),
            }
        }
    }

    /// Exact-host loopback detection across host-only, host:port, and
    /// bracketed/bare IPv6 forms — and the look-alike spoofs it rejects.
    #[test]
    fn is_localhost_registry_matches_exact_host_only() {
        for ok in [
            "localhost",
            "localhost:5000",
            "127.0.0.1",
            "127.0.0.1:5001",
            "::1",
            "[::1]",
            "[::1]:5002",
        ] {
            assert!(is_localhost_registry(ok), "{ok} should be localhost");
        }
        for bad in [
            "localhost.attacker.example",
            "127.0.0.1.evil.com",
            "localhostregistry.corp",
            "ghcr.io",
            "[2001:db8::1]:5000",
            "2001:db8::1",
        ] {
            assert!(!is_localhost_registry(bad), "{bad} must not be localhost");
        }
    }

    /// Operator-supplied `insecure_registries` get appended in
    /// addition to the localhost default set.
    #[test]
    fn client_config_merges_operator_supplied_insecure_list() {
        let opts = OciClientOptions {
            insecure_registries: vec!["dev.internal:5000".to_owned(), "air-gap.corp".to_owned()],
        };
        let cfg = opts.client_config_for("dev.internal:5000");
        let ClientProtocol::HttpsExcept(hosts) = cfg.protocol else {
            panic!("expected HttpsExcept protocol");
        };
        assert!(hosts.iter().any(|h| h == "dev.internal:5000"));
        assert!(hosts.iter().any(|h| h == "air-gap.corp"));
    }

    #[test]
    fn plugin_artifact_config_roundtrips_json() {
        let c = PluginArtifactConfig {
            id: "dev.mcpg.test".into(),
            name: "Test".into(),
            class: "tool_gate".into(),
            runtime: "native-cdylib-v1".into(),
            protocol_version: "1.0".into(),
            schema: "mcpg.dev/plugin/v1".into(),
            has_signature: true,
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: PluginArtifactConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, c.id);
        assert_eq!(back.class, c.class);
        assert_eq!(back.runtime, c.runtime);
        assert!(back.has_signature);
    }
}
