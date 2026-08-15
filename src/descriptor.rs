//! Filesystem loader for `plugin.yaml` descriptors.
//!
//! Parsing itself lives in the in-code type
//! [`mcpg_plugin_protocol::PluginDescriptor`]. This module adds the
//! thin veneer of:
//!
//! * Reading a `plugin.yaml` file from disk.
//! * Cross-checking the declared descriptor against a plugin's
//!   runtime [`PluginManifest`](mcpg_plugin_protocol::PluginManifest) so
//!   a packaging drift (e.g. yaml says `transform`, Rust says
//!   `tool_gate`) is caught loudly at startup rather than producing
//!   wrong chain placement silently.
//!
//! The type signature is deliberately narrow — the loader takes a
//! path and returns a descriptor or a structured error; it never
//! reads more than the one file it was asked about.

use std::path::{Path, PathBuf};

use mcpg_plugin_protocol::{DESCRIPTOR_SCHEMA_V1, PluginDescriptor, PluginManifest};
use thiserror::Error;

/// Errors returned by [`load_descriptor`] and [`validate_descriptor`].
#[derive(Debug, Error)]
pub enum DescriptorError {
    #[error("failed to read plugin descriptor at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse plugin descriptor at {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("plugin descriptor schema mismatch at {path}: expected {expected}, got {found}")]
    UnknownSchema {
        path: PathBuf,
        expected: String,
        found: String,
    },
    #[error(
        "plugin descriptor disagrees with in-code manifest: field={field}, \
         descriptor={descriptor}, manifest={manifest}"
    )]
    ManifestMismatch {
        field: &'static str,
        descriptor: String,
        manifest: String,
    },
}

/// Load and parse a `plugin.yaml` descriptor from the given path.
///
/// The schema field is validated against
/// [`DESCRIPTOR_SCHEMA_V1`]; an unknown schema yields
/// [`DescriptorError::UnknownSchema`] so operators see a
/// descriptive error instead of a partial parse.
pub fn load_descriptor(path: impl AsRef<Path>) -> Result<PluginDescriptor, DescriptorError> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|e| DescriptorError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let descriptor: PluginDescriptor =
        serde_yaml::from_str(&raw).map_err(|e| DescriptorError::Parse {
            path: path.to_path_buf(),
            source: e,
        })?;
    if descriptor.schema != DESCRIPTOR_SCHEMA_V1 {
        return Err(DescriptorError::UnknownSchema {
            path: path.to_path_buf(),
            expected: DESCRIPTOR_SCHEMA_V1.to_owned(),
            found: descriptor.schema,
        });
    }
    Ok(descriptor)
}

/// Verify that a descriptor agrees with the plugin's in-code
/// [`PluginManifest`] on the fields that affect chain placement,
/// discovery, and compatibility.
///
/// Fields compared:
///
/// * `id` — reverse-DNS identifier
/// * `name` — display name
/// * `plugin_class` — determines chain slot
/// * `protocol_version` — semver compatibility gate
///
/// Version is **not** cross-checked because the descriptor omits
/// it by design (Cargo.toml is the source of truth for crate
/// version).
///
/// `required_capabilities` is **not** cross-checked:
/// the descriptor's typed `Vec<Capability>` and the
/// manifest's legacy `Vec<String>` describe the same concept in
/// different shapes; the authoritative source is the cdylib's
/// `PluginRegistration.capabilities` (read by `firstparty.rs`).
pub fn validate_descriptor(
    descriptor: &PluginDescriptor,
    manifest: &PluginManifest,
) -> Result<(), DescriptorError> {
    if descriptor.id != manifest.id {
        return Err(DescriptorError::ManifestMismatch {
            field: "id",
            descriptor: descriptor.id.clone(),
            manifest: manifest.id.clone(),
        });
    }
    if descriptor.name != manifest.name {
        return Err(DescriptorError::ManifestMismatch {
            field: "name",
            descriptor: descriptor.name.clone(),
            manifest: manifest.name.clone(),
        });
    }
    if descriptor.class != manifest.plugin_class {
        return Err(DescriptorError::ManifestMismatch {
            field: "class",
            descriptor: descriptor.class.to_string(),
            manifest: manifest.plugin_class.to_string(),
        });
    }
    // `protocol_version` follows the host's semver rule: same major
    // = compatible (additive minors allowed). Plugins authored
    // against `1.0` continue to load on a `1.22` host without YAML
    // edits — matches the WARN-only behaviour of
    // `PluginRegistry::validate_manifest` for the same field, and
    // matches the documented loadability rule on
    // `mcpg_plugin_protocol::PROTOCOL_VERSION`. A major-version
    // mismatch (e.g. descriptor `2.0` vs manifest `1.22`) is still
    // fatal — that's an explicit ABI break.
    let descriptor_major = descriptor.protocol_version.split('.').next().unwrap_or("");
    let manifest_major = manifest.protocol_version.split('.').next().unwrap_or("");
    if descriptor_major != manifest_major {
        return Err(DescriptorError::ManifestMismatch {
            field: "protocol_version",
            descriptor: descriptor.protocol_version.clone(),
            manifest: manifest.protocol_version.clone(),
        });
    }
    // Capability declarations live on
    // `PluginRegistration.capabilities` (typed) for cdylibs. The
    // legacy `manifest.required_capabilities: Vec<String>` field is
    // retained for display purposes only and is not cross-checked
    // against the descriptor's typed `required_capabilities`. The
    // authoritative check is in `firstparty.rs::register_with_descriptor`
    // against the operator's typed `granted_capabilities`.

    // Cluster slot-role `provides` IS cross-checked:
    // the descriptor (`plugin.yaml`) and
    // the in-code manifest must declare the same role set so a
    // coordinator's wiring affordances can't silently drift between the
    // two surfaces. Order-independent (compare as sets); empty == empty
    // for the non-cluster classes that never set it.
    {
        use std::collections::BTreeSet;
        let d: BTreeSet<&str> = descriptor.provides.iter().map(String::as_str).collect();
        let m: BTreeSet<&str> = manifest.provides.iter().map(String::as_str).collect();
        if d != m {
            return Err(DescriptorError::ManifestMismatch {
                field: "provides",
                descriptor: descriptor.provides.join(","),
                manifest: manifest.provides.join(","),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::{PluginClass, RuntimeClass};
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn tmp_yaml(contents: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f
    }

    #[test]
    fn load_accepts_valid_descriptor() {
        let f = tmp_yaml(
            r#"
schema: mcpg.dev/plugin/v1
id: dev.mcpg.example
name: Example
description: A demo plugin.
class: tool_gate
runtime: static-firstparty-v1
protocol_version: "1.0"
required_capabilities: []
"#,
        );
        let d = load_descriptor(f.path()).unwrap();
        assert_eq!(d.id, "dev.mcpg.example");
        assert_eq!(d.class, PluginClass::ToolGate);
        assert_eq!(d.runtime, RuntimeClass::StaticFirstparty);
    }

    #[test]
    fn load_rejects_unknown_schema() {
        let f = tmp_yaml(
            r#"
schema: mcpg.dev/plugin/v99
id: x
name: X
class: tool_gate
runtime: static-firstparty-v1
protocol_version: "1.0"
"#,
        );
        let err = load_descriptor(f.path()).unwrap_err();
        match err {
            DescriptorError::UnknownSchema { found, .. } => {
                assert_eq!(found, "mcpg.dev/plugin/v99")
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn load_reports_parse_errors_with_path() {
        let f = tmp_yaml("not: [yaml: at all");
        let err = load_descriptor(f.path()).unwrap_err();
        assert!(matches!(err, DescriptorError::Parse { .. }));
    }

    #[test]
    fn load_reports_missing_file_with_path() {
        let err = load_descriptor("/definitely/does/not/exist/plugin.yaml").unwrap_err();
        assert!(matches!(err, DescriptorError::Io { .. }));
    }

    fn make_manifest(id: &str, class: PluginClass) -> PluginManifest {
        PluginManifest {
            id: id.into(),
            version: "1.0.0".into(),
            name: format!("Plugin {id}"),
            plugin_class: class,
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
        }
    }

    fn make_descriptor(id: &str, class: PluginClass) -> PluginDescriptor {
        PluginDescriptor {
            schema: DESCRIPTOR_SCHEMA_V1.into(),
            id: id.into(),
            name: format!("Plugin {id}"),
            description: String::new(),
            class,
            runtime: RuntimeClass::StaticFirstparty,
            protocol_version: "1.0".into(),
            license: None,
            required_capabilities: vec![],
            tags: Vec::new(),
            provides: Vec::new(),
            provides_schemes: Vec::new(),
        }
    }

    #[test]
    fn validate_happy_path() {
        let d = make_descriptor("dev.mcpg.x", PluginClass::ToolGate);
        let m = make_manifest("dev.mcpg.x", PluginClass::ToolGate);
        assert!(validate_descriptor(&d, &m).is_ok());
    }

    #[test]
    fn validate_catches_id_drift() {
        let d = make_descriptor("dev.mcpg.x", PluginClass::ToolGate);
        let m = make_manifest("dev.mcpg.y", PluginClass::ToolGate);
        let err = validate_descriptor(&d, &m).unwrap_err();
        match err {
            DescriptorError::ManifestMismatch { field, .. } => assert_eq!(field, "id"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn validate_catches_class_drift() {
        let d = make_descriptor("dev.mcpg.x", PluginClass::ToolGate);
        let m = make_manifest("dev.mcpg.x", PluginClass::Transform);
        let err = validate_descriptor(&d, &m).unwrap_err();
        match err {
            DescriptorError::ManifestMismatch { field, .. } => assert_eq!(field, "class"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_matching_provides_order_independent() {
        // Cluster slot-role `provides` is cross-checked, as a
        // SET — order doesn't matter.
        let mut d = make_descriptor("dev.mcpg.cluster.redis", PluginClass::Cluster);
        d.provides = vec!["cache".into(), "kv".into()];
        let mut m = make_manifest("dev.mcpg.cluster.redis", PluginClass::Cluster);
        m.provides = vec!["kv".into(), "cache".into()]; // different order
        assert!(validate_descriptor(&d, &m).is_ok());
    }

    #[test]
    fn validate_catches_provides_drift() {
        // Descriptor claims a `bus` role the manifest doesn't — the kind
        // of drift the old (absent) cross-check let through silently.
        let mut d = make_descriptor("dev.mcpg.cluster.redis", PluginClass::Cluster);
        d.provides = vec!["cache".into(), "kv".into(), "bus".into()];
        let mut m = make_manifest("dev.mcpg.cluster.redis", PluginClass::Cluster);
        m.provides = vec!["cache".into(), "kv".into()];
        let err = validate_descriptor(&d, &m).unwrap_err();
        match err {
            DescriptorError::ManifestMismatch { field, .. } => assert_eq!(field, "provides"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    // `required_capabilities` is not
    // cross-checked between descriptor (typed Vec<Capability>) and
    // runtime manifest (Vec<String> for legacy display only). The
    // authoritative source is `PluginRegistration.capabilities`.

    #[test]
    fn validate_catches_protocol_version_drift() {
        let mut d = make_descriptor("dev.mcpg.x", PluginClass::ToolGate);
        d.protocol_version = "2.0".into();
        let m = make_manifest("dev.mcpg.x", PluginClass::ToolGate);
        let err = validate_descriptor(&d, &m).unwrap_err();
        match err {
            DescriptorError::ManifestMismatch { field, .. } => {
                assert_eq!(field, "protocol_version")
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
