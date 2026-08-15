//! First-party plugin registrar.
//!
//! Every first-party plugin in the workspace ships a `plugin.yaml`
//! descriptor at its crate root. The descriptor is the authoritative
//! statement of the plugin's identity and runtime class; the in-code
//! [`PluginManifest`](mcpg_plugin_protocol::PluginManifest) returned
//! by the plugin's `manifest()` hook is the runtime-typed mirror of
//! that statement.
//!
//! Before this module, the gateway constructed each first-party
//! plugin via a bespoke block — read config, build the plugin,
//! [`PluginRegistry::register_tool_gate`] (or peer method) — and the
//! descriptor was only used by external tooling. A drift between the
//! yaml and the Rust code (e.g. operator renames a plugin in code but
//! forgets the yaml) would not surface until someone inspected the
//! admin endpoint.
//!
//! [`FirstPartyRegistrar`] closes that loop. Each call site:
//!
//! 1. hands in the embedded `plugin.yaml` contents (via the plugin
//!    crate's `DESCRIPTOR_YAML` const);
//! 2. supplies the per-entry capability grants (a slice from the
//!    matching `plugins[]` entry, or `&[]` for built-ins that never
//!    appear in operator config);
//! 3. runs its plugin-specific registration closure (the existing
//!    `register_tool_gate` / `register_transform` / ... logic);
//! 4. has the registrar cross-check the parsed descriptor against
//!    the newly-registered runtime manifest and fail startup loudly
//!    on mismatch.
//!
//! The registrar does **not** attempt to be a uniform plugin
//! constructor — per-plugin config shapes are legitimately different,
//! and flattening them into one config model is a much bigger
//! project. The facade's value is that every first-party plugin
//! reaches the registry through the same validation choke point.
//!
//! ## Non-first-party callers
//!
//! Runtime-loaded wasm plugins and OCI-fetched cdylib artefacts
//! source their descriptors at runtime, not from a compile-time
//! `include_str!`. They call
//! [`FirstPartyRegistrar::register_with_descriptor`] with an
//! already-parsed [`PluginDescriptor`] — typically loaded from a
//! sidecar `plugin.yaml` next to the artefact, or read from an
//! OCI annotation. Same per-entry grants passing as first-party.

use anyhow::{Context, Result, bail};
use mcpg_plugin_protocol::{DESCRIPTOR_SCHEMA_V1, PluginDescriptor};
use tracing::info;

use crate::PluginRegistry;

/// Borrows a mutable reference to a [`PluginRegistry`] and adds
/// uniform descriptor validation around each registration.
///
/// The registrar is a zero-cost wrapper — it holds nothing beyond
/// the registry borrow and is cheap to construct on the stack at
/// each call site. Per-plugin capability grants are passed
/// explicitly to each `register*` call: the
/// source of truth is the per-entry `granted_capabilities` field
/// on the matching `plugins[]` entry, not a centralized map built
/// once at boot).
pub struct FirstPartyRegistrar<'a> {
    registry: &'a mut PluginRegistry,
}

impl<'a> FirstPartyRegistrar<'a> {
    /// Build a new registrar wrapping the given registry.
    pub fn new(registry: &'a mut PluginRegistry) -> Self {
        Self { registry }
    }

    /// Access the underlying registry without any wrapping.
    ///
    /// Useful for registrations that predate the descriptor format
    /// (none remain in the workspace today — provided for
    /// forward-compat with code paths that wire in plugins
    /// lazily).
    pub fn registry_mut(&mut self) -> &mut PluginRegistry {
        self.registry
    }

    /// Register a first-party plugin.
    ///
    /// `descriptor_yaml` is the raw UTF-8 contents of the plugin's
    /// `plugin.yaml`. Typically the caller passes a constant
    /// exported by the plugin crate, e.g.:
    ///
    /// ```ignore
    /// registrar.register(
    ///     mcpg_plugin_circuit_breaker::DESCRIPTOR_YAML,
    ///     &[],   // built-in: no operator-grantable capabilities
    ///     host,  // HostHandle bound to this entry's alias
    ///     |registry, _host| {
    ///         let p = CircuitBreakerPlugin::from_config(&cfg)?;
    ///         registry.register_tool_gate(Box::new(p), tier, cfg)
    ///     },
    /// )?;
    /// ```
    ///
    /// `granted` is the per-entry `granted_capabilities` slice
    /// from the matching `plugins[]` config entry. Built-ins that
    /// don't appear in operator config pass `&[]` — fine because
    /// they declare empty `required_capabilities`.
    ///
    /// The closure runs only after the descriptor's required
    /// capabilities are checked against `granted`. On registration
    /// success the registrar parses the descriptor and calls
    /// [`PluginRegistry::validate_registered_descriptor`]. If the
    /// parse, the capability check, or the cross-check fails, the
    /// caller (the gateway `serve` path) is expected to abort
    /// startup.
    pub fn register<H, F>(
        &mut self,
        descriptor_yaml: &str,
        granted: &[mcpg_plugin_protocol::capability::Capability],
        host: H,
        register_fn: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut PluginRegistry, H) -> Result<()>,
    {
        let descriptor: PluginDescriptor =
            serde_yaml::from_str(descriptor_yaml).context("parsing embedded plugin descriptor")?;
        self.register_with_descriptor(&descriptor, granted, host, register_fn)
    }

    /// Variant of [`Self::register`] that accepts an already-parsed
    /// [`PluginDescriptor`]. Useful for non-first-party callers
    /// that source the descriptor from somewhere other than a
    /// compile-time `include_str!` — for example, a sidecar
    /// `plugin.yaml` loaded from disk next to a runtime-loaded
    /// wasm component, or an OCI annotation on a cdylib artefact.
    ///
    /// `granted` is the per-entry `granted_capabilities` slice
    /// from the matching `plugins[]` config entry — same semantics
    /// as [`Self::register`].
    ///
    /// The closure receives an opaque `H` (the
    /// caller's host-handle type — typically `mcpg_plugin_sdk::HostHandle`).
    /// Made generic to avoid a plugin-host → plugin-sdk dependency
    /// cycle; the registrar treats the host arg as opaque and just
    /// forwards it to the closure.
    pub fn register_with_descriptor<H, F>(
        &mut self,
        descriptor: &PluginDescriptor,
        granted: &[mcpg_plugin_protocol::capability::Capability],
        host: H,
        register_fn: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut PluginRegistry, H) -> Result<()>,
    {
        if !descriptor.is_current_schema() {
            bail!(
                "plugin descriptor for {:?} declares schema {:?}; host supports {:?}",
                descriptor.id,
                descriptor.schema,
                DESCRIPTOR_SCHEMA_V1,
            );
        }

        // Typed capability validation. The
        // descriptor's `required_capabilities` is itself typed via
        // the same serde shape used by operator-config grants. A
        // descriptor declaring a future-host kind decodes to
        // `Capability::Unknown` and we surface that distinctly.
        let required = &descriptor.required_capabilities;
        match mcpg_plugin_protocol::capability::validate_typed_capabilities(
            &descriptor.id,
            required,
            granted,
        ) {
            mcpg_plugin_protocol::capability::CapabilityCheck::Satisfied => {}
            mcpg_plugin_protocol::capability::CapabilityCheck::UnknownRequiredCapabilities(
                caps,
            ) => {
                bail!(
                    "plugin {:?} declares unknown capabilities {:?} — host \
                     vocabulary is {:?}. Typo, or the plugin targets a future \
                     host version.",
                    descriptor.id,
                    caps,
                    mcpg_plugin_protocol::capability::Capability::known_names(),
                );
            }
            mcpg_plugin_protocol::capability::CapabilityCheck::UnknownGrantedCapabilities(caps) => {
                bail!(
                    "plugin {:?}: operator config grants unknown capabilities {:?} — \
                     either a typo or a future-version kind. Host vocabulary is {:?}.",
                    descriptor.id,
                    caps,
                    mcpg_plugin_protocol::capability::Capability::known_names(),
                );
            }
            mcpg_plugin_protocol::capability::CapabilityCheck::UngrantedCapabilities(caps) => {
                bail!(
                    "plugin {:?} requires capabilities {:?} that have not been \
                     granted in the operator config \
                     (`plugins[].granted_capabilities` on the entry whose id matches)",
                    descriptor.id,
                    caps,
                );
            }
        }

        register_fn(self.registry, host)
            .with_context(|| format!("registering first-party plugin {:?}", descriptor.id))?;
        self.registry
            .validate_registered_descriptor(descriptor)
            .with_context(|| {
                format!(
                    "descriptor / runtime-manifest cross-check for plugin {:?}",
                    descriptor.id
                )
            })?;
        // `runtime` is HOW this plugin was loaded, which for everything
        // reaching this registrar is "linked into the binary" — not what the
        // descriptor claims. The three plugins that ALSO ship as signed
        // cdylibs (observability.otlp, observability.prometheus,
        // identity.oidc) declare `native-cdylib-v1`, so reporting the
        // descriptor made a compiled-in copy indistinguishable from a
        // verified artifact in the logs. `descriptor_runtime` keeps the
        // claim visible, which is what makes those dual-source plugins
        // greppable.
        info!(
            plugin_id = %descriptor.id,
            class = %descriptor.class,
            runtime = "static-firstparty-v1",
            descriptor_runtime = %descriptor.runtime,
            "first-party plugin registered (descriptor verified)"
        );
        Ok(())
    }
}

/// Cross-check the typed capability list a cdylib carries on its
/// `PluginRegistration` against the typed list its sidecar
/// descriptor declares. Both surfaces describe
/// the same set; a mismatch is a packaging bug (e.g. descriptor was
/// updated but the cdylib wasn't rebuilt, or vice versa).
///
/// The check is order-insensitive but exact: every capability on
/// one side must appear on the other (by value, including variant
/// args). Operators that need slack should declare a single
/// capability the descriptor and cdylib agree on; this is not a
/// place for "descriptor narrower than cdylib" semantics — that
/// invites silent privilege escalation by a stale binary against a
/// freshly-tightened YAML.
pub fn cross_check_cdylib_capabilities(
    plugin_id: &str,
    descriptor: &[mcpg_plugin_protocol::capability::Capability],
    cdylib: &[mcpg_plugin_protocol::capability::Capability],
) -> Result<()> {
    let descriptor_set: std::collections::HashSet<_> = descriptor.iter().collect();
    let cdylib_set: std::collections::HashSet<_> = cdylib.iter().collect();
    if descriptor_set != cdylib_set {
        let only_in_descriptor: Vec<_> = descriptor_set
            .difference(&cdylib_set)
            .map(|c| c.kind())
            .collect();
        let only_in_cdylib: Vec<_> = cdylib_set
            .difference(&descriptor_set)
            .map(|c| c.kind())
            .collect();
        bail!(
            "plugin {:?}: descriptor / cdylib capability lists disagree. \
             only in descriptor: {:?}; only in cdylib: {:?}. \
             Rebuild the cdylib or update plugin.yaml to match.",
            plugin_id,
            only_in_descriptor,
            only_in_cdylib,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use mcpg_plugin_protocol::{
        GateDecision, PluginClass, PluginContext, PluginManifest, PluginTier, ToolGatePlugin,
    };

    struct AllowGate(PluginManifest);

    #[async_trait]
    impl ToolGatePlugin for AllowGate {
        fn manifest(&self) -> &PluginManifest {
            &self.0
        }
        async fn evaluate_pre_dispatch(
            &self,
            _ctx: &PluginContext,
            _args: &serde_json::Value,
            _meta: Option<&serde_json::Value>,
            _config: &serde_json::Value,
        ) -> GateDecision {
            GateDecision::allow()
        }
    }

    fn manifest(id: &str) -> PluginManifest {
        manifest_with_caps(id, &[])
    }

    fn manifest_with_caps(
        id: &str,
        caps: &[mcpg_plugin_protocol::capability::Capability],
    ) -> PluginManifest {
        PluginManifest {
            id: id.into(),
            version: "1.0.0".into(),
            name: format!("Plugin {id}"),
            plugin_class: PluginClass::ToolGate,
            protocol_version: "1.0".into(),
            license: None,
            required_capabilities: caps.to_vec(),
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

    const MATCHING_YAML: &str = "\
schema: mcpg.dev/plugin/v1
id: dev.mcpg.test
name: Plugin dev.mcpg.test
description: Test descriptor
class: tool_gate
runtime: static-firstparty-v1
protocol_version: \"1.0\"
required_capabilities: []
";

    #[test]
    fn register_happy_path_validates_descriptor() {
        let mut reg = PluginRegistry::new();
        let mut r = FirstPartyRegistrar::new(&mut reg);
        r.register(MATCHING_YAML, &[], (), |registry, _host| {
            registry.register_tool_gate(
                Box::new(AllowGate(manifest("dev.mcpg.test"))),
                PluginTier::Native,
                serde_json::json!({}),
            )
        })
        .unwrap();
    }

    #[test]
    fn register_detects_id_drift() {
        let mut reg = PluginRegistry::new();
        let mut r = FirstPartyRegistrar::new(&mut reg);
        // Descriptor says dev.mcpg.test, runtime manifest says dev.mcpg.other.
        let err = r
            .register(MATCHING_YAML, &[], (), |registry, _host| {
                registry.register_tool_gate(
                    Box::new(AllowGate(manifest("dev.mcpg.other"))),
                    PluginTier::Native,
                    serde_json::json!({}),
                )
            })
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("cross-check"), "got: {msg}");
    }

    #[test]
    fn register_rejects_unknown_schema() {
        let mut reg = PluginRegistry::new();
        let mut r = FirstPartyRegistrar::new(&mut reg);
        let yaml = MATCHING_YAML.replace("mcpg.dev/plugin/v1", "mcpg.dev/plugin/v99");
        let err = r.register(&yaml, &[], (), |_, _| Ok(())).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("schema"), "got: {msg}");
    }

    #[test]
    fn register_surfaces_closure_errors() {
        let mut reg = PluginRegistry::new();
        let mut r = FirstPartyRegistrar::new(&mut reg);
        let err = r
            .register(MATCHING_YAML, &[], (), |_, _| {
                Err(anyhow::anyhow!("construction failed"))
            })
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("construction failed"), "got: {msg}");
    }

    #[test]
    fn register_rejects_malformed_yaml() {
        let mut reg = PluginRegistry::new();
        let mut r = FirstPartyRegistrar::new(&mut reg);
        let err = r
            .register("this: is: not: valid", &[], (), |_, _| Ok(()))
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("parsing embedded"), "got: {msg}");
    }

    #[test]
    fn register_with_descriptor_accepts_preparsed() {
        // Path used by non-first-party callers (wasm loaders, OCI
        // pullers) that source the descriptor from somewhere other
        // than a compile-time include_str!.
        let descriptor = PluginDescriptor {
            schema: mcpg_plugin_protocol::DESCRIPTOR_SCHEMA_V1.into(),
            id: "dev.mcpg.preparsed".into(),
            name: "Plugin dev.mcpg.preparsed".into(),
            description: String::new(),
            class: PluginClass::ToolGate,
            runtime: mcpg_plugin_protocol::RuntimeClass::Wasi,
            protocol_version: "1.0".into(),
            license: None,
            required_capabilities: vec![],
            tags: Vec::new(),
            provides: Vec::new(),
            provides_schemes: Vec::new(),
        };
        let mut reg = PluginRegistry::new();
        let mut r = FirstPartyRegistrar::new(&mut reg);
        r.register_with_descriptor(&descriptor, &[], (), |registry, _host| {
            registry.register_tool_gate(
                Box::new(AllowGate(manifest("dev.mcpg.preparsed"))),
                PluginTier::Wasm,
                serde_json::json!({}),
            )
        })
        .unwrap();
        assert_eq!(
            reg.lifecycle_state("dev.mcpg.preparsed"),
            Some(crate::PluginState::Active)
        );
    }

    // -- Capability-grant enforcement --------------------------------------

    fn descriptor_with_caps(
        id: &str,
        caps: Vec<mcpg_plugin_protocol::capability::Capability>,
    ) -> PluginDescriptor {
        PluginDescriptor {
            schema: mcpg_plugin_protocol::DESCRIPTOR_SCHEMA_V1.into(),
            id: id.into(),
            name: format!("Plugin {id}"),
            description: String::new(),
            class: PluginClass::ToolGate,
            runtime: mcpg_plugin_protocol::RuntimeClass::StaticFirstparty,
            protocol_version: "1.0".into(),
            license: None,
            required_capabilities: caps,
            tags: Vec::new(),
            provides: Vec::new(),
            provides_schemes: Vec::new(),
        }
    }

    #[test]
    fn capability_grant_happy_path() {
        use mcpg_plugin_protocol::capability::Capability;
        let desc = descriptor_with_caps("dev.mcpg.cap.happy", vec![Capability::NetworkOutbound]);
        let granted = vec![Capability::NetworkOutbound];
        let mut reg = PluginRegistry::new();
        let mut r = FirstPartyRegistrar::new(&mut reg);
        r.register_with_descriptor(&desc, &granted, (), |registry, _host| {
            registry.register_tool_gate(
                Box::new(AllowGate(manifest_with_caps("dev.mcpg.cap.happy", &[]))),
                PluginTier::Native,
                serde_json::json!({}),
            )
        })
        .unwrap();
        assert_eq!(
            reg.lifecycle_state("dev.mcpg.cap.happy"),
            Some(crate::PluginState::Active)
        );
    }

    #[test]
    fn capability_missing_grant_fails_startup() {
        use mcpg_plugin_protocol::capability::Capability;
        let desc =
            descriptor_with_caps("dev.mcpg.cap.ungranted", vec![Capability::NetworkOutbound]);
        let mut reg = PluginRegistry::new();
        let mut r = FirstPartyRegistrar::new(&mut reg);
        let err = r
            .register_with_descriptor(&desc, &[], (), |_, _| Ok(()))
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("capabilit"), "got: {msg}");
        assert!(msg.contains("network_outbound"), "got: {msg}");
    }

    #[test]
    fn capability_check_runs_before_closure() {
        // If the grant check runs after the closure, a plugin
        // with an ungranted cap would nonetheless be constructed
        // (wasting resources) before being rejected. This test
        // proves the closure is not entered on denial.
        use mcpg_plugin_protocol::capability::Capability;
        use std::sync::atomic::{AtomicBool, Ordering};
        let closure_ran = AtomicBool::new(false);
        let desc = descriptor_with_caps("dev.mcpg.cap.order", vec![Capability::MetricEmit]);
        let mut reg = PluginRegistry::new();
        let mut r = FirstPartyRegistrar::new(&mut reg);
        let _ = r.register_with_descriptor(&desc, &[], (), |_registry, _host| {
            closure_ran.store(true, Ordering::Relaxed);
            Ok(())
        });
        assert!(
            !closure_ran.load(Ordering::Relaxed),
            "capability check must run before the registration closure"
        );
    }

    #[test]
    fn register_without_grants_rejects_any_required_cap() {
        // Empty `granted` is fail-closed: a plugin with any
        // required capability gets nothing granted and is rejected.
        use mcpg_plugin_protocol::capability::Capability;
        let desc = descriptor_with_caps("dev.mcpg.cap.nogrants", vec![Capability::NetworkOutbound]);
        let mut reg = PluginRegistry::new();
        let mut r = FirstPartyRegistrar::new(&mut reg);
        assert!(
            r.register_with_descriptor(&desc, &[], (), |_, _| Ok(()))
                .is_err()
        );
    }

    #[test]
    fn capability_filesystem_read_satisfied_with_superset_paths() {
        // Typed subset semantics: a plugin
        // requiring read of `/a` is satisfied by an operator who
        // granted `/a, /b`.
        use mcpg_plugin_protocol::capability::Capability;
        let desc = descriptor_with_caps(
            "dev.mcpg.cap.fsread",
            vec![Capability::FilesystemRead {
                paths: vec!["/etc/myapp/config.yaml".into()],
            }],
        );
        let granted = vec![Capability::FilesystemRead {
            paths: vec!["/etc/myapp/config.yaml".into(), "/etc/myapp/keys".into()],
        }];
        let mut reg = PluginRegistry::new();
        let mut r = FirstPartyRegistrar::new(&mut reg);
        r.register_with_descriptor(&desc, &granted, (), |registry, _host| {
            registry.register_tool_gate(
                Box::new(AllowGate(manifest_with_caps("dev.mcpg.cap.fsread", &[]))),
                PluginTier::Native,
                serde_json::json!({}),
            )
        })
        .unwrap();
    }

    #[test]
    fn capability_filesystem_read_disjoint_paths_rejected() {
        use mcpg_plugin_protocol::capability::Capability;
        let desc = descriptor_with_caps(
            "dev.mcpg.cap.fsdisjoint",
            vec![Capability::FilesystemRead {
                paths: vec!["/etc/myapp/a".into()],
            }],
        );
        let granted = vec![Capability::FilesystemRead {
            paths: vec!["/etc/myapp/b".into()],
        }];
        let mut reg = PluginRegistry::new();
        let mut r = FirstPartyRegistrar::new(&mut reg);
        let err = r
            .register_with_descriptor(&desc, &granted, (), |_, _| Ok(()))
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("filesystem_read"), "got: {msg}");
    }

    #[test]
    fn cross_check_matching_capabilities_is_ok() {
        use mcpg_plugin_protocol::capability::Capability;
        let descriptor = vec![
            Capability::NetworkOutbound,
            Capability::FilesystemRead {
                paths: vec!["/etc".into()],
            },
        ];
        // Same set, different order — still ok.
        let cdylib = vec![
            Capability::FilesystemRead {
                paths: vec!["/etc".into()],
            },
            Capability::NetworkOutbound,
        ];
        cross_check_cdylib_capabilities("dev.mcpg.x", &descriptor, &cdylib).unwrap();
    }

    #[test]
    fn cross_check_mismatched_capabilities_fails() {
        use mcpg_plugin_protocol::capability::Capability;
        let descriptor = vec![Capability::NetworkOutbound];
        let cdylib = vec![Capability::AuditWrite];
        let err = cross_check_cdylib_capabilities("dev.mcpg.x", &descriptor, &cdylib).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("dev.mcpg.x"), "got: {msg}");
        assert!(msg.contains("network_outbound"), "got: {msg}");
        assert!(msg.contains("audit_write"), "got: {msg}");
    }
}
