//! # mcpg-plugin-host
//!
//! Gateway-side plugin hosting infrastructure: registry, loading, chain evaluation,
//! and lifecycle management.
//!
//! This crate is depended on by the mcpg gateway binary. It manages plugin loading
//! from configured sources, signature verification, and runtime chain evaluation.
//!
//! ## Feature flags
//!
//! - `wasm` — Enable Wasmtime Component Model plugin loading. Adds ~20MB to binary
//!   size and significant compile time. Disabled by default.

pub(crate) mod approval_notifier_metering;
pub mod audit_events;
pub(crate) mod cache_metering;
pub(crate) mod catalog_metering;
pub mod cluster_encryption;
pub mod cluster_metering;
pub mod cluster_tenant;
pub(crate) mod config_metering;
pub mod credential_cache;
pub mod credential_cache_cipher;
pub mod credential_cache_clustered;
pub(crate) mod credential_metering;
pub mod credential_resolver;
pub mod descriptor;
pub mod docker_credentials;
pub(crate) mod ffi_metering;
pub mod firstparty;
pub mod health_prober;
pub mod host_bridge;
pub mod host_services;
pub(crate) mod identity_metering;
pub mod identity_sig;
pub mod lifecycle;
pub mod native;
pub mod native_loader;
pub mod oci;
pub mod package;
pub(crate) mod policy_metering;
pub mod registry;
pub mod revocation;
pub(crate) mod secret_metering;
pub mod secret_resolver;
pub mod secret_watcher;
pub mod signature;
pub mod span_sampling;
pub(crate) mod store_metering;
pub(crate) mod transport_metering;
pub mod uri_routing;
pub mod verify;

/// Wasm plugin loader — requires the `wasm` feature.
#[cfg(feature = "wasm")]
pub mod wasm;

pub use descriptor::{DescriptorError, load_descriptor, validate_descriptor};
pub use firstparty::{FirstPartyRegistrar, cross_check_cdylib_capabilities};
pub use lifecycle::{AtomicPluginState, Lifecycle, LifecycleError, PluginState};
pub use package::{
    ArtifactKind, PackInputs, Package, PackageError, UnpackedPackage, canonical_filename,
    short_name_from_id,
};
pub use registry::{
    AuditEmitPolicy, AuditEmitResult, AuditEnforcementFailure, ChainIdentityOutcome,
    HttpRouteEntry, HttpRouteOverrideEntry, HttpRouteOverrides, LoadedPluginInfo, PluginRegistry,
    PolicyChainOutcome, RESERVED_OVERRIDE_PATH_PREFIXES,
};
pub use signature::SignaturePolicy;
