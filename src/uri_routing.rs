//! Reserved URI schemes for secret / config auto-routing.
//!
//! `secret_provider` / `config_provider` plugins are routed by the
//! scheme prefix of the URI they resolve (`vault://…`, `aws-sm://…`,
//! `consul://…`). The authoritative scheme set is the runtime trait
//! method `SecretProvider::supported_schemes()` /
//! `ConfigProvider::supported_schemes()` (FFI-carried via the
//! `supported_schemes_json` vtable slot). At boot the registry's
//! `auto_bind_*_provider_schemes` walks every loaded provider and
//! builds the live `scheme → plugin_id` binding tables
//! (`secret_scheme_bindings` / `config_scheme_bindings`); runtime
//! dispatch goes through `secret_provider_for_scheme` /
//! `config_provider_for_scheme`.
//!
//! The two routing invariants live on that auto-bind path:
//!  - **reserved schemes** (`env` / `file`) cannot be claimed by a
//!    third-party plugin — enforced by `PluginRegistry::reject_reserved_scheme`
//!    (which consults [`RESERVED_SCHEMES`] below); the built-in env/file
//!    providers are bound directly by id and are exempt;
//!  - **scheme conflicts** (two plugins claiming one scheme) refuse boot
//!    — enforced inside `auto_bind_secret_provider_schemes` /
//!    `auto_bind_config_provider_schemes`.
//!
//! (Historically this module also held a `UriRouter` table type that
//! duplicated those invariants but was never wired into the live path;
//! it was removed once the auto-bind path became authoritative — the
//! only surviving export is the reserved-scheme list.)

/// Built-in schemes the gateway reserves. Plugins cannot claim
/// these; the gateway resolves them via host-internal helpers
/// (env-var lookup, filesystem read) without dispatching to a
/// plugin. Consulted by `PluginRegistry::reject_reserved_scheme`
/// on the third-party auto-bind path.
pub const RESERVED_SCHEMES: &[&str] = &["env", "file"];
