//! Per-request credential resolution.
//!
//! Walks a `serde_json::Value` (typically a binding's runtime
//! config) and replaces any string matching a `cred://` URI with
//! the credential the bound `credential_issuer` plugin returns.
//!
//! Mirrors `secret_resolver` in shape but operates per-request
//! (not per-boot) because credentials depend on caller identity.
//!
//! # URI shape
//!
//! - `cred://<plugin_id>/<target>` — substituted with
//!   `IssuedCredential.value`. Single-value credentials
//!   (Bearer tokens, simple passwords).
//! - `cred://<plugin_id>/<target>#<part>` — substituted with
//!   `IssuedCredential.parts[<part>]`. Multi-part credentials
//!   (Vault DB returning username + password, STS returning
//!   access_key_id + secret_access_key + session_token).
//!
//! Two CredRefs sharing `(plugin_id, target)` (differing only in
//! `part`) hit the same cache entry.
//!
//! # Walk semantics
//!
//! - Walks `Value` depth-first. Strings only — object keys,
//!   numbers, booleans pass through untouched.
//! - Strings that DON'T parse as `cred://` URIs pass through.
//! - Strings that DO parse but reference an unbound plugin id
//!   surface as a [`CredentialResolverError::UnknownPlugin`].
//! - Any plugin-side `CredentialError` surfaces as
//!   [`CredentialResolverError::Issuance`] with the URI that
//!   triggered it for operator triage.
//!
//! # Failure semantics
//!
//! Hard-fail on first error. Credential resolution is a security-
//! sensitive operation — partial substitution would mean the
//! binding gets a config with some `cred://` URIs unreplaced + some
//! resolved, which is worse than failing the call cleanly.

use mcpg_plugin_protocol::credential::{CredRef, CredentialError, IssuedCredential};
use mcpg_plugin_protocol::types::PluginIdentity;
use serde_json::Value;
use thiserror::Error;

use crate::PluginRegistry;
use crate::credential_cache::CredentialCache;

#[derive(Debug, Error)]
pub enum CredentialResolverError {
    #[error("unknown credential_issuer plugin: `{plugin_id}` (referenced by `{uri}`)")]
    UnknownPlugin { plugin_id: String, uri: String },
    #[error("credential issuance failed for `{uri}`: {error}")]
    Issuance {
        uri: String,
        #[source]
        error: CredentialError,
    },
    #[error(
        "credential `{uri}` selects part `{part}` but the issued credential \
         has no such part (available: {available:?})"
    )]
    UnknownPart {
        uri: String,
        part: String,
        available: Vec<String>,
    },
    #[error(
        "credential `{uri}` resolved to a multi-part credential but no \
         part was specified — add `#<part>` to the URI"
    )]
    PartRequired { uri: String },
}

impl CredentialResolverError {
    /// HTTP status the gateway should return when this error
    /// surfaces from a request that triggered resolution.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            Self::UnknownPlugin { .. } | Self::UnknownPart { .. } | Self::PartRequired { .. } => {
                500
            }
            Self::Issuance { error, .. } => error.http_status(),
        }
    }

    /// Caller-visible message — never includes plugin_id, target,
    /// part, or any other plugin-topology information. Always
    /// includes the gateway request_id as `id:` so an operator can
    /// link the caller's complaint to a log/audit line. Variants
    /// collapse to one of three caller-visible categories
    /// deliberately — the `UnknownPart` / `PartRequired` distinction
    /// is operator-only.
    #[must_use]
    pub fn caller_message(&self, correlation_id: &str) -> String {
        match self {
            Self::UnknownPlugin { .. } => {
                format!("backend credential is not configured (id: {correlation_id})")
            }
            Self::Issuance { .. } => {
                format!("backend credential issuance failed (id: {correlation_id})")
            }
            Self::UnknownPart { .. } | Self::PartRequired { .. } => {
                format!("backend credential is missing a required field (id: {correlation_id})")
            }
        }
    }

    /// Operator-visible message — full structured detail including
    /// `(plugin_id, target, part)` triple. Goes to audit + tracing
    /// span events. NEVER reaches the caller. Identical to
    /// `Display::fmt` today; kept as a distinct method so future
    /// changes to either surface (caller redaction, operator
    /// elaboration) don't accidentally drift.
    #[must_use]
    pub fn operator_message(&self) -> String {
        self.to_string()
    }

    /// Structured fields suitable for an audit event's payload. The
    /// gateway emits these via `audit_events::credential_resolution_failed_event`
    /// at the call site that detects the failure.
    #[must_use]
    pub fn audit_fields(&self) -> CredentialResolutionFailureFields {
        match self {
            Self::UnknownPlugin { plugin_id, uri } => CredentialResolutionFailureFields {
                kind: "unknown_plugin",
                plugin_id: plugin_id.clone(),
                target: parse_target_from_uri(uri).unwrap_or_default(),
                part: None,
                detail: "credential issuer plugin not registered".to_owned(),
            },
            Self::Issuance { uri, error } => CredentialResolutionFailureFields {
                kind: "issuance",
                plugin_id: parse_plugin_id_from_uri(uri).unwrap_or_default(),
                target: parse_target_from_uri(uri).unwrap_or_default(),
                part: parse_part_from_uri(uri),
                detail: error.to_string(),
            },
            Self::UnknownPart {
                uri,
                part,
                available,
            } => CredentialResolutionFailureFields {
                kind: "unknown_part",
                plugin_id: parse_plugin_id_from_uri(uri).unwrap_or_default(),
                target: parse_target_from_uri(uri).unwrap_or_default(),
                part: Some(part.clone()),
                detail: format!("available parts: {available:?}"),
            },
            Self::PartRequired { uri } => CredentialResolutionFailureFields {
                kind: "part_required",
                plugin_id: parse_plugin_id_from_uri(uri).unwrap_or_default(),
                target: parse_target_from_uri(uri).unwrap_or_default(),
                part: None,
                detail: "issued credential is multi-part but URI selects no `#part`".to_owned(),
            },
        }
    }
}

/// Structured payload for the credential-resolution-failure audit
/// event. All fields are operator-visible — this struct is never
/// serialised back to the caller.
#[derive(Debug, Clone)]
pub struct CredentialResolutionFailureFields {
    /// Stable error-kind discriminator: `"unknown_plugin"` /
    /// `"issuance"` / `"unknown_part"` / `"part_required"`. Suitable
    /// for SIEM cardinality.
    pub kind: &'static str,
    pub plugin_id: String,
    pub target: String,
    pub part: Option<String>,
    /// Free-form detail. NEVER includes credential bytes. May
    /// include the underlying transport error from a Vault / STS
    /// plugin; redaction is the issuer plugin's responsibility.
    pub detail: String,
}

/// Best-effort parse of `cred://<plugin>/<target>[#<part>]` for
/// audit-field synthesis. Returns the plugin id segment.
fn parse_plugin_id_from_uri(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("cred://")?;
    let (plugin, _) = rest.split_once('/')?;
    Some(plugin.to_owned())
}

fn parse_target_from_uri(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("cred://")?;
    let (_, after_plugin) = rest.split_once('/')?;
    let target = match after_plugin.split_once('#') {
        Some((t, _)) => t,
        None => after_plugin,
    };
    Some(target.to_owned())
}

fn parse_part_from_uri(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("cred://")?;
    rest.split_once('#').map(|(_, p)| p.to_owned())
}

/// Walk `value` and substitute every `cred://` URI with the
/// resolved credential value. Mutates in place.
///
/// On any error (unknown plugin, plugin issuance failure,
/// missing-part, etc.) the walk halts and the partially-mutated
/// `value` is returned along with the error. Callers MUST NOT use
/// `value` on the error path — partial substitution leaves the
/// config in an inconsistent state.
pub async fn resolve_credential_refs(
    value: &mut Value,
    identity: &PluginIdentity,
    registry: &PluginRegistry,
    cache: &CredentialCache,
) -> Result<usize, CredentialResolverError> {
    let mut count = 0usize;
    resolve_walk(value, identity, registry, cache, &mut count).await?;
    Ok(count)
}

/// Collect the set of `cred://` issuer plugin-ids referenced anywhere in
/// `value`. Recognises both forms a string can carry: a bare
/// `cred://<issuer>/<target>` (the shape [`resolve_credential_refs`]
/// substitutes) and one or more `${cred://…}` interpolation tokens (the
/// config-authoring grammar). Used to derive the per-plugin config-origin
/// allowlist at boot and to vet a plugin-supplied value at the
/// `resolve_credentials` host-FFI slot — a plugin may only resolve issuers
/// its own operator-authored config references.
#[must_use]
pub fn collect_cred_issuers(value: &Value) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    collect_walk(value, &mut out);
    out
}

fn collect_walk(value: &Value, out: &mut std::collections::HashSet<String>) {
    match value {
        Value::String(s) => collect_from_str(s, out),
        Value::Array(items) => {
            for item in items {
                collect_walk(item, out);
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                collect_walk(v, out);
            }
        }
        _ => {}
    }
}

fn collect_from_str(s: &str, out: &mut std::collections::HashSet<String>) {
    // Bare `cred://issuer/target` — the substituted shape.
    if let Some(cred_ref) = CredRef::parse(s) {
        out.insert(cred_ref.plugin_id);
    }
    // `${cred://issuer/target}` interpolation tokens — the authoring shape.
    for inner in mcpg_plugin_protocol::credential::cred_tokens(s) {
        if let Some(cred_ref) = CredRef::parse(&inner) {
            out.insert(cred_ref.plugin_id);
        }
    }
}

/// Collect the set of full `cred://<issuer>/<target>` refs a config
/// references, keyed by the `(issuer, target)` cache dimension and rendered
/// as the canonical `"<issuer>/<target>"` string (the `#part` fragment is
/// dropped — parts of one target share an issued credential). Companion to
/// [`collect_cred_issuers`]: that one gates the *issuer*, this one gates the
/// exact *target* so a plugin can only resolve the credentials its own
/// operator-authored config names — not every target on an issuer it happens
/// to reference.
#[must_use]
pub fn collect_cred_refs(value: &Value) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    collect_refs_walk(value, &mut out);
    out
}

/// Canonical allowlist key for a `(issuer, target)` pair — the shape both
/// [`collect_cred_refs`] records and the `resolve_credentials` host-FFI gate
/// looks up.
#[must_use]
pub fn cred_ref_key(issuer: &str, target: &str) -> String {
    format!("{issuer}/{target}")
}

fn collect_refs_walk(value: &Value, out: &mut std::collections::HashSet<String>) {
    match value {
        Value::String(s) => collect_refs_from_str(s, out),
        Value::Array(items) => {
            for item in items {
                collect_refs_walk(item, out);
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                collect_refs_walk(v, out);
            }
        }
        _ => {}
    }
}

fn collect_refs_from_str(s: &str, out: &mut std::collections::HashSet<String>) {
    if let Some(cred_ref) = CredRef::parse(s) {
        out.insert(cred_ref_key(&cred_ref.plugin_id, &cred_ref.target));
    }
    for inner in mcpg_plugin_protocol::credential::cred_tokens(s) {
        if let Some(cred_ref) = CredRef::parse(&inner) {
            out.insert(cred_ref_key(&cred_ref.plugin_id, &cred_ref.target));
        }
    }
}

/// Recursive walker. Boxed-pinned future so the recursion compiles
/// (Rust forbids direct async recursion without indirection). Send-
/// safe — no raw pointers held across awaits, so callers in
/// async_trait Send-bound contexts (the gateway's `BackendHost`
/// impl) can drive this future.
fn resolve_walk<'a>(
    value: &'a mut Value,
    identity: &'a PluginIdentity,
    registry: &'a PluginRegistry,
    cache: &'a CredentialCache,
    count: &'a mut usize,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(), CredentialResolverError>> + Send + 'a>,
> {
    Box::pin(async move {
        match value {
            Value::String(s) => {
                let Some(cred_ref) = CredRef::parse(s) else {
                    return Ok(());
                };
                let issuer = match registry.credential_issuer(&cred_ref.plugin_id) {
                    Some(issuer) => issuer,
                    None => {
                        // Audit the unknown-plugin failure path.
                        let event = crate::audit_events::credential_issued_event(
                            identity.clone(),
                            &cred_ref.plugin_id,
                            &cred_ref.target,
                            false,
                            Some("issuer plugin not registered"),
                        );
                        let _ = registry.emit_audit_event(&event).await;
                        return Err(CredentialResolverError::UnknownPlugin {
                            plugin_id: cred_ref.plugin_id.clone(),
                            uri: s.clone(),
                        });
                    }
                };
                let plugin_cfg = serde_json::Value::Object(serde_json::Map::new());
                let credential = match cache
                    .get_or_issue(&issuer, identity, &cred_ref.target, &plugin_cfg)
                    .await
                {
                    Ok(cred) => {
                        let event = crate::audit_events::credential_issued_event(
                            identity.clone(),
                            &cred_ref.plugin_id,
                            &cred_ref.target,
                            true,
                            None,
                        );
                        let _ = registry.emit_audit_event(&event).await;
                        cred
                    }
                    Err(e) => {
                        let err_msg = e.to_string();
                        let event = crate::audit_events::credential_issued_event(
                            identity.clone(),
                            &cred_ref.plugin_id,
                            &cred_ref.target,
                            false,
                            Some(&err_msg),
                        );
                        let _ = registry.emit_audit_event(&event).await;
                        return Err(CredentialResolverError::Issuance {
                            uri: s.clone(),
                            error: e,
                        });
                    }
                };
                let substituted =
                    pick_part(&credential, &cred_ref).map_err(|err| err.with_uri(s.clone()))?;
                *value = Value::String(substituted);
                *count += 1;
            }
            Value::Array(items) => {
                for item in items.iter_mut() {
                    resolve_walk(item, identity, registry, cache, count).await?;
                }
            }
            Value::Object(map) => {
                for (_k, val) in map.iter_mut() {
                    resolve_walk(val, identity, registry, cache, count).await?;
                }
            }
            _ => {}
        }
        Ok(())
    })
}

/// Internal pick-part error before we know the URI. The walker
/// adds the URI via [`PartError::with_uri`] on the way out.
enum PartError {
    Unknown {
        part: String,
        available: Vec<String>,
    },
    Required,
}

impl PartError {
    fn with_uri(self, uri: String) -> CredentialResolverError {
        match self {
            Self::Unknown { part, available } => CredentialResolverError::UnknownPart {
                uri,
                part,
                available,
            },
            Self::Required => CredentialResolverError::PartRequired { uri },
        }
    }
}

fn pick_part(credential: &IssuedCredential, cred_ref: &CredRef) -> Result<String, PartError> {
    match &cred_ref.part {
        Some(part) => credential
            .part(part)
            .map(str::to_owned)
            .ok_or_else(|| PartError::Unknown {
                part: part.clone(),
                available: credential.parts.keys().cloned().collect(),
            }),
        None => match credential.value.as_ref() {
            Some(v) => Ok(v.clone()),
            None => Err(PartError::Required),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use mcpg_plugin_protocol::PluginTier;
    use mcpg_plugin_protocol::credential::CredentialIssuer;
    use mcpg_plugin_protocol::manifest::{PluginClass, PluginManifest};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[test]
    fn collect_cred_issuers_finds_bare_and_token_forms_nested() {
        let cfg = json!({
            "url": "https://api.example.com",
            "headers": {
                // bare form — the substituted shape
                "authorization": "cred://vault-pg/orders#token",
                // ${cred://…} token form — the authoring shape
                "x-api-key": "Bearer ${cred://oauth-sts/notion}",
            },
            "nested": ["cred://static-creds/svc", { "k": "no-cred-here" }],
            "plain": "https://no.creds/here",
        });
        let issuers = collect_cred_issuers(&cfg);
        assert!(issuers.contains("vault-pg"), "{issuers:?}");
        assert!(issuers.contains("oauth-sts"), "{issuers:?}");
        assert!(issuers.contains("static-creds"), "{issuers:?}");
        assert_eq!(issuers.len(), 3, "no spurious issuers: {issuers:?}");
    }

    #[test]
    fn collect_cred_refs_records_full_issuer_target_pairs() {
        let cfg = json!({
            "headers": {
                // bare form with a `#part` fragment — the fragment is dropped.
                "authorization": "cred://vault-pg/orders-ro#token",
                // ${cred://…} token form.
                "x-api-key": "Bearer ${cred://oauth-sts/notion}",
            },
            // two targets on the SAME issuer — both recorded distinctly.
            "also": "cred://vault-pg/payroll-rw",
            "plain": "https://no.creds/here",
        });
        let refs = collect_cred_refs(&cfg);
        assert!(
            refs.contains(&cred_ref_key("vault-pg", "orders-ro")),
            "{refs:?}"
        );
        assert!(
            refs.contains(&cred_ref_key("vault-pg", "payroll-rw")),
            "{refs:?}"
        );
        assert!(
            refs.contains(&cred_ref_key("oauth-sts", "notion")),
            "{refs:?}"
        );
        assert_eq!(refs.len(), 3, "exact (issuer,target) pairs only: {refs:?}");
    }

    struct StubIssuer {
        manifest: PluginManifest,
    }

    impl StubIssuer {
        fn new(id: &str) -> Self {
            Self {
                manifest: PluginManifest {
                    id: id.into(),
                    version: "0.0.1".into(),
                    name: "stub".into(),
                    plugin_class: PluginClass::CredentialIssuer,
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
                },
            }
        }
    }

    #[async_trait]
    impl CredentialIssuer for StubIssuer {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn issue(
            &self,
            _: &PluginIdentity,
            target: &str,
            _: &Value,
        ) -> Result<IssuedCredential, CredentialError> {
            // Multi-part: returns username + password derived from target.
            let mut parts = BTreeMap::new();
            parts.insert("username".into(), format!("u-{target}"));
            parts.insert("password".into(), format!("p-{target}"));
            Ok(IssuedCredential {
                value: None,
                parts,
                ttl_seconds: 60,
                lease_id: Some(format!("lease-{target}")),
                issued_at: "2026-04-26T00:00:00Z".into(),
                metadata: BTreeMap::new(),
            })
        }
    }

    fn identity() -> PluginIdentity {
        PluginIdentity {
            kind: "verified".into(),
            trust_level: "verified".into(),
            subject_id: Some("alice".into()),
            auth_provider: None,
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: BTreeMap::new(),
        }
    }

    fn registry_with_stub() -> PluginRegistry {
        let mut reg = PluginRegistry::new();
        let issuer: Arc<dyn CredentialIssuer> = Arc::new(StubIssuer::new("vault-pg"));
        reg.register_credential_issuer(issuer, PluginTier::Native)
            .expect("register");
        reg
    }

    #[tokio::test]
    async fn resolves_multi_part_credential_in_binding_config() {
        let reg = registry_with_stub();
        let cache = CredentialCache::default();
        let mut cfg = json!({
            "url": "postgres://orders.svc:5432/orders",
            "username": "cred://vault-pg/orders-readonly#username",
            "password": "cred://vault-pg/orders-readonly#password",
        });
        let count = resolve_credential_refs(&mut cfg, &identity(), &reg, &cache)
            .await
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(cfg["username"], "u-orders-readonly");
        assert_eq!(cfg["password"], "p-orders-readonly");
        assert_eq!(cfg["url"], "postgres://orders.svc:5432/orders");
        // Single cache entry — both URIs hit the same key.
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn unknown_plugin_surfaces_error() {
        let reg = PluginRegistry::new();
        let cache = CredentialCache::default();
        let mut cfg = json!({"k": "cred://no-such-plugin/x"});
        let err = resolve_credential_refs(&mut cfg, &identity(), &reg, &cache)
            .await
            .unwrap_err();
        match err {
            CredentialResolverError::UnknownPlugin { plugin_id, .. } => {
                assert_eq!(plugin_id, "no-such-plugin");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_part_surfaces_error_with_available_list() {
        let reg = registry_with_stub();
        let cache = CredentialCache::default();
        let mut cfg = json!({"k": "cred://vault-pg/x#missing-part"});
        let err = resolve_credential_refs(&mut cfg, &identity(), &reg, &cache)
            .await
            .unwrap_err();
        match err {
            CredentialResolverError::UnknownPart {
                part, available, ..
            } => {
                assert_eq!(part, "missing-part");
                assert!(available.contains(&"username".to_owned()));
                assert!(available.contains(&"password".to_owned()));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn part_required_when_credential_is_multi_part() {
        let reg = registry_with_stub();
        let cache = CredentialCache::default();
        let mut cfg = json!({"k": "cred://vault-pg/x"});
        let err = resolve_credential_refs(&mut cfg, &identity(), &reg, &cache)
            .await
            .unwrap_err();
        matches!(err, CredentialResolverError::PartRequired { .. });
    }

    #[tokio::test]
    async fn non_cred_strings_pass_through() {
        let reg = registry_with_stub();
        let cache = CredentialCache::default();
        let mut cfg = json!({
            "url": "https://example.com",
            "msg": "not a credential",
            "vault_ref": "vault://something",
        });
        resolve_credential_refs(&mut cfg, &identity(), &reg, &cache)
            .await
            .unwrap();
        assert_eq!(cfg["url"], "https://example.com");
        assert_eq!(cfg["msg"], "not a credential");
        assert_eq!(cfg["vault_ref"], "vault://something");
    }

    #[tokio::test]
    async fn http_status_maps_through_to_credential_error() {
        let err = CredentialResolverError::Issuance {
            uri: "cred://x/y".into(),
            error: CredentialError::Backend {
                reason: "vault down".into(),
            },
        };
        assert_eq!(err.http_status(), 503);
        let err = CredentialResolverError::UnknownPlugin {
            plugin_id: "x".into(),
            uri: "cred://x/y".into(),
        };
        assert_eq!(err.http_status(), 500);
    }

    // ---------------------------------------------------------------
    // caller/operator error-message split.
    // ---------------------------------------------------------------

    fn unknown_plugin_err() -> CredentialResolverError {
        CredentialResolverError::UnknownPlugin {
            plugin_id: "vault-pg".into(),
            uri: "cred://vault-pg/orders-readonly#username".into(),
        }
    }

    fn issuance_err() -> CredentialResolverError {
        CredentialResolverError::Issuance {
            uri: "cred://vault-pg/orders-readonly".into(),
            error: CredentialError::Backend {
                reason: "vault transient timeout".into(),
            },
        }
    }

    fn unknown_part_err() -> CredentialResolverError {
        CredentialResolverError::UnknownPart {
            uri: "cred://vault-pg/orders-readonly#hostname".into(),
            part: "hostname".into(),
            available: vec!["username".into(), "password".into()],
        }
    }

    fn part_required_err() -> CredentialResolverError {
        CredentialResolverError::PartRequired {
            uri: "cred://vault-pg/orders-readonly".into(),
        }
    }

    #[test]
    fn caller_message_never_includes_plugin_id_or_target() {
        let cid = "req-abc-123";
        for err in [
            unknown_plugin_err(),
            issuance_err(),
            unknown_part_err(),
            part_required_err(),
        ] {
            let msg = err.caller_message(cid);
            assert!(
                !msg.contains("vault-pg"),
                "caller msg leaked plugin_id: {msg}"
            );
            assert!(
                !msg.contains("orders-readonly"),
                "caller msg leaked target: {msg}"
            );
            assert!(!msg.contains("username"), "caller msg leaked part: {msg}");
            assert!(!msg.contains("hostname"), "caller msg leaked part: {msg}");
            assert!(
                msg.contains(cid),
                "caller msg missing correlation id: {msg}"
            );
        }
    }

    #[test]
    fn unknown_part_and_part_required_collapse_to_same_caller_text() {
        let cid = "rq-1";
        let a = unknown_part_err().caller_message(cid);
        let b = part_required_err().caller_message(cid);
        assert_eq!(a, b);
    }

    #[test]
    fn operator_message_includes_full_topology() {
        let msg = unknown_plugin_err().operator_message();
        assert!(
            msg.contains("vault-pg"),
            "operator msg should include plugin_id: {msg}"
        );
        assert!(
            msg.contains("orders-readonly"),
            "operator msg should include target"
        );
    }

    #[test]
    fn audit_fields_unknown_plugin() {
        let f = unknown_plugin_err().audit_fields();
        assert_eq!(f.kind, "unknown_plugin");
        assert_eq!(f.plugin_id, "vault-pg");
        assert_eq!(f.target, "orders-readonly");
    }

    #[test]
    fn audit_fields_issuance_carries_part() {
        let f = issuance_err().audit_fields();
        assert_eq!(f.kind, "issuance");
        assert_eq!(f.plugin_id, "vault-pg");
        assert_eq!(f.target, "orders-readonly");
        assert_eq!(f.part, None);
        assert!(f.detail.contains("vault transient timeout"));
    }

    #[test]
    fn audit_fields_unknown_part() {
        let f = unknown_part_err().audit_fields();
        assert_eq!(f.kind, "unknown_part");
        assert_eq!(f.part.as_deref(), Some("hostname"));
        assert!(f.detail.contains("username"));
    }

    #[test]
    fn audit_fields_part_required() {
        let f = part_required_err().audit_fields();
        assert_eq!(f.kind, "part_required");
        assert_eq!(f.part, None);
    }
}
