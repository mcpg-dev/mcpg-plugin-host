//! Secret-reference resolution.
//!
//! Walks a `serde_json::Value` (typically an operator-supplied
//! plugin config) and replaces any string matching a bound
//! `scheme://...` URI with the secret the bound provider
//! returns. Replaces the ad-hoc env-var expansion pattern with
//! URI refs in plugin configs.
//!
//! # Scope
//!
//! - String values only. `resolve_secret_refs` does not look at
//!   object keys, integer literals, etc.
//! - Schemes the registry has bound are expanded; other
//!   `scheme://...` strings pass through untouched so the
//!   resolver is safe to run against config that contains URLs
//!   or other non-secret URI shapes.
//! - Errors are collected per-reference into a
//!   `ResolveReport`; the caller decides whether to hard-fail
//!   on any error or proceed with partial substitution (the
//!   `fail_on_error` knob).

use std::collections::BTreeSet;

use mcpg_plugin_protocol::secret::{SecretError, parse_secret_ref};
use serde_json::Value;

use crate::PluginRegistry;

/// Per-reference resolution outcome. Successful expansions are
/// silent (the caller just reads the mutated `Value`); failed
/// ones land here so the operator can inspect them before deciding
/// whether to proceed.
#[derive(Debug, Clone)]
pub struct ResolveFailure {
    pub secret_ref: String,
    pub error: SecretError,
}

/// Report of the resolution pass. `expanded` counts
/// successfully substituted references; `failures` enumerates
/// per-reference errors. `skipped_schemes` records scheme
/// prefixes observed that had no bound provider — these are
/// benign by default (URLs in configs, custom schemes the
/// operator hasn't bound), and the caller can opt into strict
/// mode if they want to treat any unbound `scheme://` string
/// as a config bug.
///
/// `resolved_refs` is the deduplicated list of `scheme://...` URIs
/// that were successfully expanded. The gateway's secret-watch
/// task uses this to spawn one watcher per unique URI, and backend
/// plugins use it (via the `BackendHost::subscribe_secret_rotation`
/// callback) to scope eviction to the secrets their profile actually
/// referenced.
#[derive(Debug, Clone, Default)]
pub struct ResolveReport {
    pub expanded: usize,
    pub failures: Vec<ResolveFailure>,
    pub skipped_schemes: BTreeSet<String>,
    pub resolved_refs: BTreeSet<String>,
}

impl ResolveReport {
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Recursively walk `value` and resolve every string that starts
/// with `scheme://` where `scheme` is bound in the registry.
/// Returns a `ResolveReport` summarising the pass.
///
/// The walk is depth-first and mutates in-place. Objects with a
/// bound-scheme URI as a VALUE have that value replaced by the
/// secret's UTF-8 bytes (non-UTF-8 secrets record a failure and
/// leave the original string in place). Object KEYS are never
/// expanded — a secret key that happened to look like a URI
/// would silently corrupt the config.
pub async fn resolve_secret_refs(value: &mut Value, registry: &PluginRegistry) -> ResolveReport {
    let mut report = ResolveReport::default();
    resolve_walk(value, registry, &mut report).await;
    report
}

/// Resolve a single string field iff it carries a bound `scheme://...`
/// URI. Returns:
/// - `Ok(Some(resolved))` — the URI's scheme was bound and the
///   provider returned a UTF-8 secret.
/// - `Ok(None)` — the string is not a `scheme://...` URI, OR the
///   scheme is not bound to any provider (caller proceeds with the
///   raw string).
/// - `Err(_)` — the URI looked valid + the scheme was bound, but
///   the provider failed (network, permission, non-UTF-8 secret).
///
/// Companion to [`resolve_secret_refs`] for callers that hold a
/// single string instead of a JSON tree (OAuth `client_secret`,
/// HTTP basic-auth credentials, state-config passwords, etc.).
pub async fn resolve_single_secret_ref(
    input: &str,
    registry: &PluginRegistry,
) -> Result<Option<String>, SecretError> {
    let Some((scheme, _)) = parse_secret_ref(input) else {
        return Ok(None);
    };
    let Some(provider) = registry.secret_provider_for_scheme(scheme) else {
        return Ok(None);
    };
    let secret = provider.get(input).await?;
    let text = std::str::from_utf8(&secret.bytes).map_err(|_| SecretError::Backend {
        reason: "secret value is not valid UTF-8; cannot use as a string field".to_owned(),
    })?;
    Ok(Some(text.to_owned()))
}

/// Canonical per-plugin resource-allowlist key for a `scheme://resource`
/// secret/config URI — the FULL form, `#anchor` PRESERVED. The anchor is NOT
/// stripped because for some schemes it selects a distinct secret: the Vault
/// KV provider, for example, reads one path and then picks `#field`
/// client-side, so `vault://kv/app#github` and `vault://kv/app#stripe` are
/// independent secrets sharing a path. Stripping would let a plugin that
/// references one field read its siblings. The whole-resource case (a bare
/// `scheme://path` grant covering any `#field` on it) is handled in the gate
/// via [`resource_allowlist_base_key`], not by collapsing the key here.
/// Returns `None` for strings that aren't `scheme://…` URIs.
#[must_use]
pub fn resource_allowlist_key(uri: &str) -> Option<String> {
    let (scheme, rest) = parse_secret_ref(uri)?;
    Some(format!("{scheme}://{rest}"))
}

/// The anchor-stripped `scheme://resource` base of a URI (the `#anchor`
/// removed). The gate uses this so a plugin granted the WHOLE resource (a
/// bare `scheme://path` reference in config) may also read any `#field` on it
/// — while a plugin granted only a single field cannot widen to its siblings.
/// Returns `None` for non-URI strings.
#[must_use]
pub fn resource_allowlist_base_key(uri: &str) -> Option<String> {
    let (scheme, rest) = parse_secret_ref(uri)?;
    let base = rest.split('#').next().unwrap_or(rest);
    Some(format!("{scheme}://{base}"))
}

/// Collect the set of concrete secret/config `scheme://resource` URIs a plugin
/// config statically references (anchor-stripped via [`resource_allowlist_key`]).
/// Used to derive the per-plugin host-FFI resource allowlist at boot: a
/// cdylib's `resolve_secret` / `config_snapshot` callback is then scoped to
/// the resources its OWN operator-authored config names, so holding
/// `SecretsRead{env}` no longer lets it read EVERY env var (nor `SecretsRead{file}`
/// every file). Over-collection is benign — a non-secret URL (`http://…`)
/// lands in the set but the scheme-level capability gate refuses it first.
///
/// MUST run against the PRE-resolution config: [`resolve_secret_refs`]
/// substitutes these URIs in place, so a post-resolution walk finds nothing.
#[must_use]
pub fn collect_resource_refs(value: &Value) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    collect_resource_walk(value, &mut out);
    out
}

fn collect_resource_walk(value: &Value, out: &mut std::collections::HashSet<String>) {
    match value {
        Value::String(s) => {
            if let Some(key) = resource_allowlist_key(s) {
                out.insert(key);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_resource_walk(item, out);
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                collect_resource_walk(v, out);
            }
        }
        _ => {}
    }
}

// Send-safe wrapper around `*mut Value`. The walker is single-
// threaded between awaits — the future may be moved between
// tokio worker threads when not awaiting, but no two threads
// ever access the same pointer concurrently. The `Value` the
// pointer aliases lives in storage owned by the caller of
// [`resolve_secret_refs`], which itself is held inside a future
// state — the storage moves with the future, so the pointer
// stays valid across thread moves.
//
// Wrapping is purely so the enclosing future is `Send` (so axum
// admin handlers can call into `reload_config` without hitting
// "future is !Send" — `*mut T` is `!Send` by default).
struct SendPtr(*mut Value);
// SAFETY: see comment above. The pointer is only ever
// dereferenced on the task that owns the underlying future, and
// the future itself owns the `&mut Value` chain rooted in the
// caller's storage.
unsafe impl Send for SendPtr {}

// Recursive walker. Async recursion is awkward, so we push each
// nested `Value` onto a stack instead of recursing through `.await`
// — keeps the stack bounded + makes the implementation a single
// async fn without Box::pin gymnastics.
async fn resolve_walk(value: &mut Value, registry: &PluginRegistry, report: &mut ResolveReport) {
    // Depth-first via an explicit stack of mut references. We
    // push each reachable leaf + nested container onto the stack;
    // leaves get resolved; containers get their children pushed.
    //
    // Using `&mut Value` pointers inside the stack is sound
    // because each element is popped + its children pushed before
    // any aliasing reference is taken — classic "one-token"
    // borrow walking.
    let mut stack: Vec<SendPtr> = vec![SendPtr(value as *mut Value)];
    while let Some(SendPtr(ptr)) = stack.pop() {
        // SAFETY: pointers in the stack were derived from the
        // caller's `&mut Value` + every child-pointer we push
        // comes from the parent we just inspected; we never
        // hold two overlapping `&mut Value` at the same time
        // (each iteration processes one node before touching
        // any child).
        let v = unsafe { &mut *ptr };
        match v {
            Value::String(s) => {
                if let Some((scheme, _)) = parse_secret_ref(s) {
                    // Look up the provider. An unbound scheme
                    // leaves the string alone (records the
                    // skip) — this is benign for configs that
                    // contain URLs etc.
                    let Some(provider) = registry.secret_provider_for_scheme(scheme) else {
                        report.skipped_schemes.insert(scheme.to_owned());
                        continue;
                    };
                    // Snapshot scheme + ref strings before the
                    // mutable borrow on `*v` to keep the audit emit
                    // path borrow-clean.
                    let scheme_owned = scheme.to_owned();
                    let secret_ref_owned = s.clone();
                    match provider.get(s).await {
                        Ok(secret_value) => {
                            // Only UTF-8 bytes replace a JSON
                            // string; non-UTF-8 records a
                            // failure + leaves the original.
                            match std::str::from_utf8(&secret_value.bytes) {
                                Ok(text) => {
                                    *v = Value::String(text.to_owned());
                                    report.expanded += 1;
                                    report.resolved_refs.insert(secret_ref_owned.clone());
                                    // Every secret
                                    // expansion lands on the audit lane.
                                    let event = crate::audit_events::secret_resolved_event(
                                        crate::audit_events::system_identity(),
                                        &scheme_owned,
                                        &secret_ref_owned,
                                        true,
                                        None,
                                    );
                                    let _ = registry.emit_audit_event(&event).await;
                                }
                                Err(_) => {
                                    let event = crate::audit_events::secret_resolved_event(
                                        crate::audit_events::system_identity(),
                                        &scheme_owned,
                                        &secret_ref_owned,
                                        false,
                                        Some("secret value is not valid UTF-8"),
                                    );
                                    let _ = registry.emit_audit_event(&event).await;
                                    report.failures.push(ResolveFailure {
                                        secret_ref: secret_ref_owned,
                                        error: SecretError::Backend {
                                            reason: "secret value is not valid UTF-8; \
                                                 cannot replace JSON string"
                                                .into(),
                                        },
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            let err_msg = e.to_string();
                            let event = crate::audit_events::secret_resolved_event(
                                crate::audit_events::system_identity(),
                                &scheme_owned,
                                &secret_ref_owned,
                                false,
                                Some(&err_msg),
                            );
                            let _ = registry.emit_audit_event(&event).await;
                            report.failures.push(ResolveFailure {
                                secret_ref: secret_ref_owned,
                                error: e,
                            });
                        }
                    }
                }
            }
            Value::Array(items) => {
                for item in items.iter_mut() {
                    stack.push(SendPtr(item as *mut Value));
                }
            }
            Value::Object(map) => {
                for (_k, item) in map.iter_mut() {
                    stack.push(SendPtr(item as *mut Value));
                }
            }
            // Null, Bool, Number — nothing to resolve.
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use mcpg_plugin_protocol::{
        PluginClass, PluginManifest, PluginTier,
        secret::{SecretError, SecretProvider, SecretValue},
    };

    #[test]
    fn resource_allowlist_key_preserves_anchor_and_rejects_non_uris() {
        assert_eq!(
            resource_allowlist_key("env://OPENAI_KEY").as_deref(),
            Some("env://OPENAI_KEY")
        );
        // `#anchor` is PRESERVED — for some schemes (vault) it selects a
        // distinct secret, so it is part of the authorization key.
        assert_eq!(
            resource_allowlist_key("vault://kv/app#stripe").as_deref(),
            Some("vault://kv/app#stripe")
        );
        // The base key strips the anchor (used for whole-resource grants).
        assert_eq!(
            resource_allowlist_base_key("vault://kv/app#stripe").as_deref(),
            Some("vault://kv/app")
        );
        assert_eq!(resource_allowlist_key("not-a-uri"), None);
        assert_eq!(resource_allowlist_key("://missing-scheme"), None);
        assert_eq!(resource_allowlist_base_key("not-a-uri"), None);
    }

    #[test]
    fn collect_resource_refs_finds_secret_and_config_uris_nested() {
        let cfg = serde_json::json!({
            "api_key": "env://OPENAI_KEY",
            // anchored vault ref — the anchor is preserved (distinct secret).
            "tls": { "ca": "vault://secret/data/tls#ca" },
            "list": ["vault://secret/data/db", { "k": "plain-string" }],
            // already-resolved literal — not a URI, must not appear.
            "host": "db.internal",
        });
        let refs = collect_resource_refs(&cfg);
        assert!(refs.contains("env://OPENAI_KEY"), "{refs:?}");
        assert!(refs.contains("vault://secret/data/tls#ca"), "{refs:?}");
        assert!(refs.contains("vault://secret/data/db"), "{refs:?}");
        assert_eq!(refs.len(), 3, "no spurious resources: {refs:?}");
    }

    struct FixedProvider {
        manifest: PluginManifest,
        schemes: Vec<String>,
        bytes: bytes::Bytes,
    }

    #[mcpg_plugin_protocol::async_trait]
    impl SecretProvider for FixedProvider {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn supported_schemes(&self) -> Vec<String> {
            self.schemes.clone()
        }
        async fn get(&self, _r: &str) -> Result<SecretValue, SecretError> {
            Ok(SecretValue::new(self.bytes.clone()))
        }
    }

    fn provider(id: &str, schemes: &[&str], body: &'static [u8]) -> Arc<FixedProvider> {
        Arc::new(FixedProvider {
            manifest: PluginManifest {
                id: id.into(),
                version: "0.1.0".into(),
                name: "fixed".into(),
                plugin_class: PluginClass::SecretProvider,
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
            schemes: schemes.iter().map(|s| (*s).to_owned()).collect(),
            bytes: bytes::Bytes::from_static(body),
        })
    }

    fn registry_with(scheme: &str, body: &'static [u8]) -> PluginRegistry {
        let mut reg = PluginRegistry::new();
        reg.register_secret_provider(
            provider("dev.test.secret", &[scheme], body),
            PluginTier::Native,
        )
        .unwrap();
        reg.bind_secret_scheme(scheme, "dev.test.secret").unwrap();
        reg
    }

    #[tokio::test]
    async fn resolves_top_level_string() {
        let reg = registry_with("vault", b"hunter2");
        let mut v = serde_json::json!("vault://DB_PASS");
        let report = resolve_secret_refs(&mut v, &reg).await;
        assert!(report.is_ok());
        assert_eq!(report.expanded, 1);
        assert_eq!(v, serde_json::json!("hunter2"));
    }

    #[tokio::test]
    async fn resolves_nested_string_in_object() {
        let reg = registry_with("vault", b"secret-value");
        let mut v = serde_json::json!({
            "db": {
                "password": "vault://DB_PASS",
                "host": "localhost"
            }
        });
        let report = resolve_secret_refs(&mut v, &reg).await;
        assert!(report.is_ok());
        assert_eq!(report.expanded, 1);
        assert_eq!(v["db"]["password"], "secret-value");
        assert_eq!(v["db"]["host"], "localhost");
    }

    #[tokio::test]
    async fn resolves_string_in_array() {
        let reg = registry_with("vault", b"v");
        let mut v = serde_json::json!(["plain", "vault://A", 42, "vault://B"]);
        let report = resolve_secret_refs(&mut v, &reg).await;
        assert_eq!(report.expanded, 2);
        assert_eq!(v[1], "v");
        assert_eq!(v[3], "v");
        // Non-strings pass through.
        assert_eq!(v[2], 42);
        assert_eq!(v[0], "plain");
    }

    #[tokio::test]
    async fn unbound_scheme_is_skipped_not_errored() {
        let reg = registry_with("aws", b"v");
        let mut v = serde_json::json!({
            "vault_ref": "vault://secret/data/db#password",
            "http_url": "https://example.com/api",
        });
        let report = resolve_secret_refs(&mut v, &reg).await;
        assert!(report.is_ok(), "unbound schemes aren't errors");
        assert!(
            report.skipped_schemes.contains("vault"),
            "skipped set includes vault: {:?}",
            report.skipped_schemes
        );
        assert!(
            report.skipped_schemes.contains("https"),
            "https also looks like a scheme"
        );
        // Original strings preserved.
        assert_eq!(v["vault_ref"], "vault://secret/data/db#password");
        assert_eq!(v["http_url"], "https://example.com/api");
    }

    #[tokio::test]
    async fn provider_error_lands_in_report_not_panic() {
        struct FailingProvider {
            manifest: PluginManifest,
        }
        #[mcpg_plugin_protocol::async_trait]
        impl SecretProvider for FailingProvider {
            fn manifest(&self) -> &PluginManifest {
                &self.manifest
            }
            fn supported_schemes(&self) -> Vec<String> {
                vec!["vault".into()]
            }
            async fn get(&self, _r: &str) -> Result<SecretValue, SecretError> {
                Err(SecretError::PermissionDenied)
            }
        }

        let mut reg = PluginRegistry::new();
        reg.register_secret_provider(
            Arc::new(FailingProvider {
                manifest: PluginManifest {
                    id: "dev.test.failing".into(),
                    version: "0.1.0".into(),
                    name: "fail".into(),
                    plugin_class: PluginClass::SecretProvider,
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
            }),
            PluginTier::Native,
        )
        .unwrap();
        reg.bind_secret_scheme("vault", "dev.test.failing").unwrap();

        let mut v = serde_json::json!({
            "password": "vault://DENY_ME"
        });
        let report = resolve_secret_refs(&mut v, &reg).await;
        assert!(!report.is_ok());
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].error.kind_label(), "permission_denied");
        // Original string preserved on failure.
        assert_eq!(v["password"], "vault://DENY_ME");
    }

    #[tokio::test]
    async fn non_utf8_secret_records_failure() {
        let reg = registry_with("vault", &[0xFF, 0xFE, 0xFD]);
        let mut v = serde_json::json!("vault://BINARY_SECRET");
        let report = resolve_secret_refs(&mut v, &reg).await;
        assert_eq!(report.expanded, 0);
        assert_eq!(report.failures.len(), 1);
        // Original string preserved.
        assert_eq!(v, serde_json::json!("vault://BINARY_SECRET"));
    }

    #[tokio::test]
    async fn object_keys_are_not_expanded() {
        let reg = registry_with("vault", b"expanded");
        // A string that looks like a vault:// URI used as a key
        // MUST NOT be mutated — JSON key = value structure is
        // structural.
        let mut v = serde_json::json!({
            "vault://LOOKS_LIKE_A_KEY": "plain-value"
        });
        let report = resolve_secret_refs(&mut v, &reg).await;
        assert_eq!(report.expanded, 0);
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["vault://LOOKS_LIKE_A_KEY"]);
    }
}
