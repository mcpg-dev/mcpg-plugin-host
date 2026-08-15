//! Metrics wrapper around `Arc<dyn CredentialIssuer>`.
//! Transparent — callers see `Arc<dyn CredentialIssuer>` and
//! never know about this type. Mirrors `policy_metering`.
//!
//! Three metrics per request:
//!
//!   - `mcpg_credential_issue_total{plugin_id, target, result}`
//!     — counter. `result` is `ok` | `<error_kind>` per
//!     `CredentialError::kind_label()` (bounded labels).
//!   - `mcpg_credential_issue_latency_seconds{plugin_id, target}`
//!     — histogram, sampled regardless of outcome.
//!   - `mcpg_credential_revoke_total{plugin_id, result}` —
//!     counter. `result` is `ok` | `<error_kind>`.

use std::sync::Arc;
use std::time::Instant;

use mcpg_plugin_protocol::PluginManifest;
use mcpg_plugin_protocol::async_trait;
use mcpg_plugin_protocol::credential::{CredentialError, CredentialIssuer, IssuedCredential};
use mcpg_plugin_protocol::types::PluginIdentity;
use tracing::Instrument;

pub(crate) struct MeteredCredentialIssuer {
    plugin_id: String,
    inner: Arc<dyn CredentialIssuer>,
}

impl MeteredCredentialIssuer {
    pub(crate) fn wrap(inner: Arc<dyn CredentialIssuer>) -> Arc<dyn CredentialIssuer> {
        let plugin_id = inner.manifest().id.clone();
        Arc::new(Self { plugin_id, inner })
    }
}

#[async_trait]
impl CredentialIssuer for MeteredCredentialIssuer {
    fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }

    fn credential_kind(&self) -> String {
        // Forward the inner issuer's kind so an explicit override survives
        // the metering decorator — otherwise the host's kind-precise
        // capability gate would fall back to the manifest-id default.
        self.inner.credential_kind()
    }

    async fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        config: &serde_json::Value,
    ) -> Result<IssuedCredential, CredentialError> {
        // Plugin-attributed span so traces resolve back
        // to the credential-issuer plugin id for per-plugin override.
        let span = crate::sampled_info_span!(
            "credential_issue",
            plugin_id = %self.plugin_id,
            target = %target,
        );
        let started = Instant::now();
        let result = self
            .inner
            .issue(identity, target, config)
            .instrument(span)
            .await;
        let label = match &result {
            Ok(_) => "ok",
            Err(e) => e.kind_label(),
        };
        metrics::histogram!(
            "mcpg_credential_issue_latency_seconds",
            "plugin_id" => self.plugin_id.clone(),
            "target" => target.to_owned(),
        )
        .record(started.elapsed().as_secs_f64());
        metrics::counter!(
            "mcpg_credential_issue_total",
            "plugin_id" => self.plugin_id.clone(),
            "target" => target.to_owned(),
            "result" => label,
        )
        .increment(1);
        result
    }

    async fn revoke(&self, lease_id: &str) -> Result<(), CredentialError> {
        let span = crate::sampled_info_span!(
            "credential_revoke",
            plugin_id = %self.plugin_id,
        );
        let result = self.inner.revoke(lease_id).instrument(span).await;
        let label = match &result {
            Ok(_) => "ok",
            Err(e) => e.kind_label(),
        };
        metrics::counter!(
            "mcpg_credential_revoke_total",
            "plugin_id" => self.plugin_id.clone(),
            "result" => label,
        )
        .increment(1);
        result
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::credential::IssuedCredential;
    use mcpg_plugin_protocol::manifest::{PluginClass, PluginManifest};
    use std::collections::BTreeMap;

    struct StubIssuer {
        manifest: PluginManifest,
    }

    #[async_trait]
    impl CredentialIssuer for StubIssuer {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn issue(
            &self,
            _identity: &PluginIdentity,
            _target: &str,
            _config: &serde_json::Value,
        ) -> Result<IssuedCredential, CredentialError> {
            Ok(IssuedCredential::from_value("token", 60))
        }
    }

    fn manifest() -> PluginManifest {
        PluginManifest {
            id: "test.cred".into(),
            version: "0.0.1".into(),
            name: "test".into(),
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

    #[tokio::test]
    async fn metering_wrapper_delegates_issue() {
        let stub = StubIssuer {
            manifest: manifest(),
        };
        let wrapped = MeteredCredentialIssuer::wrap(Arc::new(stub));
        let cred = wrapped
            .issue(&identity(), "tgt", &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(cred.value.as_deref(), Some("token"));
    }
}
