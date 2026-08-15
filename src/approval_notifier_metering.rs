//! Metrics wrapper around `Arc<dyn ApprovalNotifier>`.
//! Transparent — callers see `Arc<dyn ApprovalNotifier>` and never
//! observe this type. Mirrors `credential_metering`.
//!
//! Two metrics per request:
//!
//!   - `mcpg_approval_notify_total{plugin_id, channel, result}`
//!     — counter. `result` is `ok` | `<error_kind>` per
//!     `NotificationError::kind_label()` (bounded labels).
//!   - `mcpg_approval_notify_latency_seconds{plugin_id}`
//!     — histogram, sampled regardless of outcome.

use std::sync::Arc;
use std::time::Instant;

use mcpg_plugin_protocol::PluginManifest;
use mcpg_plugin_protocol::approval_notifier::{
    ApprovalNotifier, NotificationError, NotificationRequest, NotificationResult,
};
use mcpg_plugin_protocol::async_trait;
use tracing::Instrument;

pub(crate) struct MeteredApprovalNotifier {
    plugin_id: String,
    inner: Arc<dyn ApprovalNotifier>,
}

impl MeteredApprovalNotifier {
    pub(crate) fn wrap(inner: Arc<dyn ApprovalNotifier>) -> Arc<dyn ApprovalNotifier> {
        let plugin_id = inner.manifest().id.clone();
        Arc::new(Self { plugin_id, inner })
    }
}

#[async_trait]
impl ApprovalNotifier for MeteredApprovalNotifier {
    fn manifest(&self) -> &PluginManifest {
        self.inner.manifest()
    }

    async fn notify(
        &self,
        request: &NotificationRequest,
    ) -> Result<NotificationResult, NotificationError> {
        // Plugin-attributed span so approval notify
        // traces resolve to the notifier plugin id.
        let span = crate::sampled_info_span!(
            "approval_notify",
            plugin_id = %self.plugin_id,
        );
        let started = Instant::now();
        let result = self.inner.notify(request).instrument(span).await;
        metrics::histogram!(
            "mcpg_approval_notify_latency_seconds",
            "plugin_id" => self.plugin_id.clone(),
        )
        .record(started.elapsed().as_secs_f64());
        let (label, channel) = match &result {
            Ok(ok) => ("ok", ok.channel.clone()),
            Err(e) => (e.kind_label(), "unknown".to_owned()),
        };
        metrics::counter!(
            "mcpg_approval_notify_total",
            "plugin_id" => self.plugin_id.clone(),
            "channel" => channel,
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
    use mcpg_plugin_protocol::manifest::{PluginClass, PluginManifest};

    struct StubNotifier {
        manifest: PluginManifest,
    }

    #[async_trait]
    impl ApprovalNotifier for StubNotifier {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn notify(
            &self,
            _request: &NotificationRequest,
        ) -> Result<NotificationResult, NotificationError> {
            Ok(NotificationResult {
                channel: "slack#secops".into(),
                metadata: Default::default(),
            })
        }
    }

    fn manifest() -> PluginManifest {
        PluginManifest {
            id: "test.approval".into(),
            version: "0.0.1".into(),
            name: "test".into(),
            plugin_class: PluginClass::ApprovalNotifier,
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

    fn request() -> NotificationRequest {
        NotificationRequest {
            approval_id: "appr_1".into(),
            summary: "test".into(),
            deadline_at: "2026-04-26T10:00:00Z".into(),
            direct_callback_url: "https://gw.example.com/webhooks/approvals/appr_1?sig=abc".into(),
            identity: mcpg_plugin_protocol::types::PluginIdentity {
                kind: "verified".into(),
                trust_level: "verified".into(),
                subject_id: Some("alice".into()),
                auth_provider: None,
                issuer: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: std::collections::BTreeMap::new(),
            },
            tool_name: "rm".into(),
            arguments: None,
            metadata: None,
        }
    }

    #[tokio::test]
    async fn metering_wrapper_delegates_notify() {
        let stub = StubNotifier {
            manifest: manifest(),
        };
        let wrapped = MeteredApprovalNotifier::wrap(Arc::new(stub));
        let res = wrapped.notify(&request()).await.unwrap();
        assert_eq!(res.channel, "slack#secops");
    }

    #[tokio::test]
    async fn metering_wrapper_preserves_manifest_id() {
        let stub = StubNotifier {
            manifest: manifest(),
        };
        let wrapped = MeteredApprovalNotifier::wrap(Arc::new(stub));
        assert_eq!(wrapped.manifest().id, "test.approval");
    }
}
