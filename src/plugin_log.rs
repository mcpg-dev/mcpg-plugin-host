//! A native plugin's own `tracing` events, as the plugin SDK forwards them
//! (a [`PLUGIN_LOG_EVENT`](mcpg_plugin_protocol::logs::PLUGIN_LOG_EVENT) span
//! event whose attrs are a [`LogRecord`]), written to the host log.

use std::collections::BTreeMap;

use mcpg_plugin_protocol::logs::{LogLevel, LogRecord, PLUGIN_LOG_TARGET};
use mcpg_plugin_protocol::redact::{redact_in_text, redact_value};
use serde_json::Value;

/// Log `record` under [`PLUGIN_LOG_TARGET`] at its own level, with the
/// plugin entry's `alias` as `plugin_id` and the plugin's target as
/// `plugin_target`.
pub(crate) fn emit(alias: &str, record: LogRecord) {
    let message = render(&record.message, record.fields);
    let target = record.target;
    match record.level {
        LogLevel::Error => tracing::error!(
            target: PLUGIN_LOG_TARGET,
            plugin_id = %alias,
            plugin_target = %target,
            "{message}"
        ),
        LogLevel::Warn => tracing::warn!(
            target: PLUGIN_LOG_TARGET,
            plugin_id = %alias,
            plugin_target = %target,
            "{message}"
        ),
        LogLevel::Info => tracing::info!(
            target: PLUGIN_LOG_TARGET,
            plugin_id = %alias,
            plugin_target = %target,
            "{message}"
        ),
        LogLevel::Debug => tracing::debug!(
            target: PLUGIN_LOG_TARGET,
            plugin_id = %alias,
            plugin_target = %target,
            "{message}"
        ),
        LogLevel::Trace => tracing::trace!(
            target: PLUGIN_LOG_TARGET,
            plugin_id = %alias,
            plugin_target = %target,
            "{message}"
        ),
    }
}

/// The message with each field appended as `key=value`. The plugin chose
/// every part of it, so URL credentials are redacted as they are in span
/// attributes.
fn render(message: &str, fields: BTreeMap<String, Value>) -> String {
    let mut out = redact_in_text(message);
    for (key, mut value) in fields {
        redact_value(&mut value);
        let text = match value {
            Value::String(s) => s,
            other => other.to_string(),
        };
        out.push(' ');
        out.push_str(&key);
        out.push('=');
        out.push_str(&text);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_follow_the_message_as_key_value_pairs() {
        let mut fields = BTreeMap::new();
        fields.insert("bucket".to_owned(), Value::from("leases"));
        fields.insert("attempts".to_owned(), Value::from(3));
        assert_eq!(
            render("sweep failed", fields),
            "sweep failed attempts=3 bucket=leases"
        );
    }

    #[test]
    fn url_credentials_are_redacted_in_the_message_and_the_fields() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "server".to_owned(),
            Value::from("nats://ops:hunter2@nats.internal:4222"),
        );
        let line = render(
            "connect to nats://ops:hunter2@nats.internal:4222 failed",
            fields,
        );
        assert!(!line.contains("hunter2"), "{line}");
        assert!(line.contains("nats.internal:4222"), "{line}");
    }
}
