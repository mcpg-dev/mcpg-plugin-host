//! Helpers for building [`mcpg_plugin_protocol::audit::AuditEvent`]s
//! from gateway-side contexts — avoids scattering
//! `AuditEvent { event_id: Uuid::now_v7(), occurred_at: chrono::Utc::
//! now().to_rfc3339(), ... }` boilerplate across every emit site.
//!
//! All helpers mint a UUIDv7 event_id (time-sortable — audit
//! consumers replay in creation order), stamp `occurred_at` from
//! the host's wall clock, and leave `prev_event_hash = None` (each
//! sink is responsible for its own chain, per spec §9.12).

use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::{PluginContext, PluginIdentity};

/// Mint an RFC 3339 UTC timestamp with millisecond precision —
/// matches the wire format every compliance vendor expects and is
/// what `dev.mcpg.builtin.audit.local-file` uses for `persisted_at`.
pub fn now_rfc3339_utc() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Fresh UUIDv7 as the canonical event_id shape. Sorts
/// lexicographically by creation time — handy for auditors
/// replaying the chain.
pub fn new_event_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Build a `system`-actor identity for lifecycle events (gateway
/// boot, plugin load/unload, admin actions). Distinct from
/// `anonymous` so consumers can tell apart "no caller identity"
/// from "the gateway itself emitted this".
#[must_use]
pub fn system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "system".into(),
        subject_id: Some("mcpg-gateway".into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: std::collections::BTreeMap::new(),
    }
}

/// Build an audit event for a tool-gate short-circuit decision.
/// `outcome` is `Denied` for a `Deny`, `Partial` for a
/// `Challenge`, `Success` for Allow (used by the success-path
/// helpers below).
#[must_use]
pub fn tool_gate_event(
    ctx: &PluginContext,
    plugin_id: &str,
    action: &str,
    outcome: AuditOutcome,
    details: serde_json::Value,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: action.into(),
        resource: Some(format!("tool://{}", ctx.tool_name)),
        outcome,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "plugin_id": plugin_id,
            "decision": details,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.tool.call.allowed` event — emitted at the end of
/// the pre-dispatch tool_gate chain when no plugin denied or
/// challenged. Records who-called-what for SOC2 / HIPAA "every
/// access on record" auditors. Carries the count of plugins that
/// participated so consumers can correlate against
/// `mcpg_plugin_evaluations_total`.
#[must_use]
pub fn tool_gate_allowed_event(
    ctx: &PluginContext,
    plugin_count: usize,
    chain: &[ChainEntry],
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: "mcpg.tool.call.allowed".into(),
        resource: Some(format!("tool://{}", ctx.tool_name)),
        outcome: AuditOutcome::Success,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "tool_gate_plugins_evaluated": plugin_count,
            "surface": ctx.surface,
            "chain": chain,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.tool.call.completed` event — emitted at the end
/// of the post-dispatch tool_gate chain when no plugin denied or
/// challenged on the way out. Records execution duration so
/// auditors can flag long-running calls.
#[must_use]
pub fn tool_gate_completed_event(
    ctx: &PluginContext,
    plugin_count: usize,
    execution_duration_ms: u64,
    chain: &[ChainEntry],
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: "mcpg.tool.call.completed".into(),
        resource: Some(format!("tool://{}", ctx.tool_name)),
        outcome: AuditOutcome::Success,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "tool_gate_plugins_evaluated": plugin_count,
            "execution_duration_ms": execution_duration_ms,
            "surface": ctx.surface,
            "chain": chain,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.tool.call.unknown` event — emitted when a client
/// calls `tools/call` with a tool name that isn't registered in
/// the capability registry. Closes an enterprise audit gap:
/// SOC2 / PCI-DSS auditors require every access attempt
/// (success or fail) on record. Without this event, an attacker
/// enumerating the tool surface looks identical to a legitimate
/// caller with a typo.
///
/// `tool_name` is captured raw from the client request and SHOULD
/// be capped to 256 bytes by the caller — an attacker could
/// otherwise inject an unbounded payload via the audit lane.
#[must_use]
pub fn tool_call_unknown_event(ctx: &PluginContext) -> AuditEvent {
    // Cap the tool name at 256 bytes to keep the audit event size
    // bounded even when the caller probes with pathological input.
    // Truncate at a UTF-8 boundary so downstream JSON serializers
    // don't choke on a split codepoint.
    let safe_name = sanitize_resource_segment(&ctx.tool_name, 256);
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: "mcpg.tool.call.unknown".into(),
        resource: Some(format!("tool://{safe_name}")),
        outcome: AuditOutcome::Failure,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "surface": ctx.surface,
            "transport": ctx.transport,
            "reason": "tool_not_registered",
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.tool.call.access_denied` event — emitted when the
/// pre-dispatch policy gate rejects a `tools/call` because the
/// caller's trust level / CEL access policy doesn't grant the
/// tool. Distinct from `mcpg.tool.call.denied` (which fires when a
/// tool-gate plugin in the chain denies); this one fires *before*
/// the chain ever runs.
///
/// `audit_reason` is the policy gate's structured reason string
/// (e.g. `tool_trust_requirement_not_met:foo:Verified:Anonymous`)
/// — already designed for audit consumption.
#[must_use]
pub fn tool_call_access_denied_event(ctx: &PluginContext, audit_reason: &str) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: "mcpg.tool.call.access_denied".into(),
        resource: Some(format!("tool://{}", ctx.tool_name)),
        outcome: AuditOutcome::Denied,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "surface": ctx.surface,
            "transport": ctx.transport,
            "audit_reason": audit_reason,
            "trust_level": ctx.identity.trust_level,
        }),
        prev_event_hash: None,
    }
}

/// Truncate `s` to at most `max_bytes` bytes at a UTF-8 character
/// boundary. Audit-side defence so a malicious caller can't blow
/// up the event payload by probing a giant tool name.
fn sanitize_resource_segment(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

/// Build a `mcpg.resource.read.success` event — emitted when a
/// `resources/read` call returned data to the client. Closes an
/// enterprise audit gap: SOC2 CC6.1 + GDPR 30.1.b
/// require "every access to identifiable resources on record."
/// Today resource reads are silent on the audit lane.
///
/// `uri` is captured raw and capped at 1024 bytes (resource URIs
/// can legitimately be longer than tool names — e.g. nested
/// `customer/{id}/profile/{ts}/snapshot`).
#[must_use]
pub fn resource_read_success_event(
    ctx: &PluginContext,
    uri: &str,
    bytes_returned: u64,
) -> AuditEvent {
    let safe_uri = sanitize_resource_segment(uri, 1024);
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: "mcpg.resource.read.success".into(),
        resource: Some(format!("resource://{safe_uri}")),
        outcome: AuditOutcome::Success,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "surface": ctx.surface,
            "transport": ctx.transport,
            "bytes_returned": bytes_returned,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.resource.read.denied` event — emitted when the
/// resource-read surface gate (tool-gate chain run with
/// `surface: "resource"`) denied the call. Distinct from the
/// chain's own `mcpg.tool.call.denied` so auditors filtering by
/// data-access action have a single canonical event.
#[must_use]
pub fn resource_read_denied_event(ctx: &PluginContext, uri: &str, plugin_id: &str) -> AuditEvent {
    let safe_uri = sanitize_resource_segment(uri, 1024);
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: "mcpg.resource.read.denied".into(),
        resource: Some(format!("resource://{safe_uri}")),
        outcome: AuditOutcome::Denied,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "surface": ctx.surface,
            "transport": ctx.transport,
            "denied_by_plugin": plugin_id,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.resource.read.not_found` event — emitted when a
/// `resources/read` references a URI that doesn't match any
/// registered resource. Mirrors the unknown-tool enumeration-
/// detection pattern: an attacker probing the resource catalog
/// looks identical to a typo today; with this event auditors can
/// flag patterns.
#[must_use]
pub fn resource_read_not_found_event(ctx: &PluginContext, uri: &str) -> AuditEvent {
    let safe_uri = sanitize_resource_segment(uri, 1024);
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: "mcpg.resource.read.not_found".into(),
        resource: Some(format!("resource://{safe_uri}")),
        outcome: AuditOutcome::Failure,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "surface": ctx.surface,
            "transport": ctx.transport,
            "reason": "resource_not_registered",
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.prompt.get.success` event — emitted when a
/// `prompts/get` call returned a prompt template to the client.
/// Closes an enterprise audit gap: AI compliance
/// requires a record of every prompt loaded (prompt-engineering
/// IP, PII templates, model-input provenance).
#[must_use]
pub fn prompt_get_success_event(ctx: &PluginContext, prompt_name: &str) -> AuditEvent {
    let safe_name = sanitize_resource_segment(prompt_name, 256);
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: "mcpg.prompt.get.success".into(),
        resource: Some(format!("prompt://{safe_name}")),
        outcome: AuditOutcome::Success,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "surface": ctx.surface,
            "transport": ctx.transport,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.prompt.get.denied` event — emitted when the
/// prompt-get surface gate denied the call.
#[must_use]
pub fn prompt_get_denied_event(
    ctx: &PluginContext,
    prompt_name: &str,
    plugin_id: &str,
) -> AuditEvent {
    let safe_name = sanitize_resource_segment(prompt_name, 256);
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: "mcpg.prompt.get.denied".into(),
        resource: Some(format!("prompt://{safe_name}")),
        outcome: AuditOutcome::Denied,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "surface": ctx.surface,
            "transport": ctx.transport,
            "denied_by_plugin": plugin_id,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.tool.list` / `mcpg.prompt.list` / `mcpg.resource.list`
/// / `mcpg.resource.template.list` event — emitted when a client
/// enumerates the catalog. Closes an enterprise audit gap:
/// useful as a low-volume "the catalog was viewed" event
/// for compliance, plus discovery-phase reconnaissance detection
/// (a single client cycling through every list endpoint repeatedly
/// is a recognizable enumeration pattern).
///
/// `kind` is the catalog kind: `"tool"`, `"prompt"`, `"resource"`,
/// `"resource_template"`. The `details.count` field tells auditors
/// what the user actually saw — important when policy filters /
/// catalog plugins reduce the visible set.
#[must_use]
pub fn list_call_event(
    actor: PluginIdentity,
    request_id: &str,
    session_id: Option<&str>,
    kind: &str,
    count: u64,
    transport: &str,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: format!("mcpg.{kind}.list"),
        resource: Some(format!("catalog://{kind}")),
        outcome: AuditOutcome::Success,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::json!({
            "kind": kind,
            "count": count,
            "session_id": session_id,
            "transport": transport,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.apps.offered` event — emitted when a `tools/list`
/// reply offered the caller one or more SEP-1865 UI-enabled tools.
/// `apps` is a JSON array of `{tool, resourceUri}` objects (the tools
/// carrying `_meta.ui.resourceUri`). Lets the audit trail answer
/// "which apps did principal X see?".
pub fn apps_offered_event(
    actor: PluginIdentity,
    request_id: &str,
    session_id: Option<&str>,
    transport: &str,
    apps: serde_json::Value,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: "mcpg.apps.offered".to_owned(),
        resource: Some("catalog://tool".to_owned()),
        outcome: AuditOutcome::Success,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::json!({
            "apps": apps,
            "session_id": session_id,
            "transport": transport,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.resource.subscribe` event — emitted when a client
/// opens a long-lived subscription to a resource URI.
/// SOC2 wants subscription-time bracketing per identity for "user
/// X had observation access to URI from T1 to T2." Pairs with
/// the matching `mcpg.resource.unsubscribe` event keyed by the
/// shared `details.uri`.
#[must_use]
pub fn resource_subscribe_event(ctx: &PluginContext, uri: &str) -> AuditEvent {
    let safe_uri = sanitize_resource_segment(uri, 1024);
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: "mcpg.resource.subscribe".into(),
        resource: Some(format!("resource://{safe_uri}")),
        outcome: AuditOutcome::Success,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "uri": safe_uri,
            "transport": ctx.transport,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.resource.unsubscribe` event — emitted when a
/// client closes a subscription. `was_subscribed` distinguishes
/// "actually had a subscription that got cancelled" from
/// "no-op against an unknown subscription" — auditors want both
/// on record.
#[must_use]
pub fn resource_unsubscribe_event(
    ctx: &PluginContext,
    uri: &str,
    was_subscribed: bool,
) -> AuditEvent {
    let safe_uri = sanitize_resource_segment(uri, 1024);
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: "mcpg.resource.unsubscribe".into(),
        resource: Some(format!("resource://{safe_uri}")),
        outcome: AuditOutcome::Success,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "uri": safe_uri,
            "was_subscribed": was_subscribed,
            "transport": ctx.transport,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.elicitation.requested` event — emitted when the
/// gateway sends a server-initiated `elicitation/create` to the
/// client (typically from a pipeline step). A
/// "client surface manipulation" record so auditors see when the
/// gateway prompted a user mid-flow.
#[must_use]
pub fn elicitation_requested_event(
    actor: PluginIdentity,
    request_id: &str,
    session_id: Option<&str>,
    pipeline_id: &str,
    step_id: &str,
    server_request_id: &str,
    mode: &str,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: "mcpg.elicitation.requested".into(),
        resource: Some(format!("elicitation://{step_id}")),
        outcome: AuditOutcome::Success,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::json!({
            "session_id": session_id,
            "pipeline_id": pipeline_id,
            "step_id": step_id,
            "server_request_id": server_request_id,
            "mode": mode,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.elicitation.completed` event — emitted when the
/// client posts `notifications/elicitation/complete`.
/// Pairs with `mcpg.elicitation.requested` for symmetry. `action`
/// is the user's response:
/// `"accept"` / `"decline"` / `"cancel"` — declined and cancelled
/// flow the same way through the pipeline but compliance auditors
/// want them distinguishable.
#[must_use]
pub fn elicitation_completed_event(
    ctx: &PluginContext,
    elicitation_id: &str,
    user_action: &str,
) -> AuditEvent {
    let outcome = match user_action {
        "accept" => AuditOutcome::Success,
        "decline" | "cancel" => AuditOutcome::Denied,
        _ => AuditOutcome::Failure,
    };
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: "mcpg.elicitation.completed".into(),
        resource: Some(format!("elicitation://{elicitation_id}")),
        outcome,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "elicitation_id": elicitation_id,
            "user_action": user_action,
            "transport": ctx.transport,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.roots.requested` event — emitted when the gateway
/// sends a server-initiated `roots/list` to the client. A
/// disclosure event — the server learned something about the
/// client's filesystem boundaries. Less risky than sampling but
/// enterprise audit wants every server→client capability probe on
/// record.
#[must_use]
pub fn roots_requested_event(
    actor: PluginIdentity,
    request_id: &str,
    session_id: Option<&str>,
    pipeline_id: &str,
    step_id: &str,
    server_request_id: &str,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: "mcpg.roots.requested".into(),
        resource: Some(format!("roots://{step_id}")),
        outcome: AuditOutcome::Success,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::json!({
            "session_id": session_id,
            "pipeline_id": pipeline_id,
            "step_id": step_id,
            "server_request_id": server_request_id,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.completion.requested` event — emitted when a
/// client requests autocomplete suggestions via
/// `completion/complete`. Completions can touch
/// confidential data (e.g. SQL column names from a schema), so
/// auditors want a record of which `argument` was completed
/// against which reference.
#[must_use]
pub fn completion_requested_event(
    ctx: &PluginContext,
    ref_kind: &str,
    ref_name: &str,
    argument_name: &str,
    suggestion_count: u64,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: "mcpg.completion.requested".into(),
        resource: Some(format!("completion://{ref_kind}/{ref_name}")),
        outcome: AuditOutcome::Success,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "ref_kind": ref_kind,
            "ref_name": ref_name,
            "argument_name": argument_name,
            "suggestion_count": suggestion_count,
            "transport": ctx.transport,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.operation.cancelled` event — emitted when a
/// caller posts `notifications/cancelled` for an in-flight
/// operation. Useful for incident reconstruction
/// ("did the operation actually run before cancel?"). The
/// matching `mcpg.tool.call.completed` event (or its absence)
/// answers that question.
#[must_use]
pub fn operation_cancelled_event(
    ctx: &PluginContext,
    cancelled_request_id: &str,
    reason: Option<&str>,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: "mcpg.operation.cancelled".into(),
        resource: Some(format!("request://{cancelled_request_id}")),
        outcome: AuditOutcome::Success,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "cancelled_request_id": cancelled_request_id,
            "reason": reason,
            "transport": ctx.transport,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.pipeline.started` event — emitted when a multi-
/// step pipeline begins execution. Closes an enterprise audit
/// gap: SOC2 transaction-integrity expectation.
/// Today individual steps emit `mcpg.tool.call.*` events but the
/// pipeline-as-transaction is invisible — auditors can't tell
/// "did all 5 steps run, or did step 3 fail and 1+2 not roll
/// back?". Bookend with the matching `mcpg.pipeline.completed`
/// event keyed by `details.pipeline_id`.
#[must_use]
pub fn pipeline_started_event(
    actor: PluginIdentity,
    request_id: &str,
    session_id: Option<&str>,
    pipeline_id: &str,
    profile: &str,
    step_count: u64,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: "mcpg.pipeline.started".into(),
        resource: Some(format!("pipeline://{profile}")),
        outcome: AuditOutcome::Success,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::json!({
            "pipeline_id": pipeline_id,
            "session_id": session_id,
            "profile": profile,
            "step_count": step_count,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.pipeline.completed` / `mcpg.pipeline.failed`
/// event — emitted when the pipeline reaches a terminal state.
/// `success = false` flips the action to `failed` and the outcome
/// to `Failure`. `duration_ms` covers from start to terminal
/// (including suspended-elicitation/sampling time the pipeline
/// spent waiting on the client).
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn pipeline_completed_event(
    actor: PluginIdentity,
    request_id: &str,
    session_id: Option<&str>,
    pipeline_id: &str,
    profile: &str,
    success: bool,
    steps_completed: u64,
    duration_ms: u64,
    error_message: Option<&str>,
) -> AuditEvent {
    let (action, outcome) = if success {
        ("mcpg.pipeline.completed", AuditOutcome::Success)
    } else {
        ("mcpg.pipeline.failed", AuditOutcome::Failure)
    };
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: action.into(),
        resource: Some(format!("pipeline://{profile}")),
        outcome,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::json!({
            "pipeline_id": pipeline_id,
            "session_id": session_id,
            "profile": profile,
            "steps_completed": steps_completed,
            "duration_ms": duration_ms,
            "error_message": error_message,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.payment.charged` / `mcpg.payment.failed` event —
/// emitted when a payment plugin in the tool-gate chain produces a
/// terminal decision. Closes an enterprise audit gap:
/// PCI-DSS 10.2.1 / 10.2.2 / 10.2.5 require every
/// charge / capture / refund / void / authorize / dispute on the
/// audit lane with the receipt-grade trinity (id, amount,
/// currency).
///
/// `plugin_id` is the payment plugin (e.g. `dev.mcpg.payment.mpp`)
/// — `payment_kind` is derived from the suffix.
/// `success` selects between the two action names. The
/// `receipt_metadata` is the Allow-decision metadata blob from
/// the plugin (typically nested under `org.paymentauth/receipt`);
/// the builder projects its standard fields into
/// `details.receipt` for auditor-friendly access.
#[must_use]
pub fn payment_outcome_event(
    ctx: &PluginContext,
    plugin_id: &str,
    success: bool,
    receipt_metadata: Option<&serde_json::Value>,
    deny_reason: Option<&str>,
) -> AuditEvent {
    let payment_kind = plugin_id
        .strip_prefix("dev.mcpg.payment.")
        .unwrap_or(plugin_id)
        .to_owned();
    let (action, outcome) = if success {
        ("mcpg.payment.charged", AuditOutcome::Success)
    } else {
        ("mcpg.payment.failed", AuditOutcome::Denied)
    };

    // Project the well-known receipt envelope. Payment plugins
    // attach their receipt under `org.paymentauth/receipt` by
    // convention — capture the whole subobject so
    // protocol-specific fields (reference, status, amount,
    // currency, recipient, network) all flow through.
    let receipt = receipt_metadata
        .and_then(|m| m.get("org.paymentauth/receipt").cloned())
        .or_else(|| receipt_metadata.cloned());
    let receipt_id = receipt
        .as_ref()
        .and_then(|r| r.get("reference").or_else(|| r.get("id")))
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: action.into(),
        // Use the receipt id (if known) for the resource URI so
        // auditors can chain {payment://receipt} → original session.
        resource: Some(format!(
            "payment://{}",
            receipt_id.as_deref().unwrap_or("unknown")
        )),
        outcome,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "payment_kind": payment_kind,
            "plugin_id": plugin_id,
            "tool": ctx.tool_name,
            "surface": ctx.surface,
            "receipt": receipt,
            "deny_reason": deny_reason,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.sampling.created` event — emitted when the
/// gateway proxies a `sampling/createMessage` request from a
/// pipeline step to the client. Closes an enterprise audit
/// gap: critical for cost attribution + AI
/// governance ("who asked the gateway to spend tokens, what
/// model, what prompt"). Today only `mcpg_pipeline_suspensions_total`
/// counts these — no per-request audit trail.
///
/// `prompt_hash` is a stable correlation key (the gateway
/// computes BLAKE3 of the canonical message form). Auditors
/// match on this hash without ever storing the prompt
/// plaintext on the audit lane.
///
/// FinOps note: `details.model_hint` + `details.max_tokens`
/// feed cost-attribution dashboards directly — operator runs a
/// sum over the sampling audit stream to spot run-away clients
/// before the bill arrives.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn sampling_requested_event(
    actor: PluginIdentity,
    request_id: &str,
    session_id: Option<&str>,
    pipeline_id: &str,
    step_id: &str,
    server_request_id: &str,
    prompt_hash: &str,
    message_count: u64,
    max_tokens: i64,
    model_hint: Option<&str>,
    include_context: Option<&str>,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: "mcpg.sampling.created".into(),
        // The proxied LLM call's "resource" is the model the
        // client will dispatch to; capture the hint or fall back
        // to a generic identifier.
        resource: Some(format!("sampling://{}", model_hint.unwrap_or("any"))),
        outcome: AuditOutcome::Success,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::json!({
            "session_id": session_id,
            "pipeline_id": pipeline_id,
            "step_id": step_id,
            "server_request_id": server_request_id,
            "prompt_hash": prompt_hash,
            "message_count": message_count,
            "max_tokens": max_tokens,
            "model_hint": model_hint,
            "include_context": include_context,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.auth.failed` event — emitted when identity
/// resolution rejects an inbound credential (invalid JWT, OIDC
/// issuer mismatch, expired token, signature mismatch, etc.).
/// Closes an enterprise audit gap: SOC2 / HIPAA
/// require failed-login dashboards. Today these failures only
/// surface as `tracing::warn!` and a fallback to anonymous —
/// nothing on the audit lane.
///
/// `auth_method` is the verifier kind that rejected the
/// credential: `"oidc"` / `"jwt"` / `"mtls"` etc. `reason` is
/// the verifier's structured rejection string (already designed
/// to be safe to log). `request_id` is the inbound request id;
/// auditors join this against subsequent `mcpg.session.opened`
/// events on the same request_id to spot pattern attacks.
///
/// Actor is set to [`system_identity`] since by definition there
/// is no verified actor — the credential failed to verify.
#[must_use]
pub fn auth_failed_event(
    auth_method: &str,
    reason: &str,
    request_id: &str,
    transport: &str,
) -> AuditEvent {
    // Cap reason at 1024 bytes — verifier messages SHOULD be
    // bounded but a misbehaving plugin could produce something
    // pathological. UTF-8-safe via the existing helper.
    let safe_reason = sanitize_resource_segment(reason, 1024);
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: system_identity(),
        action: "mcpg.auth.failed".into(),
        resource: None,
        outcome: AuditOutcome::Failure,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::json!({
            "auth_method": auth_method,
            "reason": safe_reason,
            "transport": transport,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.session.opened` event — emitted at the success
/// path of `LifecycleOperation::Initialize`. Closes an enterprise
/// audit gap: SOC2 wants session-time
/// bracketing per identity for "user X had an active session
/// from T1 to T2." Without this event, only `gateway_started` /
/// `gateway_stopping` mark time boundaries — operators can't
/// reconstruct per-user session windows.
///
/// `actor` is the request identity at initialize time —
/// resolved by the identity-resolution chain that ran before
/// the dispatch reached the lifecycle handler. Sessions don't
/// carry the actor in the snapshot today, so the matching
/// `session.terminated` event uses [`system_identity`] until
/// actor stash is added.
#[must_use]
pub fn session_opened_event(
    actor: PluginIdentity,
    session_id: &str,
    protocol_version: &str,
    client_name: &str,
    client_version: &str,
    transport: &str,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: "mcpg.session.opened".into(),
        resource: Some(format!("session://{session_id}")),
        outcome: AuditOutcome::Success,
        request_id: None,
        node_id: None,
        details: serde_json::json!({
            "session_id": session_id,
            "protocol_version": protocol_version,
            "client_name": client_name,
            "client_version": client_version,
            "transport": transport,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.session.terminated` event — emitted from
/// `GatewayRuntime::terminate_session` when a session is removed
/// (explicit DELETE / quota rollback / shutdown / idle expiry —
/// `reason` distinguishes). Carries `duration_secs` so auditors
/// can reconstruct session windows + spot anomalously long-lived
/// sessions.
///
/// Actor resolution: today the session snapshot doesn't carry
/// the original actor identity, so this event uses
/// [`system_identity`]. Auditors join opened ↔ terminated via
/// the shared `details.session_id` to recover the actor from
/// the matching `mcpg.session.opened` event.
#[must_use]
pub fn session_terminated_event(
    session_id: &str,
    duration_secs: f64,
    reason: &str,
    client_name: Option<&str>,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: system_identity(),
        action: "mcpg.session.terminated".into(),
        resource: Some(format!("session://{session_id}")),
        outcome: AuditOutcome::Success,
        request_id: None,
        node_id: None,
        details: serde_json::json!({
            "session_id": session_id,
            "duration_secs": duration_secs,
            "reason": reason,
            "client_name": client_name,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.prompt.get.not_found` event — emitted when a
/// `prompts/get` references a name that doesn't match any
/// registered prompt.
#[must_use]
pub fn prompt_get_not_found_event(ctx: &PluginContext, prompt_name: &str) -> AuditEvent {
    let safe_name = sanitize_resource_segment(prompt_name, 256);
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: "mcpg.prompt.get.not_found".into(),
        resource: Some(format!("prompt://{safe_name}")),
        outcome: AuditOutcome::Failure,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "surface": ctx.surface,
            "transport": ctx.transport,
            "reason": "prompt_not_registered",
        }),
        prev_event_hash: None,
    }
}

/// Build an audit event for an admin API action (disable / enable
/// / drain). `actor` is the operator identity as resolved by the
/// admin API auth, or [`system_identity`] if the admin endpoint
/// runs unauthenticated.
#[must_use]
pub fn admin_event(
    actor: PluginIdentity,
    action: &str,
    plugin_id: &str,
    outcome: AuditOutcome,
    details: serde_json::Value,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: action.into(),
        resource: Some(format!("plugin://{plugin_id}")),
        outcome,
        request_id: None,
        node_id: None,
        details,
        prev_event_hash: None,
    }
}

/// Build a gateway-lifecycle audit event. Used for
/// `mcpg.lifecycle.gateway_started` / `gateway_stopping` /
/// `plugin_loaded` / `plugin_unloaded`.
#[must_use]
pub fn lifecycle_event(
    action: &str,
    outcome: AuditOutcome,
    details: serde_json::Value,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: system_identity(),
        action: action.into(),
        resource: None,
        outcome,
        request_id: None,
        node_id: None,
        details,
        prev_event_hash: None,
    }
}

// ---------------------------------------------------------------------------
// Plugin invocation visibility events
// ---------------------------------------------------------------------------

/// Canonical-JSON BLAKE3 of a `serde_json::Value`. Returns the
/// `blake3:<hex>` shape established by the sampling events so audit
/// consumers can interpret hashes uniformly across event types.
/// Serialisation goes through `serde_json::to_vec` for stable byte
/// ordering (serde_json preserves field order from the parsed
/// `Value`, which is good enough — auditors compare equal vs not,
/// they don't reconstruct the value).
#[must_use]
pub fn hash_json_value(v: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(v).unwrap_or_default();
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

/// Build a `mcpg.backend.executed` / `mcpg.backend.failed` event —
/// emitted at every backend dispatch (NATS publish, Kafka publish,
/// SQL query, webhook delivery, LLM completion). Closes an
/// enterprise audit gap: bindings have side effects on
/// external systems and SOC2 wants every "the gateway reached out"
/// moment on the audit lane, not just metered.
///
/// `success = false` flips the action to `failed` and the outcome
/// to `Failure`, and the `error_message` is captured in details.
/// `duration_ms` covers from dispatch to terminal response.
/// `payload_bytes` / `response_bytes` are coarse byte counts so
/// auditors can tell apart "small ack" from "large data exfil"
/// without inspecting payloads on the audit lane.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn backend_executed_event(
    actor: PluginIdentity,
    request_id: &str,
    session_id: Option<&str>,
    kind: &str,
    profile: &str,
    success: bool,
    duration_ms: u64,
    payload_bytes: u64,
    response_bytes: u64,
    error_message: Option<&str>,
    extra_details: serde_json::Map<String, serde_json::Value>,
) -> AuditEvent {
    let (action, outcome) = if success {
        ("mcpg.backend.executed", AuditOutcome::Success)
    } else {
        ("mcpg.backend.failed", AuditOutcome::Failure)
    };
    // Build the details map deterministically so the baseline keys
    // always appear in the same order. Plugin-supplied keys via
    // `extra_details` (P6.3) merge in afterwards — collisions favour
    // the baseline so plugins can't override system-controlled
    // fields like `duration_ms`.
    let mut details = serde_json::Map::new();
    details.insert("kind".into(), kind.into());
    details.insert("profile".into(), profile.into());
    details.insert(
        "session_id".into(),
        match session_id {
            Some(s) => s.into(),
            None => serde_json::Value::Null,
        },
    );
    details.insert("duration_ms".into(), duration_ms.into());
    details.insert("payload_bytes".into(), payload_bytes.into());
    details.insert("response_bytes".into(), response_bytes.into());
    details.insert(
        "error_message".into(),
        match error_message {
            Some(s) => s.into(),
            None => serde_json::Value::Null,
        },
    );
    for (k, v) in extra_details {
        details.entry(k).or_insert(v);
    }
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: action.into(),
        resource: Some(format!("backend://{kind}/{profile}")),
        outcome,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::Value::Object(details),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.transform.applied` event — emitted when a
/// transform plugin returns `Modified` (i.e. the plugin actually
/// rewrote the argument or result). Closes an audit gap:
/// today the metric `mcpg_transform_applies_total{outcome=
/// modified}` records that *something* was rewritten but not the
/// what; the audit event carries `pre_hash` + `post_hash` (BLAKE3
/// of canonical JSON) so auditors can correlate against the
/// call-logger lane (which retains plaintext under the operator's
/// retention policy) and replay the transform chain.
///
/// `phase` is `"pre"` (arguments rewriting before dispatch) or
/// `"post"` (results rewriting after dispatch). Per-plugin
/// attribution comes from `plugin_id`.
#[must_use]
pub fn transform_applied_event(
    ctx: &PluginContext,
    plugin_id: &str,
    phase: &str,
    pre: &serde_json::Value,
    post: &serde_json::Value,
) -> AuditEvent {
    let pre_hash = hash_json_value(pre);
    let post_hash = hash_json_value(post);
    let pre_bytes = serde_json::to_vec(pre).map(|b| b.len() as u64).unwrap_or(0);
    let post_bytes = serde_json::to_vec(post)
        .map(|b| b.len() as u64)
        .unwrap_or(0);
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: ctx.identity.clone(),
        action: "mcpg.transform.applied".into(),
        resource: Some(format!("plugin://{plugin_id}")),
        outcome: AuditOutcome::Success,
        request_id: Some(ctx.request_id.clone()),
        node_id: None,
        details: serde_json::json!({
            "plugin_id": plugin_id,
            "phase": phase,
            "tool": ctx.tool_name,
            "surface": ctx.surface,
            "pre_hash": pre_hash,
            "post_hash": post_hash,
            "pre_bytes": pre_bytes,
            "post_bytes": post_bytes,
            "session_id": ctx.session_id,
            "transport": ctx.transport,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.catalog.filtered` event — emitted once per
/// `tools/list` response after the catalog provider chain runs.
/// Closes an audit gap: operators want "did Alice
/// see tool X in her tools/list?" answerable from the audit lane.
///
/// `hidden` is `(tool_name, plugin_id_that_hid_it)` pairs in the
/// order each provider removed them. The chain is walked
/// sequentially, so the first plugin to drop a tool gets the
/// attribution. `before_count` is the number of tools entering the
/// chain; `after_count` is what survived. When the chain is empty
/// (no catalog providers configured), the call site SHOULD skip
/// the emit — there is no decision to log.
#[must_use]
pub fn catalog_filtered_event(
    actor: PluginIdentity,
    request_id: &str,
    session_id: Option<&str>,
    surface: &str,
    before_count: u64,
    after_count: u64,
    hidden: Vec<(String, String)>,
) -> AuditEvent {
    let hidden_json: Vec<serde_json::Value> = hidden
        .into_iter()
        .map(|(name, plugin_id)| serde_json::json!({ "name": name, "plugin_id": plugin_id }))
        .collect();
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: "mcpg.catalog.filtered".into(),
        resource: Some(format!("catalog://{surface}")),
        outcome: AuditOutcome::Success,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::json!({
            "surface": surface,
            "session_id": session_id,
            "before_count": before_count,
            "after_count": after_count,
            "hidden_count": hidden_json.len() as u64,
            "hidden": hidden_json,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.watch.fired` event — emitted when a watch
/// strategy detects an upstream change and fans out
/// `notifications/resources/updated` to subscribers. Closes an
/// audit gap: auditors track "the system reacted to an
/// external change at T because of watch W."
///
/// `strategy` is one of `"poll"`, `"webhook"`, `"plugin"`. For the
/// plugin variant, `plugin_kind` carries the registered kind
/// (e.g. `"nats_topic"`). `subscriber_count` is the number of
/// subscribers that received the notification — zero is still
/// audit-worthy because it bookends "the change happened" even if
/// no one was listening.
#[must_use]
pub fn watch_fired_event(
    uri: &str,
    strategy: &str,
    plugin_kind: Option<&str>,
    subscriber_count: u64,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: system_identity(),
        action: "mcpg.watch.fired".into(),
        resource: Some(format!("resource://{uri}")),
        outcome: AuditOutcome::Success,
        request_id: None,
        node_id: None,
        details: serde_json::json!({
            "uri": uri,
            "strategy": strategy,
            "plugin_kind": plugin_kind,
            "subscriber_count": subscriber_count,
        }),
        prev_event_hash: None,
    }
}

// ---------------------------------------------------------------------------
// Config / credential / secret / approval / http_route /
// chain effect summary events
// ---------------------------------------------------------------------------

/// One entry in `details.chain[]` of a `mcpg.tool.call.allowed` /
/// `mcpg.tool.call.completed` event. Captures one
/// plugin's contribution to the dispatch — the plugin id, which
/// phase ran (`pre_dispatch` / `post_dispatch`), the decision
/// label (`allow` / `deny` / `challenge` / `pending_approval` /
/// `shadow_allow`), and the wall-clock latency the plugin spent
/// in that evaluation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainEntry {
    pub plugin_id: String,
    pub phase: &'static str,
    pub decision: &'static str,
    pub latency_ms: u64,
}

/// Build a `mcpg.config.loaded` event — emitted from `app::run`
/// once the registry is up and the gateway is about to start
/// serving traffic. Closes an audit gap: every
/// downstream audit event in scope (tool denials, credential
/// issuances, plugin registration outcomes) is anchored to *some*
/// loaded config snapshot; this event lets auditors correlate
/// `event_id` → `config_sha256` → the YAML that was running.
///
/// The SHA-256 covers the post-figment-merge / pre-CEL-expansion
/// shape of `AppConfig` (see `AppConfig::canonical_sha256`). Two
/// gateways loading the same source-of-truth produce the same
/// digest regardless of YAML key ordering or `MCPG_*` env-var
/// overlay reorderings.
///
/// `source_paths` is the slice of YAML paths the operator passed
/// via `MCPG_CONFIG=base.yaml:overlay.yaml`. Empty slice means
/// the gateway booted off `AppConfig::default()` (test / minimal
/// shape).
#[must_use]
pub fn config_loaded_event(sha256: &str, source_paths: &[String]) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: system_identity(),
        action: "mcpg.config.loaded".into(),
        resource: Some("config://gateway".into()),
        outcome: AuditOutcome::Success,
        request_id: None,
        node_id: None,
        details: serde_json::json!({
            "config_sha256": sha256,
            "source_paths": source_paths,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.config.secrets_resolved` event — emitted at boot
/// (after `mcpg.config.loaded`) when the secret-reference scanner
/// finds at least one `${env.X}` or `<scheme>://...`
/// reference in the loaded `AppConfig`.
///
/// Auditors get the explicit "what credentials does this gateway
/// consume" record without parsing the YAML themselves; the
/// `details.refs` array carries one entry per (kind, name,
/// field_path) tuple, sorted + deduplicated. Default-configured
/// gateways (no env-var or secret-URI references) skip the event
/// entirely so the ledger stays quiet for the common case.
///
/// `refs` should be the JSON serialisation of the gateway's
/// `Vec<SecretRef>` from `apps/gateway/src/config/secret_scan.rs`.
#[must_use]
pub fn config_secrets_resolved_event(refs: serde_json::Value) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: system_identity(),
        action: "mcpg.config.secrets_resolved".into(),
        resource: Some("config://gateway/secrets".into()),
        outcome: AuditOutcome::Success,
        request_id: None,
        node_id: None,
        details: serde_json::json!({ "refs": refs }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.config.feature_flags_active` event — emitted at
/// boot and after every reload when at least one operator-controlled
/// strictness flag in the `feature_flags:` block is flipped off the
/// safe default. Auditors get an explicit record of which
/// strictness gates the deployment overrides; default-only
/// configurations skip the event entirely so the ledger stays
/// quiet for the common case.
#[must_use]
pub fn config_feature_flags_active_event(active: serde_json::Value) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: system_identity(),
        action: "mcpg.config.feature_flags_active".into(),
        resource: Some("config://gateway/feature_flags".into()),
        outcome: AuditOutcome::Success,
        request_id: None,
        node_id: None,
        details: active,
        prev_event_hash: None,
    }
}

/// Build a `mcpg.config.reloaded` event — emitted at the end of
/// `app::reload_config`, success or failure path. Closes an audit
/// gap: operators pushing config changes via
/// SIGHUP / Control-Plane pull need an audit trail for "config
/// drift" investigations. Today only `mcpg_config_reloads_total`
/// is metered.
///
/// `source` is `"sighup"` / `"control_plane"` / `"manual"` so
/// auditors can distinguish operator vs CP-driven reloads.
///
/// `prev_sha256` / `next_sha256` carry the
/// [`crate::audit_events::config_loaded_event`]-style hashes
/// before and after the reload. On the failure path
/// `next_sha256` is `None` — the reload aborted before swapping
/// in the new runtime, so the previous config is still live.
#[must_use]
pub fn config_reloaded_event(
    source: &str,
    success: bool,
    error: Option<&str>,
    prev_sha256: Option<&str>,
    next_sha256: Option<&str>,
) -> AuditEvent {
    let outcome = if success {
        AuditOutcome::Success
    } else {
        AuditOutcome::Failure
    };
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: system_identity(),
        action: "mcpg.config.reloaded".into(),
        resource: Some("config://gateway".into()),
        outcome,
        request_id: None,
        node_id: None,
        details: serde_json::json!({
            "source": source,
            "error": error,
            "prev_config_sha256": prev_sha256,
            "next_config_sha256": next_sha256,
        }),
        prev_event_hash: None,
    }
}

/// Build a `governance.quota.exceeded` event — emitted by the
/// runtime quota gate when a request is
/// refused because a rate-limit / budget / concurrency policy
/// blocked it. The event lands on the audit lane regardless of
/// whether the request was anonymous; SOC2 / compliance trails
/// want every refused-by-policy moment on record.
///
/// `backend_name` is the binding the request was targeting,
/// `policy_id` is the operator-declared id from
/// `governance.quotas.{rate_limits,budgets,concurrency}[].id`,
/// and `kind` is one of `"rate_limit"` / `"budget"` /
/// `"concurrency"` (the kind of policy that tripped).
/// `reason` is a short human-readable string ("rate-limit `tier-pro`
/// exhausted for scope `acme-corp`") suitable for audit trails.
#[must_use]
pub fn quota_exceeded_event(
    actor: PluginIdentity,
    request_id: &str,
    backend_name: &str,
    policy_id: &str,
    kind: &str,
    reason: &str,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: "governance.quota.exceeded".into(),
        resource: Some(format!("tool://{backend_name}")),
        outcome: AuditOutcome::Failure,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::json!({
            "policy_id": policy_id,
            "kind": kind,
            "reason": reason,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.credential.issued` event — emitted from the
/// host-side credential resolver alongside the metric counter.
/// Closes an audit gap: SOC2 wants every "secret
/// was exposed to a binding" moment on the audit lane, not just
/// metered. Cache hits don't emit (the credential was already
/// audited on the cache-fill path); this fires only for fresh
/// issuance and re-issuance paths.
///
/// `success = false` flips the action to `mcpg.credential.failed`
/// and outcome to Failure. `target` is the per-binding identifier
/// (e.g. database name, vault path) the credential was scoped to.
#[must_use]
pub fn credential_issued_event(
    actor: PluginIdentity,
    plugin_id: &str,
    target: &str,
    success: bool,
    error: Option<&str>,
) -> AuditEvent {
    let (action, outcome) = if success {
        ("mcpg.credential.issued", AuditOutcome::Success)
    } else {
        ("mcpg.credential.failed", AuditOutcome::Failure)
    };
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: action.into(),
        resource: Some(format!("plugin://{plugin_id}")),
        outcome,
        request_id: None,
        node_id: None,
        details: serde_json::json!({
            "plugin_id": plugin_id,
            "target": target,
            "error": error,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.credential.resolution_failed` event — emitted by
/// backend adapters when a `cred://` URI in their config fails to
/// resolve at dispatch time. Operator-visible only — the caller's
/// surface is an opaque message + correlation id (see
/// `CredentialResolverError::caller_message`).
#[must_use]
pub fn credential_resolution_failed_event(
    actor: PluginIdentity,
    request_id: Option<String>,
    plugin_id: &str,
    target: &str,
    part: Option<&str>,
    error_kind: &'static str,
    error_detail: &str,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: "mcpg.credential.resolution_failed".into(),
        resource: Some(format!("plugin://{plugin_id}")),
        outcome: AuditOutcome::Failure,
        request_id,
        node_id: None,
        details: serde_json::json!({
            "plugin_id": plugin_id,
            "target": target,
            "part": part,
            "error_kind": error_kind,
            "error_detail": error_detail,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.secret.resolved` event — emitted from the
/// host-side secret resolver. Closes an audit gap:
/// every `${scheme://path}` the gateway expanded at request time
/// touches credential material; SOC2 expects the audit lane.
///
/// `success = false` flips the action to `mcpg.secret.failed`
/// and outcome to Failure. The full `secret_ref` is captured —
/// secret URIs identify the *location* of the secret, not its
/// value, so they're safe to record.
#[must_use]
pub fn secret_resolved_event(
    actor: PluginIdentity,
    scheme: &str,
    secret_ref: &str,
    success: bool,
    error: Option<&str>,
) -> AuditEvent {
    let (action, outcome) = if success {
        ("mcpg.secret.resolved", AuditOutcome::Success)
    } else {
        ("mcpg.secret.failed", AuditOutcome::Failure)
    };
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: action.into(),
        resource: Some(secret_ref.to_owned()),
        outcome,
        request_id: None,
        node_id: None,
        details: serde_json::json!({
            "scheme": scheme,
            "secret_ref": secret_ref,
            "error": error,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.approval.requested` event — emitted when the
/// gateway opens a PendingApproval entry. Auditors get every
/// operator-grant / operator-deny decision on record with the
/// approver identity, not just the resulting tool-call audit.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn approval_requested_event(
    actor: PluginIdentity,
    request_id: &str,
    approval_id: &str,
    tool_name: &str,
    summary: &str,
    deadline_at: &str,
    target_notifiers: &[String],
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: "mcpg.approval.requested".into(),
        resource: Some(format!("approval://{approval_id}")),
        outcome: AuditOutcome::Success,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::json!({
            "approval_id": approval_id,
            "tool_name": tool_name,
            "summary": summary,
            "deadline_at": deadline_at,
            "target_notifiers": target_notifiers,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.approval.granted` / `mcpg.approval.denied`
/// event — emitted when a pending approval is resolved. Phase
/// B.12. `granted = true` selects between the two action names
/// and outcomes (Success / Denied).
#[must_use]
pub fn approval_resolved_event(
    actor: PluginIdentity,
    request_id: &str,
    approval_id: &str,
    tool_name: &str,
    granted: bool,
    approver_subject: Option<&str>,
    reason: Option<&str>,
) -> AuditEvent {
    let (action, outcome) = if granted {
        ("mcpg.approval.granted", AuditOutcome::Success)
    } else {
        ("mcpg.approval.denied", AuditOutcome::Denied)
    };
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: action.into(),
        resource: Some(format!("approval://{approval_id}")),
        outcome,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::json!({
            "approval_id": approval_id,
            "tool_name": tool_name,
            "approver_subject": approver_subject,
            "reason": reason,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.approval.expired` event — emitted when the
/// approval deadline elapses without resolution.
/// Outcome is Failure (not Denied) because no operator decision
/// was made; auditors should be able to distinguish "operator
/// rejected" from "operator never saw it".
#[must_use]
pub fn approval_expired_event(
    actor: PluginIdentity,
    request_id: &str,
    approval_id: &str,
    tool_name: &str,
    deadline_at: &str,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: "mcpg.approval.expired".into(),
        resource: Some(format!("approval://{approval_id}")),
        outcome: AuditOutcome::Failure,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::json!({
            "approval_id": approval_id,
            "tool_name": tool_name,
            "deadline_at": deadline_at,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.http_route.dispatched` event — emitted at the
/// end of `transports::http_route::dispatch_inner` for every
/// plugin-handled HTTP route override. Closes an audit gap:
/// HTTP routes bypass the tool-call surface
/// entirely; without this event the gateway's plugin reach into
/// the HTTP plane is invisible to compliance auditors.
///
/// Outcome is derived from the HTTP status: 2xx → Success, 4xx
/// → Denied (auth / forbidden / not-found / etc.), 5xx → Failure.
/// `actor` is `None` when the route allowed anonymous access; the
/// builder substitutes a system identity in that case.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn http_route_dispatched_event(
    actor: Option<PluginIdentity>,
    request_id: &str,
    plugin_id: &str,
    entity_name: &str,
    method: &str,
    path: &str,
    status: u16,
    duration_ms: u64,
) -> AuditEvent {
    let outcome = if (200..400).contains(&status) {
        AuditOutcome::Success
    } else if (400..500).contains(&status) {
        AuditOutcome::Denied
    } else {
        AuditOutcome::Failure
    };
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: actor.unwrap_or_else(system_identity),
        action: "mcpg.http_route.dispatched".into(),
        resource: Some(format!("http_route://{plugin_id}/{entity_name}")),
        outcome,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::json!({
            "plugin_id": plugin_id,
            "entity_name": entity_name,
            "method": method,
            "path": path,
            "status": status,
            "duration_ms": duration_ms,
        }),
        prev_event_hash: None,
    }
}

// ---------------------------------------------------------------------------
// Cluster lifecycle events
// ---------------------------------------------------------------------------

/// Build a `mcpg.cluster.member_joined` / `.member_left` /
/// `.member_health_changed` event — emitted from the centralized
/// `watch_peers` audit subscriber spawned at gateway boot. Closes
/// an audit gap: SREs ask "when did the leader
/// flip the night the alert fired?" and "when did node X drop?"
/// — both answerable from the audit lane via these events.
///
/// `kind` is the PeerEvent variant (`"joined"` / `"left"` /
/// `"health_changed"`); the builder maps to the matching action.
/// `node_id` is the cluster-stable id of the affected peer.
/// `health` is filled for health_changed; None otherwise.
#[must_use]
pub fn cluster_member_event(
    kind: &str,
    node_id: &str,
    health: Option<&str>,
    metadata: Option<&serde_json::Value>,
) -> AuditEvent {
    let action = match kind {
        "joined" => "mcpg.cluster.member_joined",
        "left" => "mcpg.cluster.member_left",
        "health_changed" => "mcpg.cluster.member_health_changed",
        _ => "mcpg.cluster.member_event",
    };
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: system_identity(),
        action: action.into(),
        resource: Some(format!("node://{node_id}")),
        outcome: AuditOutcome::Success,
        request_id: None,
        node_id: Some(node_id.to_owned()),
        details: serde_json::json!({
            "kind": kind,
            "node_id": node_id,
            "health": health,
            "metadata": metadata,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.cluster.leader_changed` event — emitted from the
/// host-side `acquire_leadership` Ok arm in `cluster_metering`.
/// An explicit leader-flip signal. `success = false` flips
/// to `mcpg.cluster.leader_acquire_failed` for the Err arm.
#[must_use]
pub fn cluster_leader_event(
    plugin_id: &str,
    role: &str,
    success: bool,
    error: Option<&str>,
) -> AuditEvent {
    let (action, outcome) = if success {
        ("mcpg.cluster.leader_changed", AuditOutcome::Success)
    } else {
        ("mcpg.cluster.leader_acquire_failed", AuditOutcome::Failure)
    };
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: system_identity(),
        action: action.into(),
        resource: Some(format!("leadership://{role}")),
        outcome,
        request_id: None,
        node_id: None,
        details: serde_json::json!({
            "plugin_id": plugin_id,
            "role": role,
            "error": error,
        }),
        prev_event_hash: None,
    }
}

// ---------------------------------------------------------------------------
// Low-priority protocol bookend events
// ---------------------------------------------------------------------------

/// Build a `mcpg.ping.received` event — emitted at the
/// `ping` handler. Low compliance value; emitted only
/// when the operator explicitly enables `audit.emit.ping = true`
/// to avoid drowning the SIEM at typical keepalive rates.
#[must_use]
pub fn ping_received_event(
    actor: PluginIdentity,
    request_id: &str,
    session_id: Option<&str>,
    transport: &str,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: "mcpg.ping.received".into(),
        resource: Some("system://ping".into()),
        outcome: AuditOutcome::Success,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::json!({
            "session_id": session_id,
            "transport": transport,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.session.initialized_acked` event — emitted at the
/// `notifications/initialized` handler when the client confirms
/// handshake completion. Pairs with
/// `mcpg.session.opened` at Initialize-success; together they
/// bookend the negotiation phase.
#[must_use]
pub fn session_initialized_acked_event(
    actor: PluginIdentity,
    session_id: Option<&str>,
    transport: &str,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: "mcpg.session.initialized_acked".into(),
        resource: session_id.map(|s| format!("session://{s}")),
        outcome: AuditOutcome::Success,
        request_id: None,
        node_id: None,
        details: serde_json::json!({
            "session_id": session_id,
            "transport": transport,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.progress.notified` event — emitted at the central
/// outbound progress-notification site (per chunk for streaming
/// LLM, per pipeline-step transition for elicitation/sampling).
/// High volume; emit only when `audit.emit.progress`
/// is on. Resource URI carries `request://{progress_token}` so
/// auditors can stitch the progress trail to the originating
/// tool call.
#[must_use]
pub fn progress_notified_event(
    actor: PluginIdentity,
    progress_token: &str,
    session_id: Option<&str>,
    progress_value: f64,
    progress_total: Option<f64>,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: "mcpg.progress.notified".into(),
        resource: Some(format!("request://{progress_token}")),
        outcome: AuditOutcome::Success,
        request_id: None,
        node_id: None,
        details: serde_json::json!({
            "progress_token": progress_token,
            "session_id": session_id,
            "progress": progress_value,
            "total": progress_total,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.list.changed_broadcast` event — emitted when the
/// gateway broadcasts a `notifications/{tools,prompts,resources}/
/// list_changed` to a session after a config reload.
/// `kind` distinguishes the catalog whose contents changed.
#[must_use]
pub fn list_changed_event(kind: &str, session_count: u64) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor: system_identity(),
        action: "mcpg.list.changed_broadcast".into(),
        resource: Some(format!("catalog://{kind}")),
        outcome: AuditOutcome::Success,
        request_id: None,
        node_id: None,
        details: serde_json::json!({
            "kind": kind,
            "session_count": session_count,
        }),
        prev_event_hash: None,
    }
}

/// Build a `mcpg.logging.level_set` event — emitted at the
/// `logging/setLevel` handler when a client adjusts its output
/// verbosity. Could roll into
/// `mcpg.session.config_changed` if a future client uses level
/// changes for sensitive purposes; standalone for now to keep the
/// taxonomy explicit.
#[must_use]
pub fn logging_level_set_event(
    actor: PluginIdentity,
    request_id: &str,
    session_id: Option<&str>,
    level: &str,
) -> AuditEvent {
    AuditEvent {
        event_id: new_event_id(),
        occurred_at: now_rfc3339_utc(),
        actor,
        action: "mcpg.logging.level_set".into(),
        resource: session_id.map(|s| format!("session://{s}")),
        outcome: AuditOutcome::Success,
        request_id: Some(request_id.to_owned()),
        node_id: None,
        details: serde_json::json!({
            "session_id": session_id,
            "level": level,
        }),
        prev_event_hash: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_event_id_is_uuidv7_shape() {
        let id = new_event_id();
        // UUIDv7 is a standard 36-char hyphenated form, same as
        // v4 — the difference is in the version nibble. Shape check
        // is enough here; the real cryptographic guarantees come
        // from the `uuid` crate itself.
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn now_rfc3339_utc_ends_with_z() {
        let t = now_rfc3339_utc();
        assert!(t.ends_with('Z'), "expected UTC Z suffix, got {t}");
    }

    #[test]
    fn system_identity_has_system_kind() {
        let id = system_identity();
        assert_eq!(id.kind, "system");
        assert_eq!(id.trust_level, "system");
        assert_eq!(id.subject_id.as_deref(), Some("mcpg-gateway"));
    }

    #[test]
    fn tool_gate_event_populates_request_fields() {
        let ctx = PluginContext {
            request_id: "req-42".into(),
            session_id: Some("s1".into()),
            tool_name: "payments.charge".into(),
            surface: "tool".into(),
            identity: PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: std::collections::BTreeMap::new(),
            },
            transport: "http".into(),
        };
        let ev = tool_gate_event(
            &ctx,
            "dev.mcpg.guard",
            "tool.call.denied",
            AuditOutcome::Denied,
            serde_json::json!({"code": -32000, "message": "blocked"}),
        );
        assert_eq!(ev.action, "tool.call.denied");
        assert_eq!(ev.outcome, AuditOutcome::Denied);
        assert_eq!(ev.resource.as_deref(), Some("tool://payments.charge"));
        assert_eq!(ev.request_id.as_deref(), Some("req-42"));
        assert_eq!(ev.details["plugin_id"], "dev.mcpg.guard");
    }

    #[test]
    fn admin_event_resource_is_plugin_uri() {
        let ev = admin_event(
            system_identity(),
            "mcpg.admin.plugin_disabled",
            "dev.example.ratelimit",
            AuditOutcome::Success,
            serde_json::json!({}),
        );
        assert_eq!(
            ev.resource.as_deref(),
            Some("plugin://dev.example.ratelimit")
        );
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert!(ev.request_id.is_none());
    }

    #[test]
    fn lifecycle_event_has_system_actor_and_no_resource() {
        let ev = lifecycle_event(
            "mcpg.lifecycle.gateway_started",
            AuditOutcome::Success,
            serde_json::json!({"version": "1.0"}),
        );
        assert_eq!(ev.actor.kind, "system");
        assert!(ev.resource.is_none());
        assert_eq!(ev.details["version"], "1.0");
    }

    fn sample_ctx() -> PluginContext {
        PluginContext {
            request_id: "req-99".into(),
            session_id: Some("s2".into()),
            tool_name: "orders.list".into(),
            surface: "tool".into(),
            identity: PluginIdentity {
                kind: "verified".into(),
                trust_level: "verified".into(),
                subject_id: Some("alice".into()),
                auth_provider: Some("okta".into()),
                issuer: None,
                roles: vec![],
                groups: vec![],
                scopes: vec![],
                attributes: std::collections::BTreeMap::new(),
            },
            transport: "http".into(),
        }
    }

    #[test]
    fn tool_gate_allowed_event_carries_plugin_count_and_surface() {
        let ev = tool_gate_allowed_event(&sample_ctx(), 3, &[]);
        assert_eq!(ev.action, "mcpg.tool.call.allowed");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.resource.as_deref(), Some("tool://orders.list"));
        assert_eq!(ev.request_id.as_deref(), Some("req-99"));
        assert_eq!(ev.details["tool_gate_plugins_evaluated"], 3);
        assert_eq!(ev.details["surface"], "tool");
    }

    #[test]
    fn tool_gate_completed_event_carries_duration() {
        let ev = tool_gate_completed_event(&sample_ctx(), 2, 145, &[]);
        assert_eq!(ev.action, "mcpg.tool.call.completed");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.details["execution_duration_ms"], 145);
        assert_eq!(ev.details["tool_gate_plugins_evaluated"], 2);
    }

    // -- tool-call attempt + access-denied events ---------------------

    #[test]
    fn tool_call_unknown_event_records_failed_attempt() {
        let ev = tool_call_unknown_event(&sample_ctx());
        assert_eq!(ev.action, "mcpg.tool.call.unknown");
        assert_eq!(ev.outcome, AuditOutcome::Failure);
        assert_eq!(ev.resource.as_deref(), Some("tool://orders.list"));
        assert_eq!(ev.details["reason"], "tool_not_registered");
        assert_eq!(ev.details["surface"], "tool");
        assert_eq!(ev.details["transport"], "http");
    }

    #[test]
    fn tool_call_unknown_caps_long_tool_names() {
        let mut ctx = sample_ctx();
        ctx.tool_name = "x".repeat(1024);
        let ev = tool_call_unknown_event(&ctx);
        // resource = "tool://" + capped 256 = at most 7 + 256 = 263 chars
        let r = ev.resource.expect("resource set");
        assert!(r.starts_with("tool://"));
        assert!(
            r.len() <= 263,
            "resource bytes should be capped, got {}",
            r.len()
        );
    }

    #[test]
    fn tool_call_unknown_truncates_at_utf8_boundary() {
        let mut ctx = sample_ctx();
        // 4-byte chars (𝕏 = U+1D54F, 4 UTF-8 bytes). 70 of them = 280 bytes,
        // so a 256-byte cap straddles a codepoint mid-char.
        ctx.tool_name = "𝕏".repeat(70);
        let ev = tool_call_unknown_event(&ctx);
        // Must produce valid UTF-8 — String construction would panic
        // otherwise. Resource must START with the prefix and contain
        // only complete characters.
        let r = ev.resource.expect("resource set");
        assert!(r.starts_with("tool://"));
        assert!(r.is_char_boundary(r.len()));
    }

    #[test]
    fn tool_call_access_denied_event_carries_audit_reason() {
        let ev = tool_call_access_denied_event(
            &sample_ctx(),
            "tool_trust_requirement_not_met:orders.list:Verified:Anonymous",
        );
        assert_eq!(ev.action, "mcpg.tool.call.access_denied");
        assert_eq!(ev.outcome, AuditOutcome::Denied);
        assert_eq!(ev.resource.as_deref(), Some("tool://orders.list"));
        assert_eq!(
            ev.details["audit_reason"],
            "tool_trust_requirement_not_met:orders.list:Verified:Anonymous"
        );
        assert_eq!(ev.details["trust_level"], "verified");
        assert_eq!(ev.details["surface"], "tool");
    }

    #[test]
    fn sanitize_short_passes_through() {
        assert_eq!(sanitize_resource_segment("hello", 256), "hello");
    }

    #[test]
    fn sanitize_truncates_at_byte_cap() {
        let s = "a".repeat(500);
        assert_eq!(sanitize_resource_segment(&s, 100).len(), 100);
    }

    #[test]
    fn sanitize_walks_back_to_char_boundary() {
        // 5x 4-byte char = 20 bytes. cap=18 splits the 5th char.
        let s = "𝕏".repeat(5);
        let out = sanitize_resource_segment(&s, 18);
        // Truncated to 4 chars (16 bytes) — backed off the partial.
        assert_eq!(out.len(), 16);
        assert!(out.is_char_boundary(out.len()));
    }

    // -- resources/read events ---------------------------------------

    #[test]
    fn resource_read_success_event_carries_uri_and_bytes() {
        let mut ctx = sample_ctx();
        ctx.surface = "resource".into();
        let ev = resource_read_success_event(&ctx, "file:///etc/customers/42/profile.json", 8192);
        assert_eq!(ev.action, "mcpg.resource.read.success");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(
            ev.resource.as_deref(),
            Some("resource://file:///etc/customers/42/profile.json")
        );
        assert_eq!(ev.details["bytes_returned"], 8192);
        assert_eq!(ev.details["surface"], "resource");
    }

    #[test]
    fn resource_read_denied_event_carries_plugin_id() {
        let mut ctx = sample_ctx();
        ctx.surface = "resource".into();
        let ev = resource_read_denied_event(
            &ctx,
            "file:///etc/secrets/db.cred",
            "dev.mcpg.policy.cedar",
        );
        assert_eq!(ev.action, "mcpg.resource.read.denied");
        assert_eq!(ev.outcome, AuditOutcome::Denied);
        assert_eq!(ev.details["denied_by_plugin"], "dev.mcpg.policy.cedar");
    }

    #[test]
    fn resource_read_not_found_event_records_failure() {
        let mut ctx = sample_ctx();
        ctx.surface = "resource".into();
        let ev = resource_read_not_found_event(&ctx, "ghost://nowhere");
        assert_eq!(ev.action, "mcpg.resource.read.not_found");
        assert_eq!(ev.outcome, AuditOutcome::Failure);
        assert_eq!(ev.details["reason"], "resource_not_registered");
    }

    #[test]
    fn resource_read_caps_long_uri_at_1024_bytes() {
        let mut ctx = sample_ctx();
        ctx.surface = "resource".into();
        let huge = "x".repeat(2000);
        let ev = resource_read_success_event(&ctx, &huge, 0);
        let r = ev.resource.expect("resource set");
        assert!(r.starts_with("resource://"));
        // prefix (11) + cap (1024) = 1035 max.
        assert!(r.len() <= 1035, "resource bytes capped, got {}", r.len());
    }

    // -- prompts/get events ------------------------------------------

    #[test]
    fn prompt_get_success_event_carries_name() {
        let mut ctx = sample_ctx();
        ctx.surface = "prompt".into();
        ctx.tool_name = "summary.financial".into();
        let ev = prompt_get_success_event(&ctx, "summary.financial");
        assert_eq!(ev.action, "mcpg.prompt.get.success");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.resource.as_deref(), Some("prompt://summary.financial"));
        assert_eq!(ev.details["surface"], "prompt");
    }

    #[test]
    fn prompt_get_denied_event_carries_plugin_id() {
        let mut ctx = sample_ctx();
        ctx.surface = "prompt".into();
        let ev = prompt_get_denied_event(&ctx, "internal.compensation.q3", "dev.mcpg.policy.opa");
        assert_eq!(ev.action, "mcpg.prompt.get.denied");
        assert_eq!(ev.outcome, AuditOutcome::Denied);
        assert_eq!(ev.details["denied_by_plugin"], "dev.mcpg.policy.opa");
    }

    #[test]
    fn prompt_get_not_found_event_records_failure() {
        let mut ctx = sample_ctx();
        ctx.surface = "prompt".into();
        let ev = prompt_get_not_found_event(&ctx, "ghost.prompt");
        assert_eq!(ev.action, "mcpg.prompt.get.not_found");
        assert_eq!(ev.outcome, AuditOutcome::Failure);
        assert_eq!(ev.details["reason"], "prompt_not_registered");
    }

    // -- session bookend events --------------------------------------

    #[test]
    fn session_opened_event_carries_protocol_and_client_info() {
        let actor = sample_ctx().identity;
        let ev = session_opened_event(
            actor,
            "sess-abc-123",
            "2026-04-30",
            "test-client",
            "1.4.2",
            "http",
        );
        assert_eq!(ev.action, "mcpg.session.opened");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.resource.as_deref(), Some("session://sess-abc-123"));
        assert_eq!(ev.details["session_id"], "sess-abc-123");
        assert_eq!(ev.details["protocol_version"], "2026-04-30");
        assert_eq!(ev.details["client_name"], "test-client");
        assert_eq!(ev.details["client_version"], "1.4.2");
        assert_eq!(ev.details["transport"], "http");
        // Actor preserved from request context.
        assert_eq!(ev.actor.subject_id.as_deref(), Some("alice"));
    }

    #[test]
    fn session_terminated_event_carries_duration_and_reason() {
        let ev = session_terminated_event(
            "sess-abc-123",
            42.5,
            "client_terminated",
            Some("test-client"),
        );
        assert_eq!(ev.action, "mcpg.session.terminated");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.resource.as_deref(), Some("session://sess-abc-123"));
        assert_eq!(ev.details["session_id"], "sess-abc-123");
        assert!((ev.details["duration_secs"].as_f64().unwrap() - 42.5).abs() < f64::EPSILON);
        assert_eq!(ev.details["reason"], "client_terminated");
        assert_eq!(ev.details["client_name"], "test-client");
        // Actor stashed as the system identity (see builder docs).
        assert_eq!(ev.actor.kind, "system");
    }

    #[test]
    fn session_terminated_event_handles_missing_client_name() {
        let ev = session_terminated_event("sess-x", 0.0, "shutdown", None);
        assert!(ev.details["client_name"].is_null());
    }

    // -- auth failure events -----------------------------------------

    #[test]
    fn auth_failed_event_jwt_carries_method_and_reason() {
        let ev = auth_failed_event("jwt", "signature verification failed", "req-123", "http");
        assert_eq!(ev.action, "mcpg.auth.failed");
        assert_eq!(ev.outcome, AuditOutcome::Failure);
        assert!(ev.resource.is_none(), "auth failures have no resource URI");
        assert_eq!(ev.request_id.as_deref(), Some("req-123"));
        assert_eq!(ev.details["auth_method"], "jwt");
        assert_eq!(ev.details["reason"], "signature verification failed");
        assert_eq!(ev.details["transport"], "http");
        // Actor = system since by definition the credential
        // failed to verify; no verified actor exists.
        assert_eq!(ev.actor.kind, "system");
    }

    #[test]
    fn auth_failed_event_oidc_kind_label_propagates() {
        let ev = auth_failed_event(
            "oidc",
            "issuer mismatch: expected https://idp.acme.com, got https://attacker.example",
            "req-456",
            "http",
        );
        assert_eq!(ev.details["auth_method"], "oidc");
    }

    #[test]
    fn auth_failed_event_caps_long_reason_at_1024() {
        let huge = "x".repeat(2048);
        let ev = auth_failed_event("jwt", &huge, "req-1", "http");
        let reason = ev.details["reason"].as_str().unwrap();
        assert!(reason.len() <= 1024, "reason capped, got {}", reason.len());
    }

    // -- sampling/createMessage events -------------------------------

    #[test]
    fn sampling_requested_event_carries_finops_fields() {
        let actor = sample_ctx().identity;
        let ev = sampling_requested_event(
            actor,
            "req-99",
            Some("sess-x"),
            "pipe-42",
            "summarise",
            "srv-req-7",
            "blake3:abcdef0123",
            5,
            2048,
            Some("claude-sonnet-4"),
            Some("thisServer"),
        );
        assert_eq!(ev.action, "mcpg.sampling.created");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.resource.as_deref(), Some("sampling://claude-sonnet-4"));
        assert_eq!(ev.request_id.as_deref(), Some("req-99"));
        assert_eq!(ev.details["session_id"], "sess-x");
        assert_eq!(ev.details["pipeline_id"], "pipe-42");
        assert_eq!(ev.details["step_id"], "summarise");
        assert_eq!(ev.details["server_request_id"], "srv-req-7");
        assert_eq!(ev.details["prompt_hash"], "blake3:abcdef0123");
        assert_eq!(ev.details["message_count"], 5);
        assert_eq!(ev.details["max_tokens"], 2048);
        assert_eq!(ev.details["model_hint"], "claude-sonnet-4");
        assert_eq!(ev.details["include_context"], "thisServer");
        // Actor is the original session caller — auditors join
        // sampling.created against the session.opened event by
        // request_id / session_id to recover full attribution.
        assert_eq!(ev.actor.subject_id.as_deref(), Some("alice"));
    }

    // -- payment outcome events --------------------------------------

    #[test]
    fn payment_charged_event_extracts_receipt_id() {
        let receipt = serde_json::json!({
            "org.paymentauth/receipt": {
                "reference": "0xtxhash123",
                "status": "success",
                "amount": "1.50",
                "currency": "USDC",
                "recipient": "0xmerchant"
            }
        });
        let ev = payment_outcome_event(
            &sample_ctx(),
            "dev.mcpg.payment.mpp",
            true,
            Some(&receipt),
            None,
        );
        assert_eq!(ev.action, "mcpg.payment.charged");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.resource.as_deref(), Some("payment://0xtxhash123"));
        assert_eq!(ev.details["payment_kind"], "mpp");
        assert_eq!(ev.details["plugin_id"], "dev.mcpg.payment.mpp");
        assert_eq!(ev.details["receipt"]["reference"], "0xtxhash123");
        assert_eq!(ev.details["receipt"]["amount"], "1.50");
        assert_eq!(ev.details["receipt"]["currency"], "USDC");
    }

    #[test]
    fn payment_charged_falls_back_to_unknown_receipt_when_missing() {
        let ev = payment_outcome_event(&sample_ctx(), "dev.mcpg.payment.x402", true, None, None);
        assert_eq!(ev.resource.as_deref(), Some("payment://unknown"));
        assert_eq!(ev.details["payment_kind"], "x402");
        assert!(ev.details["receipt"].is_null());
    }

    // -- list-call events --------------------------------------------

    #[test]
    fn list_call_event_carries_kind_and_count() {
        let actor = sample_ctx().identity;
        let ev = list_call_event(actor, "req-1", Some("sess-1"), "tool", 12, "http");
        assert_eq!(ev.action, "mcpg.tool.list");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.resource.as_deref(), Some("catalog://tool"));
        assert_eq!(ev.details["kind"], "tool");
        assert_eq!(ev.details["count"], 12);
        assert_eq!(ev.details["session_id"], "sess-1");
    }

    #[test]
    fn list_call_event_supports_resource_template() {
        let actor = sample_ctx().identity;
        let ev = list_call_event(actor, "req-1", None, "resource_template", 0, "stdio");
        assert_eq!(ev.action, "mcpg.resource_template.list");
        assert_eq!(ev.details["count"], 0);
    }

    // -- resource subscribe / unsubscribe ----------------------------

    #[test]
    fn resource_subscribe_event_carries_uri() {
        let mut ctx = sample_ctx();
        ctx.surface = "resource".into();
        let ev = resource_subscribe_event(&ctx, "file:///watch/me.json");
        assert_eq!(ev.action, "mcpg.resource.subscribe");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(
            ev.resource.as_deref(),
            Some("resource://file:///watch/me.json")
        );
        assert_eq!(ev.details["uri"], "file:///watch/me.json");
    }

    #[test]
    fn resource_unsubscribe_event_records_was_subscribed() {
        let ctx = sample_ctx();
        let active = resource_unsubscribe_event(&ctx, "file:///x", true);
        assert_eq!(active.action, "mcpg.resource.unsubscribe");
        assert_eq!(active.details["was_subscribed"], true);
        let stale = resource_unsubscribe_event(&ctx, "file:///x", false);
        assert_eq!(stale.details["was_subscribed"], false);
    }

    // -- elicitation events ------------------------------------------

    #[test]
    fn elicitation_requested_event_carries_pipeline_context() {
        let actor = sample_ctx().identity;
        let ev = elicitation_requested_event(
            actor,
            "req-1",
            Some("sess-1"),
            "pipe-1",
            "ask_user",
            "srv-req-99",
            "form",
        );
        assert_eq!(ev.action, "mcpg.elicitation.requested");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.resource.as_deref(), Some("elicitation://ask_user"));
        assert_eq!(ev.details["server_request_id"], "srv-req-99");
        assert_eq!(ev.details["mode"], "form");
    }

    #[test]
    fn elicitation_completed_event_outcome_per_action() {
        let ctx = sample_ctx();
        let accept = elicitation_completed_event(&ctx, "elicit-1", "accept");
        assert_eq!(accept.outcome, AuditOutcome::Success);
        let decline = elicitation_completed_event(&ctx, "elicit-1", "decline");
        assert_eq!(decline.outcome, AuditOutcome::Denied);
        let cancel = elicitation_completed_event(&ctx, "elicit-1", "cancel");
        assert_eq!(cancel.outcome, AuditOutcome::Denied);
        let weird = elicitation_completed_event(&ctx, "elicit-1", "garbage");
        assert_eq!(weird.outcome, AuditOutcome::Failure);
    }

    // -- roots/list event --------------------------------------------

    #[test]
    fn roots_requested_event_carries_pipeline_context() {
        let actor = sample_ctx().identity;
        let ev = roots_requested_event(
            actor,
            "req-1",
            Some("sess-1"),
            "pipe-1",
            "list_roots",
            "srv-req-77",
        );
        assert_eq!(ev.action, "mcpg.roots.requested");
        assert_eq!(ev.resource.as_deref(), Some("roots://list_roots"));
        assert_eq!(ev.details["server_request_id"], "srv-req-77");
    }

    // -- completion event --------------------------------------------

    #[test]
    fn completion_requested_event_carries_ref_and_argument() {
        let ctx = sample_ctx();
        let ev = completion_requested_event(&ctx, "tool", "orders.list", "status", 5);
        assert_eq!(ev.action, "mcpg.completion.requested");
        assert_eq!(
            ev.resource.as_deref(),
            Some("completion://tool/orders.list")
        );
        assert_eq!(ev.details["ref_kind"], "tool");
        assert_eq!(ev.details["argument_name"], "status");
        assert_eq!(ev.details["suggestion_count"], 5);
    }

    // -- cancellation event ------------------------------------------

    #[test]
    fn operation_cancelled_event_carries_target_and_reason() {
        let ctx = sample_ctx();
        let ev = operation_cancelled_event(&ctx, "req-target-42", Some("user_pressed_stop"));
        assert_eq!(ev.action, "mcpg.operation.cancelled");
        assert_eq!(ev.resource.as_deref(), Some("request://req-target-42"));
        assert_eq!(ev.details["cancelled_request_id"], "req-target-42");
        assert_eq!(ev.details["reason"], "user_pressed_stop");
    }

    #[test]
    fn operation_cancelled_event_handles_missing_reason() {
        let ctx = sample_ctx();
        let ev = operation_cancelled_event(&ctx, "req-1", None);
        assert!(ev.details["reason"].is_null());
    }

    // -- pipeline lifecycle events -----------------------------------

    #[test]
    fn pipeline_started_event_carries_profile_and_step_count() {
        let actor = sample_ctx().identity;
        let ev = pipeline_started_event(
            actor,
            "req-pipe-1",
            Some("sess-x"),
            "pipe-id-42",
            "checkout.flow",
            5,
        );
        assert_eq!(ev.action, "mcpg.pipeline.started");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.resource.as_deref(), Some("pipeline://checkout.flow"));
        assert_eq!(ev.details["pipeline_id"], "pipe-id-42");
        assert_eq!(ev.details["session_id"], "sess-x");
        assert_eq!(ev.details["profile"], "checkout.flow");
        assert_eq!(ev.details["step_count"], 5);
    }

    #[test]
    fn pipeline_completed_event_success_path() {
        let actor = sample_ctx().identity;
        let ev = pipeline_completed_event(
            actor, "req-1", None, "pipe-1", "checkout", true, 5, 1234, None,
        );
        assert_eq!(ev.action, "mcpg.pipeline.completed");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.details["steps_completed"], 5);
        assert_eq!(ev.details["duration_ms"], 1234);
        assert!(ev.details["error_message"].is_null());
    }

    #[test]
    fn pipeline_completed_event_failure_path_carries_error() {
        let actor = sample_ctx().identity;
        let ev = pipeline_completed_event(
            actor,
            "req-1",
            None,
            "pipe-1",
            "checkout",
            false,
            2,
            500,
            Some("step 'charge' failed: gateway timeout"),
        );
        assert_eq!(ev.action, "mcpg.pipeline.failed");
        assert_eq!(ev.outcome, AuditOutcome::Failure);
        assert_eq!(ev.details["steps_completed"], 2);
        assert_eq!(
            ev.details["error_message"],
            "step 'charge' failed: gateway timeout"
        );
    }

    #[test]
    fn payment_failed_event_carries_deny_reason() {
        let ev = payment_outcome_event(
            &sample_ctx(),
            "dev.mcpg.payment.ucp",
            false,
            None,
            Some("expired_credential"),
        );
        assert_eq!(ev.action, "mcpg.payment.failed");
        assert_eq!(ev.outcome, AuditOutcome::Denied);
        assert_eq!(ev.details["payment_kind"], "ucp");
        assert_eq!(ev.details["deny_reason"], "expired_credential");
    }

    #[test]
    fn sampling_requested_event_handles_no_model_hint() {
        let actor = sample_ctx().identity;
        let ev = sampling_requested_event(
            actor, "req-1", None, "p", "s", "srv", "blake3:0", 1, 512, None, None,
        );
        // Resource falls back to the generic identifier so audit
        // queries on "every sampling call" still hit even when no
        // model preference was carried through.
        assert_eq!(ev.resource.as_deref(), Some("sampling://any"));
        assert!(ev.details["session_id"].is_null());
        assert!(ev.details["model_hint"].is_null());
    }

    // ----- plugin invocation visibility events -----------------------------

    #[test]
    fn backend_executed_event_success_path() {
        let actor = sample_ctx().identity;
        let ev = backend_executed_event(
            actor,
            "req-7",
            Some("sess-9"),
            "kafka",
            "trades.in",
            true,
            42,
            128,
            64,
            None,
            serde_json::Map::new(),
        );
        assert_eq!(ev.action, "mcpg.backend.executed");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.resource.as_deref(), Some("backend://kafka/trades.in"));
        assert_eq!(ev.details["kind"], "kafka");
        assert_eq!(ev.details["profile"], "trades.in");
        assert_eq!(ev.details["payload_bytes"], 128);
        assert_eq!(ev.details["response_bytes"], 64);
        assert!(ev.details["error_message"].is_null());
    }

    #[test]
    fn binding_failed_event_carries_error_message() {
        let actor = sample_ctx().identity;
        let ev = backend_executed_event(
            actor,
            "req-8",
            None,
            "sql",
            "users.select",
            false,
            500,
            64,
            0,
            Some("connection refused"),
            serde_json::Map::new(),
        );
        assert_eq!(ev.action, "mcpg.backend.failed");
        assert_eq!(ev.outcome, AuditOutcome::Failure);
        assert_eq!(ev.details["error_message"], "connection refused");
        assert_eq!(ev.details["response_bytes"], 0);
    }

    #[test]
    fn backend_executed_event_merges_audit_metadata_extras() {
        // P6.3: plugin-supplied audit metadata (e.g. SQL plugin's
        // `db.driver` + `db.query_ref`) merges into details.
        let actor = sample_ctx().identity;
        let mut extra = serde_json::Map::new();
        extra.insert("db.driver".into(), "postgres".into());
        extra.insert("db.query_ref".into(), "users.select".into());
        let ev = backend_executed_event(
            actor,
            "req-9",
            None,
            "sql",
            "users.select",
            true,
            12,
            8,
            64,
            None,
            extra,
        );
        assert_eq!(ev.details["db.driver"], "postgres");
        assert_eq!(ev.details["db.query_ref"], "users.select");
        // Baseline fields still present.
        assert_eq!(ev.details["kind"], "sql");
        assert_eq!(ev.details["profile"], "users.select");
        assert_eq!(ev.details["duration_ms"], 12);
    }

    #[test]
    fn backend_executed_event_extras_cannot_override_baseline_fields() {
        // System-controlled fields win over plugin-supplied ones —
        // plugins must not be able to falsify duration / kind /
        // session_id via the audit_metadata surface.
        let actor = sample_ctx().identity;
        let mut extra = serde_json::Map::new();
        extra.insert("duration_ms".into(), 99_999.into());
        extra.insert("kind".into(), "fake".into());
        extra.insert("db.engine".into(), "mysql".into());
        let ev = backend_executed_event(
            actor, "req-10", None, "sql", "x", true, 42, 8, 16, None, extra,
        );
        assert_eq!(ev.details["duration_ms"], 42, "baseline duration wins");
        assert_eq!(ev.details["kind"], "sql", "baseline kind wins");
        // Non-colliding extra still passes through.
        assert_eq!(ev.details["db.engine"], "mysql");
    }

    #[test]
    fn transform_applied_event_hashes_pre_and_post() {
        let pre = serde_json::json!({"x": 1, "y": "secret"});
        let post = serde_json::json!({"x": 1, "y": "REDACTED"});
        let ev = transform_applied_event(
            &sample_ctx(),
            "dev.mcpg.transform.masking",
            "post",
            &pre,
            &post,
        );
        assert_eq!(ev.action, "mcpg.transform.applied");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(
            ev.resource.as_deref(),
            Some("plugin://dev.mcpg.transform.masking")
        );
        assert_eq!(ev.details["plugin_id"], "dev.mcpg.transform.masking");
        assert_eq!(ev.details["phase"], "post");
        let pre_h = ev.details["pre_hash"].as_str().unwrap();
        let post_h = ev.details["post_hash"].as_str().unwrap();
        assert!(pre_h.starts_with("blake3:"));
        assert!(post_h.starts_with("blake3:"));
        // Different inputs => different hashes — auditors rely on this
        // distinction to confirm the transform actually rewrote
        // something rather than logging a no-op.
        assert_ne!(pre_h, post_h);
    }

    #[test]
    fn transform_applied_event_identical_pre_post_yields_equal_hashes() {
        let v = serde_json::json!({"a": 1});
        let ev = transform_applied_event(&sample_ctx(), "dev.mcpg.transform.noop", "pre", &v, &v);
        assert_eq!(ev.details["pre_hash"], ev.details["post_hash"]);
    }

    #[test]
    fn catalog_filtered_event_records_hidden_pairs() {
        let actor = sample_ctx().identity;
        let ev = catalog_filtered_event(
            actor,
            "req-1",
            Some("sess-2"),
            "tool",
            5,
            3,
            vec![
                ("admin.delete".into(), "dev.mcpg.catalog.role-filter".into()),
                (
                    "billing.refund".into(),
                    "dev.mcpg.catalog.role-filter".into(),
                ),
            ],
        );
        assert_eq!(ev.action, "mcpg.catalog.filtered");
        assert_eq!(ev.resource.as_deref(), Some("catalog://tool"));
        assert_eq!(ev.details["before_count"], 5);
        assert_eq!(ev.details["after_count"], 3);
        assert_eq!(ev.details["hidden_count"], 2);
        let hidden = ev.details["hidden"].as_array().unwrap();
        assert_eq!(hidden.len(), 2);
        assert_eq!(hidden[0]["name"], "admin.delete");
        assert_eq!(hidden[0]["plugin_id"], "dev.mcpg.catalog.role-filter");
    }

    #[test]
    fn catalog_filtered_event_handles_no_hidden() {
        let actor = sample_ctx().identity;
        let ev = catalog_filtered_event(actor, "r", None, "tool", 4, 4, vec![]);
        assert_eq!(ev.details["hidden_count"], 0);
        assert!(ev.details["hidden"].as_array().unwrap().is_empty());
    }

    #[test]
    fn watch_fired_event_records_strategy_and_count() {
        let ev = watch_fired_event("data://orders", "poll", None, 3);
        assert_eq!(ev.action, "mcpg.watch.fired");
        assert_eq!(ev.resource.as_deref(), Some("resource://data://orders"));
        assert_eq!(ev.details["strategy"], "poll");
        assert_eq!(ev.details["subscriber_count"], 3);
        assert!(ev.details["plugin_kind"].is_null());
        assert_eq!(ev.actor.kind, "system");
    }

    #[test]
    fn watch_fired_event_carries_plugin_kind() {
        let ev = watch_fired_event("data://nats-topic-x", "plugin", Some("nats_topic"), 0);
        assert_eq!(ev.details["plugin_kind"], "nats_topic");
        // subscriber_count = 0 is still emitted — bookends the change.
        assert_eq!(ev.details["subscriber_count"], 0);
    }

    #[test]
    fn hash_json_value_is_stable_for_same_input() {
        let v = serde_json::json!({"foo": [1, 2, 3], "bar": "baz"});
        assert_eq!(hash_json_value(&v), hash_json_value(&v));
    }

    // ----- config / credential / secret / approval / http_route events ----

    #[test]
    fn config_reloaded_event_success_path() {
        let ev = config_reloaded_event("sighup", true, None, Some("aaaa"), Some("bbbb"));
        assert_eq!(ev.action, "mcpg.config.reloaded");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.resource.as_deref(), Some("config://gateway"));
        assert_eq!(ev.details["source"], "sighup");
        assert!(ev.details["error"].is_null());
        assert_eq!(ev.details["prev_config_sha256"], "aaaa");
        assert_eq!(ev.details["next_config_sha256"], "bbbb");
        assert_eq!(ev.actor.kind, "system");
    }

    #[test]
    fn config_reloaded_event_failure_carries_error_and_keeps_prev_sha() {
        let ev = config_reloaded_event(
            "control_plane",
            false,
            Some("yaml parse error"),
            Some("aaaa"),
            None,
        );
        assert_eq!(ev.outcome, AuditOutcome::Failure);
        assert_eq!(ev.details["error"], "yaml parse error");
        assert_eq!(ev.details["prev_config_sha256"], "aaaa");
        assert!(ev.details["next_config_sha256"].is_null());
    }

    #[test]
    fn config_loaded_event_carries_sha_and_paths() {
        let ev = config_loaded_event(
            "deadbeef",
            &["base.yaml".to_owned(), "prod.yaml".to_owned()],
        );
        assert_eq!(ev.action, "mcpg.config.loaded");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.resource.as_deref(), Some("config://gateway"));
        assert_eq!(ev.details["config_sha256"], "deadbeef");
        assert_eq!(ev.details["source_paths"][0], "base.yaml");
        assert_eq!(ev.details["source_paths"][1], "prod.yaml");
        assert_eq!(ev.actor.kind, "system");
    }

    #[test]
    fn config_secrets_resolved_event_carries_refs() {
        let refs = serde_json::json!([
            {"kind": "env_var", "name": "GH_TOKEN", "field_path": "bindings[0].headers.Authorization"},
            {"kind": "secret_uri", "name": "vault://db/orders#pw", "field_path": "binding[1].url"}
        ]);
        let ev = config_secrets_resolved_event(refs.clone());
        assert_eq!(ev.action, "mcpg.config.secrets_resolved");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.resource.as_deref(), Some("config://gateway/secrets"));
        assert_eq!(ev.details["refs"], refs);
        assert_eq!(ev.actor.kind, "system");
    }

    #[test]
    fn config_feature_flags_active_event_carries_active_flags() {
        let ev = config_feature_flags_active_event(serde_json::json!({
            "allow_header_passthrough": true,
        }));
        assert_eq!(ev.action, "mcpg.config.feature_flags_active");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(
            ev.resource.as_deref(),
            Some("config://gateway/feature_flags")
        );
        assert_eq!(ev.details["allow_header_passthrough"], true);
        assert_eq!(ev.actor.kind, "system");
    }

    #[test]
    fn credential_issued_event_success_path() {
        let actor = sample_ctx().identity;
        let ev = credential_issued_event(
            actor,
            "dev.mcpg.credential.iam",
            "postgres-prod",
            true,
            None,
        );
        assert_eq!(ev.action, "mcpg.credential.issued");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(
            ev.resource.as_deref(),
            Some("plugin://dev.mcpg.credential.iam")
        );
        assert_eq!(ev.details["target"], "postgres-prod");
    }

    #[test]
    fn credential_failed_event_carries_error() {
        let actor = sample_ctx().identity;
        let ev = credential_issued_event(
            actor,
            "dev.mcpg.credential.iam",
            "vault-token",
            false,
            Some("AssumeRole denied"),
        );
        assert_eq!(ev.action, "mcpg.credential.failed");
        assert_eq!(ev.outcome, AuditOutcome::Failure);
        assert_eq!(ev.details["error"], "AssumeRole denied");
    }

    #[test]
    fn secret_resolved_event_carries_scheme_and_ref() {
        let actor = sample_ctx().identity;
        let ev = secret_resolved_event(actor, "vault", "vault://secret/mongo/password", true, None);
        assert_eq!(ev.action, "mcpg.secret.resolved");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(
            ev.resource.as_deref(),
            Some("vault://secret/mongo/password")
        );
        assert_eq!(ev.details["scheme"], "vault");
    }

    #[test]
    fn approval_requested_event_carries_context() {
        let actor = sample_ctx().identity;
        let notifiers = vec!["slack-ops".to_string(), "email-sec".to_string()];
        let ev = approval_requested_event(
            actor,
            "req-1",
            "appr-7",
            "delete_account",
            "User requested account deletion",
            "2026-05-04T01:00:00Z",
            &notifiers,
        );
        assert_eq!(ev.action, "mcpg.approval.requested");
        assert_eq!(ev.resource.as_deref(), Some("approval://appr-7"));
        assert_eq!(ev.details["tool_name"], "delete_account");
        assert_eq!(ev.details["target_notifiers"][0], "slack-ops");
    }

    #[test]
    fn approval_resolved_event_granted_path() {
        let actor = sample_ctx().identity;
        let ev = approval_resolved_event(
            actor,
            "req-1",
            "appr-7",
            "delete_account",
            true,
            Some("alice@corp"),
            Some("authorised by ticket OPS-42"),
        );
        assert_eq!(ev.action, "mcpg.approval.granted");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.details["approver_subject"], "alice@corp");
    }

    #[test]
    fn approval_resolved_event_denied_path() {
        let actor = sample_ctx().identity;
        let ev = approval_resolved_event(actor, "r", "a", "t", false, Some("bob"), None);
        assert_eq!(ev.action, "mcpg.approval.denied");
        assert_eq!(ev.outcome, AuditOutcome::Denied);
    }

    #[test]
    fn approval_expired_event_marks_failure() {
        let actor = sample_ctx().identity;
        let ev = approval_expired_event(
            actor,
            "req-1",
            "appr-7",
            "delete_account",
            "2026-05-04T01:00:00Z",
        );
        assert_eq!(ev.action, "mcpg.approval.expired");
        // Failure (not Denied) — distinguishes "no operator decision"
        // from "operator rejected".
        assert_eq!(ev.outcome, AuditOutcome::Failure);
    }

    #[test]
    fn http_route_event_2xx_is_success() {
        let ev = http_route_dispatched_event(
            None,
            "req-9",
            "dev.mcpg.health",
            "status",
            "GET",
            "/plugins/dev.mcpg.health/status",
            200,
            12,
        );
        assert_eq!(ev.action, "mcpg.http_route.dispatched");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(
            ev.resource.as_deref(),
            Some("http_route://dev.mcpg.health/status")
        );
        assert_eq!(ev.details["status"], 200);
        assert_eq!(ev.actor.kind, "system");
    }

    #[test]
    fn http_route_event_4xx_is_denied() {
        let ev = http_route_dispatched_event(None, "r", "p", "e", "POST", "/", 401, 5);
        assert_eq!(ev.outcome, AuditOutcome::Denied);
    }

    #[test]
    fn http_route_event_5xx_is_failure() {
        let ev = http_route_dispatched_event(None, "r", "p", "e", "GET", "/", 500, 5);
        assert_eq!(ev.outcome, AuditOutcome::Failure);
    }

    // ----- cluster lifecycle + protocol-bookend events ----------------------

    #[test]
    fn cluster_member_joined_event_carries_node_id() {
        let ev = cluster_member_event("joined", "node-7", None, None);
        assert_eq!(ev.action, "mcpg.cluster.member_joined");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.resource.as_deref(), Some("node://node-7"));
        assert_eq!(ev.node_id.as_deref(), Some("node-7"));
        assert_eq!(ev.details["kind"], "joined");
    }

    #[test]
    fn cluster_member_left_event_carries_node_id() {
        let ev = cluster_member_event("left", "node-7", None, None);
        assert_eq!(ev.action, "mcpg.cluster.member_left");
    }

    #[test]
    fn cluster_member_health_changed_event_carries_health() {
        let ev = cluster_member_event("health_changed", "node-7", Some("degraded"), None);
        assert_eq!(ev.action, "mcpg.cluster.member_health_changed");
        assert_eq!(ev.details["health"], "degraded");
    }

    #[test]
    fn cluster_leader_event_success() {
        let ev = cluster_leader_event("dev.mcpg.cluster.consul", "watch.cedar", true, None);
        assert_eq!(ev.action, "mcpg.cluster.leader_changed");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.resource.as_deref(), Some("leadership://watch.cedar"));
        assert_eq!(ev.details["plugin_id"], "dev.mcpg.cluster.consul");
        assert_eq!(ev.details["role"], "watch.cedar");
    }

    #[test]
    fn cluster_leader_event_failure_carries_error() {
        let ev = cluster_leader_event(
            "dev.mcpg.cluster.consul",
            "watch.cedar",
            false,
            Some("lease conflict"),
        );
        assert_eq!(ev.action, "mcpg.cluster.leader_acquire_failed");
        assert_eq!(ev.outcome, AuditOutcome::Failure);
        assert_eq!(ev.details["error"], "lease conflict");
    }

    #[test]
    fn ping_received_event_records_transport() {
        let actor = sample_ctx().identity;
        let ev = ping_received_event(actor, "req-1", Some("sess-2"), "stdio");
        assert_eq!(ev.action, "mcpg.ping.received");
        assert_eq!(ev.resource.as_deref(), Some("system://ping"));
        assert_eq!(ev.details["transport"], "stdio");
    }

    #[test]
    fn session_initialized_acked_event_carries_session() {
        let actor = sample_ctx().identity;
        let ev = session_initialized_acked_event(actor, Some("sess-99"), "http");
        assert_eq!(ev.action, "mcpg.session.initialized_acked");
        assert_eq!(ev.resource.as_deref(), Some("session://sess-99"));
    }

    #[test]
    fn progress_notified_event_carries_progress_value() {
        let actor = sample_ctx().identity;
        let ev = progress_notified_event(actor, "tok-7", Some("sess-2"), 0.42, Some(1.0));
        assert_eq!(ev.action, "mcpg.progress.notified");
        assert_eq!(ev.resource.as_deref(), Some("request://tok-7"));
        assert_eq!(ev.details["progress"], 0.42);
        assert_eq!(ev.details["total"], 1.0);
    }

    #[test]
    fn list_changed_event_carries_kind_and_count() {
        let ev = list_changed_event("tools", 12);
        assert_eq!(ev.action, "mcpg.list.changed_broadcast");
        assert_eq!(ev.resource.as_deref(), Some("catalog://tools"));
        assert_eq!(ev.details["kind"], "tools");
        assert_eq!(ev.details["session_count"], 12);
    }

    #[test]
    fn logging_level_set_event_carries_level() {
        let actor = sample_ctx().identity;
        let ev = logging_level_set_event(actor, "req-3", Some("sess-2"), "debug");
        assert_eq!(ev.action, "mcpg.logging.level_set");
        assert_eq!(ev.resource.as_deref(), Some("session://sess-2"));
        assert_eq!(ev.details["level"], "debug");
    }

    #[test]
    fn tool_gate_allowed_event_carries_chain_when_provided() {
        let chain = vec![
            ChainEntry {
                plugin_id: "dev.mcpg.policy.cedar".into(),
                phase: "pre_dispatch",
                decision: "allow",
                latency_ms: 3,
            },
            ChainEntry {
                plugin_id: "dev.mcpg.transform.masking".into(),
                phase: "pre_dispatch",
                decision: "allow",
                latency_ms: 1,
            },
        ];
        let ev = tool_gate_allowed_event(&sample_ctx(), 2, &chain);
        let chain_arr = ev.details["chain"].as_array().unwrap();
        assert_eq!(chain_arr.len(), 2);
        assert_eq!(chain_arr[0]["plugin_id"], "dev.mcpg.policy.cedar");
        assert_eq!(chain_arr[0]["phase"], "pre_dispatch");
        assert_eq!(chain_arr[0]["decision"], "allow");
        assert_eq!(chain_arr[0]["latency_ms"], 3);
    }
}
