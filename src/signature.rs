//! Signature verification policy for native plugin artefacts.
//!
//! Three states: `Disabled` skips verification entirely (development
//! escape hatch — gateway emits a `governance.plugin.signature_policy_disabled`
//! audit event when any entry resolves to this policy so the choice
//! is visible in the compliance trail); `Warn` attempts verification,
//! logs a warning on failure, and proceeds with the load (safe
//! first-rollout default); `Enforce` refuses to load any artefact
//! whose signature is missing, invalid, or doesn't verify against the
//! configured trusted keys (production posture).
//!
//! Carried per-plugin via `NativeVerifyOptions::policy` so vendors with
//! different trust postures (in-house plugins under enforce, third-
//! party plugins under warn while a key-rotation rollout completes)
//! can coexist without flipping a single global toggle.

/// Signature verification policy for a native plugin artefact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignaturePolicy {
    /// Skip signature verification entirely. Development /
    /// air-gap-build escape hatch. Gateway emits an audit event
    /// when any entry resolves to this policy.
    Disabled,
    /// Attempt verification; on failure, proceed with the load ONLY
    /// when no trusted keys are configured (genuine first rollout —
    /// noisy log + `mcpg_plugin_unverified_load_total` metric instead
    /// of a refused boot). Once any trusted key is configured this
    /// escalates to `Enforce` semantics: a bad/missing signature is a
    /// hard failure.
    Warn,
    /// Refuse to load any artefact whose signature is missing,
    /// invalid, or doesn't verify against the configured trusted
    /// keys. The default: only signed artefacts load.
    #[default]
    Enforce,
}

impl SignaturePolicy {
    /// `true` when the host should skip the signature step
    /// entirely (no `.sig` read, no Ed25519 verify).
    pub fn skips_verification(self) -> bool {
        matches!(self, SignaturePolicy::Disabled)
    }

    /// `true` when a verification failure should block the load.
    /// `false` for `Disabled` (no verify happens) and `Warn`
    /// (failure logs but proceeds).
    pub fn refuses_on_failure(self) -> bool {
        matches!(self, SignaturePolicy::Enforce)
    }

    /// Human-friendly label for log lines + audit events.
    pub fn as_label(self) -> &'static str {
        match self {
            SignaturePolicy::Disabled => "disabled",
            SignaturePolicy::Warn => "warn",
            SignaturePolicy::Enforce => "enforce",
        }
    }
}
