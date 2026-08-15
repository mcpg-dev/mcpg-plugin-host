//! Plugin lifecycle state machine.
//!
//! Every MCPG plugin — whether static-firstparty, native-cdylib, or
//! wasi — progresses through a defined sequence of states from initial
//! discovery to runtime activation. This module encodes that sequence
//! as a typed finite-state machine so that:
//!
//! * The registry can reject invalid state transitions at runtime
//!   rather than smearing state-shape checks across every loader.
//! * Admin / inspection surfaces expose a consistent vocabulary
//!   regardless of plugin tier.
//! * Operators can reason about a plugin's status without having to
//!   read code (the states double as an operational vocabulary).
//!
//! This file is the executable reference for lifecycle semantics.
//!
//! ## State diagram (text)
//!
//! ```text
//!     Discovered ─► Installed ─► Verified ─► Compatible ─► Configured
//!                                                               │
//!                                                               ▼
//!                                   Disabled ◄───── Enabled ─► Initialized
//!                                     │   ▲                         │
//!                                     │   └──────── Active ◄────────┘
//!                                     │             ▲ │
//!                                     │             │ ▼
//!                                     │           Degraded
//!                                     ▼
//!                                  Unloaded
//!
//!   Terminal (non-recoverable): Rejected, Failed
//!   (reached from compat/verification and init/runtime errors respectively)
//! ```
//!
//! See the `Lifecycle::can_transition` implementation for the exact
//! transition table — the diagram above is a readable summary, the
//! code is the source of truth.

use std::fmt;

use thiserror::Error;

// ---------------------------------------------------------------------------
// PluginState
// ---------------------------------------------------------------------------

/// A point in a plugin's lifecycle.
///
/// States advance monotonically along the happy path
/// (`Discovered` → `Active`) with three branches:
///
/// * **Operational toggles** between `Enabled` / `Disabled` let
///   operators stop a plugin's traffic without unloading it.
/// * **Health dips** between `Active` / `Degraded` let the gateway
///   flag a struggling plugin without tearing it down.
/// * **Terminal states** (`Rejected`, `Failed`) capture
///   non-recoverable outcomes; re-entering the happy path requires
///   re-discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum PluginState {
    /// Manifest located (on disk, in config, or in a registry) but
    /// no artifact has been fetched yet.
    Discovered = 0,
    /// Artifact (dylib / wasm / static reference) is resolvable.
    Installed = 1,
    /// Signature and content hash validated against the manifest.
    Verified = 2,
    /// `protocol_version` and `required_capabilities` are compatible
    /// with this gateway build.
    Compatible = 3,
    /// Operator-supplied config merged with defaults and
    /// JSON-schema validated.
    Configured = 4,
    /// Operator intent: the plugin should be running.
    Enabled = 5,
    /// Plugin's `init()` hook has completed successfully.
    Initialized = 6,
    /// Live and participating in chain evaluation / binding
    /// dispatch.
    Active = 7,
    /// Live but failing health / liveness signals; still
    /// participating but flagged.
    Degraded = 8,
    /// Operator intent: the plugin should not run. Artifact remains
    /// loaded so re-enabling is cheap.
    Disabled = 9,
    /// Process-level resources released. Entering this state frees
    /// dylib handles and drops the instance.
    Unloaded = 10,
    /// Terminal: failed compatibility or verification checks. The
    /// plugin cannot be used at this version; operator must ship a
    /// new build or update the gateway.
    Rejected = 11,
    /// Terminal: non-recoverable runtime or init error. The plugin
    /// must be unloaded and re-loaded (typically after a fix) to
    /// re-enter the lifecycle.
    Failed = 12,
    /// Operator is draining the plugin: new calls are rejected, but
    /// in-flight calls are allowed to complete before the plugin
    /// transitions to `Disabled`. Distinct from `Disabled` so operators
    /// can observe the drain progress (admin endpoints surface the
    /// state). Entered only via [`crate::registry::PluginRegistry::mark_draining`];
    /// leaves via `Disabled` (clean drain) or `Active` (operator
    /// changed their mind and cancelled the drain — not yet wired, but
    /// the transition is permitted).
    Draining = 13,
}

impl PluginState {
    /// Reconstruct a [`PluginState`] from its `#[repr(u8)]` value.
    /// Returns `None` for values outside the valid range; used by
    /// [`AtomicPluginState`] to decode atomically-stored state.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Discovered),
            1 => Some(Self::Installed),
            2 => Some(Self::Verified),
            3 => Some(Self::Compatible),
            4 => Some(Self::Configured),
            5 => Some(Self::Enabled),
            6 => Some(Self::Initialized),
            7 => Some(Self::Active),
            8 => Some(Self::Degraded),
            9 => Some(Self::Disabled),
            10 => Some(Self::Unloaded),
            11 => Some(Self::Rejected),
            12 => Some(Self::Failed),
            13 => Some(Self::Draining),
            _ => None,
        }
    }
}

/// Thread-safe, lock-free wrapper around [`PluginState`].
///
/// Request-path code reads a plugin's state without locking the
/// registry — critical for preserving the immutable-chain
/// performance invariant. Admin-path code mutates state (disable /
/// enable / degrade) atomically from a different thread; no
/// request is blocked during the flip.
#[derive(Debug)]
pub struct AtomicPluginState(std::sync::atomic::AtomicU8);

impl AtomicPluginState {
    /// Create a new atomic cell initialised to `state`.
    #[must_use]
    pub fn new(state: PluginState) -> Self {
        Self(std::sync::atomic::AtomicU8::new(state as u8))
    }

    /// Load the current state with `Acquire` ordering — the
    /// readiness of any plugin-held state mutated before the last
    /// store is visible to callers that observe the new state.
    #[must_use]
    pub fn load(&self) -> PluginState {
        PluginState::from_u8(self.0.load(std::sync::atomic::Ordering::Acquire))
            .expect("AtomicPluginState holds a valid PluginState repr")
    }

    /// Store a new state with `Release` ordering. Callers that
    /// paired a state change with mutations to plugin-held state
    /// (e.g., flushing a buffer before flipping to `Disabled`) can
    /// rely on the happens-before relationship between the mutation
    /// and any reader that observes the new state.
    pub fn store(&self, state: PluginState) {
        self.0
            .store(state as u8, std::sync::atomic::Ordering::Release)
    }

    /// Convenience: `load().serves_traffic()`. Inlined by the
    /// compiler in the chain-evaluation hot path.
    #[must_use]
    pub fn serves_traffic(&self) -> bool {
        self.load().serves_traffic()
    }
}

impl PluginState {
    /// Whether this state is terminal (no outgoing transitions
    /// except via re-discovery after unload).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, PluginState::Rejected | PluginState::Failed)
    }

    /// Whether the plugin is reachable for chain evaluation in this
    /// state. Only `Active` and `Degraded` serve traffic; `Degraded`
    /// is included because the gateway's policy may still dispatch
    /// to it while alarms fire.
    #[must_use]
    pub const fn serves_traffic(self) -> bool {
        matches!(self, PluginState::Active | PluginState::Degraded)
    }

    /// Short lowercase label for logs / metrics / admin responses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            PluginState::Discovered => "discovered",
            PluginState::Installed => "installed",
            PluginState::Verified => "verified",
            PluginState::Compatible => "compatible",
            PluginState::Configured => "configured",
            PluginState::Enabled => "enabled",
            PluginState::Initialized => "initialized",
            PluginState::Active => "active",
            PluginState::Degraded => "degraded",
            PluginState::Disabled => "disabled",
            PluginState::Unloaded => "unloaded",
            PluginState::Rejected => "rejected",
            PluginState::Failed => "failed",
            PluginState::Draining => "draining",
        }
    }
}

impl fmt::Display for PluginState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// LifecycleError
// ---------------------------------------------------------------------------

/// Error returned when an illegal transition is attempted on a
/// [`Lifecycle`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LifecycleError {
    #[error("invalid transition {from} → {to}")]
    InvalidTransition { from: PluginState, to: PluginState },
    #[error("plugin is in terminal state {state}; must unload before reuse")]
    Terminal { state: PluginState },
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Tracks the current state of a single plugin and enforces valid
/// transitions.
///
/// Construct with [`Lifecycle::new`] (starts in `Discovered`) and
/// advance via [`Lifecycle::transition`]. For the happy path the
/// helper [`Lifecycle::advance`] moves to the next canonical state.
#[derive(Debug, Clone)]
pub struct Lifecycle {
    plugin_id: String,
    state: PluginState,
}

impl Lifecycle {
    /// Start a new lifecycle in [`PluginState::Discovered`].
    #[must_use]
    pub fn new(plugin_id: impl Into<String>) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            state: PluginState::Discovered,
        }
    }

    /// The plugin identifier this lifecycle tracks.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> PluginState {
        self.state
    }

    /// Whether the plugin is currently serving traffic.
    #[must_use]
    pub fn serves_traffic(&self) -> bool {
        self.state.serves_traffic()
    }

    /// Validate whether a direct transition from the current state
    /// to `to` is permitted, without applying it.
    #[must_use]
    pub fn can_transition(&self, to: PluginState) -> bool {
        transition_allowed(self.state, to)
    }

    /// Attempt to transition to the given state. Returns the
    /// previous state on success.
    pub fn transition(&mut self, to: PluginState) -> Result<PluginState, LifecycleError> {
        if !transition_allowed(self.state, to) {
            return Err(LifecycleError::InvalidTransition {
                from: self.state,
                to,
            });
        }
        let prev = self.state;
        self.state = to;
        Ok(prev)
    }

    /// Advance along the canonical happy path. Valid from
    /// `Discovered` through `Initialized`; from `Initialized` the
    /// next step is `Active`.
    ///
    /// Returns `LifecycleError::InvalidTransition` if there is no
    /// canonical next state from the current state (e.g. you cannot
    /// `advance` out of `Active` — you must explicitly transition
    /// to `Degraded`, `Disabled`, `Unloaded`, or `Failed`).
    pub fn advance(&mut self) -> Result<PluginState, LifecycleError> {
        let next = match self.state {
            PluginState::Discovered => PluginState::Installed,
            PluginState::Installed => PluginState::Verified,
            PluginState::Verified => PluginState::Compatible,
            PluginState::Compatible => PluginState::Configured,
            PluginState::Configured => PluginState::Enabled,
            PluginState::Enabled => PluginState::Initialized,
            PluginState::Initialized => PluginState::Active,
            other => {
                return Err(LifecycleError::InvalidTransition {
                    from: other,
                    to: other,
                });
            }
        };
        self.transition(next)
    }

    /// Mark this plugin as having failed. Allowed from any
    /// non-terminal, non-`Unloaded` state. After reaching `Failed`
    /// the only valid next step is `Unloaded`.
    pub fn fail(&mut self) -> Result<PluginState, LifecycleError> {
        self.transition(PluginState::Failed)
    }

    /// Mark this plugin as rejected due to compatibility or
    /// verification failure. Allowed only from the pre-runtime
    /// states (`Installed`, `Verified`, `Compatible`, `Configured`).
    pub fn reject(&mut self) -> Result<PluginState, LifecycleError> {
        self.transition(PluginState::Rejected)
    }
}

// ---------------------------------------------------------------------------
// Transition table
// ---------------------------------------------------------------------------

/// Single source of truth for permitted transitions.
///
/// Kept as a free function so tests can exhaustively enumerate
/// `(from, to)` pairs without having to construct `Lifecycle`
/// instances.
#[must_use]
pub(crate) fn transition_allowed(from: PluginState, to: PluginState) -> bool {
    use PluginState::*;
    match (from, to) {
        // Happy path
        (Discovered, Installed)
        | (Installed, Verified)
        | (Verified, Compatible)
        | (Compatible, Configured)
        | (Configured, Enabled)
        | (Enabled, Initialized)
        | (Initialized, Active) => true,

        // Operator toggles
        (Active | Degraded | Initialized, Disabled) => true,
        (Disabled, Enabled) => true,

        // Health transitions
        (Active, Degraded) | (Degraded, Active) => true,

        // Drain transitions: admins send a plugin into Draining to
        // stop new requests while in-flight ones finish. Entry is
        // allowed from the two traffic-serving states only; exit
        // canonically goes to Disabled (clean drain) but we also
        // permit Draining → Active so an operator can cancel a
        // drain-in-progress if they change their mind.
        (Active | Degraded, Draining) => true,
        (Draining, Disabled) | (Draining, Active) => true,

        // Verification / compatibility failure (terminal)
        (Installed | Verified | Compatible | Configured, Rejected) => true,

        // Runtime / init failure (terminal) — allowed from any
        // state that can actually run code, including Draining
        // (a panic during drain still surfaces as Failed).
        (
            Enabled | Initialized | Active | Degraded | Draining | Configured | Compatible
            | Verified | Installed,
            Failed,
        ) => true,

        // Unload path — reachable from any non-terminal state and
        // from Failed (explicit cleanup after a crash).
        (
            Installed | Verified | Compatible | Configured | Enabled | Initialized | Active
            | Degraded | Draining | Disabled | Failed | Rejected,
            Unloaded,
        ) => true,

        // Re-discovery after unload — allowed as a loop back so
        // operators can re-load the same plugin without allocating
        // a new Lifecycle.
        (Unloaded, Discovered) => true,

        // Everything else is denied (no self-loops, no skipping
        // states, no resurrecting terminal states except via
        // Unloaded → Discovered).
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_in_discovered() {
        let lc = Lifecycle::new("dev.mcpg.test");
        assert_eq!(lc.state(), PluginState::Discovered);
        assert_eq!(lc.plugin_id(), "dev.mcpg.test");
        assert!(!lc.serves_traffic());
    }

    #[test]
    fn happy_path_walks_to_active() {
        let mut lc = Lifecycle::new("p");
        let path = [
            PluginState::Installed,
            PluginState::Verified,
            PluginState::Compatible,
            PluginState::Configured,
            PluginState::Enabled,
            PluginState::Initialized,
            PluginState::Active,
        ];
        for expected in path {
            lc.advance().expect("happy-path advance must succeed");
            assert_eq!(lc.state(), expected);
        }
        assert!(lc.serves_traffic());
    }

    #[test]
    fn advance_refuses_branching_states() {
        let mut lc = Lifecycle::new("p");
        // Walk to Active.
        for _ in 0..7 {
            lc.advance().unwrap();
        }
        // From Active there is no canonical next step.
        let err = lc.advance().unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
    }

    #[test]
    fn active_to_degraded_and_back() {
        let mut lc = Lifecycle::new("p");
        for _ in 0..7 {
            lc.advance().unwrap();
        }
        assert_eq!(lc.state(), PluginState::Active);
        lc.transition(PluginState::Degraded).unwrap();
        assert!(lc.serves_traffic());
        lc.transition(PluginState::Active).unwrap();
        assert_eq!(lc.state(), PluginState::Active);
    }

    #[test]
    fn operator_disable_enable_cycle() {
        let mut lc = Lifecycle::new("p");
        for _ in 0..7 {
            lc.advance().unwrap();
        }
        lc.transition(PluginState::Disabled).unwrap();
        assert!(!lc.serves_traffic());
        lc.transition(PluginState::Enabled).unwrap();
        lc.transition(PluginState::Initialized).unwrap();
        lc.transition(PluginState::Active).unwrap();
    }

    #[test]
    fn reject_only_from_pre_runtime_states() {
        let mut lc = Lifecycle::new("p");
        lc.advance().unwrap(); // Installed
        lc.reject().unwrap();
        assert_eq!(lc.state(), PluginState::Rejected);
        assert!(lc.state().is_terminal());

        // Cannot reject from Discovered (nothing to reject yet).
        let mut fresh = Lifecycle::new("p");
        assert!(fresh.reject().is_err());

        // Cannot reject from Active (use fail).
        let mut active = Lifecycle::new("p");
        for _ in 0..7 {
            active.advance().unwrap();
        }
        assert!(active.reject().is_err());
    }

    #[test]
    fn fail_from_runtime_states() {
        let mut lc = Lifecycle::new("p");
        for _ in 0..7 {
            lc.advance().unwrap();
        }
        lc.fail().unwrap();
        assert_eq!(lc.state(), PluginState::Failed);
        // After failure the only path forward is unload.
        assert!(lc.transition(PluginState::Active).is_err());
        lc.transition(PluginState::Unloaded).unwrap();
    }

    #[test]
    fn unload_then_rediscover() {
        let mut lc = Lifecycle::new("p");
        lc.advance().unwrap();
        lc.transition(PluginState::Unloaded).unwrap();
        lc.transition(PluginState::Discovered).unwrap();
        assert_eq!(lc.state(), PluginState::Discovered);
    }

    #[test]
    fn terminal_states_cannot_transition_except_unload() {
        let mut lc = Lifecycle::new("p");
        lc.advance().unwrap(); // Installed
        lc.reject().unwrap();
        // Rejected is terminal — only Unloaded is reachable.
        assert!(lc.transition(PluginState::Active).is_err());
        assert!(lc.transition(PluginState::Enabled).is_err());
        lc.transition(PluginState::Unloaded).unwrap();
    }

    #[test]
    fn invalid_transition_reports_from_and_to() {
        let mut lc = Lifecycle::new("p");
        let err = lc.transition(PluginState::Active).unwrap_err();
        assert_eq!(
            err,
            LifecycleError::InvalidTransition {
                from: PluginState::Discovered,
                to: PluginState::Active,
            }
        );
    }

    #[test]
    fn no_state_has_a_self_loop() {
        // Self-loops are never valid — transitioning to the current
        // state is always a bug (use idempotent setters at a higher
        // level if you need it).
        for s in ALL_STATES {
            assert!(
                !transition_allowed(s, s),
                "self-loop must be rejected for {s:?}"
            );
        }
    }

    #[test]
    fn cannot_skip_happy_path_states() {
        // You cannot jump from Discovered straight to Active (or any
        // state in between that is more than one hop away).
        assert!(!transition_allowed(
            PluginState::Discovered,
            PluginState::Active
        ));
        assert!(!transition_allowed(
            PluginState::Discovered,
            PluginState::Configured
        ));
        assert!(!transition_allowed(
            PluginState::Verified,
            PluginState::Active
        ));
    }

    #[test]
    fn state_display_and_serde() {
        assert_eq!(PluginState::Active.to_string(), "active");
        let json = serde_json::to_string(&PluginState::Degraded).unwrap();
        assert_eq!(json, "\"degraded\"");
        let back: PluginState = serde_json::from_str("\"unloaded\"").unwrap();
        assert_eq!(back, PluginState::Unloaded);
    }

    #[test]
    fn serves_traffic_only_active_or_degraded() {
        for s in ALL_STATES {
            let serves = s.serves_traffic();
            let expected = matches!(s, PluginState::Active | PluginState::Degraded);
            assert_eq!(serves, expected, "serves_traffic mismatch for {s:?}");
        }
    }

    const ALL_STATES: [PluginState; 13] = [
        PluginState::Discovered,
        PluginState::Installed,
        PluginState::Verified,
        PluginState::Compatible,
        PluginState::Configured,
        PluginState::Enabled,
        PluginState::Initialized,
        PluginState::Active,
        PluginState::Degraded,
        PluginState::Disabled,
        PluginState::Unloaded,
        PluginState::Rejected,
        PluginState::Failed,
    ];
}
