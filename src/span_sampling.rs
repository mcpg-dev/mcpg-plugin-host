//! Per-call span sampling for native-plugin host-side spans.
//!
//! The host wraps every plugin FFI call in a `tracing` span (see the
//! `*_metering.rs` adapters) so traces can attribute work to a
//! specific plugin id. On hot paths (tool-gate chain → 5–15
//! spans/call; metrics_sink emit → up to 50 spans/call) the per-span
//! construction + drop overhead is ~5–20 µs each. Operators running
//! plugin-heavy workloads with the global trace subscriber already
//! sampling at a low rate can additionally dampen these *host-side*
//! plugin-call spans without touching the global subscriber.
//!
//! Mechanism: a process-wide AtomicU32 holds the sampling threshold
//! as `rate * u32::MAX`. The boot path calls [`set_plugin_call_sampling_rate`]
//! once with the operator's
//! `observability.plugin_call_sampling_rate` value (or leaves the
//! default of `u32::MAX` = always-on). Each span-creating call site
//! consults [`should_sample_plugin_call`]; on `false` it emits
//! `Span::none()` instead of `info_span!(...)`, which `tracing`
//! short-circuits at near-zero cost.
//!
//! The default (no override) is **always sample** — operators must
//! opt in to dampening. This preserves the pre-E.12 behaviour for
//! deployments that already rely on per-plugin traces.

use std::sync::atomic::{AtomicU32, Ordering};

/// Convenience macro: like `tracing::info_span!` but skipped (returns
/// a disabled `Span::none()`) when [`should_sample_plugin_call`]
/// rejects this call. Use at every native-plugin-attribution span
/// site so the operator's
/// `observability.plugin_call_sampling_rate` knob takes effect.
///
/// Example:
/// ```ignore
/// let span = $crate::sampled_info_span!("identity_resolve", plugin_id = %self.plugin_id);
/// inner.resolve_identity(...).instrument(span).await
/// ```
#[macro_export]
macro_rules! sampled_info_span {
    ($($args:tt)*) => {
        if $crate::span_sampling::should_sample_plugin_call() {
            ::tracing::info_span!($($args)*)
        } else {
            ::tracing::Span::none()
        }
    };
}

/// Sampling threshold: a random u32 less than this value passes.
/// `u32::MAX` means every call samples (the default). `0` would
/// disable plugin-call spans entirely; in practice operators set
/// `0.01–0.1` for ~1–10% sampling.
static PLUGIN_CALL_SAMPLING_THRESHOLD: AtomicU32 = AtomicU32::new(u32::MAX);

/// Set the per-call sampling rate. Called once at gateway boot from
/// the operator config. Idempotent + thread-safe (uses an atomic
/// store) so config-reload at runtime works without coordination.
///
/// `rate` is clamped to `[0.0, 1.0]`. `1.0` (the default) means
/// every span is created; `0.0` would suppress all plugin-call
/// spans. Values outside that range are clamped silently — the
/// config layer rejects them at validate-time, so reaching this
/// helper with a bad value implies a programmer error and a panic
/// would be louder than useful.
pub fn set_plugin_call_sampling_rate(rate: f64) {
    let clamped = rate.clamp(0.0, 1.0);
    let threshold = (clamped * (u32::MAX as f64)) as u32;
    PLUGIN_CALL_SAMPLING_THRESHOLD.store(threshold, Ordering::Relaxed);
}

/// Read the current per-call sampling threshold (for tests).
pub fn current_threshold() -> u32 {
    PLUGIN_CALL_SAMPLING_THRESHOLD.load(Ordering::Relaxed)
}

/// Return `true` if the calling span should be materialised, `false`
/// if it should be suppressed.
///
/// Cheap: an atomic load + (when not always-on) a single PRNG step.
/// The `always-on` fast path is one comparison + early return so
/// deployments that don't configure dampening pay nothing.
#[inline]
pub fn should_sample_plugin_call() -> bool {
    let threshold = PLUGIN_CALL_SAMPLING_THRESHOLD.load(Ordering::Relaxed);
    if threshold == u32::MAX {
        return true; // always-on fast path
    }
    if threshold == 0 {
        return false;
    }
    // Cheap xorshift PRNG seeded from a thread-local — avoids
    // pulling in a full `rand` dep just for the sampler. The
    // distribution doesn't need cryptographic quality; what matters
    // is that on average ~threshold/u32::MAX of calls pass.
    // Process-wide counter that hands each thread its own xorshift
    // seed. `ThreadId::as_u64` is still unstable on stable Rust
    // (see rust-lang/rust#67939), so we generate per-thread seeds
    // via a simple atomic counter — different per thread,
    // deterministic within a run, fine for a dampener (not a
    // security primitive).
    static SEED_COUNTER: AtomicU32 = AtomicU32::new(0x9E37_79B9);
    thread_local! {
        static SAMPLER_STATE: std::cell::Cell<u32> = std::cell::Cell::new({
            let raw = SEED_COUNTER.fetch_add(0x9E37_79B9, Ordering::Relaxed);
            // xorshift requires non-zero state.
            if raw == 0 { 0xDEAD_BEEF } else { raw }
        });
    }
    let r = SAMPLER_STATE.with(|cell| {
        // xorshift32 — small, fast, no allocation.
        let mut x = cell.get();
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        cell.set(x);
        x
    });
    r < threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests in this module touch the process-wide
    /// `PLUGIN_CALL_SAMPLING_THRESHOLD` atomic, so they must run
    /// serially to avoid one test's `set_plugin_call_sampling_rate`
    /// race against another's read. A single global Mutex serializes
    /// them.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn default_threshold_is_always_on() {
        let _g = TEST_LOCK.lock().unwrap();
        set_plugin_call_sampling_rate(1.0);
        for _ in 0..10_000 {
            assert!(should_sample_plugin_call());
        }
    }

    #[test]
    fn zero_threshold_blocks_every_call() {
        let _g = TEST_LOCK.lock().unwrap();
        set_plugin_call_sampling_rate(0.0);
        for _ in 0..10_000 {
            assert!(!should_sample_plugin_call());
        }
        set_plugin_call_sampling_rate(1.0);
    }

    #[test]
    fn partial_threshold_yields_expected_distribution() {
        let _g = TEST_LOCK.lock().unwrap();
        set_plugin_call_sampling_rate(0.10);
        let mut sampled = 0u32;
        let n = 100_000u32;
        for _ in 0..n {
            if should_sample_plugin_call() {
                sampled += 1;
            }
        }
        let ratio = sampled as f64 / n as f64;
        // 10% target with reasonable slack for the xorshift PRNG.
        assert!(
            (0.07..=0.13).contains(&ratio),
            "expected ratio near 0.10, got {ratio}"
        );
        set_plugin_call_sampling_rate(1.0);
    }

    #[test]
    fn out_of_range_rate_is_clamped() {
        let _g = TEST_LOCK.lock().unwrap();
        set_plugin_call_sampling_rate(2.5);
        assert_eq!(current_threshold(), u32::MAX);
        set_plugin_call_sampling_rate(-0.5);
        assert_eq!(current_threshold(), 0);
        set_plugin_call_sampling_rate(1.0);
    }
}
