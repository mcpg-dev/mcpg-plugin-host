//! Host-applied integrity tag on [`PluginIdentity`] crossing the cdylib FFI.
//!
//! The cdylib host-FFI is a split-trust channel: only the host-controlled
//! plugin alias is trustworthy; everything a plugin sends back — including the
//! caller `identity` it relays into `resolve_credentials` / `issue_credential` /
//! `invoke_tool` — is otherwise believed verbatim. That let a compromised
//! plugin forge a high-trust principal to launder credentials, read another
//! principal's cached credential, or forge audit attribution.
//!
//! Fix: the host stamps a keyed MAC over the identity's semantic fields bound
//! to the *target plugin alias* whenever it hands an identity to a plugin (the
//! `BackendRequest` marshalling), carried in the reserved attribute
//! [`SIG_ATTR`]; it verifies + strips that tag when a plugin relays the
//! identity back through a host callback. A plugin can therefore only ever act
//! as a principal the host actually dispatched **to that plugin** — it cannot
//! fabricate one or mutate the one it received (the MAC covers the fields).
//! The reserved attribute travels in the existing `attributes` map (no
//! protocol struct change) and is removed before the identity reaches the
//! credential cache, an issuer, policy, or audit. The key is a process-global
//! random secret: signing and verifying both happen in the gateway process,
//! so it never leaves it.
//!
//! A tag also names the *dispatch* it was minted for, and the host holds the
//! set of dispatches currently in flight toward each plugin (see
//! [`HostBridge::begin_dispatch`](crate::host_bridge::HostBridge::begin_dispatch)).
//! Verification refuses a tag whose dispatch has already completed, so an
//! identity cannot be banked from one call and relayed on a later, unrelated
//! one — without that, a tag stayed valid for the whole process lifetime and a
//! compromised plugin could replay the most privileged principal it had ever
//! served against any subsequent request.
//!
//! Residual (accepted + documented): a malicious plugin servicing two
//! concurrent requests could relay the *other* request's (validly-signed)
//! identity, for as long as that other request is still running. That is
//! bounded to principals already flowing through that very plugin — not an
//! arbitrary forged admin — and is contained further by the per-(issuer,target)
//! credential allowlist.
//!
//! The tag is opaque to plugins: the host both mints and verifies it, and a
//! plugin only ever round-trips the string. Its format is therefore internal,
//! and carries a version prefix so a future change can be told apart from
//! corruption rather than mistaken for it.

use std::sync::OnceLock;

use mcpg_plugin_protocol::types::PluginIdentity;

/// Reserved `attributes` key carrying the host integrity tag.
pub const SIG_ATTR: &str = "__mcpg_id_sig";

/// Tag format version. Tags never outlive the dispatch that minted them, so
/// changing this cannot strand a valid one.
const TAG_VERSION: &str = "2";

/// Process-global MAC key, lazily seeded from the OS CSPRNG on first use.
fn key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        use rand::RngCore;
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        k
    })
}

/// Keyed MAC over the identity's semantic fields (the reserved tag attribute
/// removed) bound to `alias` and to the `dispatch` the identity is being handed
/// out for. Deterministic for a given (identity, alias, dispatch):
/// `attributes` is a `BTreeMap` so serialization order is stable.
fn mac(identity: &PluginIdentity, alias: &str, dispatch: u64) -> String {
    let mut bare = identity.clone();
    bare.attributes.remove(SIG_ATTR);
    let mut data = serde_json::to_vec(&bare).unwrap_or_default();
    data.push(0);
    data.extend_from_slice(alias.as_bytes());
    data.push(0);
    data.extend_from_slice(&dispatch.to_be_bytes());
    blake3::keyed_hash(key(), &data).to_hex().to_string()
}

/// Stamp the host integrity tag onto an identity bound to `alias` and to the
/// in-flight `dispatch`.
///
/// Callers go through
/// [`HostBridge::begin_dispatch`](crate::host_bridge::HostBridge::begin_dispatch),
/// which allocates the dispatch and retires it again on drop; signing without
/// registering the dispatch produces a tag that never verifies.
pub fn sign(identity: &mut PluginIdentity, alias: &str, dispatch: u64) {
    let tag = format!(
        "{TAG_VERSION}:{dispatch:016x}:{}",
        mac(identity, alias, dispatch)
    );
    identity.attributes.insert(SIG_ATTR.to_owned(), tag);
}

/// Verify a plugin-relayed identity for `alias`. On success returns the
/// identity with the reserved tag stripped (clean for downstream use). Returns
/// `None` — so the caller falls back to the fail-closed system path (no caller
/// identity) — when the tag is missing, malformed, of an unknown version,
/// doesn't match the identity's fields, or names a dispatch `is_live` reports
/// is no longer running.
pub fn verify_strip(
    mut identity: PluginIdentity,
    alias: &str,
    is_live: impl Fn(u64) -> bool,
) -> Option<PluginIdentity> {
    let presented = identity.attributes.get(SIG_ATTR).cloned()?;
    let (version, rest) = presented.split_once(':')?;
    if version != TAG_VERSION {
        return None;
    }
    let (dispatch_hex, presented_mac) = rest.split_once(':')?;
    let dispatch = u64::from_str_radix(dispatch_hex, 16).ok()?;
    let expect = mac(&identity, alias, dispatch);
    if !constant_time_eq(presented_mac.as_bytes(), expect.as_bytes()) {
        return None;
    }
    // Authenticity established; now freshness. A tag the host really did mint
    // is still refused once its dispatch has finished.
    if !is_live(dispatch) {
        return None;
    }
    identity.attributes.remove(SIG_ATTR);
    Some(identity)
}

/// `verify_strip` over an `Option`, for the `resolve_credentials` relay path.
pub fn verified_or_none(
    identity: Option<PluginIdentity>,
    alias: &str,
    is_live: impl Fn(u64) -> bool,
) -> Option<PluginIdentity> {
    identity.and_then(|id| verify_strip(id, alias, is_live))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(subject: &str, trust: &str) -> PluginIdentity {
        PluginIdentity {
            kind: trust.to_owned(),
            trust_level: trust.to_owned(),
            subject_id: Some(subject.to_owned()),
            auth_provider: None,
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: Default::default(),
        }
    }

    /// Liveness oracle for a fixed set of dispatches.
    fn live(nonces: &[u64]) -> impl Fn(u64) -> bool + '_ {
        move |n| nonces.contains(&n)
    }

    #[test]
    fn signed_identity_verifies_for_its_alias_only_and_is_stripped() {
        let mut i = id("alice", "verified");
        sign(&mut i, "dev.backend.sql", 7);
        assert!(i.attributes.contains_key(SIG_ATTR));
        let clean = verify_strip(i.clone(), "dev.backend.sql", live(&[7])).expect("verifies");
        assert!(!clean.attributes.contains_key(SIG_ATTR), "tag stripped");
        // Same identity, different plugin alias → rejected (alias-bound).
        assert!(verify_strip(i, "dev.backend.http", live(&[7])).is_none());
    }

    #[test]
    fn unsigned_or_mutated_identity_is_rejected() {
        assert!(verify_strip(id("admin", "verified"), "dev.backend.sql", live(&[1])).is_none());
        // Mutated after signing: escalate trust/subject → MAC mismatch.
        let mut i = id("alice", "header_asserted");
        sign(&mut i, "dev.backend.sql", 1);
        i.trust_level = "verified".to_owned();
        i.subject_id = Some("admin".to_owned());
        assert!(verify_strip(i, "dev.backend.sql", live(&[1])).is_none());
    }

    #[test]
    fn tag_stops_verifying_once_its_dispatch_ends() {
        // The replay this guards: a plugin banks a privileged identity from
        // one call and presents it on a later, unrelated one.
        let mut admin = id("payroll-admin", "verified");
        sign(&mut admin, "dev.backend.sql", 42);
        assert!(verify_strip(admin.clone(), "dev.backend.sql", live(&[42])).is_some());
        // Dispatch 42 has completed; a different one is now running.
        assert!(verify_strip(admin.clone(), "dev.backend.sql", live(&[43])).is_none());
        assert!(verify_strip(admin, "dev.backend.sql", live(&[])).is_none());
    }

    #[test]
    fn tag_cannot_be_repointed_at_a_live_dispatch() {
        // The dispatch nonce is inside the MAC, so rewriting it to name a
        // dispatch that IS live invalidates the tag.
        let mut i = id("payroll-admin", "verified");
        sign(&mut i, "dev.backend.sql", 42);
        let tag = i.attributes[SIG_ATTR].clone();
        let mac = tag.rsplit(':').next().expect("mac segment");
        i.attributes
            .insert(SIG_ATTR.to_owned(), format!("2:{:016x}:{mac}", 43u64));
        assert!(verify_strip(i, "dev.backend.sql", live(&[42, 43])).is_none());
    }

    #[test]
    fn malformed_and_unversioned_tags_are_rejected() {
        for tag in [
            "",
            "deadbeef",
            "2:notahexnonce:aa",
            "1:0000000000000007:aa",
            "2:0000000000000007",
        ] {
            let mut i = id("alice", "verified");
            i.attributes.insert(SIG_ATTR.to_owned(), tag.to_owned());
            assert!(
                verify_strip(i, "dev.backend.sql", |_| true).is_none(),
                "accepted tag {tag:?}"
            );
        }
    }

    #[test]
    fn verified_or_none_filters() {
        let mut good = id("alice", "verified");
        sign(&mut good, "a", 5);
        assert!(verified_or_none(Some(good), "a", live(&[5])).is_some());
        assert!(verified_or_none(Some(id("admin", "verified")), "a", live(&[5])).is_none());
        assert!(verified_or_none(None, "a", live(&[5])).is_none());
    }
}
