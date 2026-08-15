//! Docker `config.json` credential resolver.
//!
//! Implements the subset of the Docker credentials protocol MCPG needs to
//! reuse operator-managed registry credentials without duplicating them into
//! `plugin_registry.auth.{username,password}`. Operators already keep their
//! GHCR / ECR / ACR / Harbor tokens in `~/.docker/config.json` via `docker
//! login`; this module reads them.
//!
//! Resolution precedence, for a given registry `host`:
//!
//! 1. `credHelpers.<host>` — a per-host helper name. Shell out to
//!    `docker-credential-<name> get` with the host URL on stdin; parse
//!    `{"Username":"...","Secret":"..."}` from stdout.
//! 2. `auths.<host>.auth` — inline base64-encoded `user:pass`.
//! 3. `auths.<host>.{username,password}` — inline plaintext (rare, produced
//!    by some tools but not by `docker login`).
//! 4. `credsStore` — a default helper name for hosts without a
//!    `credHelpers` entry.
//!
//! Host matching is mildly flexible: Docker stores some hosts as bare
//! `host[:port]` strings (`ghcr.io`, `harbor.internal.corp:5000`) and others
//! as URLs (`https://index.docker.io/v1/`). The lookup tries the exact
//! `host` argument first, then `https://<host>`, then `http://<host>`.
//!
//! Out of scope:
//!
//! - Writing or rotating credentials — that is `docker login` / vendor
//!   tooling, not MCPG.
//! - Windows `wincred` helper — protocol differs; deferred.
//! - `identitytoken` entries — a bearer-token variant used by Azure ACR and
//!   a few others; not yet produced by common `docker login` flows against
//!   GHCR / ECR. Revisit if a driver appears.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use thiserror::Error;

use crate::oci::OciAuth;

/// Resolve registry credentials for `host` from a Docker `config.json`.
///
/// Returns:
///
/// - `Ok(Some(OciAuth::Basic { .. }))` — credentials were found.
/// - `Ok(None)` — file exists but has no entry for `host` (and no
///   `credsStore` fallback applies), or the file does not exist.
/// - `Err(..)` — file exists but parsing / helper dispatch failed.
///
/// `config_path = None` resolves to `$HOME/.docker/config.json`. A non-
/// existent path returns `Ok(None)` (so the absence of a config isn't
/// surfaced as an error — it's a no-op fallback).
pub fn resolve_from_docker_config(
    host: &str,
    config_path: Option<&Path>,
) -> Result<Option<OciAuth>, DockerConfigError> {
    let path = match config_path {
        Some(p) => p.to_path_buf(),
        None => default_docker_config_path().ok_or(DockerConfigError::HomeNotSet)?,
    };

    if !path.exists() {
        return Ok(None);
    }

    let bytes =
        std::fs::read(&path).map_err(|e| DockerConfigError::Io(path.clone(), e.to_string()))?;
    let config: DockerConfig = serde_json::from_slice(&bytes)
        .map_err(|e| DockerConfigError::ParseError(path.clone(), e.to_string()))?;

    resolve_from_parsed(&config, host)
}

/// Default docker config location: `$HOME/.docker/config.json`.
pub fn default_docker_config_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".docker").join("config.json"))
}

fn resolve_from_parsed(
    config: &DockerConfig,
    host: &str,
) -> Result<Option<OciAuth>, DockerConfigError> {
    // 1. Per-host credential helper.
    if let Some(helper) = lookup_matching(&config.cred_helpers, host) {
        return run_credential_helper(helper, host).map(Some);
    }

    // 2 + 3. Inline auths entry — base64 `auth` first, then plaintext.
    if let Some(entry) = lookup_matching(&config.auths, host) {
        if let Some(auth) = entry.auth.as_deref()
            && !auth.trim().is_empty()
        {
            let (u, p) = decode_basic_auth(auth)?;
            return Ok(Some(OciAuth::Basic {
                username: u,
                password: p,
            }));
        }
        if let (Some(u), Some(p)) = (entry.username.as_deref(), entry.password.as_deref()) {
            return Ok(Some(OciAuth::Basic {
                username: u.to_owned(),
                password: p.to_owned(),
            }));
        }
    }

    // 4. Default credential store.
    if let Some(store) = config.creds_store.as_deref()
        && !store.trim().is_empty()
    {
        return run_credential_helper(store, host).map(Some);
    }

    Ok(None)
}

/// Try `host` exactly, then `https://<host>`, then `http://<host>`.
/// Docker stores the Hub as `https://index.docker.io/v1/`, vendor
/// registries as bare `host[:port]`, and private ones as either. We
/// accept whichever form is present.
fn lookup_matching<'a, V>(map: &'a BTreeMap<String, V>, host: &str) -> Option<&'a V> {
    if let Some(v) = map.get(host) {
        return Some(v);
    }
    for scheme in &["https://", "http://"] {
        let candidate = format!("{scheme}{host}");
        if let Some(v) = map.get(&candidate) {
            return Some(v);
        }
    }
    None
}

fn decode_basic_auth(b64: &str) -> Result<(String, String), DockerConfigError> {
    let bytes = STANDARD
        .decode(b64.trim())
        .map_err(|e| DockerConfigError::Base64(e.to_string()))?;
    let s = String::from_utf8(bytes).map_err(|_| DockerConfigError::NotUtf8)?;
    let (u, p) = s.split_once(':').ok_or(DockerConfigError::MalformedAuth)?;
    Ok((u.to_owned(), p.to_owned()))
}

fn run_credential_helper(helper: &str, host: &str) -> Result<OciAuth, DockerConfigError> {
    // Docker credential helper protocol:
    //   `docker-credential-<name> get` reads the server URL from stdin
    //   (just the URL, no trailing newline required by the spec but
    //   most helpers tolerate one); writes
    //   `{"Username":"...","Secret":"..."}` (with leading capitals —
    //   see `docker-credential-helpers` spec) to stdout on success.
    //
    // We send the bare `host` per conventional usage; helpers that
    // expect a scheme should be configured with a `credHelpers` key
    // that already includes the scheme.
    let binary = format!("docker-credential-{helper}");

    let mut child = Command::new(&binary)
        .arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| DockerConfigError::HelperLaunchFailed(binary.clone(), e.to_string()))?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or(DockerConfigError::HelperStdinUnavailable)?;
        stdin
            .write_all(host.as_bytes())
            .map_err(|e| DockerConfigError::HelperStdinWriteFailed(e.to_string()))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| DockerConfigError::HelperWaitFailed(e.to_string()))?;

    if !output.status.success() {
        return Err(DockerConfigError::HelperExitNonZero {
            helper: binary,
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    #[derive(Debug, Deserialize)]
    struct HelperResponse {
        #[serde(rename = "Username")]
        username: String,
        #[serde(rename = "Secret")]
        secret: String,
    }

    let resp: HelperResponse = serde_json::from_slice(&output.stdout)
        .map_err(|e| DockerConfigError::HelperParseFailed(binary.clone(), e.to_string()))?;

    Ok(OciAuth::Basic {
        username: resp.username,
        password: resp.secret,
    })
}

// ---------------------------------------------------------------------------
// Docker config.json schema (subset)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct DockerConfig {
    #[serde(default)]
    auths: BTreeMap<String, DockerAuthEntry>,

    #[serde(default, rename = "credHelpers")]
    cred_helpers: BTreeMap<String, String>,

    #[serde(default, rename = "credsStore")]
    creds_store: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct DockerAuthEntry {
    #[serde(default)]
    auth: Option<String>,

    #[serde(default)]
    username: Option<String>,

    #[serde(default)]
    password: Option<String>,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned while resolving credentials from a Docker config.
#[derive(Debug, Error)]
pub enum DockerConfigError {
    #[error(
        "HOME environment variable is not set — cannot locate the default \
         Docker config at ~/.docker/config.json"
    )]
    HomeNotSet,

    #[error("I/O error reading {0}: {1}")]
    Io(PathBuf, String),

    #[error("parse error in {0}: {1}")]
    ParseError(PathBuf, String),

    #[error("base64 decode of `auths.<host>.auth` failed: {0}")]
    Base64(String),

    #[error("decoded `auths.<host>.auth` is not valid UTF-8")]
    NotUtf8,

    #[error("`auths.<host>.auth` value is not in user:pass format")]
    MalformedAuth,

    #[error("failed to launch credential helper `{0}`: {1}")]
    HelperLaunchFailed(String, String),

    #[error("credential helper stdin was unexpectedly unavailable")]
    HelperStdinUnavailable,

    #[error("failed to write registry URL to credential helper stdin: {0}")]
    HelperStdinWriteFailed(String),

    #[error("failed to wait on credential helper: {0}")]
    HelperWaitFailed(String),

    #[error("credential helper `{helper}` exited with {status}: {stderr}")]
    HelperExitNonZero {
        helper: String,
        status: ExitStatus,
        stderr: String,
    },

    #[error("credential helper `{0}` produced unparseable output: {1}")]
    HelperParseFailed(String, String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(dir: &Path, name: &str, json: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, json).expect("write config");
        path
    }

    fn basic_auth(expected_user: &str, expected_pass: &str, auth: &OciAuth) {
        match auth {
            OciAuth::Basic { username, password } => {
                assert_eq!(username, expected_user);
                assert_eq!(password, expected_pass);
            }
            other => panic!("expected Basic, got: {other:?}"),
        }
    }

    #[test]
    fn missing_file_returns_none_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let out = resolve_from_docker_config("ghcr.io", Some(&path)).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn empty_config_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "config.json", "{}");
        let out = resolve_from_docker_config("ghcr.io", Some(&path)).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn auths_base64_inline() {
        // base64("alice:wonderland") = YWxpY2U6d29uZGVybGFuZA==
        let json = r#"{
            "auths": {
                "ghcr.io": { "auth": "YWxpY2U6d29uZGVybGFuZA==" }
            }
        }"#;
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "config.json", json);
        let out = resolve_from_docker_config("ghcr.io", Some(&path))
            .unwrap()
            .expect("auth");
        basic_auth("alice", "wonderland", &out);
    }

    #[test]
    fn auths_plaintext_fallback() {
        let json = r#"{
            "auths": {
                "harbor.internal.corp": {
                    "username": "robot", "password": "hunter2"
                }
            }
        }"#;
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "config.json", json);
        let out = resolve_from_docker_config("harbor.internal.corp", Some(&path))
            .unwrap()
            .expect("auth");
        basic_auth("robot", "hunter2", &out);
    }

    #[test]
    fn auth_base64_preferred_over_plaintext() {
        // base64("from_auth_field:s1") = ZnJvbV9hdXRoX2ZpZWxkOnMx
        let json = r#"{
            "auths": {
                "ghcr.io": {
                    "auth": "ZnJvbV9hdXRoX2ZpZWxkOnMx",
                    "username": "from_plaintext",
                    "password": "s2"
                }
            }
        }"#;
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "config.json", json);
        let out = resolve_from_docker_config("ghcr.io", Some(&path))
            .unwrap()
            .expect("auth");
        basic_auth("from_auth_field", "s1", &out);
    }

    #[test]
    fn host_matching_accepts_https_prefix() {
        // Docker Hub canonically stores as "https://index.docker.io/v1/".
        // Our caller passes the bare host; the lookup should handle both.
        // base64("bob:build") = Ym9iOmJ1aWxk
        let json = r#"{
            "auths": {
                "https://index.docker.io/v1/": { "auth": "Ym9iOmJ1aWxk" }
            }
        }"#;
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "config.json", json);
        let out = resolve_from_docker_config("index.docker.io/v1/", Some(&path))
            .unwrap()
            .expect("auth");
        basic_auth("bob", "build", &out);
    }

    #[test]
    fn malformed_base64_surfaces_error() {
        let json = r#"{
            "auths": {
                "ghcr.io": { "auth": "!!!!not-base64!!!!" }
            }
        }"#;
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "config.json", json);
        let err = resolve_from_docker_config("ghcr.io", Some(&path)).unwrap_err();
        assert!(matches!(err, DockerConfigError::Base64(_)), "got: {err:?}");
    }

    #[test]
    fn missing_host_without_store_returns_none() {
        let json = r#"{
            "auths": {
                "ghcr.io": { "auth": "YWxpY2U6d29uZGVybGFuZA==" }
            }
        }"#;
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "config.json", json);
        let out = resolve_from_docker_config("some-other-host.example", Some(&path)).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn parse_error_surfaces_with_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "config.json", "not json at all");
        let err = resolve_from_docker_config("ghcr.io", Some(&path)).unwrap_err();
        match err {
            DockerConfigError::ParseError(p, _) => assert_eq!(p, path),
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    /// Serialize PATH-mutating tests. `cargo test` runs tests in
    /// parallel by default; the helper-path tests write a shim into a
    /// tempdir and prepend it to `PATH`, which is process-global.
    /// Without this mutex, tests would overwrite each other's PATH
    /// and the wrong shim could be invoked.
    static PATH_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Unique, unlikely-to-collide shim name. Avoids picking up any
    /// real `docker-credential-*` that might be installed on the host
    /// running `cargo test`. `{test_fn}` is concatenated to the prefix
    /// to further reduce collision risk across tests.
    fn unique_helper_name(test_fn: &str) -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        format!("mcpgtest-{test_fn}-{pid}-{n}")
    }

    /// Scoped PATH-prefix guard. Locks the global PATH_MUTEX, prepends
    /// `extra` to PATH on construction, restores the original PATH on
    /// drop. Use this in every test that invokes a helper shim via
    /// PATH so concurrent tests don't stomp each other.
    struct PathPrefixGuard {
        original: std::ffi::OsString,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl PathPrefixGuard {
        fn new(extra: &Path) -> Self {
            let lock = PATH_MUTEX
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let original = std::env::var_os("PATH").unwrap_or_default();
            let mut new_path = std::ffi::OsString::from(extra);
            new_path.push(":");
            new_path.push(&original);
            // SAFETY: the Mutex guarantees single-threaded access to
            // the process-global `PATH` env var for the scope of this
            // guard. Needed so the child process (docker-credential-*)
            // resolves against our tempdir. `set_var` is nominally
            // unsafe-in-Rust-2024 because of the race the Mutex
            // prevents.
            #[allow(
                unsafe_code,
                reason = "cross-process test fixture serialized by PATH_MUTEX"
            )]
            unsafe {
                std::env::set_var("PATH", &new_path);
            }
            Self {
                original,
                _lock: lock,
            }
        }
    }

    impl Drop for PathPrefixGuard {
        fn drop(&mut self) {
            #[allow(
                unsafe_code,
                reason = "cross-process test fixture serialized by PATH_MUTEX"
            )]
            unsafe {
                std::env::set_var("PATH", &self.original);
            }
        }
    }

    #[cfg(unix)]
    fn write_shim(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, body).expect("write shim");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod +x shim");
        path
    }

    /// Integration test: a shell-based helper shim is written to a
    /// tempdir and invoked via PATH.
    ///
    /// Unix-only — shell shims don't work on Windows, and the Windows
    /// helper protocol differs anyway.
    #[cfg(unix)]
    #[test]
    fn credential_helper_path_invokes_shim_and_parses_output() {
        let dir = tempfile::tempdir().unwrap();
        let helper_id = unique_helper_name("helper_path");
        let shim_name = format!("docker-credential-{helper_id}");
        write_shim(
            dir.path(),
            &shim_name,
            r#"#!/bin/sh
# Drain stdin so the parent's write_all can complete before we exit
# (otherwise we race the parent and trigger EPIPE on slow runners).
cat >/dev/null
printf '{"Username":"helper-user","Secret":"helper-secret"}'
"#,
        );

        let json = format!(r#"{{ "credHelpers": {{ "ghcr.io": "{helper_id}" }} }}"#);
        let config_path = write_config(dir.path(), "config.json", &json);

        let _guard = PathPrefixGuard::new(dir.path());

        let out = resolve_from_docker_config("ghcr.io", Some(&config_path)).expect("helper ok");
        let out = out.expect("credential returned");
        basic_auth("helper-user", "helper-secret", &out);
    }

    #[cfg(unix)]
    #[test]
    fn creds_store_fallback_dispatches_to_default_helper() {
        let dir = tempfile::tempdir().unwrap();
        let helper_id = unique_helper_name("creds_store");
        let shim_name = format!("docker-credential-{helper_id}");
        write_shim(
            dir.path(),
            &shim_name,
            r#"#!/bin/sh
cat >/dev/null
printf '{"Username":"fb-user","Secret":"fb-secret"}'
"#,
        );

        let json = format!(r#"{{ "credsStore": "{helper_id}" }}"#);
        let config_path = write_config(dir.path(), "config.json", &json);

        let _guard = PathPrefixGuard::new(dir.path());

        let out =
            resolve_from_docker_config("any.host.example", Some(&config_path)).expect("store ok");
        let out = out.expect("credential returned");
        basic_auth("fb-user", "fb-secret", &out);
    }

    #[cfg(unix)]
    #[test]
    fn per_host_helper_takes_precedence_over_creds_store() {
        let dir = tempfile::tempdir().unwrap();
        let specific_id = unique_helper_name("precedence-specific");
        let fallback_id = unique_helper_name("precedence-fallback");
        write_shim(
            dir.path(),
            &format!("docker-credential-{specific_id}"),
            r#"#!/bin/sh
cat >/dev/null
printf '{"Username":"specific","Secret":"wins"}'
"#,
        );
        write_shim(
            dir.path(),
            &format!("docker-credential-{fallback_id}"),
            r#"#!/bin/sh
cat >/dev/null
printf '{"Username":"fallback","Secret":"should-not-fire"}'
"#,
        );

        let json = format!(
            r#"{{
                "credHelpers": {{ "ghcr.io": "{specific_id}" }},
                "credsStore": "{fallback_id}"
            }}"#
        );
        let config_path = write_config(dir.path(), "config.json", &json);

        let _guard = PathPrefixGuard::new(dir.path());

        let out = resolve_from_docker_config("ghcr.io", Some(&config_path)).expect("helper ok");
        let out = out.expect("credential returned");
        basic_auth("specific", "wins", &out);
    }

    #[cfg(unix)]
    #[test]
    fn credential_helper_nonzero_exit_surfaces_error() {
        let dir = tempfile::tempdir().unwrap();
        let helper_id = unique_helper_name("broken");
        write_shim(
            dir.path(),
            &format!("docker-credential-{helper_id}"),
            r#"#!/bin/sh
cat >/dev/null
echo "helper is sad" >&2
exit 17
"#,
        );

        let json = format!(r#"{{ "credHelpers": {{ "ghcr.io": "{helper_id}" }} }}"#);
        let config_path = write_config(dir.path(), "config.json", &json);

        let _guard = PathPrefixGuard::new(dir.path());

        let err = resolve_from_docker_config("ghcr.io", Some(&config_path)).unwrap_err();
        match err {
            DockerConfigError::HelperExitNonZero { stderr, .. } => {
                assert!(stderr.contains("helper is sad"), "got: {stderr}");
            }
            other => panic!("expected HelperExitNonZero, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn credential_helper_not_found_surfaces_error() {
        // Don't put any shim on PATH; the helper binary doesn't exist.
        // Still acquire the mutex so concurrent PATH-mutating tests
        // can't accidentally make our named helper resolvable.
        let _guard = PATH_MUTEX.lock().unwrap_or_else(|p| p.into_inner());

        let helper_id = unique_helper_name("missing");
        let json = format!(r#"{{ "credHelpers": {{ "ghcr.io": "{helper_id}" }} }}"#);
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(dir.path(), "config.json", &json);
        let err = resolve_from_docker_config("ghcr.io", Some(&config_path)).unwrap_err();
        assert!(
            matches!(err, DockerConfigError::HelperLaunchFailed(_, _)),
            "got: {err:?}"
        );
    }
}
