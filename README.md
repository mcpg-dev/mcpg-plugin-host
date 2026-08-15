# mcpg-plugin-host

> Gateway-side plugin hosting: loading, verification, registry, chain evaluation, and lifecycle.

This crate is the runtime half of the MCPG plugin platform. It resolves plugin
artefacts from their configured source, verifies them, loads them, holds them in
an ordered registry, and evaluates the plugin chains that sit on the request
path. It also owns everything flowing the other way: the host-service bridge a
plugin calls back into for secrets, credentials, audit, metrics, spans, cache and
content, wrapped in per-service metering decorators. It is not the contract —
that is `mcpg-plugin-protocol`, which this crate depends on — and it is not the
plugin-authoring surface, which is `mcpg-plugin-sdk`. Depend on this crate when
you are embedding the plugin platform, not when you are writing a plugin.

## What's here

- `PluginRegistry` — the central registry. It validates a manifest before
  accepting an entry, refuses a duplicate alias, keys every entry by the
  operator-chosen alias so one cdylib can be loaded several times under different
  configs, and evaluates each class's chain in registration order (the first
  non-`Allow` tool-gate decision short-circuits). Chain evaluation returns
  immediately when a class has no plugins, so an unconfigured gateway pays
  nothing on the request path. Alongside it: `LoadedPluginInfo`,
  `HttpRouteEntry`, `HttpRouteOverrides`, `RESERVED_OVERRIDE_PATH_PREFIXES`,
  `AuditEmitPolicy`, `AuditEmitResult`, `AuditEnforcementFailure`,
  `PolicyChainOutcome`, `ChainIdentityOutcome`, and
  `DEFAULT_PLUGIN_SHUTDOWN_TIMEOUT` — the per-plugin drain budget that stops a
  plugin blocked on a hung remote from stalling gateway teardown.
- **Shadow mode.** Every entry carries an `enforce` flag. When it is false the
  plugin is still evaluated and logged, but its `Deny` and `Challenge` decisions
  are overridden to `Allow` — so a new plugin can be assessed against production
  traffic before it is allowed to affect it.
- **Loading.** `native` and `native_loader` (`libloading` + `abi_stable`:
  `load_native_plugin`, `validate_registration`, `FfiLimits`, and the
  `Native*Adapter` types that lift each vtable into the host-side trait), the
  optional Wasmtime Component Model loader behind the `wasm` feature, `oci` for
  pulling and pushing plugin artefacts, `package` (`Package`, `PackInputs`,
  `ArtifactKind`, `UnpackedPackage`, `canonical_filename`, `short_name_from_id`),
  and `descriptor` (`load_descriptor`, `validate_descriptor`).
- **Trust.** `signature::SignaturePolicy` has three states. `Enforce` refuses any
  artefact whose signature is missing, malformed, or does not verify against the
  configured trusted keys. `Warn` — the default — proceeds past a failure only
  while no trusted key is configured at all; as soon as one exists it takes on
  `Enforce` semantics, so a genuine first rollout is not blocked but a configured
  deployment cannot silently degrade. `Disabled` skips verification entirely and
  is surfaced as an audit event, keeping the choice visible in the compliance
  trail. Policy is per plugin entry, so an in-house set can run under `Enforce`
  while a third-party set finishes a key rotation. `verify` holds the primitives
  (`sha256_file`, `verify_file_signature`, `verify_ed25519_signature`,
  `decode_pem_ed25519_public_key`, `sig_path_for`), and `revocation` adds an
  operator-shipped list of artefact SHA-256s refused **after** a valid Ed25519
  signature — the answer for a fleet with mirrored or pre-pulled artefacts, where
  deleting the upstream release is not enough.
- **Host services.** `host_services` defines the `HostServices` trait that
  `host_bridge` dispatches every plugin callback into — `resolve_secret`,
  `issue_credential`, `config_snapshot`, `audit_event`, `metric_emit`, the span
  slots, `cache_get`, `fetch_content` / `store_content`, `invoke_tool`, and the
  credential-revocation and secret-rotation subscriptions — with
  `NullHostServices` and `LateBoundHostServices` for boot ordering. Every call
  carries the calling plugin's alias, so multi-instance plugins get distinct
  attribution on audit events, metrics, and spans.
- **Callback integrity.** `identity_sig` stamps a keyed MAC over a caller
  identity's semantic fields, bound both to the target plugin alias and to the
  in-flight dispatch, and carries it in the reserved `SIG_ATTR` attribute. A
  plugin can therefore only act as a principal the host actually dispatched to
  it, and only for the duration of that call; the tag is verified and stripped
  before the identity reaches a credential cache, an issuer, policy, or audit.
- **Resolution and caching.** `credential_resolver` for `cred://` reference
  collection and resolution, `credential_cache` with its clustered variant and
  XChaCha20-Poly1305 event cipher, `secret_resolver` and `secret_watcher`,
  `cluster_encryption`, `cluster_tenant`, and `uri_routing`, whose
  `RESERVED_SCHEMES` stops a third-party provider claiming the built-in `env` and
  `file` schemes.
- **Operations.** `lifecycle` (`Lifecycle`, `PluginState`, `AtomicPluginState`)
  for runtime enable / disable / degrade / drain, `health_prober` for background
  liveness probing, `span_sampling` for the plugin-call trace sampling rate,
  `audit_events` for the canonical event constructors, `docker_credentials` for
  reading registry auth out of a Docker config file, and `firstparty`
  (`FirstPartyRegistrar`, `cross_check_cdylib_capabilities`) for the static,
  non-FFI registration path.

Two features exist. `wasm` enables the Wasmtime Component Model loader; it is off
by default because it costs significant binary size and compile time, and a stock
build does not pull Wasmtime in at all. `cluster-ffi-test-seam` is a test-only
seam that lets an external test crate wrap a macro-built cluster vtable in the
production adapter without a `dlopen`; the gateway build never enables it.

## Used by

- `apps/gateway` — the gateway binary, this crate's primary and intended
  consumer.
- `k8s/operator`, which links the same verification path so its admission-time
  checks and the gateway's load-time checks cannot drift.
- `mcpg-plugin-sdk`, optionally, through its `static-firstparty` feature, so a
  plugin crate can register in-process instead of over the FFI.

## Usage

```toml
[dependencies]
mcpg-plugin-host = "<version>"
mcpg-plugin-protocol = "<version>"
serde_json = "1"
```

```rust
use mcpg_plugin_host::PluginRegistry;
use mcpg_plugin_protocol::PluginTier;

let mut registry = PluginRegistry::new();

// `my_gate` implements `mcpg_plugin_protocol::ToolGatePlugin`.
registry.register_tool_gate(
    Box::new(my_gate),
    PluginTier::Native,
    serde_json::json!({ "window": "business-hours" }),
)?;

// On the request path: the first non-Allow decision ends the chain.
let decision = registry.evaluate_tool_gates_pre(&ctx, &arguments, None).await;
assert!(decision.is_allow());
```

## Build / test

```bash
cargo build -p mcpg-plugin-host
cargo test  -p mcpg-plugin-host                 # add --features wasm for the Wasmtime loader
```

The FFI benchmarks (`ffi_roundtrip`, `ffi_roundtrip_iai`, `ffi_matrix`,
`ffi_alloc`) `dlopen` a separately built no-op cdylib rather than depending on
it, which keeps the SDK-to-host dependency graph acyclic. The `ffi_matrix` bench
and the artefact build it needs run together:

```bash
cargo bench -p mcpg-plugin-host
```

The instruction-count bench additionally needs `valgrind` and a matching
`iai-callgrind-runner` installed locally.

## Licence

Apache-2.0.

## See also

- [Plugins and the plugin protocol](https://mcpg.dev/docs/plugins/plugins-and-protocol) — the classes, tiers, and ABI this crate enforces.
- [Plugin security](https://mcpg.dev/docs/security/plugin-security) — signing, trust roots, and revocation from the operator's side.
- `libs/plugin-protocol` — the contract crate this one implements against.
- `libs/plugin-sdk` — the plugin-authoring surface.
