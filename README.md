# Misconfig provider adapter SDK

This module is the public, provider-neutral extension boundary for governed
infrastructure-agent sessions. An adapter publishes one immutable signed
release and implements the generic prepare, verify, issue, and local-render
protocols. Provider names, credential kinds, targets, and schemas are data.

The core does not gain a provider branch when an adapter is added. A release is
usable only after its publisher is trusted, its manifest signature and digest
verify, and the tenant admits that exact digest.

## Contracts

- `Manifest` describes a provider, short-lived credential protocol, local
  renderer, schemas, and exact release identity.
- `Sign` and `Verify` bind that manifest to an Ed25519 publisher key.
- `HTTPHandler` and `HTTPClient` implement the authenticated broker protocol.
- `ConfigureRequest` and `RenderRequest` let a digest-pinned local executable
  translate generic session coordinates into provider-native configuration.

The transport is deliberately narrow: the control plane never loads adapter
code, and opaque credential material reaches only the admitted local renderer.
Unknown fields, trailing JSON, signature drift, replayed nonces, incompatible
protocols, and widened provider identities fail closed.

See [provider-fixture-orbital](https://github.com/misconfig-cloud/provider-fixture-orbital)
for a deliberately unfamiliar acceptance provider.

## Compatibility

The module follows semantic versioning. Protocol major `1` remains compatible
within the `v0.1.x` SDK line; an incompatible wire change requires a new
protocol major and explicit control-plane support.

Licensed under Apache-2.0.
