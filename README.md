# Misconfig provider adapter SDK

This module is the public, provider-neutral extension boundary for governed
infrastructure-agent sessions. An adapter publishes one immutable signed
release and implements the generic prepare, verify, issue, local-render, and
optional typed-action protocols. Provider names, credential kinds, targets,
operations, and schemas are data.

The core does not gain a provider branch when an adapter is added. A release is
usable only after its publisher is trusted, its manifest signature and digest
verify, and the tenant admits that exact digest.

## Contracts

- `Manifest` describes a provider, short-lived credential protocol, local
  renderer, per-platform artifact digests, schemas, and exact release identity.
- `Sign` and `Verify` bind that manifest to an Ed25519 publisher key.
- `HTTPHandler` and `HTTPClient` implement the authenticated inbound broker
  protocol. A signed release may instead declare `outbound-pull` and pin one
  or more runnable artifacts; the same prepare, issue, execute, and verify
  envelopes then travel through the tenant-isolated control-plane broker.
- `ActionCapability` publishes separately signed parameter, execution, and
  verification schemas. `ExecuteActionRequest` consumes one short-lived,
  action-bound authority; `VerifyActionRequest` observes provider state again.
- `ConfigureRequest` and `RenderRequest` let a digest-pinned local executable
  translate generic session coordinates into provider-native configuration.

The transport is deliberately narrow: the control plane never loads adapter
code, and opaque credential material reaches only the admitted local renderer.
Unknown fields, trailing JSON, signature drift, replayed nonces, incompatible
protocols, and widened provider identities fail closed.

An execution response is never proof by itself. Adapters return a redacted
provider receipt and a digest-bound output, then perform a distinct read-back
verification with its own evidence digest. The core remains unaware whether
the adapter controls AWS, GCP, Kubernetes, Hetzner, SaaS APIs, or an internal
system.

See [provider-fixture-orbital](https://github.com/misconfig-cloud/provider-fixture-orbital)
for a deliberately unfamiliar acceptance provider.

## Exact resources and task limits

`Authorization.ResourceIDs` and `AuthorizationRule.ResourceIDs` use byte-exact
identity matching. They cannot be combined with prefixes at the same scope.
An explicit empty list is invalid. Omitting exact IDs preserves legacy prefix
semantics; do not translate an exact ID into a prefix.

An allow or typed-action rule may include `ParameterLimits`. This is a closed
top-level object: every supplied parameter must be declared, and each declared
field is required unless marked optional. Scalars support types, explicit
allowed values and inclusive numeric bounds. Objects and arrays require exact
allowed JSON values. Numeric comparisons preserve integer precision; duplicate
JSON keys, excessive nesting and oversized values are rejected.

All matching parameter ceilings intersect. A broader allow elsewhere cannot
bypass a narrower ceiling. Limits are restrictions, never permission grants.
Provider capability schemas still apply independently.

Credential issuers must explicitly publish the features they enforce in the
signed `Credential.AuthorizationFeatures`: `exact_resources_v1` and/or
`parameter_limits_v1`. Upgrading this library does not opt an adapter in. Call
`CheckAuthorizationSupport` before issuance, and enforce the full authorization
in the actual provider credentials or execution boundary. Do not declare a
feature merely because your parser recognizes it. The control plane also
checks this declaration before issuing credentials.

Exact IDs and parameter limits participate in authorization digests. New
renderers receive exact scope through `ConfigureRequest.ResourceIDs`. Legacy
manifest and authorization bytes remain unchanged when new fields are absent;
older adapters must reject unfamiliar constrained requests, not drop fields.

## Compatibility

The module follows semantic versioning. Protocol major `2` binds every issued
credential to the immutable profile, policy, environment, operation, and
resource ceiling. An incompatible wire change requires a new protocol major
and explicit control-plane support.

Licensed under Apache-2.0.
