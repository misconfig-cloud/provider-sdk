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
for a fictional protocol-test provider. It is not a customer integration or
evidence of a real infrastructure workflow.

## Resource discovery (SDK v0.7.0)

An action can optionally publish `ResourceDiscovery` in its signed capability.
`DiscoveryRequest` supports bounded search or exact-ID revalidation, never both.
`DiscoveryPage.Validate` checks the complete request digest, observation age,
page bounds, duplicate identities and complete present/missing classification
for every selected ID. Missing resources are not permission grants.

IDs are opaque provider identities. Labels and kinds are untrusted display text;
they must not be interpreted as HTML, instructions or authority. Connection
configuration stays on the authenticated adapter transport, not UI receipts.
The request digest preserves numeric precision and rejects duplicate JSON keys.

Existing action and manifest bytes are unchanged when discovery is absent.
Declaring discovery changes signed identity and requires a new admitted release.
Implement `ResourceDiscoveryImplementation` and configure a `DiscoveryService`
with the verified immutable manifest and digest. `HTTPHandler.Discovery` exposes
the authenticated `/v1/resources/discover` route; `HTTPClient.DiscoverResources`
validates both request and response. Neither side falls back to unrestricted
search for an unsupported capability.

Outbound adapters handle `OutboundPhaseDiscoverResources` through
`Dispatch.DiscoverResources`, which checks the dispatch lifetime, connection,
exact release, capability and response before returning a page. Create these
dispatches with `DispatchRequestDigest`; discovery uses precision-preserving
JSON while existing phases retain their legacy digests. Old runtime versions
reject the new phase. The control plane must dispatch discovery only to a
release that explicitly declares support; upgrading the SDK is not enrollment.

Both transports share the same validation and provider-deadline checks. The
provider must honor context cancellation and perform read-only bounded queries.
Transport authentication is not tenant authorization: admission, connection
ownership, resource policy and selection-receipt persistence remain core duties.

Hosted dispatch integration, persisted selection receipts and console authoring
are not implemented by the SDK alone. Do not advertise an adapter's guided
resource picker just because it compiles against these types.

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

## Exact capability selection (SDK v0.8.0)

`AuthorizationRule.Capabilities` contains exact `{ref, digest}` pairs. Both
values must match a selected immutable capability. It is an additional rule
selector, intersecting provider, operation and resource; matching an operation
alone cannot select another implementation. A nil field retains legacy
semantics. Empty, duplicated, ambiguous and malformed selections are invalid.
The connection's exact provider release remains independently pinned.

Use `MatchesAuthorizationRule` for selector matching and
`ParametersWithinCapabilityRules` for applicable parameter ceilings. Neither
helper grants permission: callers must validate the full authorization, preserve
stop/deny precedence and separately enforce exact action approval. Generic
ceilings still intersect capability-specific ceilings. The legacy
`ParametersWithinRules` helper refuses capability-bearing rules because it has
no trusted capability identity; it never silently drops the new selector.

Credential issuers must explicitly declare `capability_bindings_v1` in the
signed authorization features and actually enforce it. A native credential
format that cannot bind exact capabilities must refuse issuance. Merely
updating an SDK or parsing the selector is not enforcement. Selectors change
the authorization digest; omitting them preserves legacy canonical bytes.

This SDK release alone does not enable capability selection in the console.
Core storage/rollback protection, signing, local runtime, action enforcement
and old-client rejection must ship together before removing the current
same-operation ambiguity refusal from guided task authoring.

## Outbound native target verification

An outbound release may explicitly declare
`Broker.ConnectionVerification = ConnectionVerificationProtocol`. This changes
the signed manifest identity. Registration/heartbeat alone is not native target
verification, and existing releases do not opt in by updating the SDK.

Handle `OutboundPhaseVerifyConnection` with `Dispatch.VerifyConnection` and a
`ConnectionVerificationService`. Its implementation must perform a bounded,
read-only native target check and return `ConnectionVerificationResult`: exact
request digest, target identity, verification time and a redacted evidence
digest. Do not return credentials or substitute the daemon ID for the target.
`VerifyConnectionRequestDigest` preserves configuration-number precision.
Both dispatch and response checks reject stale/substituted work before it can
become verified connection authority. Retaining proof and validating tenant
admission remain control-plane responsibilities.

This exchange is outbound-only. Inbound adapters retain their existing
authenticated verification protocol. No adapter is considered accepted merely
because it publishes the declaration. Actual target, native scope and expiry
tests are required. This SDK addition does not implement task-deadline
negotiation, native credential enforcement, or local process isolation.

## Compatibility

The module follows semantic versioning. Protocol major `2` binds every issued
credential to the immutable profile, policy, environment, operation, and
resource ceiling. An incompatible wire change requires a new protocol major
and explicit control-plane support.

Licensed under Apache-2.0.
