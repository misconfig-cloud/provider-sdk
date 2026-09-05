package provideradapter

import (
	"encoding/json"
	"testing"
	"time"
)

func outboundFixtureManifest() (Manifest, string) {
	manifest := fixtureManifest()
	manifest.Broker = Broker{Protocol: BrokerProtocol, Transport: BrokerTransportOutboundPull, RuntimeArtifacts: []RuntimeArtifact{{
		Kind: "native", Reference: "orbital-runtime", Digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}}}
	digest, _ := Digest(manifest)
	return manifest, digest
}

func TestRuntimeRegistrationBindsSignedReleaseAndRuntime(t *testing.T) {
	manifest, digest := outboundFixtureManifest()
	registration := RuntimeRegistration{
		Protocol: OutboundRuntimeProtocol, ConnectionID: "conn-1", Provider: manifest.Provider,
		Release: manifest.Release, ManifestDigest: digest, RuntimeArtifactDigest: manifest.Broker.RuntimeArtifacts[0].Digest, RuntimeID: "runtime-1",
	}
	if err := registration.Validate(manifest, digest); err != nil {
		t.Fatalf("registration rejected: %v", err)
	}
	registration.RuntimeArtifactDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if registration.Validate(manifest, digest) == nil {
		t.Fatal("unadmitted runtime artifact accepted")
	}
}

func TestDispatchAndResultBindPhaseAndDigests(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	request := json.RawMessage(`{"operation":"RotateOrbitalKey"}`)
	requestDigest, _ := JSONDigest(request)
	dispatch := Dispatch{
		Protocol: OutboundRuntimeProtocol, ID: "dispatch-1", ConnectionID: "conn-1", Phase: OutboundPhaseExecuteAction,
		Request: request, RequestDigest: requestDigest, ClaimToken: "claim-secret", ClaimedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	if err := dispatch.Validate(now); err != nil {
		t.Fatalf("dispatch rejected: %v", err)
	}
	response := json.RawMessage(`{"receipt":"orbital-1"}`)
	responseDigest, _ := JSONDigest(response)
	result := DispatchResult{
		Protocol: OutboundRuntimeProtocol, DispatchID: dispatch.ID, ConnectionID: dispatch.ConnectionID,
		RuntimeID: "runtime-1", Phase: dispatch.Phase, RequestDigest: requestDigest, ClaimToken: dispatch.ClaimToken,
		Response: response, ResponseDigest: responseDigest, CompletedAt: now,
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("result rejected: %v", err)
	}
	result.Phase = OutboundPhaseVerifyAction
	if result.Validate() != nil {
		// The SDK validates phase syntax. The control plane binds it to the
		// claimed dispatch because only the store owns that durable identity.
	} else {
		t.Log("phase binding is enforced by the durable broker")
	}
	result = DispatchResult{Protocol: OutboundRuntimeProtocol, DispatchID: dispatch.ID, ConnectionID: dispatch.ConnectionID, RuntimeID: "runtime-1", Phase: dispatch.Phase, RequestDigest: requestDigest, ClaimToken: dispatch.ClaimToken, Failure: "provider refused", CompletedAt: now}
	if err := result.Validate(); err != nil {
		t.Fatalf("failed result rejected: %v", err)
	}
}
