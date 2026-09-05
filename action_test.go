package provideradapter

import (
	"encoding/json"
	"testing"
	"time"
)

func TestActionDigestIsCanonicalAndExecuteValidationRejectsSubstitution(t *testing.T) {
	capability := ActionCapability{Ref: "unfamiliar-edge.route.shift@1.0.0", Operation: "ShiftRoute", MaximumTTLSeconds: 120, Reversible: true, ParametersSchema: map[string]any{"type": "object"}, ExecutionSchema: map[string]any{"type": "object"}, VerificationSchema: map[string]any{"type": "object"}}
	capabilityDigest, err := ActionCapabilityDigest(capability)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ActionDigest(capabilityDigest, capability.Operation, "edge://fabric-1/route/main", "production", json.RawMessage(`{"weight":12,"regions":["north","south"]}`))
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := ActionDigest(capabilityDigest, capability.Operation, "edge://fabric-1/route/main", "production", json.RawMessage(`{"regions":["north","south"],"weight":12}`))
	if err != nil || reordered != digest {
		t.Fatalf("equivalent JSON changed the digest: %q %v", reordered, err)
	}
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	request := ExecuteActionRequest{
		RequestID: "request-1", ConnectionID: "connection-1", Provider: "unfamiliar-edge", Release: "unfamiliar-edge.session@1.0.0", AccountRef: "fabric-1", Configuration: json.RawMessage(`{"endpoint":"edge.invalid"}`),
		Subject:       Subject{TenantID: "tenant-1", ActorID: "actor-1", DeviceID: "device-1", SessionID: "session-1", ProfileID: "profile-1", AccountRef: "fabric-1", Environment: "production"},
		CapabilityRef: capability.Ref, CapabilityDigest: capabilityDigest, ActionID: "action-1", ActionDigest: digest, Operation: capability.Operation, Resource: "edge://fabric-1/route/main", Environment: "production", Parameters: json.RawMessage(`{"weight":12,"regions":["north","south"]}`),
		Authority: ActionAuthority{ID: "authority-1", ActionDigest: digest, CapabilityDigest: capabilityDigest, ApprovedBy: "operator-1", ApprovedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}, Now: now,
	}
	if err := request.Validate(capability); err != nil {
		t.Fatalf("valid action failed: %v", err)
	}
	request.Parameters = json.RawMessage(`{"weight":100,"regions":["north","south"]}`)
	if err := request.Validate(capability); err == nil {
		t.Fatal("parameter substitution retained approved authority")
	}
}
