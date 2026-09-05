package provideradapter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type connectionVerifierFunc func(context.Context, VerifyRequest) (ConnectionVerificationResult, error)

func (f connectionVerifierFunc) VerifyConnection(ctx context.Context, r VerifyRequest) (ConnectionVerificationResult, error) {
	return f(ctx, r)
}

func connectionFixture(t *testing.T) (ConnectionVerificationService, VerifyRequest, Dispatch, *int) {
	t.Helper()
	m, _ := outboundFixtureManifest()
	m.Broker.ConnectionVerification = ConnectionVerificationProtocol
	digest, err := Digest(m)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	r := VerifyRequest{RequestID: "request", TenantID: "tenant", ConnectionID: "connection", Provider: m.Provider, Release: m.Release, AccountRef: "account", Configuration: json.RawMessage(`{"target":9007199254740993}`), Now: now}
	calls := new(int)
	s := ConnectionVerificationService{Manifest: m, ManifestDigest: digest, Implementation: connectionVerifierFunc(func(ctx context.Context, r VerifyRequest) (ConnectionVerificationResult, error) {
		*calls++
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("provider has no deadline")
		}
		digest, err := VerifyConnectionRequestDigest(r)
		return ConnectionVerificationResult{Protocol: ConnectionVerificationProtocol, RequestDigest: digest, TargetIdentity: "custom://target/stable-id", VerifiedAt: now, EvidenceDigest: "sha256:" + strings.Repeat("e", 64)}, err
	})}
	encoded, _ := json.Marshal(r)
	requestDigest, _ := DispatchRequestDigest(OutboundPhaseVerifyConnection, encoded)
	d := Dispatch{Protocol: OutboundRuntimeProtocol, ID: "dispatch", ConnectionID: r.ConnectionID, Phase: OutboundPhaseVerifyConnection, Request: encoded, RequestDigest: requestDigest, ClaimToken: "test", ClaimedAt: now, ExpiresAt: now.Add(30 * time.Second)}
	return s, r, d, calls
}

func TestConnectionVerificationBindsTargetAndRequest(t *testing.T) {
	s, r, d, calls := connectionFixture(t)
	result, err := d.VerifyConnection(context.Background(), s, r.Now)
	if err != nil || result.TargetIdentity != "custom://target/stable-id" || *calls != 1 {
		t.Fatalf("verification failed: %v", err)
	}
	for _, kind := range []string{"tenant", "connection", "release", "account", "configuration", "expired-result", "future-result", "evidence"} {
		t.Run(kind, func(t *testing.T) {
			changed, response := r, result
			switch kind {
			case "tenant":
				changed.TenantID = "other"
			case "connection":
				changed.ConnectionID = "other"
			case "release":
				changed.Release = "other"
			case "account":
				changed.AccountRef = "other"
			case "configuration":
				changed.Configuration = json.RawMessage(`{"target":9007199254740992}`)
			case "expired-result":
				response.VerifiedAt = r.Now.Add(-time.Minute)
			case "future-result":
				response.VerifiedAt = r.Now.Add(time.Minute)
			case "evidence":
				response.EvidenceDigest = ""
			}
			if response.Validate(changed, r.Now) == nil {
				t.Fatal("substituted verification accepted")
			}
		})
	}
}

func TestConnectionVerificationRefusesBeforeProviderCall(t *testing.T) {
	for _, kind := range []string{"expired-dispatch", "wrong-phase", "changed-digest", "wrong-connection", "unsupported-release", "cancelled", "stale-request", "future-request", "duplicate-config", "trailing-json"} {
		t.Run(kind, func(t *testing.T) {
			s, r, d, calls := connectionFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "expired-dispatch":
				d.ExpiresAt = r.Now
			case "wrong-phase":
				d.Phase = OutboundPhaseIssueCredential
			case "changed-digest":
				d.RequestDigest = "sha256:" + strings.Repeat("f", 64)
			case "wrong-connection":
				d.ConnectionID = "other"
			case "unsupported-release":
				s.Manifest.Broker.ConnectionVerification = ""
				s.ManifestDigest, _ = Digest(s.Manifest)
			case "cancelled":
				cancel()
			case "stale-request":
				r.Now = r.Now.Add(-time.Minute)
			case "future-request":
				r.Now = r.Now.Add(time.Minute)
			case "duplicate-config":
				r.Configuration = json.RawMessage(`{"target":1,"target":2}`)
			case "trailing-json":
				d.Request = append(d.Request, []byte(` {}`)...)
			}
			if kind == "stale-request" || kind == "future-request" || kind == "duplicate-config" {
				d.Request, _ = json.Marshal(r)
				d.RequestDigest, _ = DispatchRequestDigest(d.Phase, d.Request)
			}
			if _, err := d.VerifyConnection(ctx, s, d.ClaimedAt); err == nil || *calls != 0 {
				t.Fatalf("invalid request reached provider: err=%v calls=%d", err, *calls)
			}
		})
	}
}

func TestConnectionVerificationManifestDeclarationChangesIdentity(t *testing.T) {
	m, before := outboundFixtureManifest()
	encoded, _ := Canonical(m)
	if strings.Contains(string(encoded), "connection_verification") {
		t.Fatal("legacy canonical bytes changed")
	}
	m.Broker.ConnectionVerification = ConnectionVerificationProtocol
	after, err := Digest(m)
	if err != nil || after == before {
		t.Fatal("new protocol did not change signed identity")
	}
	m.Broker.ConnectionVerification = "unsupported"
	if m.Validate() == nil {
		t.Fatal("unknown verification protocol accepted")
	}
	m = fixtureManifest()
	m.Broker.ConnectionVerification = ConnectionVerificationProtocol
	if m.Validate() == nil {
		t.Fatal("outbound exchange declared on inbound handler")
	}
}
