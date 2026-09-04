package provideradapter

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

type fixtureBroker struct{ now time.Time }

func (f fixtureBroker) Prepare(_ context.Context, r PrepareRequest) (Connection, error) {
	return Connection{Configuration: json.RawMessage(`{"station":"` + r.AccountRef + `"}`), Onboarding: json.RawMessage(`{"step":"ready"}`)}, nil
}
func (f fixtureBroker) Verify(_ context.Context, r VerifyRequest) (Verification, error) {
	return Verification{TargetIdentity: "orbital://" + r.AccountRef, VerifiedAt: f.now}, nil
}
func (f fixtureBroker) Issue(_ context.Context, r IssueRequest) (Material, error) {
	return Material{Kind: "orbital.exec-token.v9", Payload: json.RawMessage(`{"token":"ephemeral"}`), ExpiresAt: f.now.Add(5 * time.Minute), TargetIdentity: "orbital://" + r.AccountRef, RevocationSemantics: "renewal-stops-immediately"}, nil
}

func TestHTTPProtocolAuthenticatesBindsAndRejectsReplay(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	digest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	handler := &HTTPHandler{Implementation: fixtureBroker{now: now}, SharedSecret: "fixture-secret", ManifestDigest: digest, Release: "orbital-fabric.session@3.7.1", Now: func() time.Time { return now }}
	serverHandler, err := handler.Handler()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(serverHandler)
	defer server.Close()
	client := HTTPClient{Endpoint: server.URL, SharedSecret: "fixture-secret", ManifestDigest: digest, Release: "orbital-fabric.session@3.7.1", HTTP: server.Client(), Now: func() time.Time { return now }, Nonce: func() (string, error) { return "nonce-1", nil }}
	prepared, err := client.Prepare(context.Background(), PrepareRequest{RequestID: "req-1", TenantID: "tenant-a", ConnectionID: "con-a", Provider: "orbital-fabric", Release: "orbital-fabric.session@3.7.1", AccountRef: "station-9", Name: "Station", Input: json.RawMessage(`{"station":"station-9"}`), Now: now})
	if err != nil || string(prepared.Configuration) != `{"station":"station-9"}` {
		t.Fatalf("prepare: %s %v", prepared.Configuration, err)
	}
	if _, err := client.Prepare(context.Background(), PrepareRequest{Release: "orbital-fabric.session@3.7.1"}); err == nil {
		t.Fatal("replayed nonce accepted")
	}
	client.Nonce = func() (string, error) { return "nonce-2", nil }
	client.SharedSecret = "wrong"
	if _, err := client.Verify(context.Background(), VerifyRequest{Release: "orbital-fabric.session@3.7.1"}); err == nil {
		t.Fatal("wrong transport secret accepted")
	}
}
