package provideradapter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCredentialLifetimeNegotiationAndCompletion(t *testing.T) {
	now := time.Date(2026, 9, 6, 1, 0, 0, 0, time.UTC)
	c := Credential{MaximumTTLSeconds: 300, LifetimeProtocol: CredentialLifetimeProtocol}
	r := IssueRequest{Now: now, Lifetime: &CredentialLifetime{Protocol: CredentialLifetimeProtocol, TaskExpiresAt: now.Add(90 * time.Second)}}
	for _, tc := range []struct {
		name   string
		expiry time.Time
		valid  bool
	}{
		{"within", now.Add(time.Minute), true}, {"exact task boundary", now.Add(90 * time.Second), true},
		{"past task", now.Add(90*time.Second + time.Nanosecond), false}, {"expired", now, false},
		{"past release", now.Add(301 * time.Second), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateIssuedLifetime(r, c, Material{ExpiresAt: tc.expiry}, now); (err == nil) != tc.valid {
				t.Fatalf("expiry acceptance: %v", err)
			}
		})
	}
	for _, kind := range []string{"missing", "unknown", "expired", "stale", "future", "undeclared", "unsupported release"} {
		t.Run(kind, func(t *testing.T) {
			request, credential := r, c
			copy := *r.Lifetime
			request.Lifetime = &copy
			switch kind {
			case "missing":
				request.Lifetime = nil
			case "unknown":
				request.Lifetime.Protocol = "unknown"
			case "expired":
				request.Lifetime.TaskExpiresAt = now
			case "stale":
				request.Now = now.Add(-time.Minute)
			case "future":
				request.Now = now.Add(time.Minute)
			case "undeclared":
				credential.LifetimeProtocol = ""
			case "unsupported release":
				credential.LifetimeProtocol = "unknown"
			}
			if ValidateIssueLifetime(request, credential, now) == nil {
				t.Fatal("incompatible deadline accepted")
			}
		})
	}
	if ValidateIssuedLifetime(r, c, Material{ExpiresAt: now.Add(time.Second)}, now.Add(2*time.Second)) == nil {
		t.Fatal("material expired during issuance accepted")
	}
	legacy := IssueRequest{Now: now}
	c.LifetimeProtocol = ""
	if ValidateIssueLifetime(legacy, c, now) != nil {
		t.Fatal("legacy request rejected")
	}
	encoded, _ := json.Marshal(legacy)
	if strings.Contains(string(encoded), "lifetime") {
		t.Fatal("legacy request wire bytes changed")
	}
}

func TestCredentialLifetimeDeclarationIsBoundAndOptional(t *testing.T) {
	m := fixtureManifest()
	before, _ := Digest(m)
	encoded, _ := Canonical(m)
	if strings.Contains(string(encoded), "lifetime_protocol") {
		t.Fatal("legacy manifest changed")
	}
	m.Credential.LifetimeProtocol = CredentialLifetimeProtocol
	after, err := Digest(m)
	if err != nil || before == after {
		t.Fatal("deadline declaration did not bind signed identity")
	}
	m.Credential.LifetimeProtocol = "unknown"
	if m.Validate() == nil {
		t.Fatal("unknown deadline declaration accepted")
	}
}
