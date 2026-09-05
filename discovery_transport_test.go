package provideradapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type discoveryImplementationFunc func(context.Context, DiscoveryRequest) (DiscoveryPage, error)

func (f discoveryImplementationFunc) DiscoverResources(ctx context.Context, r DiscoveryRequest) (DiscoveryPage, error) {
	return f(ctx, r)
}

func transportDiscoveryFixture(t *testing.T) (DiscoveryService, DiscoveryRequest, *atomic.Int32) {
	t.Helper()
	capability, request, _ := discoveryFixture(t)
	manifest := fixtureManifest()
	manifest.Provider = request.Provider
	manifest.Release = request.Release
	manifest.Actions = []ActionCapability{capability}
	digest, err := Digest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	request.ManifestDigest = digest
	calls := new(atomic.Int32)
	implementation := discoveryImplementationFunc(func(_ context.Context, r DiscoveryRequest) (DiscoveryPage, error) {
		calls.Add(1)
		digest, err := DiscoveryRequestDigest(r, capability)
		page := DiscoveryPage{Protocol: ResourceDiscoveryProtocol, RequestDigest: digest, ObservedAt: request.Now, Resources: []DiscoveredResource{}}
		if r.ResourceIDs != nil {
			page.MissingResourceIDs = append([]string{}, r.ResourceIDs...)
		} else {
			page.Resources = append(page.Resources, DiscoveredResource{ID: "custom://fabric/main", Label: "Main", Kind: "Route"})
		}
		return page, err
	})
	return DiscoveryService{Manifest: manifest, ManifestDigest: digest, Implementation: implementation}, request, calls
}

func TestDiscoveryHTTPAuthenticatesAndRevalidates(t *testing.T) {
	s, request, calls := transportDiscoveryFixture(t)
	h := &HTTPHandler{Implementation: fixtureBroker{now: request.Now}, Discovery: &s, SharedSecret: "fixture-secret", ManifestDigest: s.ManifestDigest, Release: s.Manifest.Release, Now: func() time.Time { return request.Now }}
	handler, err := h.Handler()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := HTTPClient{Endpoint: server.URL, SharedSecret: "fixture-secret", ManifestDigest: s.ManifestDigest, Release: s.Manifest.Release, HTTP: server.Client(), Now: h.Now}
	capability := s.Manifest.Actions[0]
	page, err := client.DiscoverResources(context.Background(), request, capability)
	if err != nil || len(page.Resources) != 1 {
		t.Fatalf("search: %v", err)
	}
	request.ResourceIDs = []string{"custom://fabric/removed"}
	page, err = client.DiscoverResources(context.Background(), request, capability)
	if err != nil || len(page.MissingResourceIDs) != 1 || len(page.Resources) != 0 {
		t.Fatalf("revalidation: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatal("provider was not called twice")
	}
	client.Nonce = func() (string, error) { return "discovery-fixed-nonce", nil }
	if _, err = client.DiscoverResources(context.Background(), request, capability); err != nil {
		t.Fatal(err)
	}
	if _, err = client.DiscoverResources(context.Background(), request, capability); err == nil {
		t.Fatal("replay accepted")
	}
	client.Nonce = nil
	client.SharedSecret = "wrong"
	if _, err = client.DiscoverResources(context.Background(), request, capability); err == nil {
		t.Fatal("wrong authentication accepted")
	}
	if calls.Load() != 3 {
		t.Fatal("rejected authentication reached provider")
	}
}

func TestDiscoveryHTTPRejectsIdentityAndStalenessBeforeProvider(t *testing.T) {
	for name, mutate := range map[string]func(*DiscoveryRequest){
		"provider":           func(r *DiscoveryRequest) { r.Provider = "other" },
		"release":            func(r *DiscoveryRequest) { r.Release = "other@1" },
		"manifest":           func(r *DiscoveryRequest) { r.ManifestDigest = "sha256:" + strings.Repeat("b", 64) },
		"unknown capability": func(r *DiscoveryRequest) { r.CapabilityRef = "missing@1" },
		"stale":              func(r *DiscoveryRequest) { r.Now = r.Now.Add(-time.Minute) },
		"future":             func(r *DiscoveryRequest) { r.Now = r.Now.Add(time.Minute) },
		"empty selection":    func(r *DiscoveryRequest) { r.ResourceIDs = []string{} },
	} {
		t.Run(name, func(t *testing.T) {
			s, request, calls := transportDiscoveryFixture(t)
			now := request.Now
			handler, err := (&HTTPHandler{Implementation: fixtureBroker{now: now}, Discovery: &s, SharedSecret: "secret", ManifestDigest: s.ManifestDigest, Release: s.Manifest.Release, Now: func() time.Time { return now }}).Handler()
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(handler)
			defer server.Close()
			client := HTTPClient{Endpoint: server.URL, SharedSecret: "secret", ManifestDigest: s.ManifestDigest, Release: s.Manifest.Release, HTTP: server.Client(), Now: func() time.Time { return now }}
			mutate(&request)
			// Bypass client validation to prove the server boundary independently.
			var page DiscoveryPage
			var body any = request
			if name == "empty selection" {
				encoded, _ := json.Marshal(request)
				var object map[string]any
				_ = json.Unmarshal(encoded, &object)
				object["resource_ids"] = []string{}
				body = object
			}
			if client.call(context.Background(), "/v1/resources/discover", body, &page) == nil {
				t.Fatal("invalid request accepted")
			}
			if calls.Load() != 0 {
				t.Fatal("invalid request reached provider")
			}
		})
	}
}

func TestDiscoveryOutboundUsesSameIdentityAndBounds(t *testing.T) {
	s, request, calls := transportDiscoveryFixture(t)
	outbound, _ := outboundFixtureManifest()
	s.Manifest.Broker = outbound.Broker
	s.ManifestDigest, _ = Digest(s.Manifest)
	request.ManifestDigest = s.ManifestDigest
	encoded, _ := json.Marshal(request)
	digest, err := DispatchRequestDigest(OutboundPhaseDiscoverResources, encoded)
	if err != nil {
		t.Fatal(err)
	}
	dispatch := Dispatch{Protocol: OutboundRuntimeProtocol, ID: "dispatch-1", ConnectionID: request.ConnectionID, Phase: OutboundPhaseDiscoverResources, Request: encoded, RequestDigest: digest, ClaimToken: "claim", ClaimedAt: request.Now, ExpiresAt: request.Now.Add(30 * time.Second)}
	if _, err = dispatch.DiscoverResources(context.Background(), s, request.Now); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"connection", "phase", "digest", "expired"} {
		changed := dispatch
		switch kind {
		case "connection":
			changed.ConnectionID = "other"
		case "phase":
			changed.Phase = OutboundPhaseExecuteAction
		case "digest":
			changed.RequestDigest = "sha256:" + strings.Repeat("a", 64)
		case "expired":
			changed.ExpiresAt = request.Now
		}
		if _, err = changed.DiscoverResources(context.Background(), s, request.Now); err == nil {
			t.Fatalf("%s accepted", kind)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("invalid dispatch reached provider")
	}
	// No automatic opt-in for an old signed release.
	s.Manifest.Actions[0].Discovery = nil
	s.ManifestDigest, _ = Digest(s.Manifest)
	if _, err = dispatch.DiscoverResources(context.Background(), s, request.Now); err == nil {
		t.Fatal("undeclared discovery dispatched")
	}
}

func TestDiscoveryClientRejectsAuthenticatedWrongResponseAndOldHandler(t *testing.T) {
	s, request, _ := transportDiscoveryFixture(t)
	capability := s.Manifest.Actions[0]
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := DiscoveryPage{Protocol: ResourceDiscoveryProtocol, RequestDigest: "sha256:" + strings.Repeat("b", 64), ObservedAt: request.Now, Resources: []DiscoveredResource{}}
		body, _ := json.Marshal(page)
		timestamp := request.Now.Format(time.RFC3339)
		w.Header().Set("X-Misconfig-Manifest-Digest", s.ManifestDigest)
		w.Header().Set("X-Misconfig-Timestamp", timestamp)
		w.Header().Set("X-Misconfig-Signature", Signature("secret", timestamp, r.Header.Get("X-Misconfig-Nonce"), body))
		_, _ = w.Write(body)
	}))
	defer server.Close()
	client := HTTPClient{Endpoint: server.URL, SharedSecret: "secret", ManifestDigest: s.ManifestDigest, Release: s.Manifest.Release, HTTP: server.Client(), Now: func() time.Time { return request.Now }}
	if _, err := client.DiscoverResources(context.Background(), request, capability); err == nil {
		t.Fatal("authenticated response with wrong binding accepted")
	}
	oldHandler, err := (&HTTPHandler{Implementation: fixtureBroker{now: request.Now}, SharedSecret: "secret", ManifestDigest: s.ManifestDigest, Release: s.Manifest.Release, Now: client.Now}).Handler()
	if err != nil {
		t.Fatal(err)
	}
	oldServer := httptest.NewTLSServer(oldHandler)
	defer oldServer.Close()
	client.Endpoint = oldServer.URL
	client.HTTP = oldServer.Client()
	if _, err := client.DiscoverResources(context.Background(), request, capability); err == nil {
		t.Fatal("old handler silently accepted discovery")
	}
}

func TestDiscoveryRejectsBadProviderResponseAndLateCompletion(t *testing.T) {
	s, request, _ := transportDiscoveryFixture(t)
	s.Implementation = discoveryImplementationFunc(func(context.Context, DiscoveryRequest) (DiscoveryPage, error) {
		return DiscoveryPage{Protocol: ResourceDiscoveryProtocol, RequestDigest: "sha256:" + strings.Repeat("b", 64), ObservedAt: request.Now, Resources: []DiscoveredResource{}}, nil
	})
	if _, err := s.DiscoverResources(context.Background(), request, request.Now); err == nil {
		t.Fatal("bad provider response accepted")
	}
	s.Implementation = discoveryImplementationFunc(func(ctx context.Context, _ DiscoveryRequest) (DiscoveryPage, error) {
		<-ctx.Done()
		return DiscoveryPage{}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if _, err := s.DiscoverResources(ctx, request, request.Now); err != context.DeadlineExceeded {
		t.Fatalf("late completion: %v", err)
	}
}

func TestDiscoveryDispatchDigestPreservesPrecisionAndLegacyDigests(t *testing.T) {
	a := json.RawMessage(`{"coordinate":9007199254740993}`)
	b := json.RawMessage(`{"coordinate":9007199254740992}`)
	x, _ := DispatchRequestDigest(OutboundPhaseDiscoverResources, a)
	y, _ := DispatchRequestDigest(OutboundPhaseDiscoverResources, b)
	if x == y {
		t.Fatal("discovery coordinates collided")
	}
	x, _ = DispatchRequestDigest(OutboundPhaseExecuteAction, a)
	y, _ = JSONDigest(a)
	if x != y {
		t.Fatal("legacy dispatch identity changed")
	}
	if _, err := DispatchRequestDigest(OutboundPhaseDiscoverResources, json.RawMessage(`{"x":1,"x":2}`)); err == nil {
		t.Fatal("duplicate keys accepted")
	}
}
