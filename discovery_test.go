package provideradapter

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func discoveryFixture(t *testing.T) (ActionCapability, DiscoveryRequest, DiscoveryPage) {
	t.Helper()
	c := ActionCapability{Ref: "custom.route.adjust@1", Operation: "AdjustRoute", MaximumTTLSeconds: 120, ParametersSchema: map[string]any{"type": "object"}, ExecutionSchema: map[string]any{"type": "object"}, VerificationSchema: map[string]any{"type": "object"}, Discovery: &ResourceDiscovery{Protocol: ResourceDiscoveryProtocol, MaximumPageSize: 20, MaximumAgeSeconds: 60}}
	digest, err := ActionCapabilityDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	r := DiscoveryRequest{Protocol: ResourceDiscoveryProtocol, RequestID: "request-1", TenantID: "tenant-1", ConnectionID: "connection-1", Provider: "custom", Release: "custom@1", ManifestDigest: "sha256:" + strings.Repeat("a", 64), AccountRef: "fabric-1", CapabilityRef: c.Ref, CapabilityDigest: digest, Configuration: json.RawMessage(`{"number":9007199254740993,"scope":"fabric-1"}`), Limit: 20, Now: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}
	requestDigest, err := DiscoveryRequestDigest(r, c)
	if err != nil {
		t.Fatal(err)
	}
	p := DiscoveryPage{Protocol: ResourceDiscoveryProtocol, RequestDigest: requestDigest, ObservedAt: r.Now, Resources: []DiscoveredResource{{ID: "custom://fabric-1/main", Label: "Main route", Kind: "Route"}}}
	return c, r, p
}

func TestDiscoverySearchAndExactRevalidation(t *testing.T) {
	c, r, p := discoveryFixture(t)
	if err := p.Validate(r, c, r.Now); err != nil {
		t.Fatal(err)
	}
	p.Resources = []DiscoveredResource{}
	if err := p.Validate(r, c, r.Now); err != nil {
		t.Fatalf("empty search: %v", err)
	}
	r.ResourceIDs = []string{"custom://fabric-1/main", "custom://fabric-1/deleted"}
	p.RequestDigest, _ = DiscoveryRequestDigest(r, c)
	p.Resources = []DiscoveredResource{{ID: r.ResourceIDs[0], Label: "Main route", Kind: "Route"}}
	p.MissingResourceIDs = []string{r.ResourceIDs[1]}
	if err := p.Validate(r, c, r.Now); err != nil {
		t.Fatal(err)
	}
	p.Resources = []DiscoveredResource{}
	p.MissingResourceIDs = r.ResourceIDs
	if err := p.Validate(r, c, r.Now); err != nil {
		t.Fatalf("all removed: %v", err)
	}
}

func TestDiscoveryRejectsInvalidRequests(t *testing.T) {
	for name, mutate := range map[string]func(*DiscoveryRequest){
		"empty tenant":            func(r *DiscoveryRequest) { r.TenantID = "" },
		"wrong protocol":          func(r *DiscoveryRequest) { r.Protocol = "v0" },
		"capability substitution": func(r *DiscoveryRequest) { r.CapabilityRef = "other@1" },
		"digest substitution":     func(r *DiscoveryRequest) { r.CapabilityDigest = r.ManifestDigest },
		"empty selection":         func(r *DiscoveryRequest) { r.ResourceIDs = []string{} },
		"duplicate selection":     func(r *DiscoveryRequest) { r.ResourceIDs = []string{"x", "x"} },
		"mixed search":            func(r *DiscoveryRequest) { r.ResourceIDs = []string{"x"}; r.Query = "x" },
		"mixed cursor":            func(r *DiscoveryRequest) { r.ResourceIDs = []string{"x"}; r.Cursor = "page-2" },
		"zero limit":              func(r *DiscoveryRequest) { r.Limit = 0 },
		"excessive limit":         func(r *DiscoveryRequest) { r.Limit = 21 },
		"selection exceeds limit": func(r *DiscoveryRequest) { r.Limit = 1; r.ResourceIDs = []string{"a", "b"} },
		"control characters":      func(r *DiscoveryRequest) { r.Query = "x\ny" },
		"oversized cursor":        func(r *DiscoveryRequest) { r.Cursor = strings.Repeat("x", 4097) },
		"null config":             func(r *DiscoveryRequest) { r.Configuration = json.RawMessage(`null`) },
		"duplicate config key":    func(r *DiscoveryRequest) { r.Configuration = json.RawMessage(`{"scope":"a","scope":"b"}`) },
	} {
		t.Run(name, func(t *testing.T) {
			c, r, _ := discoveryFixture(t)
			mutate(&r)
			if r.Validate(c) == nil {
				t.Fatal("accepted invalid request")
			}
		})
	}
	c, r, _ := discoveryFixture(t)
	c.Discovery = nil
	if r.Validate(c) == nil {
		t.Fatal("legacy capability gained discovery")
	}
}

func TestDiscoveryRejectsStaleSubstitutedAndIncompleteResponses(t *testing.T) {
	for name, mutate := range map[string]func(*DiscoveryPage){
		"wrong request":  func(p *DiscoveryPage) { p.RequestDigest = "sha256:" + strings.Repeat("b", 64) },
		"wrong protocol": func(p *DiscoveryPage) { p.Protocol = "v0" },
		"null resources": func(p *DiscoveryPage) { p.Resources = nil },
		"stale":          func(p *DiscoveryPage) { p.ObservedAt = p.ObservedAt.Add(-60 * time.Second) },
		"future":         func(p *DiscoveryPage) { p.ObservedAt = p.ObservedAt.Add(31 * time.Second) },
		"duplicate":      func(p *DiscoveryPage) { p.Resources = append(p.Resources, p.Resources[0]) },
		"excessive": func(p *DiscoveryPage) {
			for i := 0; i < 21; i++ {
				p.Resources = append(p.Resources, DiscoveredResource{ID: strings.Repeat("a", i+1), Label: "Route", Kind: "route"})
			}
		},
		"empty label":       func(p *DiscoveryPage) { p.Resources[0].Label = "" },
		"missing in search": func(p *DiscoveryPage) { p.MissingResourceIDs = []string{"other"} },
	} {
		t.Run(name, func(t *testing.T) {
			c, r, p := discoveryFixture(t)
			mutate(&p)
			if p.Validate(r, c, r.Now) == nil {
				t.Fatal("accepted invalid response")
			}
		})
	}
	for _, kind := range []string{"omitted", "substituted", "contradictory", "paginated", "duplicated missing"} {
		t.Run(kind, func(t *testing.T) {
			c, r, p := discoveryFixture(t)
			r.ResourceIDs = []string{p.Resources[0].ID}
			p.RequestDigest, _ = DiscoveryRequestDigest(r, c)
			switch kind {
			case "omitted":
				p.Resources = []DiscoveredResource{}
			case "substituted":
				p.Resources[0].ID += "-other"
			case "contradictory":
				p.MissingResourceIDs = r.ResourceIDs
			case "paginated":
				p.NextCursor = "next"
			case "duplicated missing":
				p.Resources = []DiscoveredResource{}
				p.MissingResourceIDs = []string{r.ResourceIDs[0], r.ResourceIDs[0]}
			}
			if p.Validate(r, c, r.Now) == nil {
				t.Fatal("accepted invalid exact revalidation")
			}
		})
	}
	c, r, p := discoveryFixture(t)
	r.Cursor = "next"
	p.RequestDigest, _ = DiscoveryRequestDigest(r, c)
	p.NextCursor = "next"
	if p.Validate(r, c, r.Now) == nil {
		t.Fatal("cursor loop accepted")
	}
	_, r, p = discoveryFixture(t)
	if p.Validate(r, c, r.Now.Add(time.Minute)) == nil {
		t.Fatal("expired request accepted")
	}
}

func TestDiscoveryDigestBindsCoordinatesAndPreservesConfigurationPrecision(t *testing.T) {
	c, r, p := discoveryFixture(t)
	reordered := r
	reordered.Configuration = json.RawMessage(`{"scope":"fabric-1", "number":9007199254740993}`)
	digest, err := DiscoveryRequestDigest(reordered, c)
	if err != nil || digest != p.RequestDigest {
		t.Fatal("config ordering changed identity")
	}
	for name, mutate := range map[string]func(*DiscoveryRequest){
		"tenant":     func(r *DiscoveryRequest) { r.TenantID = "tenant-2" },
		"connection": func(r *DiscoveryRequest) { r.ConnectionID = "connection-2" },
		"release":    func(r *DiscoveryRequest) { r.Release = "custom@2" },
		"account":    func(r *DiscoveryRequest) { r.AccountRef = "fabric-2" },
		"configuration precision": func(r *DiscoveryRequest) {
			r.Configuration = json.RawMessage(`{"scope":"fabric-1","number":9007199254740992}`)
		},
		"query": func(r *DiscoveryRequest) { r.Query = "other" },
		"mode":  func(r *DiscoveryRequest) { r.ResourceIDs = []string{"exact"} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			mutate(&changed)
			if p.Validate(changed, c, r.Now) == nil {
				t.Fatal("substitution preserved response identity")
			}
		})
	}
}

func TestDiscoveryIsSignedAndLegacyActionBytesRemainUnchanged(t *testing.T) {
	c, _, _ := discoveryFixture(t)
	manifest := fixtureManifest()
	manifest.Actions = []ActionCapability{c}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(manifest, private)
	if err != nil {
		t.Fatal(err)
	}
	trusted := TrustedPublisher{ID: manifest.Publisher.ID, KeyID: manifest.Publisher.KeyID, PublicKey: public}
	if Verify(signed, trusted) != nil {
		t.Fatal("valid signature rejected")
	}
	signed.Manifest.Actions[0].Discovery = nil
	if Verify(signed, trusted) == nil {
		t.Fatal("stripped discovery retained signed identity")
	}
	c.Discovery = nil
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	const legacy = `{"ref":"custom.route.adjust@1","operation":"AdjustRoute","maximum_ttl_seconds":120,"reversible":false,"parameters_schema":{"type":"object"},"execution_schema":{"type":"object"},"verification_schema":{"type":"object"}}`
	if string(encoded) != legacy {
		t.Fatalf("legacy action bytes changed: %s", encoded)
	}
}
