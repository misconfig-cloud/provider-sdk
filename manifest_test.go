package provideradapter

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

func fixtureManifest() Manifest {
	return Manifest{
		Protocol:      ManifestProtocol,
		Publisher:     Publisher{ID: "fixture-labs", KeyID: "fixture-2026"},
		Compatibility: Compatibility{Protocol: ManifestProtocol, Major: 2},
		Release:       "orbital-fabric.session@3.7.1", Provider: "orbital-fabric",
		ConfigurationSchema: map[string]any{"type": "object", "required": []string{"station"}},
		Credential:          &Credential{Kind: "orbital.exec-token.v9", MaximumTTLSeconds: 300, RevocationSemantics: "renewal-stops-immediately", PayloadSchema: map[string]any{"type": "object"}},
		Renderer: &Renderer{Protocol: RendererProtocol, Executable: "misconfig-orbital-adapter", Artifacts: []RendererArtifact{
			{OS: "darwin", Arch: "arm64", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			{OS: "linux", Arch: "amd64", Digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		}},
		Broker: Broker{Protocol: BrokerProtocol, Endpoint: "https://orbital.example.test"},
	}
}

func TestActionOnlyManifestIsExplicitAndValid(t *testing.T) {
	manifest := fixtureManifest()
	manifest.Credential = nil
	manifest.Renderer = nil
	manifest.Actions = []ActionCapability{{
		Ref: "unfamiliar.object.adjust@1", Operation: "AdjustObject", MaximumTTLSeconds: 120,
		ParametersSchema: map[string]any{"type": "object"}, ExecutionSchema: map[string]any{"type": "object"}, VerificationSchema: map[string]any{"type": "object"},
	}}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("action-only release rejected: %v", err)
	}
	if manifest.SupportsCredentials() {
		t.Fatal("action-only release claims credential support")
	}
	manifest.Actions = nil
	if err := manifest.Validate(); err == nil {
		t.Fatal("empty release was accepted")
	}
}

func TestCredentialAndRendererAreAtomic(t *testing.T) {
	manifest := fixtureManifest()
	manifest.Renderer = nil
	if err := manifest.Validate(); err == nil {
		t.Fatal("credential without renderer was accepted")
	}
	manifest = fixtureManifest()
	manifest.Credential = nil
	if err := manifest.Validate(); err == nil {
		t.Fatal("renderer without credential was accepted")
	}
}

func TestCredentialFeatureDeclarationIsSigned(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := fixtureManifest()
	manifest.Credential.AuthorizationFeatures = []string{AuthorizationExactResourcesV1, AuthorizationParameterLimitsV1}
	signed, err := Sign(manifest, private)
	if err != nil {
		t.Fatal(err)
	}
	trusted := TrustedPublisher{ID: manifest.Publisher.ID, KeyID: manifest.Publisher.KeyID, PublicKey: public}
	if err := Verify(signed, trusted); err != nil {
		t.Fatal(err)
	}
	signed.Manifest.Credential.AuthorizationFeatures = nil
	if Verify(signed, trusted) == nil {
		t.Fatal("stripped credential features preserved signature")
	}
}

func TestSignedManifestRejectsTamperAndUnknownPublisher(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(fixtureManifest(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	trusted := TrustedPublisher{ID: "fixture-labs", KeyID: "fixture-2026", PublicKey: publicKey}
	if err := Verify(signed, trusted); err != nil {
		t.Fatalf("verify: %v", err)
	}
	tampered := signed
	tampered.Manifest.Provider = "widened-fabric"
	if Verify(tampered, trusted) == nil {
		t.Fatal("tampered manifest accepted")
	}
	if Verify(signed, TrustedPublisher{ID: "other", KeyID: trusted.KeyID, PublicKey: publicKey}) == nil {
		t.Fatal("unknown publisher accepted")
	}
	encoded, _ := json.Marshal(signed)
	var roundTrip SignedManifest
	if err := json.Unmarshal(encoded, &roundTrip); err != nil || Verify(roundTrip, trusted) != nil {
		t.Fatal("signed manifest does not round trip")
	}
}

func TestManifestRejectsIncompatibleAndMutableEndpoint(t *testing.T) {
	manifest := fixtureManifest()
	manifest.Compatibility.Major = 1
	if _, err := Digest(manifest); err == nil {
		t.Fatal("incompatible manifest accepted")
	}
	manifest = fixtureManifest()
	manifest.Broker.Endpoint = "http://orbital.example.test?redirect=evil"
	if _, err := Digest(manifest); err == nil {
		t.Fatal("unsafe endpoint accepted")
	}
}

func TestManifestAcceptsProviderNeutralOutboundPullAndPinsRuntime(t *testing.T) {
	manifest := fixtureManifest()
	manifest.Broker = Broker{
		Protocol:  BrokerProtocol,
		Transport: BrokerTransportOutboundPull,
		RuntimeArtifacts: []RuntimeArtifact{{
			Kind:      "oci",
			Reference: "ghcr.io/fixture-labs/orbital-runtime",
			Digest:    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		}},
	}
	if _, err := Digest(manifest); err != nil {
		t.Fatalf("provider-neutral outbound runtime rejected: %v", err)
	}

	manifest.Broker.Endpoint = "https://orbital.example.test"
	if _, err := Digest(manifest); err == nil {
		t.Fatal("outbound runtime with an inbound endpoint accepted")
	}
	manifest.Broker.Endpoint = ""
	manifest.Broker.RuntimeArtifacts[0].Digest = "latest"
	if _, err := Digest(manifest); err == nil {
		t.Fatal("unpinned outbound runtime accepted")
	}
	manifest.Broker.RuntimeArtifacts[0].Digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	manifest.Broker.RuntimeArtifacts = append(manifest.Broker.RuntimeArtifacts, manifest.Broker.RuntimeArtifacts[0])
	if _, err := Digest(manifest); err == nil {
		t.Fatal("duplicate outbound runtime accepted")
	}
}

func TestLegacyInboundManifestCanonicalIdentityIsUnchanged(t *testing.T) {
	manifest := fixtureManifest()
	encoded, err := Canonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"protocol":"misconfig.provider-adapter/v2","publisher":{"id":"fixture-labs","key_id":"fixture-2026"},"compatibility":{"protocol":"misconfig.provider-adapter/v2","major":2},"release":"orbital-fabric.session@3.7.1","provider":"orbital-fabric","configuration_schema":{"required":["station"],"type":"object"},"credential":{"kind":"orbital.exec-token.v9","maximum_ttl_seconds":300,"revocation_semantics":"renewal-stops-immediately","payload_schema":{"type":"object"}},"renderer":{"protocol":"misconfig.credential-renderer/v1","executable":"misconfig-orbital-adapter","artifacts":[{"os":"darwin","arch":"arm64","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"os":"linux","arch":"amd64","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]},"broker":{"protocol":"misconfig.credential-broker/v2","endpoint":"https://orbital.example.test"}}` {
		t.Fatalf("legacy inbound canonical identity changed: %s", encoded)
	}
}

func TestManifestRejectsRendererPathAndInvalidSensitiveEnvironment(t *testing.T) {
	manifest := fixtureManifest()
	manifest.Renderer.Executable = "../untrusted/renderer"
	if _, err := Digest(manifest); err == nil {
		t.Fatal("renderer path accepted")
	}
	manifest = fixtureManifest()
	manifest.Renderer.SensitiveEnvironment = []string{"ORBITAL_TOKEN", "bad-name"}
	if _, err := Digest(manifest); err == nil {
		t.Fatal("invalid sensitive environment accepted")
	}
	manifest.Renderer.SensitiveEnvironment = []string{"ORBITAL_TOKEN", "ORBITAL_TOKEN"}
	if _, err := Digest(manifest); err == nil {
		t.Fatal("duplicate sensitive environment accepted")
	}
}

func TestManifestRequiresUniqueDigestPinnedRendererPlatforms(t *testing.T) {
	manifest := fixtureManifest()
	manifest.Renderer.Artifacts = nil
	if _, err := Digest(manifest); err == nil {
		t.Fatal("renderer without platform artifacts accepted")
	}
	manifest = fixtureManifest()
	manifest.Renderer.Artifacts[0].Digest = "latest"
	if _, err := Digest(manifest); err == nil {
		t.Fatal("unpinned renderer artifact accepted")
	}
	manifest = fixtureManifest()
	manifest.Renderer.Artifacts = append(manifest.Renderer.Artifacts, manifest.Renderer.Artifacts[0])
	if _, err := Digest(manifest); err == nil {
		t.Fatal("duplicate renderer platform accepted")
	}
	manifest = fixtureManifest()
	manifest.Renderer.Artifacts[0].OS = "darwin/../../tmp"
	if _, err := Digest(manifest); err == nil {
		t.Fatal("invalid renderer platform accepted")
	}
}

func TestManifestAcceptsProviderNeutralTypedActionAndRejectsWidening(t *testing.T) {
	manifest := fixtureManifest()
	manifest.Actions = []ActionCapability{{
		Ref: "orbital-fabric.station.throttle@1.0.0", Operation: "ThrottleStation",
		MaximumTTLSeconds: 300, Reversible: true,
		ParametersSchema:   map[string]any{"type": "object", "required": []string{"rate"}},
		ExecutionSchema:    map[string]any{"type": "object", "required": []string{"change_id"}},
		VerificationSchema: map[string]any{"type": "object", "required": []string{"observed_rate"}},
	}}
	if _, err := Digest(manifest); err != nil {
		t.Fatalf("provider-neutral action rejected: %v", err)
	}
	manifest.Actions = append(manifest.Actions, manifest.Actions[0])
	if _, err := Digest(manifest); err == nil {
		t.Fatal("duplicate action capability accepted")
	}
	manifest = fixtureManifest()
	manifest.Actions = []ActionCapability{{Ref: "orbital.action@1", Operation: "DoThing", MaximumTTLSeconds: 3600, ParametersSchema: map[string]any{"type": "object"}, ExecutionSchema: map[string]any{"type": "object"}, VerificationSchema: map[string]any{"type": "object"}}}
	if _, err := Digest(manifest); err == nil {
		t.Fatal("overlong action authority accepted")
	}
}
