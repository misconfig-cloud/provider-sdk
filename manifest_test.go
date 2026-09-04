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
		Compatibility: Compatibility{Protocol: ManifestProtocol, Major: 1},
		Release:       "orbital-fabric.session@3.7.1", Provider: "orbital-fabric",
		ConfigurationSchema: map[string]any{"type": "object", "required": []string{"station"}},
		Credential:          Credential{Kind: "orbital.exec-token.v9", MaximumTTLSeconds: 300, RevocationSemantics: "renewal-stops-immediately", PayloadSchema: map[string]any{"type": "object"}},
		Renderer:            Renderer{Protocol: RendererProtocol, Executable: "misconfig-orbital-adapter", ArtifactDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Broker:              Broker{Protocol: BrokerProtocol, Endpoint: "https://orbital.example.test"},
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
	manifest.Compatibility.Major = 2
	if _, err := Digest(manifest); err == nil {
		t.Fatal("incompatible manifest accepted")
	}
	manifest = fixtureManifest()
	manifest.Broker.Endpoint = "http://orbital.example.test?redirect=evil"
	if _, err := Digest(manifest); err == nil {
		t.Fatal("unsafe endpoint accepted")
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
