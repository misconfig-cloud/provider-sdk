package provideradapter

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
)

const (
	ManifestProtocol = "misconfig.provider-adapter/v2"
	BrokerProtocol   = "misconfig.credential-broker/v2"
	RendererProtocol = "misconfig.credential-renderer/v1"
)

var (
	identityPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._/@:-]{0,127}$`)
	executablePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Publisher struct {
	ID    string `json:"id"`
	KeyID string `json:"key_id"`
}

type Compatibility struct {
	Protocol string `json:"protocol"`
	Major    int    `json:"major"`
}

type Credential struct {
	Kind                string `json:"kind"`
	MaximumTTLSeconds   int64  `json:"maximum_ttl_seconds"`
	RevocationSemantics string `json:"revocation_semantics"`
	PayloadSchema       any    `json:"payload_schema"`
}

type Renderer struct {
	Protocol             string             `json:"protocol"`
	Executable           string             `json:"executable"`
	Artifacts            []RendererArtifact `json:"artifacts"`
	SensitiveEnvironment []string           `json:"sensitive_environment,omitempty"`
}

type RendererArtifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Digest string `json:"digest"`
}

type Broker struct {
	Protocol string `json:"protocol"`
	Endpoint string `json:"endpoint"`
}

type Manifest struct {
	Protocol            string        `json:"protocol"`
	Publisher           Publisher     `json:"publisher"`
	Compatibility       Compatibility `json:"compatibility"`
	Release             string        `json:"release"`
	Provider            string        `json:"provider"`
	ConfigurationSchema any           `json:"configuration_schema"`
	Credential          Credential    `json:"credential"`
	Renderer            Renderer      `json:"renderer"`
	Broker              Broker        `json:"broker"`
}

type SignedManifest struct {
	Manifest  Manifest `json:"manifest"`
	Digest    string   `json:"digest"`
	Signature string   `json:"signature"`
}

type TrustedPublisher struct {
	ID        string
	KeyID     string
	PublicKey ed25519.PublicKey
}

func (m Manifest) Validate() error {
	if m.Protocol != ManifestProtocol || m.Compatibility.Protocol != ManifestProtocol || m.Compatibility.Major != 2 {
		return errors.New("provider adapter protocol is incompatible")
	}
	for label, value := range map[string]string{
		"publisher id": m.Publisher.ID, "publisher key id": m.Publisher.KeyID,
		"release": m.Release, "provider": m.Provider, "credential kind": m.Credential.Kind,
		"revocation semantics": m.Credential.RevocationSemantics,
	} {
		if !identityPattern.MatchString(value) {
			return fmt.Errorf("%s is invalid", label)
		}
	}
	if m.Credential.MaximumTTLSeconds <= 0 || m.Credential.MaximumTTLSeconds > 86400 {
		return errors.New("maximum credential ttl is invalid")
	}
	if m.Renderer.Protocol != RendererProtocol || !executablePattern.MatchString(m.Renderer.Executable) || len(m.Renderer.Artifacts) == 0 {
		return errors.New("renderer contract is invalid")
	}
	seenArtifacts := map[string]struct{}{}
	for _, artifact := range m.Renderer.Artifacts {
		identity := artifact.OS + "\x00" + artifact.Arch
		if !executablePattern.MatchString(artifact.OS) || !executablePattern.MatchString(artifact.Arch) || !digestPattern.MatchString(artifact.Digest) {
			return errors.New("renderer artifact contract is invalid")
		}
		if _, exists := seenArtifacts[identity]; exists {
			return errors.New("renderer artifact platform is duplicated")
		}
		seenArtifacts[identity] = struct{}{}
	}
	seenEnvironment := map[string]struct{}{}
	for _, name := range m.Renderer.SensitiveEnvironment {
		if !environmentPattern.MatchString(name) {
			return errors.New("renderer sensitive environment contract is invalid")
		}
		if _, exists := seenEnvironment[name]; exists {
			return errors.New("renderer sensitive environment contract is duplicated")
		}
		seenEnvironment[name] = struct{}{}
	}
	if m.Broker.Protocol != BrokerProtocol {
		return errors.New("broker protocol is invalid")
	}
	endpoint, err := url.Parse(m.Broker.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return errors.New("broker endpoint must be an absolute https URL without credentials, query, or fragment")
	}
	if err := validateSchema(m.ConfigurationSchema, "configuration"); err != nil {
		return err
	}
	return validateSchema(m.Credential.PayloadSchema, "credential payload")
}

func validateSchema(value any, label string) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || bytes.Equal(encoded, []byte("null")) {
		return fmt.Errorf("%s schema is invalid", label)
	}
	var object map[string]any
	if json.Unmarshal(encoded, &object) != nil || object["type"] != "object" {
		return fmt.Errorf("%s schema must be a JSON object schema", label)
	}
	return nil
}

func Canonical(manifest Manifest) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(manifest)
}

func Digest(manifest Manifest) (string, error) {
	canonical, err := Canonical(manifest)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func Sign(manifest Manifest, privateKey ed25519.PrivateKey) (SignedManifest, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedManifest{}, errors.New("ed25519 private key is invalid")
	}
	canonical, err := Canonical(manifest)
	if err != nil {
		return SignedManifest{}, err
	}
	digest := sha256.Sum256(canonical)
	return SignedManifest{
		Manifest:  manifest,
		Digest:    "sha256:" + hex.EncodeToString(digest[:]),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)),
	}, nil
}

func Verify(signed SignedManifest, trusted TrustedPublisher) error {
	if signed.Manifest.Publisher.ID != trusted.ID || signed.Manifest.Publisher.KeyID != trusted.KeyID || len(trusted.PublicKey) != ed25519.PublicKeySize {
		return errors.New("provider publisher is not trusted")
	}
	canonical, err := Canonical(signed.Manifest)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	if signed.Digest != "sha256:"+hex.EncodeToString(digest[:]) {
		return errors.New("provider manifest digest does not match")
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(trusted.PublicKey, canonical, signature) {
		return errors.New("provider manifest signature is invalid")
	}
	return nil
}
