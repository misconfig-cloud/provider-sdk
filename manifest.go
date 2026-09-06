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
	"strings"
)

const (
	ManifestProtocol = "misconfig.provider-adapter/v2"
	BrokerProtocol   = "misconfig.credential-broker/v2"
	RendererProtocol = "misconfig.credential-renderer/v1"

	BrokerTransportInboundHTTPS = "inbound-https"
	BrokerTransportOutboundPull = "outbound-pull"
)

var (
	identityPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._/@:-]{0,127}$`)
	operationPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,127}$`)
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
	Kind                  string   `json:"kind"`
	MaximumTTLSeconds     int64    `json:"maximum_ttl_seconds"`
	RevocationSemantics   string   `json:"revocation_semantics"`
	PayloadSchema         any      `json:"payload_schema"`
	AuthorizationFeatures []string `json:"authorization_features,omitempty"`
	LifetimeProtocol      string   `json:"lifetime_protocol,omitempty"`
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
	Protocol               string            `json:"protocol"`
	Transport              string            `json:"transport,omitempty"`
	Endpoint               string            `json:"endpoint,omitempty"`
	RuntimeArtifacts       []RuntimeArtifact `json:"runtime_artifacts,omitempty"`
	ConnectionVerification string            `json:"connection_verification,omitempty"`
}

// RuntimeArtifact is an immutable, publisher-owned executable identity used
// by an outbound adapter. Kind and reference remain provider-neutral: a
// publisher may identify an OCI image, native binary, package, appliance, or
// another independently verifiable runtime. The control plane never executes
// the reference and accepts registration only for an exact signed digest.
type RuntimeArtifact struct {
	Kind      string `json:"kind"`
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
}

func (b Broker) TransportMode() string {
	if b.Transport == "" {
		return BrokerTransportInboundHTTPS
	}
	return b.Transport
}

// ActionCapability is an immutable, provider-owned typed action contract. The
// control plane treats every field as signed runtime data: it never maintains
// a provider or operation enum. Execute and verify schemas deliberately remain
// separate so an adapter cannot claim that a successful API response proves
// the requested provider state.
type ActionCapability struct {
	Ref                string             `json:"ref"`
	Operation          string             `json:"operation"`
	MaximumTTLSeconds  int64              `json:"maximum_ttl_seconds"`
	Reversible         bool               `json:"reversible"`
	ParametersSchema   any                `json:"parameters_schema"`
	ExecutionSchema    any                `json:"execution_schema"`
	VerificationSchema any                `json:"verification_schema"`
	Discovery          *ResourceDiscovery `json:"resource_discovery,omitempty"`
	// Semantics are a signed maximum-effect declaration, not permission. Old
	// releases omit this field and retain their exact original digest. Consumers
	// must treat absent semantics as unknown, never infer safety from Operation.
	Semantics *ActionSemantics `json:"semantics,omitempty"`
}

func (a ActionCapability) Validate() error {
	if a.Semantics != nil {
		if err := a.Semantics.Validate(); err != nil {
			return err
		}
	}
	if a.Discovery != nil {
		if err := a.Discovery.Validate(); err != nil {
			return err
		}
	}
	if !identityPattern.MatchString(a.Ref) || !operationPattern.MatchString(a.Operation) {
		return errors.New("action capability identity is invalid")
	}
	if a.MaximumTTLSeconds <= 0 || a.MaximumTTLSeconds > 900 {
		return errors.New("action capability authority ttl is invalid")
	}
	if err := validateSchema(a.ParametersSchema, "action parameters"); err != nil {
		return err
	}
	if err := validateSchema(a.ExecutionSchema, "action execution"); err != nil {
		return err
	}
	return validateSchema(a.VerificationSchema, "action verification")
}

func ActionCapabilityDigest(action ActionCapability) (string, error) {
	if err := action.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(action)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

type Manifest struct {
	Protocol            string             `json:"protocol"`
	Publisher           Publisher          `json:"publisher"`
	Compatibility       Compatibility      `json:"compatibility"`
	Release             string             `json:"release"`
	Provider            string             `json:"provider"`
	ConfigurationSchema any                `json:"configuration_schema"`
	Credential          *Credential        `json:"credential,omitempty"`
	Renderer            *Renderer          `json:"renderer,omitempty"`
	Broker              Broker             `json:"broker"`
	Actions             []ActionCapability `json:"actions,omitempty"`
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
		"release": m.Release, "provider": m.Provider,
	} {
		if !identityPattern.MatchString(value) {
			return fmt.Errorf("%s is invalid", label)
		}
	}
	if (m.Credential == nil) != (m.Renderer == nil) {
		return errors.New("credential and renderer contracts must be published together")
	}
	if m.Credential != nil {
		if err := ValidateCredentialLifetimeProtocol(m.Credential.LifetimeProtocol); err != nil {
			return err
		}
		if err := ValidateAuthorizationFeatures(m.Credential.AuthorizationFeatures); err != nil {
			return err
		}
		for label, value := range map[string]string{
			"credential kind":      m.Credential.Kind,
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
	}
	if m.Broker.Protocol != BrokerProtocol {
		return errors.New("broker protocol is invalid")
	}
	if m.Broker.ConnectionVerification != "" && m.Broker.ConnectionVerification != ConnectionVerificationProtocol {
		return errors.New("connection verification protocol is incompatible")
	}
	if m.Broker.ConnectionVerification != "" && m.Broker.TransportMode() != BrokerTransportOutboundPull {
		return errors.New("connection verification exchange requires outbound transport")
	}
	switch m.Broker.TransportMode() {
	case BrokerTransportInboundHTTPS:
		endpoint, err := url.Parse(m.Broker.Endpoint)
		if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return errors.New("inbound broker endpoint must be an absolute https URL without credentials, query, or fragment")
		}
		if len(m.Broker.RuntimeArtifacts) != 0 {
			return errors.New("inbound broker cannot publish outbound runtime artifacts")
		}
	case BrokerTransportOutboundPull:
		if strings.TrimSpace(m.Broker.Endpoint) != "" || len(m.Broker.RuntimeArtifacts) == 0 {
			return errors.New("outbound broker requires a signed runtime artifact and no inbound endpoint")
		}
		seenRuntimeArtifacts := make(map[string]struct{}, len(m.Broker.RuntimeArtifacts))
		for _, artifact := range m.Broker.RuntimeArtifacts {
			identity := artifact.Kind + "\x00" + artifact.Reference
			if !identityPattern.MatchString(artifact.Kind) || !runtimeReferenceValid(artifact.Reference) || !digestPattern.MatchString(artifact.Digest) {
				return errors.New("outbound runtime artifact contract is invalid")
			}
			if _, exists := seenRuntimeArtifacts[identity]; exists {
				return errors.New("outbound runtime artifact is duplicated")
			}
			seenRuntimeArtifacts[identity] = struct{}{}
		}
	default:
		return errors.New("broker transport is invalid")
	}
	if err := validateSchema(m.ConfigurationSchema, "configuration"); err != nil {
		return err
	}
	if m.Credential != nil {
		if err := validateSchema(m.Credential.PayloadSchema, "credential payload"); err != nil {
			return err
		}
	}
	seenActions := map[string]struct{}{}
	for _, action := range m.Actions {
		if err := action.Validate(); err != nil {
			return err
		}
		if _, exists := seenActions[action.Ref]; exists {
			return errors.New("action capability is duplicated")
		}
		seenActions[action.Ref] = struct{}{}
	}
	if m.Credential == nil && len(m.Actions) == 0 {
		return errors.New("provider release must publish credentials, actions, or both")
	}
	return nil
}

func (m Manifest) SupportsCredentials() bool {
	return m.Credential != nil && m.Renderer != nil
}

func runtimeReferenceValid(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 1024 {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f {
			return false
		}
	}
	return true
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
