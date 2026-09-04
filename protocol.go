package provideradapter

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
)

var environmentPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
var authorizationDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type PrepareRequest struct {
	RequestID    string          `json:"request_id"`
	TenantID     string          `json:"tenant_id"`
	ConnectionID string          `json:"connection_id"`
	Provider     string          `json:"provider"`
	Release      string          `json:"release"`
	AccountRef   string          `json:"account_ref"`
	Name         string          `json:"name"`
	Input        json.RawMessage `json:"input"`
	Now          time.Time       `json:"now"`
}

type Connection struct {
	Configuration json.RawMessage `json:"configuration"`
	Onboarding    json.RawMessage `json:"onboarding"`
}

type VerifyRequest struct {
	RequestID     string          `json:"request_id"`
	TenantID      string          `json:"tenant_id"`
	ConnectionID  string          `json:"connection_id"`
	Provider      string          `json:"provider"`
	Release       string          `json:"release"`
	AccountRef    string          `json:"account_ref"`
	Configuration json.RawMessage `json:"configuration"`
	Now           time.Time       `json:"now"`
}

type Verification struct {
	TargetIdentity string    `json:"target_identity"`
	VerifiedAt     time.Time `json:"verified_at"`
}

type Subject struct {
	TenantID    string `json:"tenant_id"`
	ActorID     string `json:"actor_id"`
	DeviceID    string `json:"device_id"`
	SessionID   string `json:"session_id"`
	ProfileID   string `json:"profile_id"`
	AccountRef  string `json:"account_ref"`
	Environment string `json:"environment"`
}

// Authorization is the immutable provider-neutral ceiling an admitted
// credential adapter must enforce when it issues native credentials. Rules
// remain generic operation and resource matchers; an adapter either maps the
// complete ceiling to its provider or refuses issuance.
type Authorization struct {
	ProfileDigest    string              `json:"profile_digest"`
	PolicyRelease    string              `json:"policy_release"`
	Provider         string              `json:"provider"`
	AccountRef       string              `json:"account_ref"`
	Environments     []string            `json:"environments"`
	ResourcePrefixes []string            `json:"resource_prefixes,omitempty"`
	Rules            []AuthorizationRule `json:"rules"`
}

type AuthorizationRule struct {
	ID               string   `json:"id"`
	Effect           string   `json:"effect"`
	Providers        []string `json:"providers,omitempty"`
	Operations       []string `json:"operations,omitempty"`
	ResourcePrefixes []string `json:"resource_prefixes,omitempty"`
}

func (a Authorization) Validate() error {
	for label, value := range map[string]string{
		"profile digest": a.ProfileDigest, "policy release": a.PolicyRelease,
		"provider": a.Provider, "account ref": a.AccountRef,
	} {
		if strings.TrimSpace(value) == "" {
			return errors.New(label + " is required")
		}
	}
	if !authorizationDigestPattern.MatchString(a.ProfileDigest) || len(a.Environments) == 0 || len(a.Rules) == 0 {
		return errors.New("authorization identity, environments, and rules are required")
	}
	for _, value := range append(append([]string{}, a.Environments...), a.ResourcePrefixes...) {
		if strings.TrimSpace(value) == "" {
			return errors.New("authorization scope contains an empty matcher")
		}
	}
	seen := make(map[string]struct{}, len(a.Rules))
	for _, rule := range a.Rules {
		if strings.TrimSpace(rule.ID) == "" {
			return errors.New("authorization rule id is required")
		}
		if _, exists := seen[rule.ID]; exists {
			return errors.New("authorization rule is duplicated")
		}
		seen[rule.ID] = struct{}{}
		switch rule.Effect {
		case "allow", "deny", "require_approval", "require_typed_capability", "stop_session":
		default:
			return errors.New("authorization rule effect is invalid")
		}
		for _, value := range append(append(append([]string{}, rule.Providers...), rule.Operations...), rule.ResourcePrefixes...) {
			if strings.TrimSpace(value) == "" {
				return errors.New("authorization rule contains an empty matcher")
			}
		}
	}
	return nil
}

func AuthorizationDigest(authorization Authorization) (string, error) {
	if err := authorization.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(authorization)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(bytes.TrimSpace(encoded))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

type IssueRequest struct {
	RequestID           string          `json:"request_id"`
	ConnectionID        string          `json:"connection_id"`
	Provider            string          `json:"provider"`
	Release             string          `json:"release"`
	AccountRef          string          `json:"account_ref"`
	Configuration       json.RawMessage `json:"configuration"`
	Subject             Subject         `json:"subject"`
	Authorization       Authorization   `json:"authorization"`
	AuthorizationDigest string          `json:"authorization_digest"`
	Now                 time.Time       `json:"now"`
}

type Material struct {
	Kind                string          `json:"kind"`
	Payload             json.RawMessage `json:"payload"`
	ExpiresAt           time.Time       `json:"expires_at"`
	TargetIdentity      string          `json:"target_identity"`
	RevocationSemantics string          `json:"revocation_semantics"`
	AuthorizationDigest string          `json:"authorization_digest"`
}

// ConfigureRequest contains only immutable session and adapter coordinates.
// It never contains provider credential material. A renderer uses it to emit
// the provider-native environment and configuration files that cause the
// native client to call LeaseCommand when it needs short-lived material.
type ConfigureRequest struct {
	Protocol           string   `json:"protocol"`
	Release            string   `json:"release"`
	ManifestDigest     string   `json:"manifest_digest"`
	Provider           string   `json:"provider"`
	CredentialKind     string   `json:"credential_kind"`
	SessionID          string   `json:"session_id"`
	AccountRef         string   `json:"account_ref"`
	Environments       []string `json:"environments"`
	ResourcePrefixes   []string `json:"resource_prefixes,omitempty"`
	ActivePath         string   `json:"active_path"`
	RuntimeExecutable  string   `json:"runtime_executable"`
	RendererExecutable string   `json:"renderer_executable"`
	RuntimeDirectory   string   `json:"runtime_directory"`
	LeaseCommand       []string `json:"lease_command"`
}

type RenderRequest struct {
	Protocol       string          `json:"protocol"`
	Release        string          `json:"release"`
	ManifestDigest string          `json:"manifest_digest"`
	SessionID      string          `json:"session_id"`
	ActivePath     string          `json:"active_path"`
	RuntimePath    string          `json:"runtime_path"`
	Material       json.RawMessage `json:"material"`
}

// RenderedMaterial is an envelope so the runtime can validate and bound the
// renderer result before writing provider-native credential output to stdout.
type RenderedMaterial struct {
	Stdout string `json:"stdout"`
}

type RenderedEnvironment struct {
	Remove []string          `json:"remove"`
	Set    map[string]string `json:"set"`
	Files  []RenderedFile    `json:"files,omitempty"`
}

type RenderedFile struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Mode    uint32 `json:"mode"`
}

func Signature(secret, timestamp, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("\n"))
	mac.Write([]byte(nonce))
	mac.Write([]byte("\n"))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func VerifySignature(secret, timestamp, nonce, signature string, body []byte, now time.Time) error {
	parsed, err := time.Parse(time.RFC3339, timestamp)
	if err != nil || parsed.Before(now.Add(-2*time.Minute)) || parsed.After(now.Add(2*time.Minute)) {
		return errors.New("adapter request timestamp is invalid")
	}
	if strings.TrimSpace(nonce) == "" || !hmac.Equal([]byte(Signature(secret, timestamp, nonce, body)), []byte(signature)) {
		return errors.New("adapter request signature is invalid")
	}
	return nil
}
