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

func JSONDigest(value json.RawMessage) (string, error) {
	var decoded any
	if len(value) == 0 || json.Unmarshal(value, &decoded) != nil {
		return "", errors.New("value is not valid JSON")
	}
	canonical, err := json.Marshal(decoded)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// ActionDigest canonically binds one typed action to the immutable capability,
// provider operation, exact resource, environment, and decoded parameters.
// Both the control plane and the provider adapter must recompute it. A caller
// cannot substitute parameters after approval while retaining the authority.
func ActionDigest(capabilityDigest, operation, resource, environment string, parameters json.RawMessage) (string, error) {
	if !authorizationDigestPattern.MatchString(capabilityDigest) || strings.TrimSpace(operation) == "" || strings.TrimSpace(resource) == "" || strings.TrimSpace(environment) == "" {
		return "", errors.New("typed action identity is incomplete")
	}
	var decoded any
	if len(parameters) == 0 || json.Unmarshal(parameters, &decoded) != nil {
		return "", errors.New("typed action parameters are invalid")
	}
	canonical, err := json.Marshal(struct {
		CapabilityDigest string `json:"capability_digest"`
		Operation        string `json:"operation"`
		Resource         string `json:"resource"`
		Environment      string `json:"environment"`
		Parameters       any    `json:"parameters"`
	}{capabilityDigest, operation, resource, environment, decoded})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

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

// ActionAuthority is the single-action authority consumed by an adapter. It
// is distinct from a credential lease: it binds one approved action digest to
// one capability release and expires quickly.
type ActionAuthority struct {
	ID               string    `json:"id"`
	ActionDigest     string    `json:"action_digest"`
	CapabilityDigest string    `json:"capability_digest"`
	ApprovedBy       string    `json:"approved_by"`
	ApprovedAt       time.Time `json:"approved_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}

func (a ActionAuthority) Validate(now time.Time, actionDigest, capabilityDigest string, maximumTTL time.Duration) error {
	if strings.TrimSpace(a.ID) == "" || strings.TrimSpace(a.ApprovedBy) == "" ||
		a.ActionDigest != actionDigest || a.CapabilityDigest != capabilityDigest ||
		!authorizationDigestPattern.MatchString(a.ActionDigest) || !authorizationDigestPattern.MatchString(a.CapabilityDigest) ||
		a.ApprovedAt.IsZero() || a.ExpiresAt.IsZero() || a.ExpiresAt.Before(a.ApprovedAt) ||
		!a.ExpiresAt.After(now) || a.ExpiresAt.After(now.Add(maximumTTL).Add(time.Second)) {
		return errors.New("action authority is invalid or expired")
	}
	return nil
}

type ExecuteActionRequest struct {
	RequestID        string          `json:"request_id"`
	ConnectionID     string          `json:"connection_id"`
	Provider         string          `json:"provider"`
	Release          string          `json:"release"`
	AccountRef       string          `json:"account_ref"`
	Configuration    json.RawMessage `json:"configuration"`
	Subject          Subject         `json:"subject"`
	CapabilityRef    string          `json:"capability_ref"`
	CapabilityDigest string          `json:"capability_digest"`
	ActionID         string          `json:"action_id"`
	ActionDigest     string          `json:"action_digest"`
	Operation        string          `json:"operation"`
	Resource         string          `json:"resource"`
	Environment      string          `json:"environment"`
	Parameters       json.RawMessage `json:"parameters"`
	Authority        ActionAuthority `json:"authority"`
	Now              time.Time       `json:"now"`
}

func (r ExecuteActionRequest) Validate(capability ActionCapability) error {
	for _, value := range []string{r.RequestID, r.ConnectionID, r.Provider, r.Release, r.AccountRef, r.Subject.TenantID, r.Subject.ActorID, r.Subject.DeviceID, r.Subject.SessionID, r.Subject.ProfileID, r.CapabilityRef, r.ActionID, r.Operation, r.Resource, r.Environment} {
		if strings.TrimSpace(value) == "" {
			return errors.New("typed action request identity is incomplete")
		}
	}
	capabilityDigest, err := ActionCapabilityDigest(capability)
	actionDigest, digestErr := ActionDigest(r.CapabilityDigest, r.Operation, r.Resource, r.Environment, r.Parameters)
	if err != nil || digestErr != nil || r.CapabilityRef != capability.Ref || r.Operation != capability.Operation || r.CapabilityDigest != capabilityDigest || r.ActionDigest != actionDigest {
		return errors.New("typed action capability binding is invalid")
	}
	if len(r.Configuration) == 0 || !json.Valid(r.Configuration) || len(r.Parameters) == 0 || !json.Valid(r.Parameters) || r.Now.IsZero() {
		return errors.New("typed action request payload is invalid")
	}
	if r.Subject.AccountRef != r.AccountRef || r.Subject.Environment != r.Environment {
		return errors.New("typed action subject is outside the requested scope")
	}
	return r.Authority.Validate(r.Now, r.ActionDigest, r.CapabilityDigest, time.Duration(capability.MaximumTTLSeconds)*time.Second)
}

// ActionExecution is a redacted provider receipt. Provider credentials and
// raw response payloads are forbidden; the adapter returns only stable
// identities and digests needed for independent verification and audit.
type ActionExecution struct {
	ProviderReceipt   string          `json:"provider_receipt"`
	ExecutionIdentity string          `json:"execution_identity"`
	ExecutedAt        time.Time       `json:"executed_at"`
	Output            json.RawMessage `json:"output"`
	OutputDigest      string          `json:"output_digest"`
}

func (e ActionExecution) Validate() error {
	if strings.TrimSpace(e.ProviderReceipt) == "" || strings.TrimSpace(e.ExecutionIdentity) == "" || e.ExecutedAt.IsZero() {
		return errors.New("action execution identity is incomplete")
	}
	digest, err := JSONDigest(e.Output)
	if err != nil || digest != e.OutputDigest {
		return errors.New("action execution output digest does not match")
	}
	return nil
}

type VerifyActionRequest struct {
	RequestID        string          `json:"request_id"`
	ConnectionID     string          `json:"connection_id"`
	Provider         string          `json:"provider"`
	Release          string          `json:"release"`
	AccountRef       string          `json:"account_ref"`
	Configuration    json.RawMessage `json:"configuration"`
	Subject          Subject         `json:"subject"`
	CapabilityRef    string          `json:"capability_ref"`
	CapabilityDigest string          `json:"capability_digest"`
	ActionID         string          `json:"action_id"`
	ActionDigest     string          `json:"action_digest"`
	Operation        string          `json:"operation"`
	Resource         string          `json:"resource"`
	Environment      string          `json:"environment"`
	Parameters       json.RawMessage `json:"parameters"`
	Execution        ActionExecution `json:"execution"`
	Now              time.Time       `json:"now"`
}

type ActionVerification struct {
	State           string          `json:"state"`
	VerifiedAt      time.Time       `json:"verified_at"`
	VerifierRelease string          `json:"verifier_release"`
	Evidence        json.RawMessage `json:"evidence"`
	EvidenceDigest  string          `json:"evidence_digest"`
}

func (r VerifyActionRequest) Validate(capability ActionCapability) error {
	for _, value := range []string{r.RequestID, r.ConnectionID, r.Provider, r.Release, r.AccountRef, r.Subject.TenantID, r.Subject.ActorID, r.Subject.DeviceID, r.Subject.SessionID, r.Subject.ProfileID, r.CapabilityRef, r.ActionID, r.Operation, r.Resource, r.Environment} {
		if strings.TrimSpace(value) == "" {
			return errors.New("typed action verification identity is incomplete")
		}
	}
	capabilityDigest, err := ActionCapabilityDigest(capability)
	actionDigest, digestErr := ActionDigest(r.CapabilityDigest, r.Operation, r.Resource, r.Environment, r.Parameters)
	if err != nil || digestErr != nil || r.CapabilityRef != capability.Ref || r.Operation != capability.Operation || r.CapabilityDigest != capabilityDigest || r.ActionDigest != actionDigest {
		return errors.New("typed action verification binding is invalid")
	}
	if len(r.Configuration) == 0 || !json.Valid(r.Configuration) || len(r.Parameters) == 0 || !json.Valid(r.Parameters) || r.Now.IsZero() || r.Subject.AccountRef != r.AccountRef || r.Subject.Environment != r.Environment || r.Execution.Validate() != nil {
		return errors.New("typed action verification payload is invalid")
	}
	return nil
}

func (v ActionVerification) Validate() error {
	if v.State != "verified" && v.State != "failed" {
		return errors.New("action verification state is invalid")
	}
	if v.VerifiedAt.IsZero() || strings.TrimSpace(v.VerifierRelease) == "" {
		return errors.New("action verification identity is incomplete")
	}
	digest, err := JSONDigest(v.Evidence)
	if err != nil || digest != v.EvidenceDigest {
		return errors.New("action verification evidence digest does not match")
	}
	return nil
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
