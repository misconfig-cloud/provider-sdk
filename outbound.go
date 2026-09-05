package provideradapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	OutboundRuntimeProtocol = "misconfig.provider-runtime/v1"

	OutboundPhaseIssueCredential   = "issue_credential"
	OutboundPhaseExecuteAction     = "execute_action"
	OutboundPhaseVerifyAction      = "verify_action"
	OutboundPhaseDiscoverResources = "discover_resources"
)

// RuntimeRegistration identifies one independently running outbound adapter.
// Authentication is carried separately by the enrollment bearer token; the
// token must never appear in this payload, logs, receipts, or persisted state.
type RuntimeRegistration struct {
	Protocol              string `json:"protocol"`
	ConnectionID          string `json:"connection_id"`
	Provider              string `json:"provider"`
	Release               string `json:"release"`
	ManifestDigest        string `json:"manifest_digest"`
	RuntimeArtifactDigest string `json:"runtime_artifact_digest"`
	RuntimeID             string `json:"runtime_id"`
}

func (r RuntimeRegistration) Validate(manifest Manifest, manifestDigest string) error {
	if r.Protocol != OutboundRuntimeProtocol || manifest.Broker.TransportMode() != BrokerTransportOutboundPull ||
		r.Provider != manifest.Provider || r.Release != manifest.Release || r.ManifestDigest != manifestDigest ||
		strings.TrimSpace(r.ConnectionID) == "" || strings.TrimSpace(r.RuntimeID) == "" || !digestPattern.MatchString(r.RuntimeArtifactDigest) {
		return errors.New("outbound runtime registration identity is invalid")
	}
	for _, artifact := range manifest.Broker.RuntimeArtifacts {
		if artifact.Digest == r.RuntimeArtifactDigest {
			return nil
		}
	}
	return errors.New("outbound runtime artifact is not admitted by the signed release")
}

type DispatchClaim struct {
	Protocol     string `json:"protocol"`
	ConnectionID string `json:"connection_id"`
	RuntimeID    string `json:"runtime_id"`
}

type Dispatch struct {
	Protocol      string          `json:"protocol"`
	ID            string          `json:"id"`
	ConnectionID  string          `json:"connection_id"`
	Phase         string          `json:"phase"`
	Request       json.RawMessage `json:"request"`
	RequestDigest string          `json:"request_digest"`
	ClaimToken    string          `json:"claim_token"`
	ClaimedAt     time.Time       `json:"claimed_at"`
	ExpiresAt     time.Time       `json:"expires_at"`
}

func (d Dispatch) Validate(now time.Time) error {
	if d.Protocol != OutboundRuntimeProtocol || strings.TrimSpace(d.ID) == "" || strings.TrimSpace(d.ConnectionID) == "" ||
		strings.TrimSpace(d.ClaimToken) == "" || d.ClaimedAt.IsZero() || d.ExpiresAt.IsZero() || !d.ExpiresAt.After(now) || d.ExpiresAt.Before(d.ClaimedAt) {
		return errors.New("outbound dispatch identity or lifetime is invalid")
	}
	switch d.Phase {
	case OutboundPhaseIssueCredential, OutboundPhaseExecuteAction, OutboundPhaseVerifyAction, OutboundPhaseDiscoverResources:
	default:
		return errors.New("outbound dispatch phase is invalid")
	}
	digest, err := DispatchRequestDigest(d.Phase, d.Request)
	if err != nil || digest != d.RequestDigest {
		return errors.New("outbound dispatch request digest does not match")
	}
	return nil
}

// DispatchRequestDigest preserves legacy dispatch digests. Discovery requests
// use exact-number canonical JSON so configuration coordinates cannot collide
// through float64 rounding. Call this when creating discovery dispatches.
func DispatchRequestDigest(phase string, request json.RawMessage) (string, error) {
	if phase != OutboundPhaseDiscoverResources {
		return JSONDigest(request)
	}
	decoded, err := decodeParameterJSON(request)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

type DispatchResult struct {
	Protocol       string          `json:"protocol"`
	DispatchID     string          `json:"dispatch_id"`
	ConnectionID   string          `json:"connection_id"`
	RuntimeID      string          `json:"runtime_id"`
	Phase          string          `json:"phase"`
	RequestDigest  string          `json:"request_digest"`
	ClaimToken     string          `json:"claim_token"`
	Response       json.RawMessage `json:"response,omitempty"`
	ResponseDigest string          `json:"response_digest,omitempty"`
	Failure        string          `json:"failure,omitempty"`
	CompletedAt    time.Time       `json:"completed_at"`
}

func (r DispatchResult) Validate() error {
	if r.Protocol != OutboundRuntimeProtocol || strings.TrimSpace(r.DispatchID) == "" || strings.TrimSpace(r.ConnectionID) == "" ||
		strings.TrimSpace(r.RuntimeID) == "" || strings.TrimSpace(r.ClaimToken) == "" || !authorizationDigestPattern.MatchString(r.RequestDigest) || r.CompletedAt.IsZero() {
		return errors.New("outbound dispatch result identity is invalid")
	}
	switch r.Phase {
	case OutboundPhaseIssueCredential, OutboundPhaseExecuteAction, OutboundPhaseVerifyAction, OutboundPhaseDiscoverResources:
	default:
		return errors.New("outbound dispatch result phase is invalid")
	}
	if strings.TrimSpace(r.Failure) != "" {
		if len(r.Response) != 0 || strings.TrimSpace(r.ResponseDigest) != "" {
			return errors.New("failed outbound dispatch cannot include a response")
		}
		return nil
	}
	digest, err := JSONDigest(r.Response)
	if err != nil || digest != r.ResponseDigest {
		return errors.New("outbound dispatch response digest does not match")
	}
	return nil
}
