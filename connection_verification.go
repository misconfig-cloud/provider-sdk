package provideradapter

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const ConnectionVerificationProtocol = "misconfig.connection-verification/v1"
const connectionVerificationAge = time.Minute

// ConnectionVerificationResult proves which request the provider checked. It
// contains no credential material. TargetIdentity must come from a read-only
// provider identity check, never from the daemon's enrollment/runtime ID.
type ConnectionVerificationResult struct {
	Protocol       string    `json:"protocol"`
	RequestDigest  string    `json:"request_digest"`
	TargetIdentity string    `json:"target_identity"`
	VerifiedAt     time.Time `json:"verified_at"`
	EvidenceDigest string    `json:"evidence_digest"`
}

func VerifyConnectionRequestDigest(request VerifyRequest) (string, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	return DispatchRequestDigest(OutboundPhaseVerifyConnection, encoded)
}

func ValidateConnectionVerificationRequest(request VerifyRequest, manifest Manifest, now time.Time) error {
	if manifest.Broker.ConnectionVerification != ConnectionVerificationProtocol || request.Provider != manifest.Provider || request.Release != manifest.Release {
		return errors.New("connection verification release is not supported")
	}
	for _, value := range []string{request.RequestID, request.TenantID, request.ConnectionID, request.AccountRef} {
		if strings.TrimSpace(value) == "" {
			return errors.New("connection verification identity is incomplete")
		}
	}
	if now.IsZero() || request.Now.IsZero() || request.Now.After(now.Add(30*time.Second)) || !request.Now.Add(connectionVerificationAge).After(now) {
		return errors.New("connection verification request is stale or future dated")
	}
	if _, err := decodeParameterJSON(request.Configuration); err != nil {
		return errors.New("connection configuration is invalid")
	}
	return nil
}

func (r ConnectionVerificationResult) Validate(request VerifyRequest, now time.Time) error {
	digest, err := VerifyConnectionRequestDigest(request)
	if err != nil || r.Protocol != ConnectionVerificationProtocol || r.RequestDigest != digest || !digestPattern.MatchString(r.EvidenceDigest) || strings.TrimSpace(r.TargetIdentity) == "" || len(r.TargetIdentity) > 2048 {
		return errors.New("connection verification result does not bind the requested target")
	}
	if now.IsZero() || request.Now.IsZero() || r.VerifiedAt.IsZero() || r.VerifiedAt.Before(request.Now.Add(-30*time.Second)) || r.VerifiedAt.After(now.Add(30*time.Second)) || !request.Now.Add(connectionVerificationAge).After(now) {
		return errors.New("connection verification result is stale or future dated")
	}
	return nil
}

type ConnectionVerificationImplementation interface {
	VerifyConnection(context.Context, VerifyRequest) (ConnectionVerificationResult, error)
}

type ConnectionVerificationService struct {
	Manifest       Manifest
	ManifestDigest string
	Implementation ConnectionVerificationImplementation
}

func (s ConnectionVerificationService) VerifyConnection(ctx context.Context, request VerifyRequest, now time.Time) (ConnectionVerificationResult, error) {
	digest, err := Digest(s.Manifest)
	if err != nil || digest != s.ManifestDigest || s.Implementation == nil {
		return ConnectionVerificationResult{}, errors.New("connection verification service release is invalid")
	}
	if err := ValidateConnectionVerificationRequest(request, s.Manifest, now); err != nil {
		return ConnectionVerificationResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return ConnectionVerificationResult{}, err
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, request.Now.Add(connectionVerificationAge).Sub(now))
	defer cancel()
	result, err := s.Implementation.VerifyConnection(ctx, request)
	if err != nil {
		return ConnectionVerificationResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return ConnectionVerificationResult{}, err
	}
	if err := result.Validate(request, now.Add(time.Since(started))); err != nil {
		return ConnectionVerificationResult{}, err
	}
	return result, nil
}

func (d Dispatch) VerifyConnection(ctx context.Context, service ConnectionVerificationService, now time.Time) (ConnectionVerificationResult, error) {
	if err := d.Validate(now); err != nil {
		return ConnectionVerificationResult{}, err
	}
	if d.Phase != OutboundPhaseVerifyConnection || service.Manifest.Broker.TransportMode() != BrokerTransportOutboundPull {
		return ConnectionVerificationResult{}, errors.New("not an outbound connection verification dispatch")
	}
	request, err := decodeStrict[VerifyRequest](d.Request)
	if err != nil || request.ConnectionID != d.ConnectionID {
		return ConnectionVerificationResult{}, errors.New("connection verification dispatch identity mismatch")
	}
	ctx, cancel := context.WithTimeout(ctx, d.ExpiresAt.Sub(now))
	defer cancel()
	return service.VerifyConnection(ctx, request, now)
}
