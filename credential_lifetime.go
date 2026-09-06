package provideradapter

import (
	"errors"
	"time"
)

const CredentialLifetimeProtocol = "misconfig.credential-lifetime/v1"

// CredentialLifetime carries the original task deadline, not a renewable TTL.
// The control plane derives it from retained policy. Native issuers must use
// the actual provider expiry and refuse a minimum TTL that cannot fit. Never
// shorten response metadata while leaving a longer-lived token underneath.
type CredentialLifetime struct {
	Protocol      string    `json:"protocol"`
	TaskExpiresAt time.Time `json:"task_expires_at"`
}

func ValidateCredentialLifetimeProtocol(protocol string) error {
	if protocol != "" && protocol != CredentialLifetimeProtocol {
		return errors.New("credential lifetime protocol is incompatible")
	}
	return nil
}

// ValidateIssueLifetime is separate from authorization: passing it does not
// prove that the native credential enforces the requested access ceiling.
func ValidateIssueLifetime(request IssueRequest, credential Credential, now time.Time) error {
	if err := ValidateCredentialLifetimeProtocol(credential.LifetimeProtocol); err != nil {
		return err
	}
	if credential.LifetimeProtocol == "" {
		if request.Lifetime != nil {
			return errors.New("issuer does not support a task deadline")
		}
		return nil // Legacy request bytes and their existing validation survive.
	}
	if request.Lifetime == nil || request.Lifetime.Protocol != CredentialLifetimeProtocol ||
		now.IsZero() || request.Now.IsZero() || request.Now.After(now.Add(30*time.Second)) ||
		!request.Now.Add(time.Minute).After(now) || !request.Lifetime.TaskExpiresAt.After(now) ||
		!request.Lifetime.TaskExpiresAt.After(request.Now) {
		return errors.New("credential task deadline is missing, invalid or expired")
	}
	return nil
}

// ValidateIssuedLifetime checks actual material at completion. It does not
// rewrite the provider expiry, and accepts equality at the task deadline.
func ValidateIssuedLifetime(request IssueRequest, credential Credential, material Material, now time.Time) error {
	if err := ValidateIssueLifetime(request, credential, now); err != nil {
		return err
	}
	if request.Now.IsZero() || now.IsZero() || credential.MaximumTTLSeconds <= 0 || credential.MaximumTTLSeconds > 86400 ||
		!material.ExpiresAt.After(now) || material.ExpiresAt.After(request.Now.Add(time.Duration(credential.MaximumTTLSeconds)*time.Second)) {
		return errors.New("issued credential lifetime exceeds its release or is no longer live")
	}
	if request.Lifetime != nil && material.ExpiresAt.After(request.Lifetime.TaskExpiresAt) {
		return errors.New("issued native credential outlives its task")
	}
	return nil
}
