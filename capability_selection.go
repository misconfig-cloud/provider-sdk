package provideradapter

import (
	"errors"
	"slices"
)

// CapabilitySelector identifies one immutable implementation, not merely its
// operation or display name. The connection's pinned provider release remains
// an independent boundary. Neither reference prefixes nor digest wildcards are
// accepted. A selector is conjunctive with a rule's other matchers.
type CapabilitySelector struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

func (c CapabilitySelector) Validate() error {
	if !identityPattern.MatchString(c.Ref) || !authorizationDigestPattern.MatchString(c.Digest) {
		return errors.New("capability reference and digest must identify an exact signed implementation")
	}
	return nil
}

// ValidateCapabilitySelection preserves legacy operation-based semantics only
// when the field is absent. An explicit empty list is invalid, never wildcard.
// A reference cannot resolve to two digests in the same selection.
func ValidateCapabilitySelection(selected []CapabilitySelector) error {
	if selected != nil && (len(selected) == 0 || len(selected) > 64) {
		return errors.New("capability selection must contain between one and 64 identities")
	}
	seen := make(map[string]bool, len(selected))
	for _, capability := range selected {
		if err := capability.Validate(); err != nil {
			return err
		}
		if seen[capability.Ref] {
			return errors.New("capability reference is duplicated or ambiguous")
		}
		seen[capability.Ref] = true
	}
	return nil
}

// MatchesCapabilities does not grant authority on its own. Callers must also
// enforce provider/release, operation, resource, parameter and policy effect.
func MatchesCapabilities(actual CapabilitySelector, selected []CapabilitySelector) bool {
	if err := ValidateCapabilitySelection(selected); err != nil {
		return false
	}
	if selected == nil {
		return true
	}
	if actual.Validate() != nil {
		return false
	}
	for _, capability := range selected {
		if capability == actual {
			return true
		}
	}
	return false
}

// MatchesAuthorizationRule matches selectors only. It is not an authorization
// decision: callers must validate the complete authorization, apply deny/stop
// precedence, intersect parameter ceilings and enforce approval separately.
func MatchesAuthorizationRule(rule AuthorizationRule, provider, operation, resource string, capability CapabilitySelector) bool {
	return (len(rule.Providers) == 0 || slices.Contains(rule.Providers, provider)) &&
		(len(rule.Operations) == 0 || slices.Contains(rule.Operations, operation)) &&
		MatchesResources(resource, rule.ResourcePrefixes, rule.ResourceIDs) &&
		MatchesCapabilities(capability, rule.Capabilities)
}
