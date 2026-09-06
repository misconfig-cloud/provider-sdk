package provideradapter

import "errors"

const SimplePolicyProtocol = "misconfig.simple-policy/v1"

// SimplePolicy is an additional signed restriction, not a grant. Existing
// resource, parameter, identity and approval requirements remain in force.
// The initial protocol supports typed execution only; delegated execution is
// deliberately unavailable until its independent-proof path is accepted.
type SimplePolicy struct {
	Protocol string       `json:"protocol"`
	Preset   PolicyPreset `json:"preset"`
}

func (p SimplePolicy) Validate() error {
	if p.Protocol != SimplePolicyProtocol {
		return errors.New("simple policy protocol is incompatible")
	}
	switch p.Preset {
	case PolicyReadOnly, PolicyReviewChanges:
		return nil
	default:
		return errors.New("simple policy preset is not released")
	}
}

// Assess requires a capability resolved from an admitted signed release. A
// successful assessment still does not authorize or automatically approve it.
func (p SimplePolicy) Assess(capability ActionCapability) (EffectAssessment, error) {
	if err := p.Validate(); err != nil {
		return EffectAssessment{Protocol: ActionAssessmentProtocol, Policy: p.Preset,
			Requirement: RequirementBlocked, Reason: err.Error()}, err
	}
	return AssessCapabilityEffects(p.Preset, capability)
}
