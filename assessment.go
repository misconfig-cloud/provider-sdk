package provideradapter

import "errors"

const ActionSemanticsProtocol = "misconfig.action-semantics/v1"
const ActionAssessmentProtocol = "misconfig.action-assessment/v1"

// ActionEffect describes the maximum possible effect of an admitted capability.
// These are provider-neutral semantics, not a list of supported cloud commands.
type ActionEffect string

const (
	EffectRead               ActionEffect = "read"
	EffectWrite              ActionEffect = "write"
	EffectDelete             ActionEffect = "delete"
	EffectAccessChange       ActionEffect = "access_change"
	EffectDataExport         ActionEffect = "data_export"
	EffectCodeExecution      ActionEffect = "code_execution"
	EffectAvailabilityChange ActionEffect = "availability_change"
	EffectUnknown            ActionEffect = "unknown"
)

type ActionSemantics struct {
	Protocol string         `json:"protocol"`
	Effects  []ActionEffect `json:"effects"`
}

func (s ActionSemantics) Validate() error {
	if s.Protocol != ActionSemanticsProtocol || len(s.Effects) == 0 || len(s.Effects) > 8 {
		return errors.New("action semantics are missing or incompatible")
	}
	seen := map[ActionEffect]bool{}
	for _, effect := range s.Effects {
		switch effect {
		case EffectRead, EffectWrite, EffectDelete, EffectAccessChange, EffectDataExport,
			EffectCodeExecution, EffectAvailabilityChange, EffectUnknown:
		default:
			return errors.New("action effect is unsupported")
		}
		if seen[effect] {
			return errors.New("action effect is duplicated")
		}
		seen[effect] = true
	}
	return nil
}

type PolicyPreset string

const (
	PolicyReadOnly         PolicyPreset = "read_only"
	PolicyReviewChanges    PolicyPreset = "review_changes"
	PolicyDelegatedChanges PolicyPreset = "delegated_changes"
)

// AssessmentRequirement is an additional prerequisite, NEVER an execution
// decision. Even reads must pass scope, identity, freshness and deny/stop checks.
type AssessmentRequirement string

const (
	RequirementExistingChecks AssessmentRequirement = "existing_authority_checks"
	RequirementReview         AssessmentRequirement = "exact_action_review"
	RequirementDelegation     AssessmentRequirement = "exact_action_delegation"
	RequirementResolution     AssessmentRequirement = "effect_resolution"
	RequirementBlocked        AssessmentRequirement = "blocked_by_policy"
)

type EffectAssessment struct {
	Protocol         string                `json:"protocol"`
	Policy           PolicyPreset          `json:"policy"`
	CapabilityDigest string                `json:"capability_digest"`
	Requirement      AssessmentRequirement `json:"requirement"`
	Reason           string                `json:"reason"`
	AuthorityGranted bool                  `json:"authority_granted"`
}

// AssessCapabilityEffects is a pure, conservative prerequisite evaluator.
// Callers must obtain capability from a signature-verified, tenant-admitted
// immutable release, NOT from the agent's request or an MCP readOnlyHint.
// This function does not verify admission, approve, sign, issue credentials,
// parse shell, inspect live state or execute. A selected preset alone cannot
// override existing authorization. Its output must not be used as an allow bit.
func AssessCapabilityEffects(preset PolicyPreset, capability ActionCapability) (EffectAssessment, error) {
	result := EffectAssessment{Protocol: ActionAssessmentProtocol, Policy: preset,
		Requirement: RequirementBlocked, Reason: "Invalid policy or capability."}
	switch preset {
	case PolicyReadOnly, PolicyReviewChanges, PolicyDelegatedChanges:
	default:
		return result, errors.New("policy preset is unsupported")
	}
	digest, err := ActionCapabilityDigest(capability)
	if err != nil {
		return result, err
	}
	result.CapabilityDigest = digest
	unknown := capability.Semantics == nil
	changed, consequential := false, false
	if capability.Semantics != nil {
		for _, effect := range capability.Semantics.Effects {
			switch effect {
			case EffectUnknown:
				unknown = true
			case EffectWrite:
				changed = true
			case EffectDelete, EffectAccessChange, EffectDataExport, EffectCodeExecution, EffectAvailabilityChange:
				changed, consequential = true, true
			}
		}
	}
	if preset == PolicyReadOnly && (unknown || changed) {
		result.Reason = "Read-only policy does not permit changes or unclassified effects."
		return result, nil
	}
	if unknown {
		result.Requirement = RequirementResolution
		result.Reason = "Effects are not known. Resolve them through a supported capability before execution."
		return result, nil
	}
	if !changed {
		result.Requirement = RequirementExistingChecks
		result.Reason = "Declared read; existing access and data restrictions still apply."
		return result, nil
	}
	if preset == PolicyReviewChanges || consequential {
		result.Requirement = RequirementReview
		result.Reason = "Review the exact action and its impact within existing access."
		return result, nil
	}
	result.Requirement = RequirementDelegation
	result.Reason = "Existing exact-action delegation and all execution checks are required."
	return result, nil
}
