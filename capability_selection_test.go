package provideradapter

import (
	"encoding/json"
	"strings"
	"testing"
)

func selectedCapability(ref, digit string) CapabilitySelector {
	return CapabilitySelector{Ref: ref, Digest: "sha256:" + strings.Repeat(digit, 64)}
}

func TestCapabilitySelectionRequiresExactReferenceAndDigest(t *testing.T) {
	selected := selectedCapability("customer/change@3", "a")
	for name, actual := range map[string]CapabilitySelector{
		"missing":              {},
		"other implementation": selectedCapability("customer/change-alternate@3", "a"),
		"other version":        selectedCapability("customer/change@4", "a"),
		"other digest":         selectedCapability("customer/change@3", "b"),
		"prefix":               selectedCapability("customer/change", "a"),
		"wildcard":             selectedCapability("customer/*", "a"),
	} {
		t.Run(name, func(t *testing.T) {
			if MatchesCapabilities(actual, []CapabilitySelector{selected}) {
				t.Fatal("different or missing identity matched selected capability")
			}
		})
	}
	if !MatchesCapabilities(selected, []CapabilitySelector{selected}) {
		t.Fatal("exact identity did not match")
	}
	if !MatchesCapabilities(CapabilitySelector{}, nil) {
		t.Fatal("absent legacy selection changed meaning")
	}
}

func TestCapabilitySelectionRejectsEmptyMalformedAndAmbiguous(t *testing.T) {
	valid := selectedCapability("custom.adjust@1", "a")
	tooMany := make([]CapabilitySelector, 65)
	for _, selection := range [][]CapabilitySelector{
		{}, {{}}, {valid, valid}, {valid, selectedCapability(valid.Ref, "b")},
		{{Ref: "custom.adjust@1", Digest: "sha256:abc"}},
		{selectedCapability("custom.adjust@1 ", "a")},
		{selectedCapability("custom.adjust@1", "A")}, tooMany,
	} {
		if ValidateCapabilitySelection(selection) == nil || MatchesCapabilities(valid, selection) {
			t.Fatalf("accepted malformed or ambiguous selector: %#v", selection)
		}
	}
}

func TestCapabilityRuleIntersectsAllSelectors(t *testing.T) {
	capability := selectedCapability("customer.update@1", "a")
	rule := AuthorizationRule{ID: "r", Effect: "deny", Providers: []string{"customer"}, Operations: []string{"Update"}, ResourceIDs: []string{"target:one"}, Capabilities: []CapabilitySelector{capability}}
	for _, input := range []struct {
		provider, operation, resource string
		capability                    CapabilitySelector
		want                          bool
	}{
		{"customer", "Update", "target:one", capability, true},
		{"other", "Update", "target:one", capability, false},
		{"customer", "Delete", "target:one", capability, false},
		{"customer", "Update", "target:one-copy", capability, false},
		{"customer", "Update", "target:one", selectedCapability("customer.update-alternate@1", "a"), false},
	} {
		if MatchesAuthorizationRule(rule, input.provider, input.operation, input.resource, input.capability) != input.want {
			t.Fatalf("rule selectors did not intersect: %#v", input)
		}
	}
	// A generic deny/stop rule still matches capability-bound actions. Matching
	// an effect never turns it into an allow: decision precedence is a caller duty.
	if !MatchesAuthorizationRule(AuthorizationRule{ID: "stop", Effect: "stop_session"}, "customer", "Update", "target:one", capability) {
		t.Fatal("generic stop scope no longer applies to typed action")
	}
}

func TestCapabilityCeilingsDoNotMixSameOperationImplementations(t *testing.T) {
	one := selectedCapability("custom.threshold@1", "a")
	two := selectedCapability("custom.capacity@1", "b")
	rules := []AuthorizationRule{
		{ID: "one", Effect: "require_typed_capability", Providers: []string{"custom"}, Operations: []string{"Update"}, ResourceIDs: []string{"target:1"}, Capabilities: []CapabilitySelector{one},
			ParameterLimits: &ParameterLimits{Fields: map[string]ParameterLimit{"value": {Type: "integer", Minimum: number("70"), Maximum: number("80")}}}},
		{ID: "two", Effect: "require_typed_capability", Providers: []string{"custom"}, Operations: []string{"Update"}, ResourceIDs: []string{"target:1"}, Capabilities: []CapabilitySelector{two},
			ParameterLimits: &ParameterLimits{Fields: map[string]ParameterLimit{"value": {Type: "integer", Minimum: number("1"), Maximum: number("3")}}}},
	}
	for _, input := range []struct {
		capability CapabilitySelector
		parameters string
		want       bool
	}{{one, `{"value":75}`, true}, {one, `{"value":2}`, false}, {two, `{"value":2}`, true}, {two, `{"value":75}`, false}, {CapabilitySelector{}, `{"value":2}`, false}} {
		if got := ParametersWithinCapabilityRules(rules, "custom", "Update", "target:1", input.capability, []byte(input.parameters)); got != input.want {
			t.Fatalf("ceiling result %v for %s %s", got, input.capability.Ref, input.parameters)
		}
	}
	// An entry point without a trusted capability must fail closed on this new
	// contract, even when a generic rule elsewhere might otherwise allow it.
	if ParametersWithinRules(rules, "custom", "Update", "target:1", []byte(`{"value":2}`)) {
		t.Fatal("legacy helper dropped capability identity")
	}
	rules = append(rules, AuthorizationRule{ID: "generic-ceiling", Effect: "allow", ParameterLimits: &ParameterLimits{Fields: map[string]ParameterLimit{"value": {Type: "integer", Maximum: number("72")}}}})
	if ParametersWithinCapabilityRules(rules, "custom", "Update", "target:1", one, []byte(`{"value":75}`)) {
		t.Fatal("exact capability bypassed an applicable generic ceiling")
	}
	if !ParametersWithinCapabilityRules(rules, "custom", "Update", "target:1", one, []byte(`{"value":71}`)) {
		t.Fatal("intersected capability and generic ceilings rejected valid parameters")
	}
}

func TestCapabilityFeatureIsExplicitAndSignedIdentityCannotDropSelectors(t *testing.T) {
	legacy := `{"profile_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_release":"p","provider":"custom","account_ref":"a","environments":["test"],"rules":[{"id":"r","effect":"require_typed_capability","operations":["Update"]}]}`
	var authorization Authorization
	if err := json.Unmarshal([]byte(legacy), &authorization); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(authorization)
	if string(encoded) != legacy {
		t.Fatalf("legacy canonical bytes changed: %s", encoded)
	}
	legacyDigest, _ := AuthorizationDigest(authorization)
	authorization.Rules[0].Capabilities = []CapabilitySelector{selectedCapability("custom.update@1", "a")}
	constrainedDigest, err := AuthorizationDigest(authorization)
	if err != nil || constrainedDigest == legacyDigest {
		t.Fatal("capability selection is not identity bound", err)
	}
	if err := CheckAuthorizationSupport(authorization, []string{AuthorizationExactResourcesV1, AuthorizationParameterLimitsV1}); err == nil {
		t.Fatal("credential issuer did not explicitly opt into capability enforcement")
	}
	if err := CheckAuthorizationSupport(authorization, []string{AuthorizationCapabilityBindingsV1}); err != nil {
		t.Fatal(err)
	}
	if ValidateAuthorizationFeatures([]string{AuthorizationCapabilityBindingsV1, AuthorizationCapabilityBindingsV1}) == nil {
		t.Fatal("duplicate feature declaration accepted")
	}
	authorization.Rules[0].Capabilities[0].Digest = selectedCapability("unused", "b").Digest
	changedDigest, _ := AuthorizationDigest(authorization)
	if constrainedDigest == changedDigest {
		t.Fatal("capability substitution retained authorization digest")
	}
	authorization.Rules[0].Capabilities = nil
	downgradedDigest, _ := AuthorizationDigest(authorization)
	if downgradedDigest != legacyDigest || downgradedDigest == constrainedDigest {
		t.Fatal("stripping a new selector retained the constrained digest or changed legacy meaning")
	}
	authorization.Rules[0].Capabilities = []CapabilitySelector{}
	if _, err := AuthorizationDigest(authorization); err == nil {
		t.Fatal("empty selector serialized away as unrestricted authority")
	}
}
