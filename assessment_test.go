package provideradapter

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func assessmentCapability(effects ...ActionEffect) ActionCapability {
	c := ActionCapability{Ref: "customer.fabric.adjust@1", Operation: "Inspect",
		MaximumTTLSeconds: 120, Reversible: true,
		ParametersSchema: map[string]any{"type": "object"},
		ExecutionSchema:  map[string]any{"type": "object"}, VerificationSchema: map[string]any{"type": "object"}}
	if effects != nil {
		c.Semantics = &ActionSemantics{Protocol: ActionSemanticsProtocol, Effects: effects}
	}
	return c
}

func TestAssessmentPolicyMatrix(t *testing.T) {
	for _, tc := range []struct {
		name    string
		effects []ActionEffect
		want    [3]AssessmentRequirement
	}{
		{"missing", nil, [3]AssessmentRequirement{RequirementBlocked, RequirementResolution, RequirementResolution}},
		{"unknown", []ActionEffect{EffectUnknown}, [3]AssessmentRequirement{RequirementBlocked, RequirementResolution, RequirementResolution}},
		{"read", []ActionEffect{EffectRead}, [3]AssessmentRequirement{RequirementExistingChecks, RequirementExistingChecks, RequirementExistingChecks}},
		{"write", []ActionEffect{EffectWrite}, [3]AssessmentRequirement{RequirementBlocked, RequirementReview, RequirementDelegation}},
		{"compound", []ActionEffect{EffectRead, EffectWrite}, [3]AssessmentRequirement{RequirementBlocked, RequirementReview, RequirementDelegation}},
		{"delete", []ActionEffect{EffectRead, EffectDelete}, [3]AssessmentRequirement{RequirementBlocked, RequirementReview, RequirementReview}},
		{"access", []ActionEffect{EffectAccessChange}, [3]AssessmentRequirement{RequirementBlocked, RequirementReview, RequirementReview}},
		{"export", []ActionEffect{EffectRead, EffectDataExport}, [3]AssessmentRequirement{RequirementBlocked, RequirementReview, RequirementReview}},
		{"code", []ActionEffect{EffectCodeExecution}, [3]AssessmentRequirement{RequirementBlocked, RequirementReview, RequirementReview}},
		{"availability", []ActionEffect{EffectAvailabilityChange}, [3]AssessmentRequirement{RequirementBlocked, RequirementReview, RequirementReview}},
		{"incomplete", []ActionEffect{EffectRead, EffectWrite, EffectUnknown}, [3]AssessmentRequirement{RequirementBlocked, RequirementResolution, RequirementResolution}},
	} {
		for i, preset := range []PolicyPreset{PolicyReadOnly, PolicyReviewChanges, PolicyDelegatedChanges} {
			t.Run(tc.name+"/"+string(preset), func(t *testing.T) {
				c := assessmentCapability(tc.effects...)
				before, _ := json.Marshal(c)
				got, err := AssessCapabilityEffects(preset, c)
				digest, _ := ActionCapabilityDigest(c)
				if err != nil || got.Requirement != tc.want[i] || got.AuthorityGranted || got.CapabilityDigest != digest || got.Protocol != ActionAssessmentProtocol || got.Policy != preset || got.Reason == "" {
					t.Fatalf("invalid assessment: %+v %v", got, err)
				}
				after, _ := json.Marshal(c)
				if string(before) != string(after) {
					t.Fatal("assessment mutated the signed declaration")
				}
			})
		}
	}
}

func TestAssessmentCannotInferSafetyFromNameOrReversibility(t *testing.T) {
	for _, name := range []string{"Get", "ListResources", "ReadOnly", "SafeUpdate", "DeleteEverything"} {
		for _, reversible := range []bool{false, true} {
			c := assessmentCapability()
			c.Operation, c.Reversible = name, reversible
			r, err := AssessCapabilityEffects(PolicyDelegatedChanges, c)
			if err != nil || r.Requirement != RequirementResolution || r.AuthorityGranted {
				t.Fatalf("unclassified operation inferred safe: %+v %v", r, err)
			}
		}
	}
}

func TestAssessmentRejectsMalformedPolicyAndSemantics(t *testing.T) {
	c := assessmentCapability(EffectRead)
	for _, p := range []PolicyPreset{"", "full_access", "READ_ONLY"} {
		got, err := AssessCapabilityEffects(p, c)
		if err == nil || got.Requirement != RequirementBlocked || got.AuthorityGranted {
			t.Fatal("invalid policy did not fail closed")
		}
	}
	for _, s := range []*ActionSemantics{
		{}, {Protocol: ActionSemanticsProtocol},
		{Protocol: "future/v2", Effects: []ActionEffect{EffectRead}},
		{Protocol: ActionSemanticsProtocol, Effects: []ActionEffect{"harmless"}},
		{Protocol: ActionSemanticsProtocol, Effects: []ActionEffect{EffectRead, EffectRead}},
	} {
		c.Semantics = s
		got, err := AssessCapabilityEffects(PolicyDelegatedChanges, c)
		if err == nil || got.Requirement != RequirementBlocked || got.AuthorityGranted {
			t.Fatal("invalid semantics did not fail closed")
		}
		if c.Validate() == nil {
			t.Fatal("invalid semantics admitted into a manifest")
		}
	}
}

func TestOldActionIdentityUnchangedWithoutSemantics(t *testing.T) {
	// Pre-0099 canonical bytes, not serialized through the new type.
	const old = `{"ref":"customer.fabric.adjust@1","operation":"Inspect","maximum_ttl_seconds":120,"reversible":true,"parameters_schema":{"type":"object"},"execution_schema":{"type":"object"},"verification_schema":{"type":"object"}}`
	c := assessmentCapability()
	encoded, err := json.Marshal(c)
	if err != nil || string(encoded) != old {
		t.Fatalf("old canonical bytes changed: %s %v", encoded, err)
	}
	h := sha256.Sum256([]byte(old))
	digest, err := ActionCapabilityDigest(c)
	if err != nil || digest != "sha256:"+hex.EncodeToString(h[:]) {
		t.Fatal("old action digest changed")
	}
}

func TestSemanticsAreSignedAndCannotBeStrippedOrSubstituted(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := fixtureManifest()
	m.Actions = []ActionCapability{assessmentCapability(EffectDelete)}
	signed, err := Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	trusted := TrustedPublisher{ID: m.Publisher.ID, KeyID: m.Publisher.KeyID, PublicKey: pub}
	if err := Verify(signed, trusted); err != nil {
		t.Fatal(err)
	}
	before, _ := ActionCapabilityDigest(m.Actions[0])
	for _, semantics := range []*ActionSemantics{nil, {Protocol: ActionSemanticsProtocol, Effects: []ActionEffect{EffectRead}}} {
		tampered := signed
		tampered.Manifest.Actions = append([]ActionCapability(nil), signed.Manifest.Actions...)
		tampered.Manifest.Actions[0].Semantics = semantics
		if Verify(tampered, trusted) == nil {
			t.Fatal("semantics substitution retained authority")
		}
		after, _ := ActionCapabilityDigest(tampered.Manifest.Actions[0])
		if before == after {
			t.Fatal("semantics not bound to capability identity")
		}
	}
}

func TestAllEffectSubsetsRemainConservative(t *testing.T) {
	effects := []ActionEffect{EffectRead, EffectWrite, EffectDelete, EffectAccessChange, EffectDataExport, EffectCodeExecution, EffectAvailabilityChange, EffectUnknown}
	for mask := 1; mask < 1<<len(effects); mask++ {
		var selected []ActionEffect
		for i, effect := range effects {
			if mask&(1<<i) != 0 {
				selected = append(selected, effect)
			}
		}
		for _, preset := range []PolicyPreset{PolicyReadOnly, PolicyReviewChanges, PolicyDelegatedChanges} {
			r, err := AssessCapabilityEffects(preset, assessmentCapability(selected...))
			if err != nil || r.AuthorityGranted {
				t.Fatalf("invalid subset %d: %+v %v", mask, r, err)
			}
			if mask != 1 && r.Requirement == RequirementExistingChecks {
				t.Fatalf("non-read subset %d lost restrictions", mask)
			}
			if preset == PolicyReadOnly && mask != 1 && r.Requirement != RequirementBlocked {
				t.Fatal("read-only policy relaxed")
			}
			if mask&128 != 0 && preset != PolicyReadOnly && r.Requirement != RequirementResolution {
				t.Fatal("unknown effects were resolved by policy")
			}
			if preset == PolicyDelegatedChanges && mask&124 != 0 && mask&128 == 0 && r.Requirement != RequirementReview {
				t.Fatal("consequential work skipped review")
			}
		}
	}
}
