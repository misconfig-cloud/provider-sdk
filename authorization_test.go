package provideradapter

import "testing"

func TestAuthorizationDigestBindsProviderNeutralCeiling(t *testing.T) {
	authorization := Authorization{
		ProfileDigest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PolicyRelease:    "policy-7",
		Provider:         "unfamiliar-edge",
		AccountRef:       "fabric-4",
		Environments:     []string{"production"},
		ResourcePrefixes: []string{"fabric://cluster/4/"},
		Rules: []AuthorizationRule{{
			ID: "read-nodes", Effect: "allow", Providers: []string{"unfamiliar-edge"},
			Operations: []string{"InspectNode"}, ResourcePrefixes: []string{"fabric://cluster/4/"},
		}},
	}
	digest, err := AuthorizationDigest(authorization)
	if err != nil {
		t.Fatal(err)
	}
	if digest == "" {
		t.Fatal("authorization digest is empty")
	}
	authorization.Rules[0].Operations[0] = "MutateNode"
	changed, err := AuthorizationDigest(authorization)
	if err != nil {
		t.Fatal(err)
	}
	if digest == changed {
		t.Fatal("operation widening did not change authorization identity")
	}
}

func TestAuthorizationRejectsInvalidOrDuplicateRules(t *testing.T) {
	base := Authorization{
		ProfileDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PolicyRelease: "policy-7", Provider: "unfamiliar-edge", AccountRef: "fabric-4",
		Environments: []string{"production"},
		Rules:        []AuthorizationRule{{ID: "rule-1", Effect: "allow", Operations: []string{"InspectNode"}}},
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	base.Rules = append(base.Rules, base.Rules[0])
	if err := base.Validate(); err == nil {
		t.Fatal("duplicate rule was accepted")
	}
	base.Rules = base.Rules[:1]
	base.Rules[0].Effect = "invented"
	if err := base.Validate(); err == nil {
		t.Fatal("unknown effect was accepted")
	}
}
