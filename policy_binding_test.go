package provideradapter

import "testing"

func TestSimplePolicyReleasedProtocols(t *testing.T) {
	for _, p := range []SimplePolicy{
		{SimplePolicyProtocol, PolicyReadOnly}, {SimplePolicyProtocol, PolicyReviewChanges},
	} {
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []SimplePolicy{
		{}, {"next", PolicyReadOnly}, {SimplePolicyProtocol, PolicyDelegatedChanges},
		{SimplePolicyProtocol, "full_access"},
	} {
		if p.Validate() == nil {
			t.Fatalf("accepted unsupported policy: %+v", p)
		}
		assessment, err := p.Assess(ActionCapability{})
		if err == nil || assessment.AuthorityGranted || assessment.Requirement != RequirementBlocked {
			t.Fatalf("invalid policy did not fail closed: %+v, %v", assessment, err)
		}
	}
}
