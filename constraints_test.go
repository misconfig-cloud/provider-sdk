package provideradapter

import (
	"encoding/json"
	"strings"
	"testing"
)

func number(s string) *json.Number { n := json.Number(s); return &n }

func TestExactResourcesDoNotMatchPrefixesOrEmptySelection(t *testing.T) {
	for _, id := range []string{"fabric://station/7/node/a", "projects/7/targets/a", "arn:custom:resource:a"} {
		if !MatchesResources(id, nil, []string{id}) || MatchesResources(id+"-backup", nil, []string{id}) {
			t.Fatal("exact resource ceiling widened")
		}
		if MatchesResources(id, []string{id}, []string{id}) || MatchesResources(id, nil, []string{}) {
			t.Fatal("ambiguous selector accepted")
		}
		if !MatchesResources(id+"-backup", []string{id}, nil) {
			t.Fatal("legacy prefix semantics changed")
		}
	}
	for _, ids := range [][]string{{""}, {" a"}, {"a", "a"}, {"a\nb"}} {
		if ValidateResourceSelection(nil, ids) == nil {
			t.Fatalf("accepted %q", ids)
		}
	}
}

func TestParameterLimitsClosedObjectAndBoundaries(t *testing.T) {
	limits := ParameterLimits{Fields: map[string]ParameterLimit{
		"threshold": {Type: "integer", Minimum: number("70"), Maximum: number("80")},
		"enabled":   {Type: "boolean", AllowedValues: []json.RawMessage{json.RawMessage(`true`)}},
		"label":     {Type: "string", Optional: true, AllowedValues: []json.RawMessage{json.RawMessage(`"cpu"`)}},
	}}
	if err := limits.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"threshold":70,"enabled":true}`, `{"threshold":80,"enabled":true,"label":"cpu"}`, `{"enabled":true,"threshold":75.0}`, `{"threshold":8e1,"enabled":true}`} {
		if !limits.Matches([]byte(raw)) {
			t.Fatalf("rejected bounded parameters %s", raw)
		}
	}
	for _, raw := range []string{`{}`, `null`, `[]`, `{"threshold":69,"enabled":true}`, `{"threshold":81,"enabled":true}`, `{"threshold":75.1,"enabled":true}`, `{"threshold":"75","enabled":true}`, `{"threshold":75,"enabled":false}`, `{"threshold":75,"enabled":true,"delete":true}`, `{"threshold":75,"threshold":80,"enabled":true}`, `{"threshold":75,"enabled":true} {}`, `{"threshold":1e9999999,"enabled":true}`} {
		if limits.Matches([]byte(raw)) {
			t.Fatalf("accepted unbounded parameters %s", raw)
		}
	}
}

func TestCredentialFeaturesAreExplicitAndRuleCeilingsIntersect(t *testing.T) {
	for _, features := range [][]string{{"unknown"}, {AuthorizationExactResourcesV1, AuthorizationExactResourcesV1}} {
		if ValidateAuthorizationFeatures(features) == nil {
			t.Fatal("invalid feature declaration accepted")
		}
	}
	rules := []AuthorizationRule{
		{ID: "broad", Effect: "allow"},
		{ID: "narrow", Effect: "allow", Operations: []string{"Change"}, ResourceIDs: []string{"fabric://station/a"}, ParameterLimits: &ParameterLimits{Fields: map[string]ParameterLimit{"value": {Type: "number", Maximum: number("80")}}}},
	}
	if ParametersWithinRules(rules, "fabric", "Change", "fabric://station/a", []byte(`{"value":81}`)) {
		t.Fatal("broad grant bypassed ceiling")
	}
	if !ParametersWithinRules(rules, "fabric", "Read", "fabric://station/a", []byte(`{}`)) {
		t.Fatal("unrelated operation inherited ceiling")
	}
	if !ParametersWithinRules(rules, "fabric", "Change", "fabric://station/a", []byte(`{"value":80}`)) {
		t.Fatal("bounded action rejected")
	}
}

func TestParameterExactStructuredValuesAndNumericPrecision(t *testing.T) {
	limits := ParameterLimits{Fields: map[string]ParameterLimit{"body": {Type: "object", AllowedValues: []json.RawMessage{json.RawMessage(`{"a":9007199254740993,"b":[true,"yes"]}`)}}}}
	if !limits.Matches([]byte(`{"body":{"b":[true,"yes"],"a":9007199254740993}}`)) {
		t.Fatal("key order changed meaning")
	}
	for _, raw := range []string{`{"body":{"a":9007199254740992,"b":[true,"yes"]}}`, `{"body":{"a":9007199254740993,"b":[true,"yes"],"delete":true}}`, `{"body":{"a":9007199254740993,"a":9007199254740993,"b":[true,"yes"]}}`} {
		if limits.Matches([]byte(raw)) {
			t.Fatal("structured limit widened")
		}
	}
}

func TestInvalidParameterLimitsFailClosed(t *testing.T) {
	for _, limit := range []ParameterLimit{
		{Type: "unknown"}, {Type: "string", Minimum: number("1")}, {Type: "number", Minimum: number("null")},
		{Type: "integer", Minimum: number("2"), Maximum: number("1")}, {Type: "object"},
		{Type: "boolean", AllowedValues: []json.RawMessage{json.RawMessage(`1`)}},
		{Type: "number", Minimum: number("1e999999")},
	} {
		p := ParameterLimits{Fields: map[string]ParameterLimit{"value": limit}}
		if p.Validate() == nil || p.Matches([]byte(`{"value":1}`)) {
			t.Fatalf("accepted invalid limit %#v", limit)
		}
	}
	if (ParameterLimits{}).Matches([]byte(`{}`)) {
		t.Fatal("nil limits accepted")
	}
	if !(ParameterLimits{Fields: map[string]ParameterLimit{}}).Matches([]byte(`{}`)) {
		t.Fatal("explicit no-parameters contract rejected")
	}
	if _, err := decodeParameterJSON([]byte(strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18))); err == nil {
		t.Fatal("unbounded depth")
	}
}

func TestLegacyAuthorizationEncodingAndDowngrade(t *testing.T) {
	legacy := `{"profile_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_release":"p","provider":"edge","account_ref":"a","environments":["test"],"resource_prefixes":["edge://a/"],"rules":[{"id":"r","effect":"allow","operations":["Read"]}]}`
	var a Authorization
	if err := json.Unmarshal([]byte(legacy), &a); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(a)
	if string(encoded) != legacy {
		t.Fatalf("legacy bytes changed: %s", encoded)
	}
	before, _ := AuthorizationDigest(a)
	a.ResourcePrefixes = nil
	a.ResourceIDs = []string{"edge://a/1"}
	a.Rules[0].ParameterLimits = &ParameterLimits{Fields: map[string]ParameterLimit{}}
	after, err := AuthorizationDigest(a)
	if err != nil || before == after {
		t.Fatal("new constraints not identity-bound")
	}
	// A downgraded representation cannot retain the new digest.
	a.ResourceIDs = nil
	a.Rules[0].ParameterLimits = nil
	downgraded, _ := AuthorizationDigest(a)
	if after == downgraded {
		t.Fatal("constraint stripping did not change digest")
	}
}
