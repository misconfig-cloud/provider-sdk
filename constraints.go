package provideradapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"slices"
	"strconv"
	"strings"
)

const (
	AuthorizationExactResourcesV1     = "exact_resources_v1"
	AuthorizationParameterLimitsV1    = "parameter_limits_v1"
	AuthorizationCapabilityBindingsV1 = "capability_bindings_v1"
)

// Authorization features are publisher assertions in a signed credential
// manifest. Merely upgrading the SDK does not opt an issuer into enforcement.
func ValidateAuthorizationFeatures(features []string) error {
	seen := map[string]bool{}
	for _, feature := range features {
		if (feature != AuthorizationExactResourcesV1 && feature != AuthorizationParameterLimitsV1 && feature != AuthorizationCapabilityBindingsV1) || seen[feature] {
			return errors.New("unsupported or duplicate credential authorization feature")
		}
		seen[feature] = true
	}
	return nil
}

// CheckAuthorizationSupport must run before issuing credentials. An issuer
// must implement every constraint it declares, including rule intersections.
func CheckAuthorizationSupport(a Authorization, features []string) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if err := ValidateAuthorizationFeatures(features); err != nil {
		return err
	}
	exact, parameters, capabilities := a.ResourceIDs != nil, false, false
	for _, rule := range a.Rules {
		exact = exact || rule.ResourceIDs != nil
		parameters = parameters || rule.ParameterLimits != nil
		capabilities = capabilities || rule.Capabilities != nil
	}
	if exact && !slices.Contains(features, AuthorizationExactResourcesV1) {
		return errors.New("credential release does not enforce exact resources")
	}
	if parameters && !slices.Contains(features, AuthorizationParameterLimitsV1) {
		return errors.New("credential release does not enforce parameter limits")
	}
	if capabilities && !slices.Contains(features, AuthorizationCapabilityBindingsV1) {
		return errors.New("credential release does not enforce capability bindings")
	}
	return nil
}

// ValidateResourceSelection forbids ambiguous mixed matchers. A supplied empty
// exact selection is invalid, not a synonym for unrestricted scope.
func ValidateResourceSelection(prefixes, ids []string) error {
	if ids != nil && (len(ids) == 0 || len(prefixes) != 0) {
		return errors.New("exact resources must be nonempty and cannot be mixed with prefixes")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if strings.TrimSpace(id) == "" || strings.TrimSpace(id) != id || strings.ContainsAny(id, "\x00\r\n") || seen[id] {
			return errors.New("exact resource identity is empty, malformed or duplicated")
		}
		seen[id] = true
	}
	return nil
}

// MatchesResources uses byte-exact equality for IDs; legacy prefix behavior is
// preserved only when no exact selector is supplied. Callers requiring bounded
// scope must additionally reject the absence of both selectors.
func MatchesResources(resource string, prefixes, ids []string) bool {
	if ValidateResourceSelection(prefixes, ids) != nil {
		return false
	}
	if ids != nil {
		return slices.Contains(ids, resource)
	}
	if len(prefixes) == 0 {
		return true
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(resource, prefix) {
			return true
		}
	}
	return false
}

// ParameterLimits is a closed, top-level parameter object. Every supplied key
// must be declared. Fields are required unless Optional is explicitly true.
// Nested structured values can be allowed only by exact JSON equality.
type ParameterLimits struct {
	Fields map[string]ParameterLimit `json:"fields"`
}

type ParameterLimit struct {
	Type          string            `json:"type"`
	Optional      bool              `json:"optional,omitempty"`
	AllowedValues []json.RawMessage `json:"allowed_values,omitempty"`
	Minimum       *json.Number      `json:"minimum,omitempty"`
	Maximum       *json.Number      `json:"maximum,omitempty"`
}

// ParametersWithinRules intersects all applicable parameter ceilings. A broad
// allow elsewhere must never bypass the limits on this operation/resource.
func ParametersWithinRules(rules []AuthorizationRule, provider, operation, resource string, parameters json.RawMessage) bool {
	// This legacy entry point has no trusted capability identity. Do not silently
	// omit a new selector, even when another operation/resource would match.
	for _, rule := range rules {
		if rule.Capabilities != nil {
			return false
		}
	}
	return ParametersWithinCapabilityRules(rules, provider, operation, resource, CapabilitySelector{}, parameters)
}

// ParametersWithinCapabilityRules intersects parameter ceilings only within
// the applicable exact capability and the remaining rule scope. Generic rules
// still apply. This checks ceilings, not allow/deny effects or approval.
func ParametersWithinCapabilityRules(rules []AuthorizationRule, provider, operation, resource string, capability CapabilitySelector, parameters json.RawMessage) bool {
	for _, rule := range rules {
		if ValidateCapabilitySelection(rule.Capabilities) != nil || (rule.Capabilities != nil && capability.Validate() != nil) {
			return false
		}
		if rule.ParameterLimits == nil || !MatchesAuthorizationRule(rule, provider, operation, resource, capability) {
			continue
		}
		if !rule.ParameterLimits.Matches(parameters) {
			return false
		}
	}
	return true
}

func (p ParameterLimits) Validate() error {
	if p.Fields == nil || len(p.Fields) > 64 {
		return errors.New("parameter fields must be an explicit bounded object")
	}
	for key, limit := range p.Fields {
		if key == "" || len(key) > 256 || len(limit.AllowedValues) > 64 {
			return errors.New("invalid parameter limit")
		}
		switch limit.Type {
		case "string", "boolean", "integer", "number", "object", "array":
		default:
			return errors.New("unsupported parameter type")
		}
		if limit.Minimum != nil || limit.Maximum != nil {
			if limit.Type != "integer" && limit.Type != "number" {
				return errors.New("numeric limits require numeric type")
			}
			for _, n := range []*json.Number{limit.Minimum, limit.Maximum} {
				if n != nil {
					value, err := decodeParameterJSON([]byte(*n))
					if err != nil || !parameterType(value, limit.Type) {
						return errors.New("invalid numeric limit")
					}
				}
			}
			if limit.Minimum != nil && limit.Maximum != nil && compareNumber(*limit.Minimum, *limit.Maximum) > 0 {
				return errors.New("parameter range is inverted")
			}
		}
		if limit.AllowedValues != nil && len(limit.AllowedValues) == 0 {
			return errors.New("empty allowed values")
		}
		if (limit.Type == "object" || limit.Type == "array") && len(limit.AllowedValues) == 0 {
			return errors.New("structured parameters require exact allowed values")
		}
		for _, raw := range limit.AllowedValues {
			value, err := decodeParameterJSON(raw)
			if err != nil || !parameterType(value, limit.Type) || !limit.inRange(value) {
				return errors.New("invalid allowed parameter value")
			}
		}
	}
	return nil
}

func (p ParameterLimits) Matches(raw json.RawMessage) bool {
	if p.Validate() != nil {
		return false
	}
	decoded, err := decodeParameterJSON(raw)
	values, ok := decoded.(map[string]any)
	if err != nil || !ok {
		return false
	}
	for key := range values {
		if _, ok := p.Fields[key]; !ok {
			return false
		}
	}
	for key, limit := range p.Fields {
		value, present := values[key]
		if !present {
			if limit.Optional {
				continue
			}
			return false
		}
		if !parameterType(value, limit.Type) || !limit.inRange(value) {
			return false
		}
		if len(limit.AllowedValues) > 0 {
			matched := false
			for _, raw := range limit.AllowedValues {
				allowed, err := decodeParameterJSON(raw)
				if err == nil && parameterEqual(value, allowed) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	return true
}

func (p ParameterLimit) inRange(value any) bool {
	n, ok := value.(json.Number)
	if !ok {
		return p.Minimum == nil && p.Maximum == nil
	}
	return (p.Minimum == nil || compareNumber(n, *p.Minimum) >= 0) && (p.Maximum == nil || compareNumber(n, *p.Maximum) <= 0)
}

func parameterType(value any, kind string) bool {
	switch kind {
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "number", "integer":
		n, ok := value.(json.Number)
		if !ok {
			return false
		}
		r, ok := new(big.Rat).SetString(string(n))
		return ok && (kind == "number" || r.IsInt())
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	}
	return false
}

func compareNumber(a, b json.Number) int {
	x, _ := new(big.Rat).SetString(string(a))
	y, _ := new(big.Rat).SetString(string(b))
	return x.Cmp(y) // validated before comparison
}

func parameterEqual(a, b any) bool {
	if x, ok := a.(json.Number); ok {
		y, ok := b.(json.Number)
		return ok && compareNumber(x, y) == 0
	}
	if x, ok := a.(map[string]any); ok {
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !parameterEqual(v, w) {
				return false
			}
		}
		return true
	}
	if x, ok := a.([]any); ok {
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !parameterEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	}
	return a == b
}

// Reject duplicate keys and pathological numeric/depth inputs rather than
// accepting differing JSON interpretations across the agent and provider.
func decodeParameterJSON(raw []byte) (any, error) {
	if len(raw) == 0 || len(raw) > 64*1024 {
		return nil, errors.New("parameter JSON exceeds bounds")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := readParameterValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing parameter JSON")
	}
	return value, nil
}

func readParameterValue(d *json.Decoder, depth int) (any, error) {
	if depth > 16 {
		return nil, errors.New("parameter JSON nesting exceeds bounds")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch v := token.(type) {
	case json.Number:
		if len(v) > 128 {
			return nil, errors.New("numeric parameter exceeds bounds")
		}
		if i := strings.IndexAny(string(v), "eE"); i >= 0 {
			exponent, err := strconv.Atoi(string(v)[i+1:])
			if err != nil || exponent < -128 || exponent > 128 {
				return nil, errors.New("numeric exponent exceeds bounds")
			}
		}
		if _, ok := new(big.Rat).SetString(string(v)); !ok {
			return nil, errors.New("invalid parameter number")
		}
	case json.Delim:
		switch v {
		case '{':
			object := map[string]any{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, err
				}
				name, ok := key.(string)
				if !ok {
					return nil, errors.New("invalid parameter key")
				}
				if _, exists := object[name]; exists {
					return nil, errors.New("duplicate parameter key")
				}
				value, err := readParameterValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				object[name] = value
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("unclosed parameter object")
			}
			return object, nil
		case '[':
			array := []any{}
			for d.More() {
				value, err := readParameterValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("unclosed parameter array")
			}
			return array, nil
		default:
			return nil, errors.New("unexpected parameter delimiter")
		}
	}
	return token, nil
}
