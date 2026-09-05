package provideradapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const ResourceDiscoveryProtocol = "misconfig.resource-discovery/v1"

// ResourceDiscovery is optional signed capability metadata, not a grant.
// Providers must implement read-only search AND exact identity revalidation.
type ResourceDiscovery struct {
	Protocol          string `json:"protocol"`
	MaximumPageSize   int    `json:"maximum_page_size"`
	MaximumAgeSeconds int    `json:"maximum_age_seconds"`
}

func (d ResourceDiscovery) Validate() error {
	if d.Protocol != ResourceDiscoveryProtocol || d.MaximumPageSize < 1 || d.MaximumPageSize > 200 || d.MaximumAgeSeconds < 1 || d.MaximumAgeSeconds > 300 {
		return errors.New("resource discovery contract is invalid")
	}
	return nil
}

// DiscoveryRequest coordinates are derived by the control plane. Configuration
// stays on the authenticated provider transport and must never enter UI receipts.
// ResourceIDs != nil selects exact revalidation, with no query or cursor.
type DiscoveryRequest struct {
	Protocol         string          `json:"protocol"`
	RequestID        string          `json:"request_id"`
	TenantID         string          `json:"tenant_id"`
	ConnectionID     string          `json:"connection_id"`
	Provider         string          `json:"provider"`
	Release          string          `json:"release"`
	ManifestDigest   string          `json:"manifest_digest"`
	AccountRef       string          `json:"account_ref"`
	CapabilityRef    string          `json:"capability_ref"`
	CapabilityDigest string          `json:"capability_digest"`
	Configuration    json.RawMessage `json:"configuration"`
	Query            string          `json:"query,omitempty"`
	Cursor           string          `json:"cursor,omitempty"`
	Limit            int             `json:"limit"`
	ResourceIDs      []string        `json:"resource_ids,omitempty"`
	Now              time.Time       `json:"now"`
}

func (r DiscoveryRequest) Validate(capability ActionCapability) error {
	if err := capability.Validate(); err != nil {
		return err
	}
	if capability.Discovery == nil {
		return errors.New("capability does not support resource discovery")
	}
	digest, err := ActionCapabilityDigest(capability)
	if err != nil || r.Protocol != ResourceDiscoveryProtocol || r.CapabilityRef != capability.Ref || r.CapabilityDigest != digest || !digestPattern.MatchString(r.ManifestDigest) || r.Now.IsZero() {
		return errors.New("discovery request identity is invalid")
	}
	for _, id := range []string{r.RequestID, r.TenantID, r.ConnectionID, r.Provider, r.Release, r.AccountRef} {
		if !discoveryText(id, 2048) {
			return errors.New("discovery coordinates are invalid")
		}
	}
	if r.Limit < 1 || r.Limit > capability.Discovery.MaximumPageSize || len(r.Configuration) > 64<<10 || !json.Valid(r.Configuration) {
		return errors.New("discovery request exceeds its bounds")
	}
	configuration, err := decodeParameterJSON(r.Configuration)
	if _, object := configuration.(map[string]any); err != nil || !object {
		return errors.New("discovery configuration must be an unambiguous object")
	}
	if r.Query != "" && !discoveryText(r.Query, 256) || r.Cursor != "" && !discoveryText(r.Cursor, 4096) {
		return errors.New("discovery query or cursor is invalid")
	}
	if r.ResourceIDs != nil {
		if r.Query != "" || r.Cursor != "" || len(r.ResourceIDs) == 0 || len(r.ResourceIDs) > r.Limit {
			return errors.New("exact resource revalidation cannot search or paginate")
		}
		if err := validDiscoveryIDs(r.ResourceIDs); err != nil {
			return err
		}
	}
	return nil
}

// DiscoveryRequestDigest binds the exact validated request, including its mode,
// freshness and private connection configuration. Retain only the digest in
// customer-safe receipts. Providers compute it from the decoded request.
func DiscoveryRequestDigest(r DiscoveryRequest, capability ActionCapability) (string, error) {
	if err := r.Validate(capability); err != nil {
		return "", err
	}
	configuration, _ := decodeParameterJSON(r.Configuration)
	r.Configuration, _ = json.Marshal(configuration)
	encoded, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

type DiscoveredResource struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  string `json:"kind"`
}

type DiscoveryPage struct {
	Protocol           string               `json:"protocol"`
	RequestDigest      string               `json:"request_digest"`
	ObservedAt         time.Time            `json:"observed_at"`
	Resources          []DiscoveredResource `json:"resources"`
	NextCursor         string               `json:"next_cursor,omitempty"`
	MissingResourceIDs []string             `json:"missing_resource_ids,omitempty"`
}

func (p DiscoveryPage) Validate(r DiscoveryRequest, capability ActionCapability, now time.Time) error {
	digest, err := DiscoveryRequestDigest(r, capability)
	if err != nil {
		return err
	}
	if p.Protocol != ResourceDiscoveryProtocol || p.RequestDigest != digest || p.Resources == nil || len(p.Resources)+len(p.MissingResourceIDs) > r.Limit {
		return errors.New("discovery response identity or bounds are invalid")
	}
	if now.IsZero() || p.ObservedAt.IsZero() || r.Now.After(now.Add(30*time.Second)) || p.ObservedAt.After(now.Add(30*time.Second)) || !p.ObservedAt.Add(time.Duration(capability.Discovery.MaximumAgeSeconds)*time.Second).After(now) || !r.Now.Add(time.Duration(capability.Discovery.MaximumAgeSeconds)*time.Second).After(now) {
		return errors.New("discovery evidence is stale or future dated")
	}
	if p.NextCursor != "" && (!discoveryText(p.NextCursor, 4096) || p.NextCursor == r.Cursor) {
		return errors.New("discovery pagination did not advance")
	}
	seen := map[string]bool{}
	for _, resource := range p.Resources {
		if !discoveryText(resource.ID, 2048) || !discoveryText(resource.Label, 256) || !discoveryText(resource.Kind, 128) || seen[resource.ID] {
			return errors.New("discovery resource identity is invalid or duplicated")
		}
		seen[resource.ID] = true
	}
	if r.ResourceIDs == nil {
		if len(p.MissingResourceIDs) != 0 {
			return errors.New("search response cannot declare missing selected resources")
		}
		return nil
	}
	if p.NextCursor != "" {
		return errors.New("exact revalidation cannot paginate")
	}
	for _, id := range p.MissingResourceIDs {
		if !discoveryText(id, 2048) || seen[id] {
			return errors.New("missing resource identity is invalid or contradictory")
		}
		seen[id] = true
	}
	if len(seen) != len(r.ResourceIDs) {
		return errors.New("exact revalidation omitted or substituted a resource")
	}
	for _, id := range r.ResourceIDs {
		if !seen[id] {
			return errors.New("exact revalidation omitted or substituted a resource")
		}
	}
	return nil
}

func validDiscoveryIDs(ids []string) error {
	seen := map[string]bool{}
	for _, id := range ids {
		if !discoveryText(id, 2048) || seen[id] {
			return errors.New("discovery resource IDs are invalid or duplicated")
		}
		seen[id] = true
	}
	return nil
}

func discoveryText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}
