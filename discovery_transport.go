package provideradapter

import (
	"context"
	"errors"
	"net/http"
	"time"
)

type ResourceDiscoveryImplementation interface {
	DiscoverResources(context.Context, DiscoveryRequest) (DiscoveryPage, error)
}

// DiscoveryService shares release, capability and freshness checks between
// inbound HTTP and outbound runtimes. Manifest must be the verified, immutable
// release used for enrollment; callers must not construct it from request data.
type DiscoveryService struct {
	Manifest       Manifest
	ManifestDigest string
	Implementation ResourceDiscoveryImplementation
}

func (s DiscoveryService) Validate() error {
	digest, err := Digest(s.Manifest)
	if err != nil || digest != s.ManifestDigest || s.Implementation == nil {
		return errors.New("discovery service release is invalid")
	}
	for _, capability := range s.Manifest.Actions {
		if capability.Discovery != nil {
			return nil
		}
	}
	return errors.New("release does not declare resource discovery")
}

func (r DiscoveryRequest) ValidateAt(capability ActionCapability, now time.Time) error {
	if err := r.Validate(capability); err != nil {
		return err
	}
	if now.IsZero() || r.Now.After(now.Add(30*time.Second)) || !r.Now.Add(time.Duration(capability.Discovery.MaximumAgeSeconds)*time.Second).After(now) {
		return errors.New("discovery request is stale or future dated")
	}
	return nil
}

func (s DiscoveryService) DiscoverResources(ctx context.Context, request DiscoveryRequest, now time.Time) (DiscoveryPage, error) {
	if err := ctx.Err(); err != nil {
		return DiscoveryPage{}, err
	}
	if err := s.Validate(); err != nil {
		return DiscoveryPage{}, err
	}
	if request.Provider != s.Manifest.Provider || request.Release != s.Manifest.Release || request.ManifestDigest != s.ManifestDigest {
		return DiscoveryPage{}, errors.New("discovery request does not match the enrolled release")
	}
	for _, capability := range s.Manifest.Actions {
		if capability.Ref != request.CapabilityRef {
			continue
		}
		if err := request.ValidateAt(capability, now); err != nil {
			return DiscoveryPage{}, err
		}
		started := time.Now()
		ctx, cancel := context.WithTimeout(ctx, request.Now.Add(time.Duration(capability.Discovery.MaximumAgeSeconds)*time.Second).Sub(now))
		defer cancel()
		page, err := s.Implementation.DiscoverResources(ctx, request)
		if err != nil {
			return DiscoveryPage{}, err
		}
		if err := ctx.Err(); err != nil {
			return DiscoveryPage{}, err
		}
		if err := page.Validate(request, capability, now.Add(time.Since(started))); err != nil {
			return DiscoveryPage{}, err
		}
		return page, nil
	}
	return DiscoveryPage{}, errors.New("release does not contain the requested discovery capability")
}

func (c HTTPClient) DiscoverResources(ctx context.Context, request DiscoveryRequest, capability ActionCapability) (DiscoveryPage, error) {
	now := c.Now
	if now == nil {
		now = time.Now
	}
	if request.Release != c.Release || request.ManifestDigest != c.ManifestDigest {
		return DiscoveryPage{}, errors.New("discovery client release does not match")
	}
	if err := request.ValidateAt(capability, now()); err != nil {
		return DiscoveryPage{}, err
	}
	var response DiscoveryPage
	if err := c.call(ctx, "/v1/resources/discover", request, &response); err != nil {
		return DiscoveryPage{}, err
	}
	if err := response.Validate(request, capability, now()); err != nil {
		return DiscoveryPage{}, err
	}
	return response, nil
}

func (h *HTTPHandler) handleDiscoverResources(w http.ResponseWriter, r *http.Request) {
	body, nonce, ok := h.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	request, err := decodeStrict[DiscoveryRequest](body)
	if err != nil || h.Discovery == nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	response, err := h.Discovery.DiscoverResources(r.Context(), request, h.Now().UTC())
	if err != nil {
		http.Error(w, "discovery refused", http.StatusUnprocessableEntity)
		return
	}
	h.respond(w, nonce, response)
}

// DiscoverResources rejects every non-discovery phase and validates dispatch
// binding before any provider API call. Outer enrollment/claim authentication
// remains the outbound control plane's responsibility.
func (d Dispatch) DiscoverResources(ctx context.Context, service DiscoveryService, now time.Time) (DiscoveryPage, error) {
	if err := d.Validate(now); err != nil {
		return DiscoveryPage{}, err
	}
	if d.Phase != OutboundPhaseDiscoverResources {
		return DiscoveryPage{}, errors.New("not a resource discovery dispatch")
	}
	if service.Manifest.Broker.TransportMode() != BrokerTransportOutboundPull {
		return DiscoveryPage{}, errors.New("release does not support outbound discovery")
	}
	request, err := decodeStrict[DiscoveryRequest](d.Request)
	if err != nil || request.ConnectionID != d.ConnectionID {
		return DiscoveryPage{}, errors.New("discovery dispatch connection mismatch")
	}
	ctx, cancel := context.WithTimeout(ctx, d.ExpiresAt.Sub(now))
	defer cancel()
	return service.DiscoverResources(ctx, request, now)
}
