package provideradapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const maxProtocolBody = 1 << 20

type BrokerImplementation interface {
	Prepare(context.Context, PrepareRequest) (Connection, error)
	Verify(context.Context, VerifyRequest) (Verification, error)
	Issue(context.Context, IssueRequest) (Material, error)
}

type ActionImplementation interface {
	ExecuteAction(context.Context, ExecuteActionRequest) (ActionExecution, error)
	VerifyAction(context.Context, VerifyActionRequest) (ActionVerification, error)
}

type HTTPClient struct {
	Endpoint       string
	SharedSecret   string
	ManifestDigest string
	Release        string
	HTTP           *http.Client
	Now            func() time.Time
	Nonce          func() (string, error)
}

func (c HTTPClient) Prepare(ctx context.Context, request PrepareRequest) (Connection, error) {
	var response Connection
	err := c.call(ctx, "/v1/prepare", request, &response)
	return response, err
}

func (c HTTPClient) Verify(ctx context.Context, request VerifyRequest) (Verification, error) {
	var response Verification
	err := c.call(ctx, "/v1/verify", request, &response)
	return response, err
}

func (c HTTPClient) Issue(ctx context.Context, request IssueRequest) (Material, error) {
	var response Material
	err := c.call(ctx, "/v1/issue", request, &response)
	return response, err
}

func (c HTTPClient) ExecuteAction(ctx context.Context, request ExecuteActionRequest) (ActionExecution, error) {
	var response ActionExecution
	err := c.call(ctx, "/v1/actions/execute", request, &response)
	return response, err
}

func (c HTTPClient) VerifyAction(ctx context.Context, request VerifyActionRequest) (ActionVerification, error) {
	var response ActionVerification
	err := c.call(ctx, "/v1/actions/verify", request, &response)
	return response, err
}

func (c HTTPClient) call(ctx context.Context, path string, input, output any) error {
	if strings.TrimSpace(c.SharedSecret) == "" || !digestPattern.MatchString(c.ManifestDigest) || strings.TrimSpace(c.Release) == "" {
		return errors.New("external adapter client is not configured")
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	nonce := randomNonce
	if c.Nonce != nil {
		nonce = c.Nonce
	}
	nonceValue, err := nonce()
	if err != nil {
		return err
	}
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	timestamp := now().UTC().Format(time.RFC3339)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.Endpoint, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Misconfig-Adapter-Release", c.Release)
	request.Header.Set("X-Misconfig-Manifest-Digest", c.ManifestDigest)
	request.Header.Set("X-Misconfig-Timestamp", timestamp)
	request.Header.Set("X-Misconfig-Nonce", nonceValue)
	request.Header.Set("X-Misconfig-Signature", Signature(c.SharedSecret, timestamp, nonceValue, body))
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxProtocolBody+1))
	if err != nil || len(encoded) > maxProtocolBody {
		return errors.New("external adapter response is invalid")
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("external adapter returned %d", response.StatusCode)
	}
	if response.Header.Get("X-Misconfig-Manifest-Digest") != c.ManifestDigest ||
		VerifySignature(c.SharedSecret, response.Header.Get("X-Misconfig-Timestamp"), nonceValue, response.Header.Get("X-Misconfig-Signature"), encoded, now().UTC()) != nil {
		return errors.New("external adapter response authenticity failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("external adapter response schema is invalid")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return errors.New("external adapter response schema is invalid")
	}
	return nil
}

func randomNonce() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

type HTTPHandler struct {
	Implementation BrokerImplementation
	Actions        ActionImplementation
	Discovery      *DiscoveryService
	SharedSecret   string
	ManifestDigest string
	Release        string
	Now            func() time.Time
	mu             sync.Mutex
	seen           map[string]time.Time
}

func (h *HTTPHandler) Handler() (http.Handler, error) {
	if h.Implementation == nil || strings.TrimSpace(h.SharedSecret) == "" || !digestPattern.MatchString(h.ManifestDigest) || strings.TrimSpace(h.Release) == "" {
		return nil, errors.New("external adapter handler is not configured")
	}
	if h.Now == nil {
		h.Now = time.Now
	}
	if h.seen == nil {
		h.seen = map[string]time.Time{}
	}
	if h.Discovery != nil {
		if err := h.Discovery.Validate(); err != nil {
			return nil, err
		}
		if h.Discovery.ManifestDigest != h.ManifestDigest || h.Discovery.Manifest.Release != h.Release || h.Discovery.Manifest.Broker.TransportMode() != BrokerTransportInboundHTTPS {
			return nil, errors.New("discovery and HTTP release identities differ")
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/prepare", h.handlePrepare)
	mux.HandleFunc("POST /v1/verify", h.handleVerify)
	mux.HandleFunc("POST /v1/issue", h.handleIssue)
	if h.Discovery != nil {
		mux.HandleFunc("POST /v1/resources/discover", h.handleDiscoverResources)
	}
	if h.Actions != nil {
		mux.HandleFunc("POST /v1/actions/execute", h.handleExecuteAction)
		mux.HandleFunc("POST /v1/actions/verify", h.handleVerifyAction)
	}
	return mux, nil
}

func (h *HTTPHandler) handleExecuteAction(w http.ResponseWriter, r *http.Request) {
	body, nonce, ok := h.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	request, err := decodeStrict[ExecuteActionRequest](body)
	if err != nil || request.Release != h.Release || h.Actions == nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	response, err := h.Actions.ExecuteAction(r.Context(), request)
	if err != nil {
		http.Error(w, "adapter failed", http.StatusUnprocessableEntity)
		return
	}
	if err := response.Validate(); err != nil {
		http.Error(w, "adapter returned invalid execution", http.StatusBadGateway)
		return
	}
	h.respond(w, nonce, response)
}

func (h *HTTPHandler) handleVerifyAction(w http.ResponseWriter, r *http.Request) {
	body, nonce, ok := h.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	request, err := decodeStrict[VerifyActionRequest](body)
	if err != nil || request.Release != h.Release || h.Actions == nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	response, err := h.Actions.VerifyAction(r.Context(), request)
	if err != nil {
		http.Error(w, "adapter failed", http.StatusUnprocessableEntity)
		return
	}
	if err := response.Validate(); err != nil {
		http.Error(w, "adapter returned invalid verification", http.StatusBadGateway)
		return
	}
	h.respond(w, nonce, response)
}

func (h *HTTPHandler) authenticate(r *http.Request) ([]byte, string, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxProtocolBody+1))
	if err != nil || len(body) > maxProtocolBody || r.Header.Get("X-Misconfig-Adapter-Release") != h.Release || r.Header.Get("X-Misconfig-Manifest-Digest") != h.ManifestDigest {
		return nil, "", false
	}
	nonce := r.Header.Get("X-Misconfig-Nonce")
	if err := VerifySignature(h.SharedSecret, r.Header.Get("X-Misconfig-Timestamp"), nonce, r.Header.Get("X-Misconfig-Signature"), body, h.Now().UTC()); err != nil {
		return nil, "", false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := h.Now().UTC().Add(-3 * time.Minute)
	for value, timestamp := range h.seen {
		if timestamp.Before(cutoff) {
			delete(h.seen, value)
		}
	}
	if _, exists := h.seen[nonce]; exists || strings.TrimSpace(nonce) == "" {
		return nil, "", false
	}
	h.seen[nonce] = h.Now().UTC()
	return body, nonce, true
}

func decodeStrict[T any](body []byte) (T, error) {
	var value T
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return value, err
	}
	return value, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func (h *HTTPHandler) respond(w http.ResponseWriter, nonce string, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "adapter response failed", http.StatusInternalServerError)
		return
	}
	timestamp := h.Now().UTC().Format(time.RFC3339)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Misconfig-Manifest-Digest", h.ManifestDigest)
	w.Header().Set("X-Misconfig-Timestamp", timestamp)
	w.Header().Set("X-Misconfig-Signature", Signature(h.SharedSecret, timestamp, nonce, body))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (h *HTTPHandler) handlePrepare(w http.ResponseWriter, r *http.Request) {
	body, nonce, ok := h.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	request, err := decodeStrict[PrepareRequest](body)
	if err != nil || request.Release != h.Release {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	response, err := h.Implementation.Prepare(r.Context(), request)
	if err != nil {
		http.Error(w, "adapter failed", http.StatusUnprocessableEntity)
		return
	}
	h.respond(w, nonce, response)
}

func (h *HTTPHandler) handleVerify(w http.ResponseWriter, r *http.Request) {
	body, nonce, ok := h.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	request, err := decodeStrict[VerifyRequest](body)
	if err != nil || request.Release != h.Release {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	response, err := h.Implementation.Verify(r.Context(), request)
	if err != nil {
		http.Error(w, "adapter failed", http.StatusUnprocessableEntity)
		return
	}
	h.respond(w, nonce, response)
}

func (h *HTTPHandler) handleIssue(w http.ResponseWriter, r *http.Request) {
	body, nonce, ok := h.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	request, err := decodeStrict[IssueRequest](body)
	if err != nil || request.Release != h.Release {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	response, err := h.Implementation.Issue(r.Context(), request)
	if err != nil {
		http.Error(w, "adapter failed", http.StatusUnprocessableEntity)
		return
	}
	h.respond(w, nonce, response)
}
