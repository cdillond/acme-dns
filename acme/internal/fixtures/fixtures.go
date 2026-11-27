// Package fixtures provides a small fake ACME server for tests in this module.
// It deliberately has no dependency on the acme package, so it can be used
// from both white-box and black-box tests without an import cycle.
package fixtures

import (
	"encoding/base64"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// DefaultNonce is the Replay-Nonce returned by the fake newNonce endpoint.
const DefaultNonce = "test-nonce-1"

// Response is a canned HTTP response from the fake server.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// Handler chooses a response for a request. It is called from the server's
// goroutine, so it must not call test failure methods.
type Handler func(*http.Request) Response

// JSON encodes v for use as a response body.
func JSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// JWS is a decoded ACME JWS request body.
type JWS struct {
	ProtectedJSON []byte
	Payload       []byte
	Signature     []byte
	SigningInput  []byte // base64url(protected) + "." + base64url(payload)
}

// Request is a request received by the fake server.
type Request struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

// JWS decodes the request body as an ACME JWS.
func (r Request) JWS(t testing.TB) JWS {
	t.Helper()

	var dto struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(r.Body, &dto); err != nil {
		t.Fatalf("decode JWS: %v", err)
	}

	decode := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("decode base64url value: %v", err)
		}
		return b
	}

	return JWS{
		ProtectedJSON: decode(dto.Protected),
		Payload:       decode(dto.Payload),
		Signature:     decode(dto.Signature),
		SigningInput:  []byte(dto.Protected + "." + dto.Payload),
	}
}

// Server is a fake ACME server with a newNonce endpoint and configurable
// responses. All requests are recorded.
type Server struct {
	srv      *httptest.Server
	mu       sync.Mutex
	handlers map[string]Handler
	requests []Request
	t        testing.TB
}

// NewServer starts a fake ACME server and registers its shutdown with t.
func NewServer(t testing.TB) *Server {
	t.Helper()

	s := &Server{t: t, handlers: make(map[string]Handler)}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead && r.URL.Path == "/newNonce" {
		s.mu.Lock()
		registered := s.handlers[r.Method+" "+r.URL.Path] != nil
		s.mu.Unlock()
		if !registered {
			w.Header().Set("Replay-Nonce", DefaultNonce)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.requests = append(s.requests, Request{
		Method: r.Method,
		Path:   r.URL.Path,
		Header: r.Header.Clone(),
		Body:   body,
	})
	h := s.handlers[r.Method+" "+r.URL.Path]
	s.mu.Unlock()

	if h == nil {
		http.NotFound(w, r)
		return
	}
	res := h(r)
	for k, values := range res.Header {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(res.Status)
	if res.Body != nil {
		_, _ = w.Write(res.Body)
	}
}

// Close shuts down the fake server. Tests can use it to make subsequent
// requests fail with a transport error.
func (s *Server) Close() { s.srv.Close() }

// URL returns the base URL of the fake server.
func (s *Server) URL() string { return s.srv.URL }

// Endpoint returns the URL of a named endpoint, e.g. Endpoint("newOrder").
func (s *Server) Endpoint(name string) string { return s.srv.URL + "/" + name }

// Directory returns a standard ACME directory response body.
func (s *Server) Directory(t testing.TB) []byte {
	t.Helper()
	return JSON(t, map[string]any{
		"newNonce":   s.Endpoint("newNonce"),
		"newAccount": s.Endpoint("newAccount"),
		"newOrder":   s.Endpoint("newOrder"),
		"newAuthz":   s.Endpoint("newAuthz"),
		"revokeCert": s.Endpoint("revokeCert"),
		"keyChange":  s.Endpoint("keyChange"),
		"meta":       map[string]any{},
	})
}

// Handle registers a handler for method and path.
func (s *Server) Handle(method, path string, h Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[method+" "+path] = h
}

// Respond registers a fixed response for method and path.
func (s *Server) Respond(method, path string, res Response) {
	s.Handle(method, path, func(*http.Request) Response { return res })
}

// Count returns the number of requests received for method and path. It may
// be called from a Handler to vary a response.
func (s *Server) Count(method, path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	for _, r := range s.requests {
		if r.Method == method && r.Path == path {
			n++
		}
	}
	return n
}

// Requests returns all requests received for method and path.
func (s *Server) Requests(method, path string) []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Request
	for _, r := range s.requests {
		if r.Method == method && r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

// LastRequest returns the most recent request for method and path, failing
// the test if there is none.
func (s *Server) LastRequest(method, path string) Request {
	s.t.Helper()
	requests := s.Requests(method, path)
	if len(requests) == 0 {
		s.t.Fatalf("no %s %s request received", method, path)
	}
	return requests[len(requests)-1]
}
