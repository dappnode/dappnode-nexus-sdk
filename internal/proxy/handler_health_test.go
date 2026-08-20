package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type healthTestSender struct {
	called bool
}

func (s *healthTestSender) Do(context.Context, string, string, string, []byte) (*http.Response, string, error) {
	s.called = true
	return nil, "", errors.New("health check must not call the Gateway")
}

func TestHealthEndpoint(t *testing.T) {
	sender := &healthTestSender{}
	handler, err := NewHandler(sender, nil)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, LocalHealthEndpoint, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
	if response.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Fatalf("body = %q", response.Body.String())
	}
	if sender.called {
		t.Fatal("health check called the Gateway")
	}
}

func TestHealthEndpointRejectsOtherMethods(t *testing.T) {
	handler, err := NewHandler(&healthTestSender{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, LocalHealthEndpoint, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
	if response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("Allow = %q", response.Header().Get("Allow"))
	}
}
