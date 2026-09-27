package crowdsec

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func mockNewRequestFail(_ context.Context, _, _ string, _ io.Reader) (*http.Request, error) {
	return nil, errors.New("simulated request creation failure")
}

func TestDefaultNewRequestWithContext(t *testing.T) {
	req, err := defaultNewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:8080/test", http.NoBody)
	if err != nil {
		t.Fatalf("defaultNewRequestWithContext() unexpected error: %v", err)
	}
	if req.Method != http.MethodGet {
		t.Fatalf("req.Method = %q, want GET", req.Method)
	}

	_, err = defaultNewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:8080/\x7f", http.NoBody)
	if err == nil {
		t.Fatalf("expected error for control char URL, got nil")
	}
}

func TestStreamDecisions_NewRequestError(t *testing.T) {
	prev := newRequestWithContext
	newRequestWithContext = mockNewRequestFail
	t.Cleanup(func() {
		newRequestWithContext = prev
	})

	client := NewClient("http://127.0.0.1:8080", "test-lapi-key", "0.0.1", nil)
	_, err := client.StreamDecisions(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "create stream request") {
		t.Fatalf("expected create stream request error, got %v", err)
	}
}

func TestTestConnection_NewRequestError(t *testing.T) {
	prev := newRequestWithContext
	newRequestWithContext = mockNewRequestFail
	t.Cleanup(func() {
		newRequestWithContext = prev
	})

	client := NewClient("http://127.0.0.1:8080", "test-lapi-key", "0.0.1", nil)
	err := client.TestConnection(context.Background())
	if err == nil || !strings.Contains(err.Error(), "create test request") {
		t.Fatalf("expected create test request error, got %v", err)
	}
}
