package cloudflare_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/cloudflare"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type errCloser struct {
	io.Reader
}

func (e *errCloser) Close() error {
	return errors.New("simulated close failure")
}

type errReader struct{}

func (e *errReader) Read(_ []byte) (int, error) {
	return 0, errors.New("simulated read failure")
}

func (e *errReader) Close() error {
	return nil
}

func TestResponseError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err        *cloudflare.ResponseError
		name       string
		wantSubstr string
	}{
		{
			err: &cloudflare.ResponseError{
				StatusCode: http.StatusBadRequest,
				Errors: []cloudflare.APIError{
					{Code: 1000, Message: "invalid parameter value"},
					{Code: 1001, Message: "missing required body attribute"},
				},
			},
			name:       "multiple api errors",
			wantSubstr: "cloudflare api status 400: [1000] invalid parameter value; [1001] missing required body attribute",
		},
		{
			err: &cloudflare.ResponseError{
				StatusCode: http.StatusUnauthorized,
				Errors: []cloudflare.APIError{
					{Code: 1003, Message: "bad credentials provided"},
				},
			},
			name:       "single api error",
			wantSubstr: "cloudflare api status 401: [1003] bad credentials provided",
		},
		{
			err: &cloudflare.ResponseError{
				StatusCode: http.StatusBadGateway,
				Message:    "upstream gateway timeout occurred",
			},
			name:       "fallback to plain message",
			wantSubstr: "cloudflare api status 502: upstream gateway timeout occurred",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.err.Error()
			if !strings.Contains(got, tc.wantSubstr) {
				t.Fatalf("Error() = %q, want substr %q", got, tc.wantSubstr)
			}
		})
	}
}

func TestResponseError_IsRetryable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err           *cloudflare.ResponseError
		name          string
		wantRetryable bool
	}{
		{
			err:           &cloudflare.ResponseError{StatusCode: http.StatusTooManyRequests},
			name:          "rate limited 429 is retryable",
			wantRetryable: true,
		},
		{
			err:           &cloudflare.ResponseError{StatusCode: http.StatusServiceUnavailable},
			name:          "server error 503 is retryable",
			wantRetryable: true,
		},
		{
			err:           &cloudflare.ResponseError{StatusCode: http.StatusBadRequest},
			name:          "client error 400 is not retryable",
			wantRetryable: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.err.IsRetryable(); got != tc.wantRetryable {
				t.Errorf("IsRetryable() = %v, want %v", got, tc.wantRetryable)
			}
		})
	}
}

func TestNewClient_DefaultTransportAndSetBaseURL(t *testing.T) {
	t.Parallel()

	client := cloudflare.NewClient("cf-auth-default", nil)
	if client == nil {
		t.Fatal("expected non-nil client")
	}

	tests := []struct {
		inputURL string
		name     string
	}{
		{
			inputURL: "http://127.0.0.1:8080",
			name:     "without trailing slash",
		},
		{
			inputURL: "http://127.0.0.1:8080/",
			name:     "with trailing slash",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client.SetBaseURL(tc.inputURL)
		})
	}
}

func TestAddItems(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		itemCount  int
		wantChunks int
	}{
		{
			name:       "single chunk add",
			itemCount:  5,
			wantChunks: 1,
		},
		{
			name:       "multiple chunks batching",
			itemCount:  1005,
			wantChunks: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var chunkCount atomic.Int32
			mockTransport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("Authorization") != "Bearer cf-auth-add" {
					return &http.Response{
						StatusCode: http.StatusUnauthorized,
						Body:       io.NopCloser(strings.NewReader(`{"success":false,"errors":[{"code":1000,"message":"Invalid token"}]}`)),
						Header:     make(http.Header),
					}, nil
				}
				if r.Method != http.MethodPost {
					return &http.Response{
						StatusCode: http.StatusMethodNotAllowed,
						Body:       io.NopCloser(strings.NewReader("")),
						Header:     make(http.Header),
					}, nil
				}

				chunkCount.Add(1)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"success":true,"result":{"operation_id":"op_123"},"errors":[],"messages":[]}`)),
					Header:     make(http.Header),
				}, nil
			})

			httpClient := &http.Client{Transport: mockTransport}
			client := cloudflare.NewClient("cf-auth-add", httpClient)
			client.SetBaseURL("http://127.0.0.1:8080/")

			items := make([]cloudflare.ItemPayload, 0, tc.itemCount)
			for i := range tc.itemCount {
				items = append(items, cloudflare.ItemPayload{
					IP:      fmt.Sprintf("192.0.2.%d", i%250+1),
					Comment: "test ban",
				})
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			err := client.AddItems(ctx, "account_1", "list_1", items)
			if err != nil {
				t.Fatalf("AddItems() unexpected error: %v", err)
			}
			if int(chunkCount.Load()) != tc.wantChunks {
				t.Errorf("chunk count = %d, want %d", chunkCount.Load(), tc.wantChunks)
			}
		})
	}
}

func TestAddItems_EmptyAndErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mockResp func() (*http.Response, error)
		name     string
		items    []cloudflare.ItemPayload
		wantErr  bool
	}{
		{
			mockResp: nil,
			name:     "empty items returns nil immediately",
			items:    nil,
			wantErr:  false,
		},
		{
			mockResp: func() (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(strings.NewReader(`{"success":false,"errors":[{"code":4000,"message":"bad request"}]}`)),
					Header:     make(http.Header),
				}, nil
			},
			name: "doWithRetry fails",
			items: []cloudflare.ItemPayload{
				{IP: "198.51.100.10", Comment: "test item"},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockTransport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				if tc.mockResp != nil {
					return tc.mockResp()
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"success":true,"result":null}`)),
					Header:     make(http.Header),
				}, nil
			})

			client := cloudflare.NewClient("cf-auth-add-err", &http.Client{Transport: mockTransport})
			client.SetBaseURL("http://127.0.0.1:8080/")

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			err := client.AddItems(ctx, "account_err", "list_err", tc.items)
			if (err != nil) != tc.wantErr {
				t.Fatalf("AddItems() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestFindItemByIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		targetIP     string
		responseJSON string
		wantID       string
		wantFound    bool
	}{
		{
			name:     "item found",
			targetIP: "192.0.2.5",
			responseJSON: `{
				"success": true,
				"result": [
					{"id": "uuid-item-123", "ip": "192.0.2.5", "comment": "cs ban"}
				],
				"errors": []
			}`,
			wantID:    "uuid-item-123",
			wantFound: true,
		},
		{
			name:     "item not found",
			targetIP: "192.0.2.99",
			responseJSON: `{
				"success": true,
				"result": [],
				"errors": []
			}`,
			wantID:    "",
			wantFound: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockTransport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if !strings.Contains(r.URL.RawQuery, "search=") {
					return &http.Response{
						StatusCode: http.StatusBadRequest,
						Body:       io.NopCloser(strings.NewReader("")),
						Header:     make(http.Header),
					}, nil
				}

				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(tc.responseJSON)),
					Header:     make(http.Header),
				}, nil
			})

			httpClient := &http.Client{Transport: mockTransport}
			client := cloudflare.NewClient("cf-auth-find", httpClient)
			client.SetBaseURL("http://127.0.0.1:8080/")

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			item, found, err := client.FindItemByIP(ctx, "acc_1", "list_1", tc.targetIP)
			if err != nil {
				t.Fatalf("FindItemByIP() unexpected error: %v", err)
			}
			if found != tc.wantFound {
				t.Fatalf("found = %v, want %v", found, tc.wantFound)
			}
			if tc.wantFound && item.ID != tc.wantID {
				t.Errorf("item.ID = %q, want %q", item.ID, tc.wantID)
			}
		})
	}
}

func TestFindItemByIP_FallbackAndErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mockResp  func() (*http.Response, error)
		name      string
		targetIP  string
		wantID    string
		wantErr   bool
		wantFound bool
	}{
		{
			mockResp: func() (*http.Response, error) {
				return nil, errors.New("search network error")
			},
			name:      "network failure during search",
			targetIP:  "198.51.100.20",
			wantID:    "",
			wantErr:   true,
			wantFound: false,
		},
		{
			mockResp: func() (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"success":true,"result":[{"id":"uuid-fallback-99","ip":"198.51.100.30/32","comment":"fallback match"}]}`)),
					Header:     make(http.Header),
				}, nil
			},
			name:      "fallback to first element when ip does not strictly equal",
			targetIP:  "198.51.100.30",
			wantID:    "uuid-fallback-99",
			wantErr:   false,
			wantFound: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockTransport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return tc.mockResp()
			})

			client := cloudflare.NewClient("cf-auth-find-err", &http.Client{Transport: mockTransport})
			client.SetBaseURL("http://127.0.0.1:8080/")

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			item, found, err := client.FindItemByIP(ctx, "acc_find_err", "list_find_err", tc.targetIP)
			if (err != nil) != tc.wantErr {
				t.Fatalf("FindItemByIP() error = %v, wantErr = %v", err, tc.wantErr)
			}
			if found != tc.wantFound {
				t.Fatalf("found = %v, want %v", found, tc.wantFound)
			}
			if tc.wantFound && item.ID != tc.wantID {
				t.Errorf("item.ID = %q, want %q", item.ID, tc.wantID)
			}
		})
	}
}

func TestDeleteItems(t *testing.T) {
	t.Parallel()

	var deleteCalled atomic.Bool
	mockTransport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodDelete {
			return &http.Response{
				StatusCode: http.StatusMethodNotAllowed,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		}
		deleteCalled.Store(true)

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"success":true,"result":null,"errors":[]}`)),
			Header:     make(http.Header),
		}, nil
	})

	httpClient := &http.Client{Transport: mockTransport}
	client := cloudflare.NewClient("cf-auth-del", httpClient)
	client.SetBaseURL("http://127.0.0.1:8080/")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := client.DeleteItems(ctx, "acc_1", "list_1", []string{"uuid-1", "uuid-2"})
	if err != nil {
		t.Fatalf("DeleteItems() unexpected error: %v", err)
	}
	if !deleteCalled.Load() {
		t.Errorf("expected DELETE call to Cloudflare API")
	}
}

func TestDeleteItems_EmptyAndErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mockResp func() (*http.Response, error)
		name     string
		itemIDs  []string
		wantErr  bool
	}{
		{
			mockResp: nil,
			name:     "empty itemIDs returns nil immediately",
			itemIDs:  nil,
			wantErr:  false,
		},
		{
			mockResp: func() (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(strings.NewReader(`{"success":false,"errors":[{"code":4001,"message":"delete failure"}]}`)),
					Header:     make(http.Header),
				}, nil
			},
			name:    "doWithRetry fails during delete",
			itemIDs: []string{"uuid-del-err-1"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockTransport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				if tc.mockResp != nil {
					return tc.mockResp()
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"success":true,"result":null}`)),
					Header:     make(http.Header),
				}, nil
			})

			client := cloudflare.NewClient("cf-auth-del-err", &http.Client{Transport: mockTransport})
			client.SetBaseURL("http://127.0.0.1:8080/")

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			err := client.DeleteItems(ctx, "acc_del_err", "list_del_err", tc.itemIDs)
			if (err != nil) != tc.wantErr {
				t.Fatalf("DeleteItems() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestDeleteItems_MultipleChunks(t *testing.T) {
	t.Parallel()

	var deleteBatches atomic.Int32
	mockTransport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodDelete {
			return &http.Response{
				StatusCode: http.StatusMethodNotAllowed,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		}
		deleteBatches.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"success":true,"result":null}`)),
			Header:     make(http.Header),
		}, nil
	})

	client := cloudflare.NewClient("cf-auth-del-chunks", &http.Client{Transport: mockTransport})
	client.SetBaseURL("http://127.0.0.1:8080/")

	ids := make([]string, 1005)
	for i := range ids {
		ids[i] = fmt.Sprintf("uuid-%d", i)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := client.DeleteItems(ctx, "acc_chunk_del", "list_chunk_del", ids)
	if err != nil {
		t.Fatalf("DeleteItems() unexpected error: %v", err)
	}
	if deleteBatches.Load() != 2 {
		t.Errorf("expected 2 batch delete calls, got %d", deleteBatches.Load())
	}
}

func TestTestConnection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
		isNotFound bool
	}{
		{
			name:       "list exists and token valid",
			statusCode: http.StatusOK,
			wantErr:    false,
			isNotFound: false,
		},
		{
			name:       "list does not exist 404",
			statusCode: http.StatusNotFound,
			wantErr:    true,
			isNotFound: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockTransport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: tc.statusCode,
					Body:       io.NopCloser(strings.NewReader(`{"success":true,"result":{}}`)),
					Header:     make(http.Header),
				}, nil
			})

			httpClient := &http.Client{Transport: mockTransport}
			client := cloudflare.NewClient("cf-auth-conn", httpClient)
			client.SetBaseURL("http://127.0.0.1:8080/")

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			err := client.TestConnection(ctx, "acc_1", "list_1")
			if (err != nil) != tc.wantErr {
				t.Fatalf("TestConnection() error = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.isNotFound && !errors.Is(err, cloudflare.ErrListNotFound) {
				t.Errorf("expected ErrListNotFound, got %v", err)
			}
		})
	}
}

func TestTestConnection_Non404Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
	}{
		{
			name:       "unauthorized error 401",
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "forbidden error 403",
			statusCode: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockTransport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: tc.statusCode,
					Body:       io.NopCloser(strings.NewReader(`{"success":false,"errors":[{"code":9999,"message":"auth or server failure"}]}`)),
					Header:     make(http.Header),
				}, nil
			})

			client := cloudflare.NewClient("cf-auth-conn-err", &http.Client{Transport: mockTransport})
			client.SetBaseURL("http://127.0.0.1:8080/")

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			err := client.TestConnection(ctx, "acc_non404", "list_non404")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if errors.Is(err, cloudflare.ErrListNotFound) {
				t.Errorf("did not expect ErrListNotFound for status %d", tc.statusCode)
			}
		})
	}
}

func TestRetryOnRateLimit(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	mockTransport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		current := attempts.Add(1)
		if current < 3 {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Body:       io.NopCloser(strings.NewReader(`{"success":false,"errors":[{"code":10013,"message":"operation pending"}]}`)),
				Header:     make(http.Header),
			}, nil
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"success":true,"result":{"operation_id":"op_ok"}}`)),
			Header:     make(http.Header),
		}, nil
	})

	httpClient := &http.Client{Transport: mockTransport}
	client := cloudflare.NewClient("cf-auth-retry", httpClient)
	client.SetBaseURL("http://127.0.0.1:8080/")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.AddItems(ctx, "acc", "list", []cloudflare.ItemPayload{{IP: "203.0.113.1", Comment: "test"}})
	if err != nil {
		t.Fatalf("expected AddItems to succeed after retrying 429, got %v", err)
	}
	if attempts.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts.Load())
	}
}

func TestDoWithRetry_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mockResp func() (*http.Response, error)
		name     string
		wantErr  bool
	}{
		{
			mockResp: func() (*http.Response, error) {
				return nil, errors.New("connection reset by peer")
			},
			name:    "transport network failure",
			wantErr: true,
		},
		{
			mockResp: func() (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(strings.NewReader("Bad Request: Plain text from reverse proxy")),
					Header:     make(http.Header),
				}, nil
			},
			name:    "non-json error body from edge gateway",
			wantErr: true,
		},
		{
			mockResp: func() (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("not-a-valid-json-string")),
					Header:     make(http.Header),
				}, nil
			},
			name:    "malformed json target response",
			wantErr: true,
		},
		{
			mockResp: func() (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       &errCloser{Reader: strings.NewReader(`{"success":true,"result":{}}`)},
					Header:     make(http.Header),
				}, nil
			},
			name:    "response body close error",
			wantErr: true,
		},
		{
			mockResp: func() (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       &errReader{},
					Header:     make(http.Header),
				}, nil
			},
			name:    "response body read error",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockTransport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return tc.mockResp()
			})

			client := cloudflare.NewClient("cf-auth-edge", &http.Client{Transport: mockTransport})
			client.SetBaseURL("http://127.0.0.1:8080/")

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			err := client.TestConnection(ctx, "acc_edge", "list_edge")
			if (err != nil) != tc.wantErr {
				t.Fatalf("TestConnection() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestDoWithRetry_InvalidURL(t *testing.T) {
	t.Parallel()

	client := cloudflare.NewClient("cf-auth-invalid-url", &http.Client{})
	client.SetBaseURL("://invalid-url-schema")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := client.TestConnection(ctx, "acc", "list")
	if err == nil {
		t.Fatal("expected error with invalid URL schema, got nil")
	}
}
