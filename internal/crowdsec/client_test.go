package crowdsec_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/crowdsec"
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

func TestStreamDecisions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		responseJSON string
		statusCode   int
		wantNewCount int
		wantDelCount int
		startup      bool
		wantErr      bool
	}{
		{
			name: "initial sync startup with active bans",
			responseJSON: `{
				"new": [
					{
						"origin": "crowdsec",
						"type": "ban",
						"scope": "Ip",
						"value": "192.0.2.1",
						"scenario": "ssh-bf",
						"duration": "4h0m0s",
						"id": 101
					}
				],
				"deleted": []
			}`,
			statusCode:   http.StatusOK,
			wantNewCount: 1,
			wantDelCount: 0,
			startup:      true,
			wantErr:      false,
		},
		{
			name: "incremental stream with additions and deletions",
			responseJSON: `{
				"new": [
					{
						"origin": "cscli",
						"type": "ban",
						"scope": "Range",
						"value": "198.51.100.0/24",
						"scenario": "manual-ban",
						"duration": "24h0m0s",
						"id": 102
					}
				],
				"deleted": [
					{
						"origin": "crowdsec",
						"type": "ban",
						"scope": "Ip",
						"value": "192.0.2.1",
						"scenario": "ssh-bf",
						"duration": "0s",
						"id": 101
					}
				]
			}`,
			statusCode:   http.StatusOK,
			wantNewCount: 1,
			wantDelCount: 1,
			startup:      false,
			wantErr:      false,
		},
		{
			name:         "malformed json payload error",
			responseJSON: `{"invalid_json": true`,
			statusCode:   http.StatusOK,
			wantNewCount: 0,
			wantDelCount: 0,
			startup:      false,
			wantErr:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockTransport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("X-Api-Key") != "dummy-lapi-auth-key" {
					return &http.Response{
						StatusCode: http.StatusUnauthorized,
						Body:       io.NopCloser(strings.NewReader(`{"message":"unauthorized"}`)),
						Header:     make(http.Header),
					}, nil
				}

				if r.Header.Get("User-Agent") != "crowdsec-cloudflare-list-bouncer/test-version" {
					return &http.Response{
						StatusCode: http.StatusBadRequest,
						Body:       io.NopCloser(strings.NewReader(`{"message":"bad user agent"}`)),
						Header:     make(http.Header),
					}, nil
				}

				return &http.Response{
					StatusCode: tc.statusCode,
					Body:       io.NopCloser(strings.NewReader(tc.responseJSON)),
					Header:     make(http.Header),
				}, nil
			})

			httpClient := &http.Client{Transport: mockTransport}
			client := crowdsec.NewClient("http://127.0.0.1:8080", "dummy-lapi-auth-key", "test-version", httpClient)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			res, err := client.StreamDecisions(ctx, tc.startup)
			if (err != nil) != tc.wantErr {
				t.Fatalf("StreamDecisions() error = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}

			if len(res.New) != tc.wantNewCount {
				t.Errorf("New decisions count = %d, want %d", len(res.New), tc.wantNewCount)
			}
			if len(res.Deleted) != tc.wantDelCount {
				t.Errorf("Deleted decisions count = %d, want %d", len(res.Deleted), tc.wantDelCount)
			}
		})
	}
}

func TestStreamDecisionsRetry(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	mockTransport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		current := attempts.Add(1)
		if current < 3 {
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       io.NopCloser(strings.NewReader(`{"error":"lapi booting"}`)),
				Header:     make(http.Header),
			}, nil
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"new":[], "deleted":[]}`)),
			Header:     make(http.Header),
		}, nil
	})

	httpClient := &http.Client{Transport: mockTransport}
	client := crowdsec.NewClient("http://127.0.0.1:8080", "retry-test-key", "0.0.0-test", httpClient)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := client.StreamDecisions(ctx, false)
	if err != nil {
		t.Fatalf("expected stream to succeed after retries, got %v", err)
	}
	if len(res.New) != 0 || len(res.Deleted) != 0 {
		t.Errorf("expected empty lists, got %v", res)
	}
	if attempts.Load() != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts.Load())
	}
}

func TestConnection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{
			name:       "successful ping",
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "forbidden invalid key",
			statusCode: http.StatusForbidden,
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockTransport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: tc.statusCode,
					Body:       io.NopCloser(strings.NewReader("")),
					Header:     make(http.Header),
				}, nil
			})

			httpClient := &http.Client{Transport: mockTransport}
			client := crowdsec.NewClient("http://127.0.0.1:8080", "test-key", "0.0.0-test", httpClient)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			err := client.TestConnection(ctx)
			if (err != nil) != tc.wantErr {
				t.Fatalf("TestConnection() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestAPIError_Error(t *testing.T) {
	t.Parallel()

	apiErr := &crowdsec.APIError{
		StatusCode: http.StatusForbidden,
		Message:    "invalid credentials",
	}
	want := "crowdsec lapi returned status 403: invalid credentials"
	if apiErr.Error() != want {
		t.Fatalf("APIError.Error() = %q, want %q", apiErr.Error(), want)
	}
}

func TestNewClient_DefaultTransportAndEmptyVersion(t *testing.T) {
	t.Parallel()

	client := crowdsec.NewClient("http://127.0.0.1:8080", "default-cs-key", "", nil)
	if client == nil {
		t.Fatalf("expected non-nil client")
	}

	clientTrailing := crowdsec.NewClient("http://127.0.0.1:8080/", "default-cs-key-alt", "1.0.0", nil)
	if clientTrailing == nil {
		t.Fatalf("expected non-nil clientTrailing")
	}
}

func TestStreamDecisions_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		transport roundTripFunc
		name      string
	}{
		{
			name: "transport network failure",
			transport: func(_ *http.Request) (*http.Response, error) {
				return nil, errors.New("simulated network drop")
			},
		},
		{
			name: "body read error",
			transport: func(_ *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       &errReader{},
					Header:     make(http.Header),
				}, nil
			},
		},
		{
			name: "body close error",
			transport: func(_ *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       &errCloser{Reader: strings.NewReader(`{"new":[],"deleted":[]}`)},
					Header:     make(http.Header),
				}, nil
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			httpClient := &http.Client{Transport: tc.transport}
			client := crowdsec.NewClient("http://127.0.0.1:8080", "edge-stream-key", "0.0.1", httpClient)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			_, err := client.StreamDecisions(ctx, false)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestTestConnection_EdgeCases(t *testing.T) {
	t.Parallel()

	badURLClient := crowdsec.NewClient("http://127.0.0.1:8080/\x7f", "bad-url-key", "0.0.1", nil)
	if err := badURLClient.TestConnection(context.Background()); err == nil {
		t.Fatalf("expected url parse error, got nil")
	}

	failTransport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, errors.New("simulated dial failure")
	})
	failClient := crowdsec.NewClient("http://127.0.0.1:8080", "fail-dial-key", "0.0.1", &http.Client{Transport: failTransport})
	if err := failClient.TestConnection(context.Background()); err == nil {
		t.Fatalf("expected dial failure error, got nil")
	}

	closeFailTransport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       &errCloser{Reader: strings.NewReader("")},
			Header:     make(http.Header),
		}, nil
	})
	closeFailClient := crowdsec.NewClient("http://127.0.0.1:8080", "close-fail-key", "0.0.1", &http.Client{Transport: closeFailTransport})
	if err := closeFailClient.TestConnection(context.Background()); err == nil {
		t.Fatalf("expected body close error, got nil")
	}

	readErrTransport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadGateway,
			Body:       &errReader{},
			Header:     make(http.Header),
		}, nil
	})
	readErrClient := crowdsec.NewClient("http://127.0.0.1:8080", "read-err-key", "0.0.1", &http.Client{Transport: readErrTransport})
	err := readErrClient.TestConnection(context.Background())
	if err == nil {
		t.Fatalf("expected error from non-200 with read error, got nil")
	}
	var apiErr *crowdsec.APIError
	if !errors.As(err, &apiErr) || apiErr.Message != "" {
		t.Fatalf("expected empty message on read error, got %v", apiErr)
	}

	msgTransport := roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(strings.NewReader("specific reason")),
			Header:     make(http.Header),
		}, nil
	})
	msgClient := crowdsec.NewClient("http://127.0.0.1:8080", "msg-key", "0.0.1", &http.Client{Transport: msgTransport})
	err = msgClient.TestConnection(context.Background())
	if err == nil {
		t.Fatalf("expected error from bad request, got nil")
	}
	if !errors.As(err, &apiErr) || apiErr.Message != "specific reason" {
		t.Fatalf("expected specific reason message, got %v", apiErr)
	}
}
