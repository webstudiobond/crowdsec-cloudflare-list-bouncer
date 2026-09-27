// Package crowdsec implements communication with the CrowdSec Local API (LAPI)
// decision stream endpoint using the standard Go 1.27 encoding/json/v2 engine.
package crowdsec

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/retry"
)

const (
	maxResponseBodyBytes = 16 * 1024 * 1024
	defaultTimeout       = 30 * time.Second
	bouncerName          = "crowdsec-cloudflare-list-bouncer"
)

func defaultNewRequestWithContext(ctx context.Context, method, rawURL string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, fmt.Errorf("new request with context: %w", err)
	}
	return req, nil
}

var newRequestWithContext = defaultNewRequestWithContext

// Decision represents an individual remediation rule issued by CrowdSec.
type Decision struct {
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Scenario string `json:"scenario"`
	Duration string `json:"duration"`
	ID       int64  `json:"id"`
}

// StreamResponse encapsulates additions and deletions returned by the decisions stream.
type StreamResponse struct {
	New     []Decision `json:"new"`
	Deleted []Decision `json:"deleted"`
}

// APIError represents an unexpected or non-success HTTP status code from LAPI.
type APIError struct {
	Message    string
	StatusCode int
}

// Error formats the HTTP status and body response message.
func (e *APIError) Error() string {
	return fmt.Sprintf("crowdsec lapi returned status %d: %s", e.StatusCode, e.Message)
}

// IsRetryable determines if the HTTP failure warrants an automated retry.
func (e *APIError) IsRetryable() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}

// Client manages authenticated HTTP requests to the CrowdSec LAPI.
type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	userAgent  string
}

// NewClient constructs a Client configured with base URL, authentication key,
// release version, and custom transport options. The version is advertised in
// the User-Agent header so the LAPI can store the bouncer type and version.
func NewClient(baseURL, apiKey, version string, customClient *http.Client) *Client {
	normalizedURL := baseURL
	if !strings.HasSuffix(normalizedURL, "/") {
		normalizedURL += "/"
	}

	userAgent := bouncerName + "/dev"
	if version != "" {
		userAgent = bouncerName + "/" + version
	}

	client := customClient
	if client == nil {
		client = &http.Client{
			Timeout: defaultTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		}
	}

	return &Client{
		httpClient: client,
		baseURL:    normalizedURL,
		apiKey:     apiKey,
		userAgent:  userAgent,
	}
}

// StreamDecisions fetches active or delta decisions from the LAPI stream endpoint with automated backoff retries.
func (c *Client) StreamDecisions(ctx context.Context, startup bool) (StreamResponse, error) {
	endpoint := c.baseURL + "v1/decisions/stream"
	if startup {
		endpoint += "?startup=true"
	}

	var result StreamResponse
	err := retry.Do(ctx, 5, 500*time.Millisecond, 10*time.Second, func(opCtx context.Context) (opErr error) {
		req, reqErr := newRequestWithContext(opCtx, http.MethodGet, endpoint, http.NoBody)
		if reqErr != nil {
			return fmt.Errorf("create stream request: %w", reqErr)
		}

		req.Header.Set("X-Api-Key", c.apiKey)
		req.Header.Set("User-Agent", c.userAgent)

		resp, doErr := c.httpClient.Do(req)
		if doErr != nil {
			return fmt.Errorf("execute stream request: %w", doErr)
		}
		defer func() {
			if closeErr := resp.Body.Close(); closeErr != nil && opErr == nil {
				opErr = fmt.Errorf("close stream response body: %w", closeErr)
			}
		}()

		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
		if readErr != nil {
			return fmt.Errorf("read stream body: %w", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			return &APIError{
				StatusCode: resp.StatusCode,
				Message:    strings.TrimSpace(string(bodyBytes)),
			}
		}

		if unmarshalErr := json.Unmarshal(bodyBytes, &result); unmarshalErr != nil {
			return fmt.Errorf("unmarshal stream response: %w", unmarshalErr)
		}

		return nil
	})

	if err != nil {
		return StreamResponse{}, fmt.Errorf("stream decisions: %w", err)
	}

	return result, nil
}

// TestConnection validates credentials and connectivity against the LAPI stream endpoint.
func (c *Client) TestConnection(ctx context.Context) (err error) {
	u, parseErr := url.Parse(c.baseURL + "v1/decisions/stream")
	if parseErr != nil {
		return fmt.Errorf("parse stream url: %w", parseErr)
	}

	q := u.Query()
	q.Set("startup", "false")
	u.RawQuery = q.Encode()

	req, reqErr := newRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if reqErr != nil {
		return fmt.Errorf("create test request: %w", reqErr)
	}

	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("User-Agent", c.userAgent)

	resp, doErr := c.httpClient.Do(req)
	if doErr != nil {
		return fmt.Errorf("execute test request: %w", doErr)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close test response body: %w", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 1024))
		msg := ""
		if readErr == nil {
			msg = strings.TrimSpace(string(bodyBytes))
		}
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    msg,
		}
	}

	return nil
}
