// Package cloudflare provides an API v4 client for managing Cloudflare
// Account-level Rules Lists with batching and resilience against rate limits.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/retry"
)

const (
	defaultBaseURL       = "https://api.cloudflare.com/client/v4/"
	defaultBatchSize     = 1000
	defaultTimeout       = 30 * time.Second
	maxResponseBodyBytes = 16 * 1024 * 1024
)

// ErrListNotFound indicates that the configured Cloudflare list ID does not exist.
var ErrListNotFound = errors.New("cloudflare list not found")

func defaultJSONMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

var jsonMarshal = defaultJSONMarshal

// ListItem represents an IP entry retrieved from a Cloudflare IP List.
type ListItem struct {
	ID      string `json:"id"`
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}

// ItemPayload represents a new IP entry to be inserted into a Cloudflare list.
type ItemPayload struct {
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}

// DeleteItemEntry represents an item identifier scheduled for removal.
type DeleteItemEntry struct {
	ID string `json:"id"`
}

// DeleteItemsPayload encapsulates the collection of item identifiers to delete.
type DeleteItemsPayload struct {
	Items []DeleteItemEntry `json:"items"`
}

// APIError represents an error entry returned in the Cloudflare response envelope.
type APIError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// APIResponse encapsulates the standard Cloudflare v4 envelope structure.
type APIResponse[T any] struct {
	Result   T          `json:"result"`
	Errors   []APIError `json:"errors"`
	Messages []string   `json:"messages"`
	Success  bool       `json:"success"`
}

// ResponseError describes an HTTP error returned by the Cloudflare API.
type ResponseError struct {
	Message    string
	Errors     []APIError
	StatusCode int
}

// Error formats the HTTP status code and any detailed API error descriptions.
func (e *ResponseError) Error() string {
	if len(e.Errors) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "cloudflare api status %d: ", e.StatusCode)
		for i, apiErr := range e.Errors {
			if i > 0 {
				b.WriteString("; ")
			}
			fmt.Fprintf(&b, "[%d] %s", apiErr.Code, apiErr.Message)
		}
		return b.String()
	}
	return fmt.Sprintf("cloudflare api status %d: %s", e.StatusCode, e.Message)
}

// IsRetryable returns true when the error represents an asynchronous lock (429) or transient 5xx server error.
func (e *ResponseError) IsRetryable() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}

// Client manages authenticated HTTP requests to the Cloudflare API v4.
type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

// NewClient constructs a Cloudflare API client with token authorization and optimized connection pooling.
func NewClient(token string, customClient *http.Client) *Client {
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
		baseURL:    defaultBaseURL,
		token:      token,
	}
}

// SetBaseURL overrides the API base URL, facilitating local mocking in tests.
func (c *Client) SetBaseURL(baseURL string) {
	if !strings.HasSuffix(baseURL, "/") {
		c.baseURL = baseURL + "/"
	} else {
		c.baseURL = baseURL
	}
}

// AddItems pushes a batch of IP items to the specified Cloudflare account list.
func (c *Client) AddItems(ctx context.Context, accountID, listID string, items []ItemPayload) error {
	if len(items) == 0 {
		return nil
	}

	for i := 0; i < len(items); i += defaultBatchSize {
		end := min(i+defaultBatchSize, len(items))
		chunk := items[i:end]

		payloadBytes, err := jsonMarshal(chunk)
		if err != nil {
			return fmt.Errorf("marshal add items payload: %w", err)
		}

		path := fmt.Sprintf("accounts/%s/rules/lists/%s/items", accountID, listID)
		if sendErr := c.doWithRetry(ctx, http.MethodPost, path, payloadBytes, nil); sendErr != nil {
			return fmt.Errorf("add items batch [%d:%d]: %w", i, end, sendErr)
		}
	}

	return nil
}

// FindItemByIP searches for an existing item in the list matching the given IP, returning its UUID if found.
func (c *Client) FindItemByIP(ctx context.Context, accountID, listID, ip string) (ListItem, bool, error) {
	escapedIP := url.QueryEscape(ip)
	path := fmt.Sprintf("accounts/%s/rules/lists/%s/items?search=%s&per_page=1", accountID, listID, escapedIP)

	var respEnvelope APIResponse[[]ListItem]
	err := c.doWithRetry(ctx, http.MethodGet, path, nil, &respEnvelope)
	if err != nil {
		return ListItem{}, false, fmt.Errorf("search item by ip %q: %w", ip, err)
	}

	for _, item := range respEnvelope.Result {
		if strings.EqualFold(item.IP, ip) {
			return item, true, nil
		}
	}

	if len(respEnvelope.Result) > 0 {
		return respEnvelope.Result[0], true, nil
	}

	return ListItem{}, false, nil
}

// DeleteItems removes items from the target list in chunks matching the item UUIDs.
func (c *Client) DeleteItems(ctx context.Context, accountID, listID string, itemIDs []string) error {
	if len(itemIDs) == 0 {
		return nil
	}

	for i := 0; i < len(itemIDs); i += defaultBatchSize {
		end := min(i+defaultBatchSize, len(itemIDs))
		chunkIDs := itemIDs[i:end]

		entries := make([]DeleteItemEntry, 0, len(chunkIDs))
		for _, id := range chunkIDs {
			entries = append(entries, DeleteItemEntry{ID: id})
		}

		payload := DeleteItemsPayload{Items: entries}
		payloadBytes, err := jsonMarshal(payload)
		if err != nil {
			return fmt.Errorf("marshal delete payload: %w", err)
		}

		path := fmt.Sprintf("accounts/%s/rules/lists/%s/items", accountID, listID)
		if delErr := c.doWithRetry(ctx, http.MethodDelete, path, payloadBytes, nil); delErr != nil {
			return fmt.Errorf("delete items batch [%d:%d]: %w", i, end, delErr)
		}
	}

	return nil
}

// TestConnection verifies that the API token is valid and the destination list exists and is accessible.
func (c *Client) TestConnection(ctx context.Context, accountID, listID string) error {
	path := fmt.Sprintf("accounts/%s/rules/lists/%s", accountID, listID)
	var respEnvelope APIResponse[map[string]any]

	err := c.doWithRetry(ctx, http.MethodGet, path, nil, &respEnvelope)
	if err != nil {
		var errResp *ResponseError
		if errors.As(err, &errResp) && errResp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("%w: list %s under account %s", ErrListNotFound, listID, accountID)
		}
		return fmt.Errorf("test connection to list %s: %w", listID, err)
	}

	return nil
}

func (c *Client) doWithRetry(ctx context.Context, method, path string, body []byte, target any) error {
	endpoint := c.baseURL + path

	retryErr := retry.Do(ctx, 5, 500*time.Millisecond, 10*time.Second, func(opCtx context.Context) (opErr error) {
		var bodyReader io.Reader = http.NoBody
		if len(body) > 0 {
			bodyReader = bytes.NewReader(body)
		}

		req, reqErr := http.NewRequestWithContext(opCtx, method, endpoint, bodyReader)
		if reqErr != nil {
			return fmt.Errorf("create cloudflare request: %w", reqErr)
		}

		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "crowdsec-cloudflare-list-bouncer")

		resp, doErr := c.httpClient.Do(req)
		if doErr != nil {
			return fmt.Errorf("execute cloudflare request: %w", doErr)
		}
		defer func() {
			if closeErr := resp.Body.Close(); closeErr != nil && opErr == nil {
				opErr = fmt.Errorf("close response body: %w", closeErr)
			}
		}()

		respBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
		if readErr != nil {
			return fmt.Errorf("read response body: %w", readErr)
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			var errEnvelope APIResponse[any]
			if unmarshalErr := json.Unmarshal(respBytes, &errEnvelope); unmarshalErr == nil && len(errEnvelope.Errors) > 0 {
				return &ResponseError{
					StatusCode: resp.StatusCode,
					Errors:     errEnvelope.Errors,
				}
			}
			return &ResponseError{
				StatusCode: resp.StatusCode,
				Message:    strings.TrimSpace(string(respBytes)),
			}
		}

		if target != nil && len(respBytes) > 0 {
			if unmarshalErr := json.Unmarshal(respBytes, target); unmarshalErr != nil {
				return fmt.Errorf("unmarshal cloudflare response: %w", unmarshalErr)
			}
		}

		return nil
	})

	if retryErr != nil {
		return fmt.Errorf("execute request: %w", retryErr)
	}

	return nil
}
