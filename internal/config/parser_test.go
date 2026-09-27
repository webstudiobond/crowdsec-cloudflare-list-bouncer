package config_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/config"
)

func TestParseDocument(t *testing.T) {
	t.Parallel()

	tests := []struct {
		wantScalars map[string]string
		wantLists   map[string][]string
		name        string
		input       string
		wantErr     bool
	}{
		{
			name: "valid flat keys and lists",
			input: `
# Main configuration
api_url: http://127.0.0.1:8080/
api_key: "secret123"
poll_interval: '15s'

# Allowed sources
allowed_origins:
  - crowdsec
  - cscli # inline comment
`,
			wantErr: false,
			wantScalars: map[string]string{
				"api_url":       "http://127.0.0.1:8080/",
				"api_key":       "secret123",
				"poll_interval": "15s",
			},
			wantLists: map[string][]string{
				"allowed_origins": {"crowdsec", "cscli"},
			},
		},
		{
			name: "list item without key",
			input: `
  - orphaned_item
`,
			wantErr: true,
		},
		{
			name: "line without colon",
			input: `
invalid_line_without_delimiter
`,
			wantErr: true,
		},
		{
			name: "empty key",
			input: `
: value
`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc, err := config.ParseDocument(strings.NewReader(tc.input))
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseDocument() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}

			for k, expectedVal := range tc.wantScalars {
				actualVal, ok := doc.Scalars[k]
				if !ok {
					t.Errorf("missing scalar key %q", k)
				} else if actualVal != expectedVal {
					t.Errorf("scalar %q = %q, want %q", k, actualVal, expectedVal)
				}
			}

			for k, expectedList := range tc.wantLists {
				actualList, ok := doc.Lists[k]
				if !ok {
					t.Errorf("missing list key %q", k)
					continue
				}
				if len(actualList) != len(expectedList) {
					t.Errorf("list %q length = %d, want %d", k, len(actualList), len(expectedList))
					continue
				}
				for i := range expectedList {
					if actualList[i] != expectedList[i] {
						t.Errorf("list %q[%d] = %q, want %q", k, i, actualList[i], expectedList[i])
					}
				}
			}
		})
	}
}

type errReader struct{}

func (e *errReader) Read(_ []byte) (int, error) {
	return 0, errors.New("simulated scan error")
}

func TestParseDocument_ScannerError(t *testing.T) {
	t.Parallel()

	_, err := config.ParseDocument(&errReader{})
	if err == nil || !strings.Contains(err.Error(), "scan configuration") {
		t.Fatalf("ParseDocument() error = %v, want scan configuration error", err)
	}
}
