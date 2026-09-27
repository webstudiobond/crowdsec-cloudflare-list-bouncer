package bouncer_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/bouncer"
	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/cloudflare"
	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/config"
	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/crowdsec"
)

type mockCSStreamer struct {
	err  error
	resp crowdsec.StreamResponse
}

func (m *mockCSStreamer) StreamDecisions(_ context.Context, _ bool) (crowdsec.StreamResponse, error) {
	return m.resp, m.err
}

type mockCFManager struct {
	addErr       error
	findErr      error
	deleteErr    error
	foundUUID    string
	addedItems   []cloudflare.ItemPayload
	deletedItems []string
	notFound     bool
}

func (m *mockCFManager) AddItems(_ context.Context, _, _ string, items []cloudflare.ItemPayload) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.addedItems = append(m.addedItems, items...)
	return nil
}

func (m *mockCFManager) FindItemByIP(_ context.Context, _, _, ip string) (cloudflare.ListItem, bool, error) {
	if m.findErr != nil {
		return cloudflare.ListItem{}, false, m.findErr
	}
	if m.notFound {
		return cloudflare.ListItem{}, false, nil
	}
	if m.foundUUID != "" {
		return cloudflare.ListItem{
			ID: m.foundUUID,
			IP: ip,
		}, true, nil
	}
	return cloudflare.ListItem{}, false, nil
}

func (m *mockCFManager) DeleteItems(_ context.Context, _, _ string, itemIDs []string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.deletedItems = append(m.deletedItems, itemIDs...)
	return nil
}

func TestSyncTick_MultiTargetFiltering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		wantFirstAddedIP string
		wantAdded1       int
		wantAdded2       int
		wantDeleted1     int
		wantDeleted2     int
	}{
		{
			name:             "fan-out filters CAPI from both, cscli from target-2",
			wantFirstAddedIP: "2001:db8:1234:5678::/64",
			wantAdded1:       1,
			wantAdded2:       1,
			wantDeleted1:     1,
			wantDeleted2:     0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			streamResp := crowdsec.StreamResponse{
				New: []crowdsec.Decision{
					{Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: "192.0.2.1", Scenario: "ssh-bf", ID: 1},
					{Origin: "cscli", Type: "custom_block", Scope: "Ip", Value: "2001:db8:1234:5678::1", Scenario: "manual-ban", ID: 2},
					{Origin: "CAPI", Type: "captcha", Scope: "Ip", Value: "198.51.100.1", Scenario: "community-blocklist", ID: 3},
				},
				Deleted: []crowdsec.Decision{
					{Origin: "local_agent", Type: "manual_remediation", Scope: "Ip", Value: "198.51.100.50", Scenario: "manual-ban", ID: 4},
				},
			}

			target1 := config.TargetConfig{
				Name:                    "target-all-local",
				CFApiToken:              "tok-multi-1",
				CFAccountID:             "acc-multi-1",
				CFListID:                "list-multi-1",
				CFCommentPrefix:         "cs",
				AllowedOriginsSet:       map[string]struct{}{"local_agent": {}, "cscli": {}},
				AllowedDecisionTypesSet: map[string]struct{}{"custom_block": {}, "manual_remediation": {}},
			}

			target2 := config.TargetConfig{
				Name:                    "target-crowdsec-only",
				CFApiToken:              "tok-multi-2",
				CFAccountID:             "acc-multi-2",
				CFListID:                "list-multi-2",
				CFCommentPrefix:         "cs",
				AllowedOriginsSet:       map[string]struct{}{"crowdsec": {}},
				AllowedDecisionTypesSet: map[string]struct{}{"ban": {}},
			}

			mainCfg := config.MainConfig{
				Targets:      []config.TargetConfig{target1, target2},
				PollInterval: 10 * time.Millisecond,
			}

			mockCS := &mockCSStreamer{resp: streamResp}
			mockCF1 := &mockCFManager{foundUUID: "uuid-target-1"}
			mockCF2 := &mockCFManager{foundUUID: "uuid-target-2"}

			factory := func(token string) bouncer.CloudflareListManager {
				if token == "tok-multi-1" {
					return mockCF1
				}
				return mockCF2
			}

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			b := bouncer.New(&mainCfg, mockCS, factory, logger)

			ctx := context.Background()
			if err := b.SyncTick(ctx, true); err != nil {
				t.Fatalf("SyncTick failed: %v", err)
			}

			if len(mockCF1.addedItems) != tc.wantAdded1 {
				t.Fatalf("target1 expected %d added items, got %d", tc.wantAdded1, len(mockCF1.addedItems))
			}
			if mockCF1.addedItems[0].IP != tc.wantFirstAddedIP {
				t.Errorf("target1 item 0 IP = %q, want %q", mockCF1.addedItems[0].IP, tc.wantFirstAddedIP)
			}

			if len(mockCF2.addedItems) != tc.wantAdded2 {
				t.Fatalf("target2 expected %d added item, got %d", tc.wantAdded2, len(mockCF2.addedItems))
			}

			if len(mockCF1.deletedItems) != tc.wantDeleted1 {
				t.Errorf("target1 deleted count = %d, want %d", len(mockCF1.deletedItems), tc.wantDeleted1)
			}
			if len(mockCF2.deletedItems) != tc.wantDeleted2 {
				t.Errorf("target2 deleted count = %d, want %d", len(mockCF2.deletedItems), tc.wantDeleted2)
			}
		})
	}
}

func TestSyncTick_EmptyAndErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		streamErr error
		addErr    error
		name      string
		resp      crowdsec.StreamResponse
		wantErr   bool
	}{
		{
			streamErr: nil,
			addErr:    nil,
			name:      "empty stream response returns nil immediately",
			resp:      crowdsec.StreamResponse{},
			wantErr:   false,
		},
		{
			streamErr: errors.New("stream network error"),
			addErr:    nil,
			name:      "stream failure returns error",
			resp:      crowdsec.StreamResponse{},
			wantErr:   true,
		},
		{
			streamErr: nil,
			addErr:    errors.New("cloudflare add items failed"),
			name:      "applyBatch error is logged without failing SyncTick",
			resp: crowdsec.StreamResponse{
				New: []crowdsec.Decision{
					{Origin: "custom_cscli", Type: "block", Scope: "Ip", Value: "192.0.2.2", Scenario: "ssh-bf", ID: 1},
				},
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			target := config.TargetConfig{
				Name:                    "target-empty-check",
				CFApiToken:              "tok-empty-check",
				CFAccountID:             "acc-empty-check",
				CFListID:                "list-empty-check",
				CFCommentPrefix:         "cs",
				AllowedOriginsSet:       map[string]struct{}{"custom_cscli": {}},
				AllowedDecisionTypesSet: map[string]struct{}{"block": {}},
			}

			mainCfg := config.MainConfig{
				Targets:      []config.TargetConfig{target},
				PollInterval: 10 * time.Millisecond,
			}

			mockCS := &mockCSStreamer{resp: tc.resp, err: tc.streamErr}
			mockCF := &mockCFManager{addErr: tc.addErr}
			factory := func(_ string) bouncer.CloudflareListManager {
				return mockCF
			}

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			b := bouncer.New(&mainCfg, mockCS, factory, logger)

			err := b.SyncTick(context.Background(), false)
			if (err != nil) != tc.wantErr {
				t.Fatalf("SyncTick() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestDecisionNormalizationAndFiltering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		newDec      []crowdsec.Decision
		delDec      []crowdsec.Decision
		wantAdded   int
		wantDeleted int
	}{
		{
			name: "unparseable or wide IP decisions are skipped",
			newDec: []crowdsec.Decision{
				{Origin: "parser", Type: "drop", Scope: "Ip", Value: "not-an-ip", Scenario: "bad-syntax"},
				{Origin: "analyzer", Type: "isolate", Scope: "Range", Value: "10.0.0.0/8", Scenario: "disallowed-wide-cidr"},
			},
			delDec: []crowdsec.Decision{
				{Origin: "filter", Type: "reject", Scope: "Country", Value: "US", Scenario: "unsupported-scope"},
			},
			wantAdded:   0,
			wantDeleted: 0,
		},
		{
			name: "origin allowed but decision type disallowed",
			newDec: []crowdsec.Decision{
				{Origin: "engine", Type: "captcha", Scope: "Ip", Value: "198.51.100.2", Scenario: "captcha-rule"},
			},
			delDec: []crowdsec.Decision{
				{Origin: "daemon", Type: "throttle", Scope: "Ip", Value: "198.51.100.3", Scenario: "throttle-rule"},
			},
			wantAdded:   0,
			wantDeleted: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			target := config.TargetConfig{
				Name:                    "target-norm-check",
				CFApiToken:              "tok-norm-check",
				CFAccountID:             "acc-norm-check",
				CFListID:                "list-norm-check",
				CFCommentPrefix:         "cs",
				AllowedOriginsSet:       map[string]struct{}{"engine": {}, "daemon": {}},
				AllowedDecisionTypesSet: map[string]struct{}{"drop": {}, "isolate": {}, "reject": {}},
			}

			mainCfg := config.MainConfig{
				Targets:      []config.TargetConfig{target},
				PollInterval: 10 * time.Millisecond,
			}

			mockCS := &mockCSStreamer{
				resp: crowdsec.StreamResponse{
					New:     tc.newDec,
					Deleted: tc.delDec,
				},
			}
			mockCF := &mockCFManager{}
			factory := func(_ string) bouncer.CloudflareListManager {
				return mockCF
			}

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			b := bouncer.New(&mainCfg, mockCS, factory, logger)

			if err := b.SyncTick(context.Background(), false); err != nil {
				t.Fatalf("SyncTick() unexpected error: %v", err)
			}

			if len(mockCF.addedItems) != tc.wantAdded {
				t.Errorf("got %d added items, want %d", len(mockCF.addedItems), tc.wantAdded)
			}
			if len(mockCF.deletedItems) != tc.wantDeleted {
				t.Errorf("got %d deleted items, want %d", len(mockCF.deletedItems), tc.wantDeleted)
			}
		})
	}
}

func TestApplyDeletions_Branches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		findErr     error
		deleteErr   error
		name        string
		foundUUID   string
		wantDeleted int
		notFound    bool
	}{
		{
			findErr:     errors.New("find failed"),
			deleteErr:   nil,
			name:        "find item returns error, continues without failure",
			foundUUID:   "",
			wantDeleted: 0,
			notFound:    false,
		},
		{
			findErr:     nil,
			deleteErr:   nil,
			name:        "item not found in list, early returns cleanly",
			foundUUID:   "",
			wantDeleted: 0,
			notFound:    true,
		},
		{
			findErr:     nil,
			deleteErr:   errors.New("delete failed"),
			name:        "delete items returns error, logged without failure",
			foundUUID:   "uuid-to-delete",
			wantDeleted: 0,
			notFound:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			target := config.TargetConfig{
				Name:                    "target-del-check",
				CFApiToken:              "tok-del-check",
				CFAccountID:             "acc-del-check",
				CFListID:                "list-del-check",
				CFCommentPrefix:         "cs",
				AllowedOriginsSet:       map[string]struct{}{"capi_feed": {}},
				AllowedDecisionTypesSet: map[string]struct{}{"deny": {}},
			}

			mainCfg := config.MainConfig{
				Targets:      []config.TargetConfig{target},
				PollInterval: 10 * time.Millisecond,
			}

			mockCS := &mockCSStreamer{
				resp: crowdsec.StreamResponse{
					Deleted: []crowdsec.Decision{
						{Origin: "capi_feed", Type: "deny", Scope: "Ip", Value: "203.0.113.1", Scenario: "manual-del"},
					},
				},
			}
			mockCF := &mockCFManager{
				findErr:   tc.findErr,
				deleteErr: tc.deleteErr,
				foundUUID: tc.foundUUID,
				notFound:  tc.notFound,
			}

			factory := func(_ string) bouncer.CloudflareListManager {
				return mockCF
			}

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			b := bouncer.New(&mainCfg, mockCS, factory, logger)

			if err := b.SyncTick(context.Background(), false); err != nil {
				t.Fatalf("SyncTick() unexpected error = %v", err)
			}
		})
	}
}

func TestRun_Scenarios(t *testing.T) {
	t.Parallel()

	tests := []struct {
		streamErr error
		name      string
		timeout   time.Duration
	}{
		{
			streamErr: nil,
			name:      "daemon advances on ticker and exits cleanly on timeout",
			timeout:   25 * time.Millisecond,
		},
		{
			streamErr: errors.New("tick stream error"),
			name:      "daemon logs tick error and continues until context canceled",
			timeout:   25 * time.Millisecond,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mainCfg := config.MainConfig{
				Targets:      []config.TargetConfig{},
				PollInterval: 5 * time.Millisecond,
			}

			mockCS := &mockCSStreamer{err: tc.streamErr}
			factory := func(_ string) bouncer.CloudflareListManager {
				return &mockCFManager{}
			}

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			b := bouncer.New(&mainCfg, mockCS, factory, logger)

			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()

			err := b.Run(ctx)
			if err != nil {
				t.Fatalf("Run() unexpected error: %v", err)
			}
		})
	}
}
