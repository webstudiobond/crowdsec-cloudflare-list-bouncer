package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/bouncer"
	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/cloudflare"
	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/config"
	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/crowdsec"
)

type mockCrowdSecClient struct {
	testConnErr error
}

func (m *mockCrowdSecClient) TestConnection(_ context.Context) error {
	return m.testConnErr
}

func (m *mockCrowdSecClient) StreamDecisions(_ context.Context, _ bool) (crowdsec.StreamResponse, error) {
	return crowdsec.StreamResponse{}, nil
}

type mockCloudflareClient struct {
	testConnErr error
}

func (m *mockCloudflareClient) TestConnection(_ context.Context, _, _ string) error {
	return m.testConnErr
}

func (m *mockCloudflareClient) AddItems(_ context.Context, _, _ string, _ []cloudflare.ItemPayload) error {
	return nil
}

func (m *mockCloudflareClient) FindItemByIP(_ context.Context, _, _, _ string) (cloudflare.ListItem, bool, error) {
	return cloudflare.ListItem{}, false, nil
}

func (m *mockCloudflareClient) DeleteItems(_ context.Context, _, _ string, _ []string) error {
	return nil
}

type mockDaemonRunnerWithFactory struct {
	factory func(token string) bouncer.CloudflareListManager
	runErr  error
}

func (m *mockDaemonRunnerWithFactory) Run(_ context.Context) error {
	if m.factory != nil {
		_ = m.factory("test-token")
	}
	return m.runErr
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	os.Stderr = w

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		if _, copyErr := io.Copy(&buf, r); copyErr != nil {
			t.Errorf("io.Copy failed: %v", copyErr)
		}
		outC <- buf.String()
	}()

	fn()

	if closeErr := w.Close(); closeErr != nil {
		t.Errorf("w.Close failed: %v", closeErr)
	}
	os.Stderr = oldStderr
	return <-outC
}

func createTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	targetsDir := filepath.Join(dir, "targets.d")
	if err := os.MkdirAll(targetsDir, 0o700); err != nil {
		t.Fatalf("mkdir targets failed: %v", err)
	}

	mainConf := fmt.Sprintf("api_url: http://127.0.0.1:8080/\napi_key: test-key\npoll_interval: 10s\nlog_level: info\nlog_type: text\ntargets_dir: %s\n", targetsDir)
	mainFile := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(mainFile, []byte(mainConf), 0o600); err != nil {
		t.Fatalf("write main config failed: %v", err)
	}

	targetConf := "name: test-target\ncf_api_token: test-token\ncf_account_id: test-account\ncf_list_id: test-list\ncf_comment_prefix: crowdsec\nallowed_origins:\n  - cscli\nallowed_decision_types:\n  - ban\n"
	targetFile := filepath.Join(targetsDir, "main.yaml")
	if err := os.WriteFile(targetFile, []byte(targetConf), 0o600); err != nil {
		t.Fatalf("write target config failed: %v", err)
	}

	return mainFile
}

func TestMain(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()

	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	tests := []struct {
		name       string
		wantStderr string
		flags      []string
		wantCode   int
		wantExit   bool
	}{
		{
			name:     "version flag exits without error",
			flags:    []string{"-v"},
			wantExit: false,
		},
		{
			name:     "help flag exits with code 0",
			flags:    []string{"-h"},
			wantExit: true,
			wantCode: 0,
		},
		{
			name:       "unknown flag exits with code 1",
			flags:      []string{"-unknown-flag-xyz"},
			wantExit:   true,
			wantCode:   1,
			wantStderr: "flag provided but not defined: -unknown-flag-xyz",
		},
		{
			name:       "non-existent config file exits with code 1",
			flags:      []string{"-c", "/path/to/non_existent_config_file.yaml"},
			wantExit:   true,
			wantCode:   1,
			wantStderr: "configuration error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exited := false
			exitCode := -1
			osExit = func(code int) {
				exited = true
				exitCode = code
			}

			os.Args = append([]string{"crowdsec-cloudflare-list-bouncer"}, tt.flags...)
			stderr := captureStderr(t, func() {
				main()
			})

			if exited != tt.wantExit {
				t.Fatalf("expected exited=%v, got %v", tt.wantExit, exited)
			}
			if tt.wantExit && exitCode != tt.wantCode {
				t.Fatalf("expected exitCode=%d, got %d", tt.wantCode, exitCode)
			}
			if tt.wantStderr != "" && !strings.Contains(stderr, tt.wantStderr) {
				t.Fatalf("expected stderr to contain %q, got %q", tt.wantStderr, stderr)
			}
		})
	}
}

type failWriter struct{}

func (f *failWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("simulated write failure")
}

func TestRun(t *testing.T) {
	testConfigFile := createTestConfig(t)

	origCS := newCrowdSecClient
	origCF := newCloudflareClient
	origBouncer := newBouncer
	defer func() {
		newCrowdSecClient = origCS
		newCloudflareClient = origCF
		newBouncer = origBouncer
	}()

	newCrowdSecClient = func(string, string, string, *http.Client) crowdsecChecker {
		return &mockCrowdSecClient{}
	}
	newCloudflareClient = func(string, *http.Client) cloudflareChecker {
		return &mockCloudflareClient{}
	}
	newBouncer = func(_ *config.MainConfig, _ bouncer.CrowdSecStreamer, cf func(token string) bouncer.CloudflareListManager, _ *slog.Logger) daemonRunner {
		return &mockDaemonRunnerWithFactory{factory: cf}
	}

	tests := []struct {
		name       string
		wantOutput string
		args       []string
		failOut    bool
		wantErr    bool
	}{
		{
			name:       "version output",
			wantOutput: "crowdsec-cloudflare-list-bouncer dev\n",
			args:       []string{"-v"},
			failOut:    false,
			wantErr:    false,
		},
		{
			name:    "version output write error",
			args:    []string{"-v"},
			failOut: true,
			wantErr: true,
		},
		{
			name:    "unknown flag",
			args:    []string{"-invalid-arg-123"},
			failOut: false,
			wantErr: true,
		},
		{
			name:    "help flag",
			args:    []string{"-h"},
			failOut: false,
			wantErr: true,
		},
		{
			name:    "missing config file",
			args:    []string{"-c", "/missing/config.yaml"},
			failOut: false,
			wantErr: true,
		},
		{
			name:    "test mode execution success",
			args:    []string{"-c", testConfigFile, "-t"},
			failOut: false,
			wantErr: false,
		},
		{
			name:    "daemon mode execution success",
			args:    []string{"-c", testConfigFile},
			failOut: false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout io.Writer = &bytes.Buffer{}
			if tt.failOut {
				stdout = &failWriter{}
			}
			var stderr bytes.Buffer
			err := run(tt.args, stdout, &stderr)

			if (err != nil) != tt.wantErr {
				t.Fatalf("run() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if buf, ok := stdout.(*bytes.Buffer); ok && tt.wantOutput != "" && buf.String() != tt.wantOutput {
				t.Fatalf("stdout got %q, want %q", buf.String(), tt.wantOutput)
			}
		})
	}
}

func TestSetupLogger(t *testing.T) {
	tests := []struct {
		name    string
		logType string
		level   slog.Level
	}{
		{
			name:    "json handler with debug level",
			logType: "json",
			level:   slog.LevelDebug,
		},
		{
			name:    "text handler with info level",
			logType: "text",
			level:   slog.LevelInfo,
		},
		{
			name:    "fallback to text handler on other type",
			logType: "unknown",
			level:   slog.LevelWarn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := setupLogger(tt.level, tt.logType, &buf)
			if logger == nil {
				t.Fatal("expected non-nil logger")
			}
			logger.Log(context.Background(), tt.level, "test message")
			if buf.Len() == 0 {
				t.Fatal("expected logger output in buffer")
			}
		})
	}
}

func TestRunTestMode(t *testing.T) {
	origCS := newCrowdSecClient
	origCF := newCloudflareClient
	defer func() {
		newCrowdSecClient = origCS
		newCloudflareClient = origCF
	}()

	cfg := &config.MainConfig{
		APIURL: "http://127.0.0.1:8080/",
		APIKey: "test-key",
		Targets: []config.TargetConfig{
			{
				Name:        "target-alpha",
				CFApiToken:  "token-alpha",
				CFAccountID: "account-alpha",
				CFListID:    "list-alpha",
			},
		},
	}
	var buf bytes.Buffer
	logger := setupLogger(slog.LevelInfo, "text", &buf)

	tests := []struct {
		csErr      error
		cfErr      error
		name       string
		wantSubstr string
		wantErr    bool
	}{
		{
			name:    "all checks pass",
			csErr:   nil,
			cfErr:   nil,
			wantErr: false,
		},
		{
			csErr:      errors.New("lapi unreachable"),
			cfErr:      nil,
			name:       "crowdsec connection failure",
			wantSubstr: "crowdsec connection failed",
			wantErr:    true,
		},
		{
			csErr:      nil,
			cfErr:      errors.New("invalid list id"),
			name:       "cloudflare target check failure",
			wantSubstr: "cloudflare target \"target-alpha\" check failed",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newCrowdSecClient = func(string, string, string, *http.Client) crowdsecChecker {
				return &mockCrowdSecClient{testConnErr: tt.csErr}
			}
			newCloudflareClient = func(string, *http.Client) cloudflareChecker {
				return &mockCloudflareClient{testConnErr: tt.cfErr}
			}

			err := runTestMode(context.Background(), cfg, logger)
			if (err != nil) != tt.wantErr {
				t.Fatalf("runTestMode() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantSubstr != "" && !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantSubstr, err.Error())
			}
		})
	}
}

func TestRunDaemon(t *testing.T) {
	origCS := newCrowdSecClient
	origCF := newCloudflareClient
	origBouncer := newBouncer
	defer func() {
		newCrowdSecClient = origCS
		newCloudflareClient = origCF
		newBouncer = origBouncer
	}()

	newCrowdSecClient = func(string, string, string, *http.Client) crowdsecChecker {
		return &mockCrowdSecClient{}
	}
	newCloudflareClient = func(string, *http.Client) cloudflareChecker {
		return &mockCloudflareClient{}
	}

	cfg := &config.MainConfig{}
	var buf bytes.Buffer
	logger := setupLogger(slog.LevelInfo, "text", &buf)

	tests := []struct {
		runErr     error
		name       string
		wantSubstr string
		wantErr    bool
	}{
		{
			name:    "daemon terminates cleanly on context cancellation",
			runErr:  nil,
			wantErr: false,
		},
		{
			runErr:     errors.New("fatal sync error"),
			name:       "daemon returns fatal error",
			wantSubstr: "daemon error",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newBouncer = func(_ *config.MainConfig, _ bouncer.CrowdSecStreamer, cf func(token string) bouncer.CloudflareListManager, _ *slog.Logger) daemonRunner {
				return &mockDaemonRunnerWithFactory{
					factory: cf,
					runErr:  tt.runErr,
				}
			}

			err := runDaemon(context.Background(), cfg, logger)
			if (err != nil) != tt.wantErr {
				t.Fatalf("runDaemon() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantSubstr != "" && !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantSubstr, err.Error())
			}
		})
	}
}

func TestDefaultFactories(t *testing.T) {
	cs := defaultNewCrowdSecClient("http://127.0.0.1:8080/", "test-key", "dev", nil)
	if cs == nil {
		t.Fatal("expected non-nil crowdsec client")
	}

	cf := defaultNewCloudflareClient("test-token", nil)
	if cf == nil {
		t.Fatal("expected non-nil cloudflare client")
	}

	cfg := &config.MainConfig{}
	var buf bytes.Buffer
	logger := setupLogger(slog.LevelInfo, "text", &buf)

	b := defaultNewBouncer(cfg, nil, nil, logger)
	if b == nil {
		t.Fatal("expected non-nil bouncer")
	}
}
