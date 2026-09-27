package config_test

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/config"
)

func TestLoad(t *testing.T) {
	tempDir := t.TempDir()
	targetsDir := filepath.Join(tempDir, "cf-targets")
	if err := os.Mkdir(targetsDir, 0o700); err != nil {
		t.Fatalf("failed to create targets dir: %v", err)
	}

	validTargetContent := `
name: target-alpha
cf_api_token: dummy_cf_token
cf_account_id: dummy_acc_id
cf_list_id: dummy_list_id
cf_comment_prefix: custom_cs
allowed_origins:
  - crowdsec
  - cscli
allowed_decision_types:
  - ban
`
	targetFile := filepath.Join(targetsDir, "target.yaml")
	if err := os.WriteFile(targetFile, []byte(validTargetContent), 0o600); err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	mainConfigContent := `
api_url: http://127.0.0.1:8080
api_key: dummy_lapi_key
poll_interval: 5s
log_level: debug
log_type: json
targets_dir: ` + targetsDir + `
`
	mainConfigFile := filepath.Join(tempDir, "main_config.yaml")
	if err := os.WriteFile(mainConfigFile, []byte(mainConfigContent), 0o600); err != nil {
		t.Fatalf("failed to write main config: %v", err)
	}

	cfg, err := config.Load(mainConfigFile)
	if err != nil {
		t.Fatalf("unexpected Load error: %v", err)
	}

	if cfg.APIURL != "http://127.0.0.1:8080/" {
		t.Errorf("APIURL = %q, want %q", cfg.APIURL, "http://127.0.0.1:8080/")
	}
	if cfg.APIKey != "dummy_lapi_key" {
		t.Errorf("APIKey = %q, want dummy_lapi_key", cfg.APIKey)
	}
	if cfg.PollInterval != 5*time.Second {
		t.Errorf("PollInterval = %v, want 5s", cfg.PollInterval)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v, want debug", cfg.LogLevel)
	}
	if cfg.LogType != "json" {
		t.Errorf("LogType = %q, want json", cfg.LogType)
	}
	if len(cfg.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(cfg.Targets))
	}

	target := cfg.Targets[0]
	if target.Name != "target-alpha" {
		t.Errorf("target Name = %q, want target-alpha", target.Name)
	}
	if target.CFCommentPrefix != "custom_cs" {
		t.Errorf("target CFCommentPrefix = %q, want custom_cs", target.CFCommentPrefix)
	}
	if _, ok := target.AllowedOriginsSet["crowdsec"]; !ok {
		t.Errorf("expected crowdsec in AllowedOriginsSet")
	}
	if _, ok := target.AllowedDecisionTypesSet["ban"]; !ok {
		t.Errorf("expected ban in AllowedDecisionTypesSet")
	}
}

func TestLoadValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		mainContent string
		targetData  string
		wantErr     bool
	}{
		{
			name: "missing api key",
			mainContent: `
api_url: http://127.0.0.1:8080
poll_interval: 10s
`,
			wantErr: true,
		},
		{
			name: "invalid poll interval",
			mainContent: `
poll_interval: invalid_duration
`,
			wantErr: true,
		},
		{
			name: "invalid log level",
			mainContent: `
log_level: verbose_unsupported
`,
			wantErr: true,
		},
		{
			name: "unset environment variable",
			mainContent: `
api_key: ${UNSET_TEST_VAR_XYZ}
`,
			wantErr: true,
		},
		{
			name: "target missing cf_account_id",
			targetData: `
cf_api_token: incomplete_token
`,
			wantErr: true,
		},
		{
			name: "target missing cf_api_token",
			targetData: `
cf_account_id: valid_acc
cf_list_id: valid_list
`,
			wantErr: true,
		},
		{
			name: "target missing cf_list_id",
			targetData: `
cf_api_token: valid_tok
cf_account_id: valid_acc
`,
			wantErr: true,
		},
		{
			name: "target syntax error",
			targetData: `
target_broken_line_without_colon
`,
			wantErr: true,
		},
		{
			name: "target scalar unset env var",
			targetData: `
cf_api_token: ${MISSING_CF_TOKEN}
cf_account_id: valid_acc
cf_list_id: valid_list
`,
			wantErr: true,
		},
		{
			name: "target list unset env var",
			targetData: `
cf_api_token: valid_tok
cf_account_id: valid_acc
cf_list_id: valid_list
allowed_origins:
  - ${MISSING_CF_ORIGIN}
`,
			wantErr: true,
		},
		{
			name: "main config syntax error",
			mainContent: `
main_broken_line_without_colon
`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			targetsDir := filepath.Join(tempDir, "validation-targets")
			if err := os.Mkdir(targetsDir, 0o700); err != nil {
				t.Fatalf("failed to create targets dir: %v", err)
			}

			targetData := tc.targetData
			if targetData == "" {
				targetData = `
cf_api_token: valid_tok
cf_account_id: valid_acc
cf_list_id: valid_list
`
			}

			targetFile := filepath.Join(targetsDir, "target.yaml")
			if err := os.WriteFile(targetFile, []byte(targetData), 0o600); err != nil {
				t.Fatalf("failed to write target: %v", err)
			}

			mainContent := tc.mainContent
			if mainContent == "" {
				mainContent = "api_key: key\n"
			}
			mainContent += "targets_dir: " + targetsDir + "\n"
			mainConfigFile := filepath.Join(tempDir, "val_config.yaml")
			if err := os.WriteFile(mainConfigFile, []byte(mainContent), 0o600); err != nil {
				t.Fatalf("failed to write main config: %v", err)
			}

			_, err := config.Load(mainConfigFile)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Load() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestDirectEnvOverrides(t *testing.T) {
	tempDir := t.TempDir()
	targetsDir := filepath.Join(tempDir, "env-targets")
	if err := os.Mkdir(targetsDir, 0o700); err != nil {
		t.Fatalf("failed to create targets dir: %v", err)
	}

	targetContent := `
cf_api_token: token123
cf_account_id: acc123
cf_list_id: list123
`
	if err := os.WriteFile(filepath.Join(targetsDir, "test.yaml"), []byte(targetContent), 0o600); err != nil {
		t.Fatalf("failed to write target: %v", err)
	}

	mainContent := `
api_url: http://127.0.0.1:8080/
api_key: initial_key
poll_interval: 30s
log_level: info
log_type: text
targets_dir: ` + targetsDir + `
`
	mainConfigFile := filepath.Join(tempDir, "override_config.yaml")
	if err := os.WriteFile(mainConfigFile, []byte(mainContent), 0o600); err != nil {
		t.Fatalf("failed to write main config: %v", err)
	}

	t.Setenv("CS_LAPI_URL", "http://192.0.2.10:8080")
	t.Setenv("CS_LAPI_KEY", "overridden_key")
	t.Setenv("POLL_INTERVAL", "2s")
	t.Setenv("LOG_LEVEL", "warn")
	t.Setenv("LOG_TYPE", "json")

	cfg, err := config.Load(mainConfigFile)
	if err != nil {
		t.Fatalf("unexpected Load error: %v", err)
	}

	if cfg.APIURL != "http://192.0.2.10:8080/" {
		t.Errorf("APIURL = %q, want http://192.0.2.10:8080/", cfg.APIURL)
	}
	if cfg.APIKey != "overridden_key" {
		t.Errorf("APIKey = %q, want overridden_key", cfg.APIKey)
	}
	if cfg.PollInterval != 2*time.Second {
		t.Errorf("PollInterval = %v, want 2s", cfg.PollInterval)
	}
	if cfg.LogLevel != slog.LevelWarn {
		t.Errorf("LogLevel = %v, want warn", cfg.LogLevel)
	}
	if cfg.LogType != "json" {
		t.Errorf("LogType = %q, want json", cfg.LogType)
	}
}

func TestLoad_NonExistentFile(t *testing.T) {
	tempDir := t.TempDir()
	missingFile := filepath.Join(tempDir, "does-not-exist.yaml")
	_, err := config.Load(missingFile)
	if err == nil {
		t.Fatalf("expected error for nonexistent config file, got nil")
	}
}

func TestLoadTargets_FilteringAndErrors(t *testing.T) {
	tempDir := t.TempDir()

	if _, err := config.LoadTargets(filepath.Join(tempDir, "missing-dir")); err == nil {
		t.Fatalf("expected error for nonexistent targets dir, got nil")
	}

	emptyDir := filepath.Join(tempDir, "empty-dir")
	if err := os.Mkdir(emptyDir, 0o700); err != nil {
		t.Fatalf("failed to create empty dir: %v", err)
	}
	if _, err := config.LoadTargets(emptyDir); err == nil || !errors.Is(err, config.ErrNoTargetsFound) {
		t.Fatalf("expected ErrNoTargetsFound, got %v", err)
	}

	filterDir := filepath.Join(tempDir, "filter-dir")
	if err := os.Mkdir(filterDir, 0o700); err != nil {
		t.Fatalf("failed to create filter dir: %v", err)
	}
	if err := os.Mkdir(filepath.Join(filterDir, "nested-subdir"), 0o700); err != nil {
		t.Fatalf("failed to create nested dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(filterDir, "ignore.txt"), []byte("not yaml"), 0o600); err != nil {
		t.Fatalf("failed to write ignore.txt: %v", err)
	}
	ymlTarget := `
cf_api_token: yml_tok
cf_account_id: yml_acc
cf_list_id: yml_list
`
	if err := os.WriteFile(filepath.Join(filterDir, "target.yml"), []byte(ymlTarget), 0o600); err != nil {
		t.Fatalf("failed to write yml target: %v", err)
	}

	targets, err := config.LoadTargets(filterDir)
	if err != nil {
		t.Fatalf("unexpected LoadTargets error: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target from yml file, got %d", len(targets))
	}

	badTargetDir := filepath.Join(tempDir, "bad-target-dir")
	if err := os.Mkdir(badTargetDir, 0o700); err != nil {
		t.Fatalf("failed to create bad target dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(badTargetDir, "syntax_error.yaml"), []byte("broken_target_without_colon"), 0o600); err != nil {
		t.Fatalf("failed to write bad target: %v", err)
	}
	if _, err := config.LoadTargets(badTargetDir); err == nil {
		t.Fatalf("expected error for syntax error in target, got nil")
	}
}
