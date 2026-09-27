package config

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mockFileCloseFail(_ *os.File) error {
	return errors.New("simulated file close failure")
}

func TestDefaultFileClose(t *testing.T) {
	tempFile, err := os.CreateTemp(t.TempDir(), "close-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	if err := defaultFileClose(tempFile); err != nil {
		t.Fatalf("defaultFileClose() failed: %v", err)
	}

	if err := defaultFileClose(tempFile); err == nil {
		t.Fatalf("defaultFileClose() on already closed file expected error, got nil")
	}
}

func TestLoadMainFile_CloseError(t *testing.T) {
	prev := fileClose
	fileClose = mockFileCloseFail
	t.Cleanup(func() {
		fileClose = prev
	})

	tempDir := t.TempDir()
	mainFile := filepath.Join(tempDir, "main.yaml")
	if err := os.WriteFile(mainFile, []byte("api_key: secret-key\n"), 0o600); err != nil {
		t.Fatalf("write main file: %v", err)
	}

	var cfg MainConfig
	err := loadMainFile(mainFile, &cfg)
	if err == nil || !strings.Contains(err.Error(), "close file") {
		t.Fatalf("expected close error, got %v", err)
	}
}

func TestLoadTargetFile_CloseError(t *testing.T) {
	prev := fileClose
	fileClose = mockFileCloseFail
	t.Cleanup(func() {
		fileClose = prev
	})

	tempDir := t.TempDir()
	targetFile := filepath.Join(tempDir, "target.yaml")
	content := "cf_api_token: sample-tok\ncf_account_id: sample-acc\ncf_list_id: sample-list\n"
	if err := os.WriteFile(targetFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write target file: %v", err)
	}

	_, err := loadTargetFile(targetFile)
	if err == nil || !strings.Contains(err.Error(), "close file") {
		t.Fatalf("expected close error, got %v", err)
	}
}

func TestLoadTargetFile_NonExistent(t *testing.T) {
	_, err := loadTargetFile("/nonexistent/target/path.yaml")
	if err == nil {
		t.Fatalf("expected error for nonexistent target file, got nil")
	}
}

func TestExpandEnv_UnclosedAndMultiple(t *testing.T) {
	unclosedRes, err := expandEnv("prefix_${UNCLOSED_VAR")
	if err != nil {
		t.Fatalf("unexpected error for unclosed env var: %v", err)
	}
	if unclosedRes != "prefix_${UNCLOSED_VAR" {
		t.Fatalf("expandEnv() = %q, want prefix_${UNCLOSED_VAR", unclosedRes)
	}

	t.Setenv("TEST_MULT_VAR_A", "first")
	t.Setenv("TEST_MULT_VAR_B", "second")
	multiRes, err := expandEnv("${TEST_MULT_VAR_A}_${TEST_MULT_VAR_B}")
	if err != nil {
		t.Fatalf("unexpected error for multi env vars: %v", err)
	}
	if multiRes != "first_second" {
		t.Fatalf("expandEnv() = %q, want first_second", multiRes)
	}
}

func TestApplyTargetList_EmptyAndErrors(t *testing.T) {
	var target TargetConfig
	if err := applyTargetList(&target, "allowed_origins", nil); err != nil {
		t.Fatalf("applyTargetList() on nil slice error = %v, want nil", err)
	}

	err := applyTargetList(&target, "allowed_origins", []string{"${UNSET_ORIGIN_SPECIFIC}"})
	if err == nil || !errors.Is(err, ErrUnsetEnvironmentVariable) {
		t.Fatalf("applyTargetList() error = %v, want ErrUnsetEnvironmentVariable", err)
	}
}

func TestApplyTargetScalar_ExpandEnvError(t *testing.T) {
	var target TargetConfig
	err := applyTargetScalar(&target, "cf_api_token", "${UNSET_SCALAR_SPECIFIC}")
	if err == nil || !errors.Is(err, ErrUnsetEnvironmentVariable) {
		t.Fatalf("applyTargetScalar() error = %v, want ErrUnsetEnvironmentVariable", err)
	}
}

func TestParseLogLevel_Variants(t *testing.T) {
	lvlError, err := parseLogLevel("error")
	if err != nil || lvlError != slog.LevelError {
		t.Fatalf("parseLogLevel(error) = %v, err = %v", lvlError, err)
	}

	lvlWarn, err := parseLogLevel("warning")
	if err != nil || lvlWarn != slog.LevelWarn {
		t.Fatalf("parseLogLevel(warning) = %v, err = %v", lvlWarn, err)
	}
}

func TestApplyMainEnvOverrides_TargetsDir(t *testing.T) {
	t.Setenv("TARGETS_DIR", "/custom/targets/directory")
	var cfg MainConfig
	applyMainEnvOverrides(&cfg)
	if cfg.TargetsDir != "/custom/targets/directory" {
		t.Fatalf("TargetsDir = %q, want /custom/targets/directory", cfg.TargetsDir)
	}
}
