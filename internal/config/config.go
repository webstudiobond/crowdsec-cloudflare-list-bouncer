package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Sentinel errors returned during configuration loading and validation.
var (
	ErrMissingRequiredField     = errors.New("missing required configuration field")
	ErrInvalidValue             = errors.New("invalid configuration value")
	ErrNoTargetsFound           = errors.New("no target configurations found")
	ErrUnsetEnvironmentVariable = errors.New("unset environment variable in configuration")
)

func defaultFileClose(f *os.File) error {
	if err := f.Close(); err != nil {
		return fmt.Errorf("close file: %w", err)
	}
	return nil
}

var fileClose = defaultFileClose

const (
	defaultAPIURL          = "http://127.0.0.1:8080/"
	defaultPollInterval    = 10 * time.Second
	defaultLogType         = "text"
	defaultTargetsDir      = "/etc/crowdsec/bouncers/cloudflare-list-targets.d/"
	defaultCFCommentPrefix = "crowdsec"
)

// TargetConfig represents an individual Cloudflare account and destination list target.
type TargetConfig struct {
	Name                    string
	CFApiToken              string
	CFAccountID             string
	CFListID                string
	CFCommentPrefix         string
	AllowedOriginsSet       map[string]struct{}
	AllowedDecisionTypesSet map[string]struct{}
	AllowedOrigins          []string
	AllowedDecisionTypes    []string
}

// MainConfig aggregates the primary daemon settings and all active Cloudflare sync targets.
type MainConfig struct {
	APIURL       string
	APIKey       string
	LogType      string
	TargetsDir   string
	Targets      []TargetConfig
	PollInterval time.Duration
	LogLevel     slog.Level
}

// Load reads and validates the primary configuration file and its associated target directory.
func Load(mainConfigPath string) (MainConfig, error) {
	cfg := MainConfig{
		Targets:      make([]TargetConfig, 0),
		APIURL:       defaultAPIURL,
		LogType:      defaultLogType,
		TargetsDir:   defaultTargetsDir,
		PollInterval: defaultPollInterval,
		LogLevel:     slog.LevelInfo,
	}

	if mainConfigPath != "" {
		if err := loadMainFile(mainConfigPath, &cfg); err != nil {
			return MainConfig{}, fmt.Errorf("load main config %q: %w", mainConfigPath, err)
		}
	}

	applyMainEnvOverrides(&cfg)

	if cfg.APIKey == "" {
		return MainConfig{}, fmt.Errorf("%w: api_key (or CS_LAPI_KEY)", ErrMissingRequiredField)
	}

	targets, err := LoadTargets(cfg.TargetsDir)
	if err != nil {
		return MainConfig{}, fmt.Errorf("load targets from %q: %w", cfg.TargetsDir, err)
	}
	cfg.Targets = targets

	return cfg, nil
}

// LoadTargets discovers and parses all target definitions within the specified directory.
func LoadTargets(dirPath string) ([]TargetConfig, error) {
	entries, err := os.ReadDir(filepath.Clean(dirPath))
	if err != nil {
		return nil, fmt.Errorf("read targets directory: %w", err)
	}

	targets := make([]TargetConfig, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		targetPath := filepath.Join(dirPath, entry.Name())
		target, err := loadTargetFile(targetPath)
		if err != nil {
			return nil, fmt.Errorf("parse target %q: %w", targetPath, err)
		}
		targets = append(targets, target)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("%w in %s", ErrNoTargetsFound, dirPath)
	}

	return targets, nil
}

func loadMainFile(path string, cfg *MainConfig) (err error) {
	file, openErr := os.Open(filepath.Clean(path))
	if openErr != nil {
		return fmt.Errorf("open file: %w", openErr)
	}
	defer func() {
		if closeErr := fileClose(file); closeErr != nil && err == nil {
			err = fmt.Errorf("close file: %w", closeErr)
		}
	}()

	doc, docErr := ParseDocument(file)
	if docErr != nil {
		return fmt.Errorf("parse document: %w", docErr)
	}

	for k, v := range doc.Scalars {
		if scalarErr := applyMainScalar(cfg, k, v); scalarErr != nil {
			return scalarErr
		}
	}

	return nil
}

func applyMainScalar(cfg *MainConfig, key, val string) error {
	expanded, err := expandEnv(val)
	if err != nil {
		return err
	}

	switch key {
	case "api_url":
		cfg.APIURL = ensureTrailingSlash(expanded)
	case "api_key":
		cfg.APIKey = expanded
	case "poll_interval":
		dur, parseErr := time.ParseDuration(expanded)
		if parseErr != nil {
			return fmt.Errorf("%w: invalid poll_interval %q: %w", ErrInvalidValue, expanded, parseErr)
		}
		cfg.PollInterval = dur
	case "log_level":
		lvl, lvlErr := parseLogLevel(expanded)
		if lvlErr != nil {
			return lvlErr
		}
		cfg.LogLevel = lvl
	case "log_type":
		cfg.LogType = strings.ToLower(expanded)
	case "targets_dir":
		cfg.TargetsDir = expanded
	}
	return nil
}

func loadTargetFile(path string) (target TargetConfig, err error) {
	file, openErr := os.Open(filepath.Clean(path))
	if openErr != nil {
		return TargetConfig{}, fmt.Errorf("open file: %w", openErr)
	}
	defer func() {
		if closeErr := fileClose(file); closeErr != nil && err == nil {
			err = fmt.Errorf("close file: %w", closeErr)
		}
	}()

	doc, docErr := ParseDocument(file)
	if docErr != nil {
		return TargetConfig{}, fmt.Errorf("parse document: %w", docErr)
	}

	baseName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	target = TargetConfig{
		AllowedOrigins:          []string{"crowdsec", "cscli"},
		AllowedDecisionTypes:    []string{"ban"},
		AllowedOriginsSet:       make(map[string]struct{}),
		AllowedDecisionTypesSet: make(map[string]struct{}),
		Name:                    baseName,
		CFCommentPrefix:         defaultCFCommentPrefix,
	}

	for k, v := range doc.Scalars {
		if scalarErr := applyTargetScalar(&target, k, v); scalarErr != nil {
			return TargetConfig{}, scalarErr
		}
	}

	for k, list := range doc.Lists {
		if listErr := applyTargetList(&target, k, list); listErr != nil {
			return TargetConfig{}, listErr
		}
	}

	if target.CFApiToken == "" {
		return TargetConfig{}, fmt.Errorf("%w: cf_api_token in %s", ErrMissingRequiredField, path)
	}
	if target.CFAccountID == "" {
		return TargetConfig{}, fmt.Errorf("%w: cf_account_id in %s", ErrMissingRequiredField, path)
	}
	if target.CFListID == "" {
		return TargetConfig{}, fmt.Errorf("%w: cf_list_id in %s", ErrMissingRequiredField, path)
	}

	for _, origin := range target.AllowedOrigins {
		target.AllowedOriginsSet[origin] = struct{}{}
	}
	for _, dType := range target.AllowedDecisionTypes {
		target.AllowedDecisionTypesSet[dType] = struct{}{}
	}

	return target, nil
}

func applyTargetScalar(target *TargetConfig, key, val string) error {
	expanded, err := expandEnv(val)
	if err != nil {
		return err
	}

	switch key {
	case "name":
		if strings.TrimSpace(expanded) != "" {
			target.Name = expanded
		}
	case "cf_api_token":
		target.CFApiToken = expanded
	case "cf_account_id":
		target.CFAccountID = expanded
	case "cf_list_id":
		target.CFListID = expanded
	case "cf_comment_prefix":
		target.CFCommentPrefix = expanded
	}
	return nil
}

func applyTargetList(target *TargetConfig, key string, list []string) error {
	if len(list) == 0 {
		return nil
	}

	expandedList := make([]string, 0, len(list))
	for _, item := range list {
		expanded, err := expandEnv(item)
		if err != nil {
			return err
		}
		expandedList = append(expandedList, expanded)
	}

	switch key {
	case "allowed_origins":
		target.AllowedOrigins = expandedList
	case "allowed_decision_types":
		target.AllowedDecisionTypes = expandedList
	}
	return nil
}

func applyMainEnvOverrides(cfg *MainConfig) {
	if val := os.Getenv("CS_LAPI_URL"); val != "" {
		cfg.APIURL = ensureTrailingSlash(val)
	}
	if val := os.Getenv("CS_LAPI_KEY"); val != "" {
		cfg.APIKey = val
	}
	if val := os.Getenv("POLL_INTERVAL"); val != "" {
		if dur, err := time.ParseDuration(val); err == nil {
			cfg.PollInterval = dur
		}
	}
	if val := os.Getenv("LOG_LEVEL"); val != "" {
		if level, err := parseLogLevel(val); err == nil {
			cfg.LogLevel = level
		}
	}
	if val := os.Getenv("LOG_TYPE"); val != "" {
		cfg.LogType = strings.ToLower(val)
	}
	if val := os.Getenv("TARGETS_DIR"); val != "" {
		cfg.TargetsDir = val
	}
}

func parseLogLevel(val string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("%w: unknown log level %q", ErrInvalidValue, val)
	}
}

func ensureTrailingSlash(url string) string {
	if !strings.HasSuffix(url, "/") {
		return url + "/"
	}
	return url
}

func expandEnv(raw string) (string, error) {
	if !strings.Contains(raw, "${") {
		return raw, nil
	}

	result := raw
	for {
		start := strings.Index(result, "${")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "}")
		if end == -1 {
			break
		}
		end += start

		varName := result[start+2 : end]
		envVal, exists := os.LookupEnv(varName)
		if !exists || envVal == "" {
			return "", fmt.Errorf("%w: %q", ErrUnsetEnvironmentVariable, varName)
		}
		result = result[:start] + envVal + result[end+1:]
	}

	return result, nil
}
