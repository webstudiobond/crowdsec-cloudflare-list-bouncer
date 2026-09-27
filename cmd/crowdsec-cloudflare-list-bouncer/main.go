// Package main provides the command-line entrypoint and execution lifecycle
// for the CrowdSec Cloudflare IP list synchronization daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/bouncer"
	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/cloudflare"
	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/config"
	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/crowdsec"
)

// Version denotes the release version injected at link time.
var (
	Version = "dev"
)

const (
	defaultConfigPath = "/etc/crowdsec/bouncers/crowdsec-cloudflare-list-bouncer.yaml"
)

type crowdsecChecker interface {
	TestConnection(ctx context.Context) error
	StreamDecisions(ctx context.Context, startup bool) (crowdsec.StreamResponse, error)
}

type cloudflareChecker interface {
	TestConnection(ctx context.Context, accountID, listID string) error
	bouncer.CloudflareListManager
}

type daemonRunner interface {
	Run(ctx context.Context) error
}

func defaultNewCrowdSecClient(apiURL, apiKey, version string, httpClient *http.Client) crowdsecChecker {
	return crowdsec.NewClient(apiURL, apiKey, version, httpClient)
}

func defaultNewCloudflareClient(token string, httpClient *http.Client) cloudflareChecker {
	return cloudflare.NewClient(token, httpClient)
}

func defaultNewBouncer(cfg *config.MainConfig, cs bouncer.CrowdSecStreamer, cf func(token string) bouncer.CloudflareListManager, logger *slog.Logger) daemonRunner {
	return bouncer.New(cfg, cs, cf, logger)
}

var (
	osExit              = os.Exit
	newCrowdSecClient   = defaultNewCrowdSecClient
	newCloudflareClient = defaultNewCloudflareClient
	newBouncer          = defaultNewBouncer
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			osExit(0)
			return
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		osExit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("crowdsec-cloudflare-list-bouncer", flag.ContinueOnError)
	fs.SetOutput(stderr)

	configPath := fs.String("c", defaultConfigPath, "path to configuration file")
	testMode := fs.Bool("t", false, "test configuration and external connectivity then exit")
	versionMode := fs.Bool("v", false, "display application version and exit")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	if *versionMode {
		if _, err := fmt.Fprintf(stdout, "crowdsec-cloudflare-list-bouncer %s\n", Version); err != nil {
			return fmt.Errorf("write version: %w", err)
		}
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	logger := setupLogger(cfg.LogLevel, cfg.LogType, stdout)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *testMode {
		return runTestMode(ctx, &cfg, logger)
	}

	return runDaemon(ctx, &cfg, logger)
}

func setupLogger(level slog.Level, logType string, out io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if logType == "json" {
		handler = slog.NewJSONHandler(out, opts)
	} else {
		handler = slog.NewTextHandler(out, opts)
	}

	return slog.New(handler)
}

func runTestMode(ctx context.Context, cfg *config.MainConfig, logger *slog.Logger) error {
	logger.Info("validating configuration syntax and targets", "targets_count", len(cfg.Targets))

	csClient := newCrowdSecClient(cfg.APIURL, cfg.APIKey, Version, nil)
	if err := csClient.TestConnection(ctx); err != nil {
		logger.Error("CrowdSec LAPI connection failed", "url", cfg.APIURL, "error", err)
		return fmt.Errorf("crowdsec connection failed: %w", err)
	}
	logger.Info("CrowdSec LAPI connection successful", "url", cfg.APIURL)

	for i := range cfg.Targets {
		target := &cfg.Targets[i]
		cfClient := newCloudflareClient(target.CFApiToken, nil)
		if err := cfClient.TestConnection(ctx, target.CFAccountID, target.CFListID); err != nil {
			logger.Error("Cloudflare target check failed",
				"target", target.Name,
				"account_id", target.CFAccountID,
				"list_id", target.CFListID,
				"error", err,
			)
			return fmt.Errorf("cloudflare target %q check failed: %w", target.Name, err)
		}
		logger.Info("Cloudflare target check successful",
			"target", target.Name,
			"list_id", target.CFListID,
		)
	}

	logger.Info("all configuration and connectivity checks passed successfully")
	return nil
}

func runDaemon(ctx context.Context, cfg *config.MainConfig, logger *slog.Logger) error {
	csClient := newCrowdSecClient(cfg.APIURL, cfg.APIKey, Version, nil)
	factory := func(token string) bouncer.CloudflareListManager {
		return newCloudflareClient(token, nil)
	}

	b := newBouncer(cfg, csClient, factory, logger)
	if err := b.Run(ctx); err != nil {
		logger.Error("daemon terminated unexpectedly", "error", err)
		return fmt.Errorf("daemon error: %w", err)
	}
	return nil
}
