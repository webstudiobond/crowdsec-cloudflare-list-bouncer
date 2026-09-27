// Package bouncer orchestrates decision streaming from CrowdSec LAPI
// and propagates qualified IP bans to configured Cloudflare list targets.
package bouncer

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/cloudflare"
	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/config"
	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/crowdsec"
	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/netutil"
)

// CrowdSecStreamer abstracts decision streaming operations for testing and decoupling.
type CrowdSecStreamer interface {
	StreamDecisions(ctx context.Context, startup bool) (crowdsec.StreamResponse, error)
}

// CloudflareListManager abstracts account list modifications for testing and decoupling.
type CloudflareListManager interface {
	AddItems(ctx context.Context, accountID, listID string, items []cloudflare.ItemPayload) error
	FindItemByIP(ctx context.Context, accountID, listID, ip string) (cloudflare.ListItem, bool, error)
	DeleteItems(ctx context.Context, accountID, listID string, itemIDs []string) error
}

type additionItem struct {
	Payload  cloudflare.ItemPayload
	Scenario string
	Origin   string
}

type deletionItem struct {
	IP       string
	Scenario string
	Origin   string
}

type targetBatch struct {
	Additions []additionItem
	Deletions []deletionItem
}

type targetRunner struct {
	cfClient CloudflareListManager
	logger   *slog.Logger
	cfg      config.TargetConfig
}

// Bouncer encapsulates the state and dependencies required for synchronization.
type Bouncer struct {
	csClient CrowdSecStreamer
	logger   *slog.Logger
	targets  []targetRunner
	cfg      config.MainConfig
}

// New constructs an initialized Bouncer with all configured target runners.
func New(cfg *config.MainConfig, csClient CrowdSecStreamer, cfClientFactory func(token string) CloudflareListManager, logger *slog.Logger) *Bouncer {
	runners := make([]targetRunner, 0, len(cfg.Targets))
	for i := range cfg.Targets {
		targetCfg := cfg.Targets[i]
		runners = append(runners, targetRunner{
			cfg:      targetCfg,
			cfClient: cfClientFactory(targetCfg.CFApiToken),
			logger:   logger.With("target", targetCfg.Name),
		})
	}

	return &Bouncer{
		cfg:      *cfg,
		csClient: csClient,
		targets:  runners,
		logger:   logger,
	}
}

// Run executes the continuous synchronization loop until the context is canceled.
func (b *Bouncer) Run(ctx context.Context) error {
	b.logger.Info("starting crowdsec to cloudflare synchronization daemon",
		"targets", len(b.targets),
		"poll_interval", b.cfg.PollInterval,
	)

	startup := true
	ticker := time.NewTicker(b.cfg.PollInterval)
	defer ticker.Stop()

	for {
		if err := b.SyncTick(ctx, startup); err != nil {
			b.logger.Error("synchronization tick failed", "error", err)
		}
		startup = false

		select {
		case <-ctx.Done():
			b.logger.Info("shutting down synchronization daemon")
			return nil
		case <-ticker.C:
		}
	}
}

// SyncTick performs a single stream poll and distributes additions and deletions to all targets.
func (b *Bouncer) SyncTick(ctx context.Context, startup bool) error {
	streamResp, err := b.csClient.StreamDecisions(ctx, startup)
	if err != nil {
		return fmt.Errorf("fetch decisions stream: %w", err)
	}

	if len(streamResp.New) == 0 && len(streamResp.Deleted) == 0 {
		return nil
	}

	batches := b.prepareBatches(streamResp)

	for i := range b.targets {
		runner := &b.targets[i]
		batch := batches[i]

		if batchErr := b.applyBatch(ctx, runner, batch); batchErr != nil {
			runner.logger.Error("failed applying batch updates", "error", batchErr)
		}
	}

	return nil
}

func (b *Bouncer) prepareBatches(streamResp crowdsec.StreamResponse) []*targetBatch {
	batches := make([]*targetBatch, len(b.targets))
	for i := range b.targets {
		batches[i] = &targetBatch{
			Additions: make([]additionItem, 0),
			Deletions: make([]deletionItem, 0),
		}
	}

	for i := range streamResp.New {
		b.dispatchNewDecision(&streamResp.New[i], batches)
	}

	for i := range streamResp.Deleted {
		b.dispatchDeletedDecision(&streamResp.Deleted[i], batches)
	}

	return batches
}

func (b *Bouncer) dispatchNewDecision(decision *crowdsec.Decision, batches []*targetBatch) {
	normIP, ok := netutil.NormalizeIP(decision.Scope, decision.Value)
	if !ok {
		b.logger.Debug("skipping decision with unparseable or out-of-range IP",
			"scope", decision.Scope,
			"value", decision.Value,
		)
		return
	}

	for i := range b.targets {
		runner := &b.targets[i]
		if !b.isDecisionAllowed(&runner.cfg, decision.Origin, decision.Type) {
			continue
		}

		comment := fmt.Sprintf("%s:%s", runner.cfg.CFCommentPrefix, decision.Scenario)
		batches[i].Additions = append(batches[i].Additions, additionItem{
			Payload: cloudflare.ItemPayload{
				IP:      normIP,
				Comment: comment,
			},
			Scenario: decision.Scenario,
			Origin:   decision.Origin,
		})
	}
}

func (b *Bouncer) dispatchDeletedDecision(decision *crowdsec.Decision, batches []*targetBatch) {
	normIP, ok := netutil.NormalizeIP(decision.Scope, decision.Value)
	if !ok {
		return
	}

	for i := range b.targets {
		runner := &b.targets[i]
		if !b.isDecisionAllowed(&runner.cfg, decision.Origin, decision.Type) {
			continue
		}

		batches[i].Deletions = append(batches[i].Deletions, deletionItem{
			IP:       normIP,
			Scenario: decision.Scenario,
			Origin:   decision.Origin,
		})
	}
}

func (b *Bouncer) applyBatch(ctx context.Context, runner *targetRunner, batch *targetBatch) error {
	if len(batch.Additions) > 0 {
		if err := b.applyAdditions(ctx, runner, batch.Additions); err != nil {
			return err
		}
	}

	if len(batch.Deletions) > 0 {
		if err := b.applyDeletions(ctx, runner, batch.Deletions); err != nil {
			return err
		}
	}

	return nil
}

func (b *Bouncer) applyAdditions(ctx context.Context, runner *targetRunner, additions []additionItem) error {
	payloads := make([]cloudflare.ItemPayload, len(additions))
	for i := range additions {
		payloads[i] = additions[i].Payload
	}

	if err := runner.cfClient.AddItems(ctx, runner.cfg.CFAccountID, runner.cfg.CFListID, payloads); err != nil {
		return fmt.Errorf("add items to target %s: %w", runner.cfg.Name, err)
	}

	for _, item := range additions {
		runner.logger.Info("added IP to cloudflare list",
			"ip", item.Payload.IP,
			"origin", item.Origin,
			"reason", item.Scenario,
		)
	}
	return nil
}

func (b *Bouncer) applyDeletions(ctx context.Context, runner *targetRunner, deletions []deletionItem) error {
	itemIDs := make([]string, 0, len(deletions))
	deletedItems := make([]deletionItem, 0, len(deletions))

	for _, del := range deletions {
		item, found, err := runner.cfClient.FindItemByIP(ctx, runner.cfg.CFAccountID, runner.cfg.CFListID, del.IP)
		if err != nil {
			runner.logger.Warn("failed searching item by IP for deletion", "ip", del.IP, "origin", del.Origin, "reason", del.Scenario, "error", err)
			continue
		}
		if !found {
			runner.logger.Debug("item not found in cloudflare list, already removed", "ip", del.IP, "origin", del.Origin, "reason", del.Scenario)
			continue
		}
		itemIDs = append(itemIDs, item.ID)
		deletedItems = append(deletedItems, del)
	}

	if len(itemIDs) == 0 {
		return nil
	}

	if err := runner.cfClient.DeleteItems(ctx, runner.cfg.CFAccountID, runner.cfg.CFListID, itemIDs); err != nil {
		return fmt.Errorf("delete items from target %s: %w", runner.cfg.Name, err)
	}

	for _, del := range deletedItems {
		runner.logger.Info("removed IP from cloudflare list",
			"ip", del.IP,
			"origin", del.Origin,
			"reason", del.Scenario,
		)
	}
	return nil
}

func (b *Bouncer) isDecisionAllowed(cfg *config.TargetConfig, origin, dType string) bool {
	if _, ok := cfg.AllowedOriginsSet[origin]; !ok {
		return false
	}
	if _, ok := cfg.AllowedDecisionTypesSet[dType]; !ok {
		return false
	}
	return true
}
