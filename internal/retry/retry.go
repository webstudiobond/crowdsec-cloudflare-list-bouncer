// Package retry provides exponential backoff execution with cryptographically secure
// jitter for resilient network operations against rate-limited and transient APIs.
package retry

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Retryable represents errors that warrant subsequent re-attempts.
type Retryable interface {
	error
	IsRetryable() bool
}

func defaultRandRead(b []byte) error {
	_, _ = rand.Read(b)
	return nil
}

var randRead = defaultRandRead

// Do executes an operation repeatedly until it succeeds, exceeds maxAttempts,
// encounters a non-retryable error, or observes context cancellation.
func Do(ctx context.Context, maxAttempts int, baseDelay, maxDelay time.Duration, fn func(ctx context.Context) error) error {
	if maxAttempts <= 0 {
		maxAttempts = 1
	}

	var lastErr error
	delay := baseDelay

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("context ended after %d attempts (last error: %w): %w", attempt-1, lastErr, ctx.Err())
			}
			return fmt.Errorf("context ended: %w", ctx.Err())
		default:
		}

		err := fn(ctx)
		if err == nil {
			return nil
		}
		lastErr = err

		if attempt == maxAttempts {
			break
		}

		var retryable Retryable
		if !errors.As(err, &retryable) || !retryable.IsRetryable() {
			return err
		}

		sleepDuration := min(computeJitter(delay), maxDelay)

		timer := time.NewTimer(sleepDuration)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("context ended during backoff sleep: %w", ctx.Err())
		case <-timer.C:
		}

		delay = min(delay*2, maxDelay)
	}

	return fmt.Errorf("operation failed after %d attempts: %w", maxAttempts, lastErr)
}

func computeJitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}

	var buf [8]byte
	if err := randRead(buf[:]); err != nil {
		return base
	}

	val := binary.BigEndian.Uint64(buf[:]) % 501
	jittered := (base * time.Duration(750+val)) / 1000
	if jittered <= 0 {
		return base
	}
	return jittered
}
