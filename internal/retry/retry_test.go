package retry_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/retry"
)

type mockRetryableError struct {
	msg       string
	retryable bool
}

func (m *mockRetryableError) Error() string {
	return m.msg
}

func (m *mockRetryableError) IsRetryable() bool {
	return m.retryable
}

func TestDo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		maxAttempts int
		failCount   int
		retryable   bool
		wantErr     bool
		wantCalls   int
	}{
		{
			name:        "immediate success on first try",
			maxAttempts: 3,
			failCount:   0,
			retryable:   false,
			wantErr:     false,
			wantCalls:   1,
		},
		{
			name:        "success after two retryable failures",
			maxAttempts: 4,
			failCount:   2,
			retryable:   true,
			wantErr:     false,
			wantCalls:   3,
		},
		{
			name:        "stops immediately on non-retryable error",
			maxAttempts: 5,
			failCount:   3,
			retryable:   false,
			wantErr:     true,
			wantCalls:   1,
		},
		{
			name:        "fails after reaching maximum attempts",
			maxAttempts: 3,
			failCount:   5,
			retryable:   true,
			wantErr:     true,
			wantCalls:   3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			calls := 0
			fn := func(_ context.Context) error {
				calls++
				if calls <= tc.failCount {
					return &mockRetryableError{
						msg:       "transient network anomaly",
						retryable: tc.retryable,
					}
				}
				return nil
			}

			ctx := context.Background()
			err := retry.Do(ctx, tc.maxAttempts, 1*time.Millisecond, 5*time.Millisecond, fn)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Do() error = %v, wantErr %v", err, tc.wantErr)
			}
			if calls != tc.wantCalls {
				t.Errorf("call count = %d, want %d", calls, tc.wantCalls)
			}
		})
	}
}

func TestDoContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	calls := 0

	fn := func(_ context.Context) error {
		calls++
		cancel()
		return &mockRetryableError{
			msg:       "rate limit active",
			retryable: true,
		}
	}

	err := retry.Do(ctx, 5, 50*time.Millisecond, 100*time.Millisecond, fn)
	if err == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled in error chain, got %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call before cancellation took effect, got %d", calls)
	}
}

func TestDo_MaxAttemptsNormalization(t *testing.T) {
	t.Parallel()

	calls := 0
	err := retry.Do(context.Background(), 0, time.Millisecond, time.Millisecond, func(_ context.Context) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("Do(maxAttempts=0) unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestDo_PreCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := retry.Do(ctx, 3, time.Millisecond, time.Millisecond, func(_ context.Context) error {
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "context ended: context canceled") {
		t.Fatalf("expected context ended error, got %v", err)
	}
}

func TestDo_ContextCancelledBetweenAttempts(t *testing.T) {
	t.Parallel()

	for range 30 {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		err := retry.Do(ctx, 3, 0, 0, func(_ context.Context) error {
			calls++
			if calls == 1 {
				cancel()
				return &mockRetryableError{msg: "retryable error", retryable: true}
			}
			return nil
		})
		if err != nil && strings.Contains(err.Error(), "context ended after") {
			return
		}
	}
}
