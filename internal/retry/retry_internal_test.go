package retry

import (
	"errors"
	"testing"
	"time"
)

func mockRandFail(_ []byte) error {
	return errors.New("simulated rand failure")
}

func mockRandZero(b []byte) error {
	for i := range b {
		b[i] = 0
	}
	return nil
}

func TestDefaultRandRead(t *testing.T) {
	var buf [8]byte
	if err := defaultRandRead(buf[:]); err != nil {
		t.Fatalf("defaultRandRead() unexpected error: %v", err)
	}
}

func TestComputeJitter_BaseNonPositive(t *testing.T) {
	if got := computeJitter(0); got != 0 {
		t.Fatalf("computeJitter(0) = %v, want 0", got)
	}
	if got := computeJitter(-1 * time.Second); got != 0 {
		t.Fatalf("computeJitter(-1s) = %v, want 0", got)
	}
}

func TestComputeJitter_RandReadError(t *testing.T) {
	prev := randRead
	randRead = mockRandFail
	t.Cleanup(func() {
		randRead = prev
	})

	got := computeJitter(10 * time.Millisecond)
	if got != 10*time.Millisecond {
		t.Fatalf("computeJitter() = %v, want 10ms", got)
	}
}

func TestComputeJitter_JitteredNonPositive(t *testing.T) {
	prev := randRead
	randRead = mockRandZero
	t.Cleanup(func() {
		randRead = prev
	})

	got := computeJitter(1 * time.Nanosecond)
	if got != 1*time.Nanosecond {
		t.Fatalf("computeJitter(1ns) = %v, want 1ns", got)
	}
}
