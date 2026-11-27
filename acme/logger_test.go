package acme

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestWithLogger(t *testing.T) {
	log := newTestLogger()
	ctx := withLogger(context.Background(), log)

	if got := ExtractLogger(ctx); got != log {
		t.Errorf("ExtractLogger(withLogger(...)) = %p, want %p", got, log)
	}
}

func TestWithLoggerNilReturnsOriginalContext(t *testing.T) {
	ctx := context.Background()
	if got := withLogger(ctx, nil); got != ctx {
		t.Error("withLogger with a nil logger did not return the original context")
	}
}

func TestExtractLoggerWithoutLogger(t *testing.T) {
	if got := ExtractLogger(context.Background()); got != nil {
		t.Errorf("ExtractLogger(background) = %p, want nil", got)
	}
}

func TestExtractLoggerIgnoresWrongValueType(t *testing.T) {
	ctx := context.WithValue(context.Background(), logKey{}, "not a logger")
	if got := ExtractLogger(ctx); got != nil {
		t.Errorf("ExtractLogger with wrong value type = %p, want nil", got)
	}
}
