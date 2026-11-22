package acme

import (
	"context"
	"log/slog"
)

type logKey struct{}

func withLogger(ctx context.Context, log *slog.Logger) context.Context {
	if log == nil {
		return ctx
	}
	return context.WithValue(ctx, logKey{}, log)
}

// ExtractLogger returns the logger associated with ctx. It returns a non-nil [*slog.Logger] on success, and
// nil on failure.
func ExtractLogger(ctx context.Context) *slog.Logger {
	logger, _ := ctx.Value(logKey{}).(*slog.Logger)
	return logger
}
