package acme

import (
	"context"
	"log/slog"
)

type LogKey struct{}

func withLogger(ctx context.Context, log *slog.Logger) context.Context {
	if log == nil {
		return ctx
	}
	return context.WithValue(ctx, LogKey{}, log)
}
