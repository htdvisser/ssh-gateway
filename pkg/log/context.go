// Package log lets you put a zap.Logger in a context.Context.
package log

import (
	"context"

	"go.uber.org/zap"
)

type ctxKeyType struct{}

var ctxKey ctxKeyType

// FromContext gets the logger from the context.
func FromContext(ctx context.Context) *zap.Logger {
	if v := ctx.Value(ctxKey); v != nil {
		if logger, ok := v.(*zap.Logger); ok {
			return logger
		}
	}
	return nil
}

// NewContext returns a new context that contains the logger.
func NewContext(ctx context.Context, logger *zap.Logger) context.Context {
	return context.WithValue(ctx, ctxKey, logger)
}
