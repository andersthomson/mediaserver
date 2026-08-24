package throttledLogger

import (
	"context"
	"log/slog"

	"golang.org/x/time/rate"
)

// ThrottledLogger wraps a rate limiter and mirrors the standard slog API.
// It is fully safe for concurrent use across multiple goroutines.
type ThrottledLogger struct {
	limiter *rate.Limiter
}

// NewThrottledLogger sets the allowed logs per second (r) and burst size (b).
func New(r rate.Limit, b int) *ThrottledLogger {
	return &ThrottledLogger{
		limiter: rate.NewLimiter(r, b),
	}
}

// Info logs at INFO level if under the rate limit.
func (tl *ThrottledLogger) Info(msg string, args ...any) {
	if tl.limiter.Allow() {
		slog.Info(msg, args...)
	}
}

// InfoCtx logs at INFO level with context if under the rate limit.
func (tl *ThrottledLogger) InfoCtx(ctx context.Context, msg string, args ...any) {
	if tl.limiter.Allow() {
		slog.InfoContext(ctx, msg, args...)
	}
}

// Warn logs at WARN level if under the rate limit.
func (tl *ThrottledLogger) Warn(msg string, args ...any) {
	if tl.limiter.Allow() {
		slog.Warn(msg, args...)
	}
}

// WarnCtx logs at WARN level with context if under the rate limit.
func (tl *ThrottledLogger) WarnCtx(ctx context.Context, msg string, args ...any) {
	if tl.limiter.Allow() {
		slog.WarnContext(ctx, msg, args...)
	}
}

// Error logs at ERROR level if under the rate limit.
func (tl *ThrottledLogger) Error(msg string, args ...any) {
	if tl.limiter.Allow() {
		slog.Error(msg, args...)
	}
}

// ErrorCtx logs at ERROR level with context if under the rate limit.
func (tl *ThrottledLogger) ErrorCtx(ctx context.Context, msg string, args ...any) {
	if tl.limiter.Allow() {
		slog.ErrorContext(ctx, msg, args...)
	}
}
