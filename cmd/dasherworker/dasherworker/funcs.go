package dasherworker

import (
	"fmt"
	"log/slog"
)

func DasherReadyFilename2(basename, streamIdx string) string {
	return basename + "-encoded-" + streamIdx + ".mp4"
}

func Error(msg string, args ...any) error {
	slog.Error(msg, args...)
	return fmt.Errorf("ERROR: %s ; %v", msg, args)
}
