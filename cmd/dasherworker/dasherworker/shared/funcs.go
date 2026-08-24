package shared

import (
	"fmt"
	"log/slog"

	"go.temporal.io/sdk/temporal"
)

func Error(msg string, args ...any) error {
	slog.Error(msg, args...)
	return fmt.Errorf("ERROR: %s ; %v", msg, args)
}

func Fatal(msg string, args ...any) error {
	slog.Error(msg, args...)
	return temporal.NewNonRetryableApplicationError(
		fmt.Sprintf("ERROR: %s ; %v", msg, args),
		"",
		nil,
	)
}
func FatalError(err error) error {
	return Fatal(err.Error())
}

func IsVideoCodec(codec string) bool {
	switch codec {
	case "x264", "h264":
		return true
	case "x265", "h265", "hevc":
		return true
	}
	return false
}
