package shared

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/andersthomson/mediaserver/scrape"
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

func GetFirstInputStreamWithPrefix(inputs []scrape.InputT, prefix string) int {
	return slices.IndexFunc(inputs, func(i scrape.InputT) bool {
		return strings.HasPrefix(i.Stream, prefix)
	})
}

func DashMs2(gopFrames int, fps int) string {
	if fps == 0 || gopFrames == 0 {
		return "ILLEGAL GOPFRAMES OR FPS" // Guard against division by zero
	}

	// 1. Calculate the exact millisecond duration of ONE single GOP
	singleGopMs := (gopFrames * 1000) / fps

	// 2. Find out how many of these GOPs fit closest to our 4000ms target.
	// We add (singleGopMs / 2) to achieve perfect "round to nearest integer" math.
	gopCount := (4000 + (singleGopMs / 2)) / singleGopMs

	// 3. Prevent a count of 0 if a single GOP happens to be massive (e.g., 6 seconds)
	if gopCount == 0 {
		gopCount = 1
	}

	// 4. Return the combined duration of the stacked GOPs
	return fmt.Sprintf("%d", gopCount*singleGopMs)
}
