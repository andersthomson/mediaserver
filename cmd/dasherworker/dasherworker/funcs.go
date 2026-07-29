package dasherworker

import (
	"fmt"
	"log/slog"
	"math"

	"github.com/pkg/errors"
)

func DasherReadyFilename2(basename, streamIdx string) string {
	return basename + "-encoded-" + streamIdx + ".mp4"
}

func Error(msg string, args ...any) error {
	slog.Error(msg, args...)
	return fmt.Errorf("ERROR: %s ; %v", msg, args)
}

func FloatToInt(f float64) (int, error) {
	// 1. Check for NaN or Infinities (unusable float states)
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, errors.New("cannot convert NaN or Infinity to int")
	}

	// 2. Prevent Int Overflow / Underflow
	// On 64-bit systems, math.MaxInt is MaxInt64. On 32-bit, it is MaxInt32.
	if f > float64(math.MaxInt) || f < float64(math.MinInt) {
		return 0, fmt.Errorf("float value %f overflows integer boundaries", f)
	}

	// 3. Counteract Floating-Point Precision Drift
	// math.Round ensures 5.00000000001 or 4.99999999999 both snap cleanly to 5
	rounded := math.Round(f)

	// 4. Verify it was actually a whole number (Tolerance Check)
	// We check if the difference between the original and rounded value is negligible
	const epsilon = 1e-9
	if math.Abs(f-rounded) > epsilon {
		return 0, fmt.Errorf("float value %f contains fractional data and is not a whole number", f)
	}

	return int(rounded), nil
}
