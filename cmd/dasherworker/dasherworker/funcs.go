package dasherworker

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"os"

	"github.com/pkg/errors"
	"go.temporal.io/sdk/temporal"
)

func DasherReadyFilename2(basename, streamIdx string) string {
	return basename + "-encoded-" + streamIdx + ".mp4"
}

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

// FloatToInt converts a whole number float64 to int.
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

func SaveStructToJSON(filename string, data interface{}) error {
	// 1. Convert struct to pretty-printed JSON bytes
	// MarshallIndent adds spacing and line breaks for readability on disk
	jsonData, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal struct to JSON: %w", err)
	}

	// 2. Write bytes to disk
	err = os.WriteFile(filename, jsonData, 0600)
	if err != nil {
		return fmt.Errorf("failed to write JSON file to disk: %w", err)
	}

	return nil
}

func LoadJSONToStruct(filename string, target interface{}) error {
	// 1. Read the raw bytes from the file
	jsonData, err := os.ReadFile(filename)
	if err != nil {
		// Provide a helpful error if the file simply doesn't exist
		if errors.Is(err, os.ErrNotExist) {
			slog.Info("File not found", "filename", filename)
		}
		return err
	}

	// 2. Parse the bytes into the struct pointer
	err = json.Unmarshal(jsonData, target)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return nil
}
