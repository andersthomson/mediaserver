package dasherworker

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"go.temporal.io/sdk/workflow"
)

func CallGetStreamDimensions(ctx workflow.Context, inputID string, inputNo int, stream string) (int, int, float64, error) {
	sDim, err := CallActivityIO[any, StreamDimensions](ctx, GetStreamDimensions, GetStreamDimensionsArgs{InputID: inputID, InputNo: inputNo, Stream: stream})
	return sDim.Width, sDim.Height, sDim.SAR, err
}

// MediaDimensions contains clean, pre-parsed float numeric values ready for calculation
type StreamDimensions struct {
	Width  int
	Height int
	SAR    float64
}

type GetStreamDimensionsArgs struct {
	InputID string
	InputNo int
	Stream  string
}

// ExtractMediaDimensions calls ffprobe natively and parses the video matrix parameters
func GetStreamDimensions(ctx context.Context, args GetStreamDimensionsArgs) (StreamDimensions, error) {
	// FFprobeOutput maps only the specific JSON fields we care about from the stream metadata
	type FFprobeOutput struct {
		Streams []struct {
			Width             int    `json:"width"`
			Height            int    `json:"height"`
			SampleAspectRatio string `json:"sample_aspect_ratio"` // e.g., "64:45"
		} `json:"streams"`
	}

	dir, msp := storage.ResolveInput(args.InputID)
	fullPath := filepath.Join(dir, msp.Inputs[args.InputNo].Filename)

	// Execute ffprobe requesting standard JSON layout arrays for the first video stream
	cmd := exec.CommandContext(ctx, "ffprobe",
		"-v", "error",
		"-select_streams", args.Stream,
		"-show_entries", "stream=width,height,sample_aspect_ratio",
		"-of", "json",
		fullPath,
	)

	output, err := cmd.Output()
	if err != nil {
		return StreamDimensions{}, errors.Wrap(err, "ffprobe execution failed")
	}

	var data FFprobeOutput
	if err := json.Unmarshal(output, &data); err != nil {
		return StreamDimensions{}, errors.Wrap(err, "failed to unmarshal ffprobe json")
	}

	// Safety check: ensure a video stream was actually located
	if len(data.Streams) == 0 {
		return StreamDimensions{}, errors.New("no video streams found in media target")
	}

	stream := data.Streams[0]
	result := StreamDimensions{
		Width:  stream.Width,
		Height: stream.Height,
		SAR:    1.0, // Default to 1:1 if metadata is missing or set to 0:1 / unknown
	}

	// Parse the fractional SAR string (e.g., "64:45") into a floating-point multiplier
	sarStr := strings.TrimSpace(stream.SampleAspectRatio)
	if sarStr != "" && sarStr != "0:1" && sarStr != "unknown" {
		parts := strings.Split(sarStr, ":")
		if len(parts) == 2 {
			num, err1 := strconv.ParseFloat(parts[0], 64)
			den, err2 := strconv.ParseFloat(parts[1], 64)
			if err1 == nil && err2 == nil && den > 0 {
				result.SAR = num / den
			}
		}
	}

	return result, nil
}
