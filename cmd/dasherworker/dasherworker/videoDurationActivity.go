package dasherworker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
)

type ProbeOutput struct {
	Format struct {
		Duration string `json:"duration"`
	} `json:"format"`
}

// FFProbeOutput matches the top-level JSON wrapper returned by ffprobe
type FFProbeOutput struct {
	Streams []StreamInfo `json:"streams"`
}

// StreamInfo extracts the specific stream-level duration
type StreamInfo struct {
	DurationStr string `json:"duration"` //seconds
}

func (s StreamInfo) GetDuration() (float64, error) {
	if s.DurationStr == "" {
		return 0, fmt.Errorf("duration metadata not found in stream")
	}
	return strconv.ParseFloat(s.DurationStr, 64)
}

func GetMediaDurationUsec(ctx context.Context, inputID string, inputNo int, stream string) (int64, error) {
	mediaPath := storage.ResolveInputNumber(inputID, inputNo)
	slog.Info("GetMediaDurationUsec", "mediaPath", mediaPath, "stream", stream)

	args := []string{"-v", "quiet",
		"-select_streams", stream,
		"-print_format", "json",
		"-show_entries", "format=duration",
		mediaPath,
	}
	cmd := exec.CommandContext(ctx, "ffprobe", args...)
	out, err := cmd.Output()
	if err != nil {
		slog.Error("Exec failed", "GetVideoDurationUsec", err)
		return 0, err
	}

	var data ProbeOutput
	if err := json.Unmarshal(out, &data); err != nil {
		slog.Error("unmarshal failed", "GetVideoDurationUsec", err)
		return 0, err
	}
	if len(data.Format.Duration) > 0 {
		duration, err := strconv.ParseFloat(data.Format.Duration, 64)
		if err != nil {
			return 0, fmt.Errorf("Failed to convert %s to int: %s", data.Format.Duration, err)
		}
		return int64(duration * 1000000), nil
	}
	return 0, fmt.Errorf("Failed to find Duration for %s, stream %s. Got: %v", mediaPath, stream, string(out))
	/*
		// Check if a stream was successfully captured
		if len(data.Streams) > 0 {
			duration, err := data.Streams[0].GetDuration()
			if err != nil {
				slog.Error("Invalid duration format", "err", err)
				return 0, err
			}
			return int64(duration * 1000000), nil
		} else {
			return 0, errors.New("No matching stream found.")
		}*/

}
