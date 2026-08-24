package durationDeriver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
)

type DurationDeriver struct {
	Storage *storage.Storage
}

func (d *DurationDeriver) GetMediaDurationUsec(ctx context.Context, inputID string, inputNo int, stream string) (int64, error) {
	type ProbeOutput struct {
		Format struct {
			Duration string `json:"duration"`
		} `json:"format"`
	}

	mediaPath := d.Storage.ResolveInputNumber(inputID, inputNo)
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
		slog.Error("Exec failed", "func", "GetVideoDurationUsec", "args", args, "err", err)
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
}
