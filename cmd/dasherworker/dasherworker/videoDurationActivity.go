package dasherworker

import (
	"context"
	"encoding/json"
	"log/slog"
	"os/exec"
	"strconv"
)

type ProbeOutput struct {
	Format struct {
		Duration string `json:"duration"`
	} `json:"format"`
}

func GetVideoDurationUsec(ctx context.Context, videoPath string) (int64, error) {
	// -print_format json: wraps the output in a JSON object
	cmd := exec.CommandContext(ctx, "ffprobe",
		"-v", "quiet",
		"-print_format", "json",
		"-show_format",
		videoPath,
	)
	slog.Info("GetVideoDurationUsec", "args", videoPath)
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	var data ProbeOutput
	if err := json.Unmarshal(out, &data); err != nil {
		return 0, err
	}

	seconds, err := strconv.ParseFloat(data.Format.Duration, 64)
	if err != nil {
		return 0, err
	}

	return int64(seconds * 1000000), nil
}
