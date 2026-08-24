package finalize

import (
	"encoding/json"
	"os/exec"
	"strconv"
)

// Helper to fetch an explicit track's start time using specifiers
func GetStremStartTime(sourceFile, streamSpecifier string) (float64, error) {
	// streamSpecifier accepts "v:0" or "a:0"
	cmd := exec.Command("ffprobe",
		"-v", "error",
		"-select_streams", streamSpecifier,
		"-show_entries", "stream=start_time",
		"-of", "json",
		sourceFile,
	)

	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	var data struct {
		Streams []struct {
			StartTime string `json:"start_time"`
		} `json:"streams"`
	}

	if err := json.Unmarshal(output, &data); err != nil {
		return 0, err
	}

	if len(data.Streams) == 0 || data.Streams[0].StartTime == "" {
		return 0, nil // No explicit tag present, defaults to absolute 0
	}

	return strconv.ParseFloat(data.Streams[0].StartTime, 64)
}
