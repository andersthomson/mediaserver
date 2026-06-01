package dasherworker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
)

// GetStreamZeroCodec invokes ffprobe to find the codec name of stream index 0
func GetStreamZeroCodec(filename string) (string, error) {
	// FFProbeResult maps only the fields we care about from the JSON response
	type FFProbeResult struct {
		Streams []struct {
			Index     int    `json:"index"`
			CodecName string `json:"codec_name"`
			CodecType string `json:"codec_type"`
		} `json:"streams"`
	}

	// Prepare the ffprobe command arguments
	// -v error: Hides system banner clutter and standard warnings
	// -select_streams 0: Explicitly isolate stream index 0
	// -show_entries stream=codec_name: Fetch only the codec_name property
	// -of json: Force output format to structural JSON
	args := []string{
		"-v", "error",
		"-select_streams", "0",
		"-show_entries", "stream=codec_name,codec_type",
		"-of", "json",
		filename,
	}

	cmd := exec.Command("ffprobe", args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute the binary task
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ffprobe failed: %v (stderr: %s)", err, stderr.String())
	}

	// Parse the structured JSON response
	var result FFProbeResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return "", fmt.Errorf("failed to parse ffprobe json: %v", err)
	}

	// Ensure we actually caught stream metadata back
	if len(result.Streams) == 0 {
		return "", fmt.Errorf("no streams found at index 0 for file: %s", filename)
	}

	// Return the parsed codec string (e.g., "h264", "hevc", "aac", "vp9")
	return result.Streams[0].CodecName, nil
}
