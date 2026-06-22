package dasherworker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
)

// GetStreamZeroLanguage runs ffprobe on the given file path and returns the language of the first stream.
func GetStreamZeroLanguage(filePath string) (string, error) {
	// FFProbeResult maps only the necessary JSON structure returned by ffprobe.
	type FFProbeResult struct {
		Streams []struct {
			Tags struct {
				Language string `json:"language"`
			} `json:"tags"`
		} `json:"streams"`
	}

	// Build the ffprobe command targeting only the first stream index (0)
	cmd := exec.Command("ffprobe",
		"-v", "quiet",
		"-print_format", "json",
		"-show_entries", "stream_tags=language",
		"-select_streams", "0",
		filePath,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute the command
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ffprobe error: %w (stderr: %s)", err, stderr.String())
	}

	// Unmarshal the JSON output
	var result FFProbeResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return "", fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Ensure at least one stream was found
	if len(result.Streams) == 0 {
		return "", fmt.Errorf("no streams found in file")
	}

	// Extract the language tag
	lang := result.Streams[0].Tags.Language
	if lang == "" {
		return "und", nil
	}

	return lang, nil
}
