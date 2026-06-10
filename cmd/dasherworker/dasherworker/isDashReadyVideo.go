package dasherworker

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// FileType holds the detected track types
type detectedFileTypes struct {
	IsVideo bool
	IsAudio bool
}

func detectMP4ContentsJSON(filePath string) (detectedFileTypes, error) {
	// ProbeResult matches the expected JSON structure from ffprobe
	type ProbeResult struct {
		Streams []struct {
			CodecType string `json:"codec_type"`
		} `json:"streams"`
	}

	var result detectedFileTypes

	// Execute ffprobe with JSON output format
	cmd := exec.Command("ffprobe",
		"-v", "error",
		"-show_entries", "stream=codec_type",
		"-of", "json",
		filePath,
	)

	out, err := cmd.Output()
	if err != nil {
		return result, fmt.Errorf("ffprobe failed: %w", err)
	}

	// Unmarshal the JSON into our struct
	var probe ProbeResult
	if err := json.Unmarshal(out, &probe); err != nil {
		return result, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Loop through the detected streams
	for _, stream := range probe.Streams {
		switch stream.CodecType {
		case "video":
			result.IsVideo = true
		case "audio":
			result.IsAudio = true
		}
	}

	return result, nil
}

func isDashReadyVideo(filePath string) bool {
	contents, err := detectMP4ContentsJSON(filePath)
	if err != nil {
		//panic(fmt.Sprintf("Error: %v\n", err))
		return false
	}

	return contents.IsVideo && !contents.IsAudio
}
func isDashReadyAudio(filePath string) bool {
	contents, err := detectMP4ContentsJSON(filePath)
	if err != nil {
		//panic(fmt.Sprintf("Error: %v\n", err))
		return false
	}

	return contents.IsAudio && !contents.IsVideo
}
