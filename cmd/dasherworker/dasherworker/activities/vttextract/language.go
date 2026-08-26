package vttextract

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/davecgh/go-spew/spew"
)

// GetSubtitleLanguage connects to ffprobe to fetch the ISO language code
// of the first subtitle track (s:0) inside the target video container.
func getSubtitleLanguage(ctx context.Context, videoPath string, stream string) (string, error) {
	// SubtitleMetadata holds the parsed stream language tags from ffprobe
	type SubtitleMetadata struct {
		Streams []struct {
			Tags struct {
				Language string `json:"language"`
			} `json:"tags"`
		} `json:"streams"`
	}

	// Add an internal timeout layer to ensure metadata probes exit quickly
	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	args := []string{
		"-v", "error",
		"-select_streams", stream,
		"-show_entries", "stream_tags=language",
		"-of", "json",
		videoPath,
	}
	spew.Dump(args)
	cmd := exec.CommandContext(probeCtx, "ffprobe", args...)

	output, err := cmd.Output()
	if err != nil {
		// Provide context-specific error if the timeout boundary cut the execution short
		if probeCtx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("ffprobe execution timed out: %w", probeCtx.Err())
		}
		return "", fmt.Errorf("ffprobe command failed: %w", err)
	}

	var metadata SubtitleMetadata
	if err := json.Unmarshal(output, &metadata); err != nil {
		return "", fmt.Errorf("failed to decode ffprobe metadata JSON: %w", err)
	}
	spew.Dump(metadata)
	// Fallback to "und" (Undetermined) if no subtitle track exists or language tags are blank
	if len(metadata.Streams) == 0 || metadata.Streams[0].Tags.Language == "" {
		return "und", nil
	}

	return metadata.Streams[0].Tags.Language, nil
}
