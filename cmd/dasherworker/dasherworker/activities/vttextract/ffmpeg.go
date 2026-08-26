package vttextract

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// ExtractSubtitlesFromContainer calls the local ffmpeg binary to extract the
// first subtitle track as a WebVTT data stream completely in memory.
func extractSubtitlesFromContainer(ctx context.Context, videoPath string, stream string) (string, error) {
	// Set a 30-second processing deadline safety context so a stuck file can't stall your backend
	execCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer

	// Configure the exact command flags to target stdout (-)
	cmd := exec.CommandContext(execCtx, "ffmpeg",
		"-v", "error", // Suppress logs and banners from entering stdout
		"-y",            // Force overwrite settings internally
		"-i", videoPath, // Source video path boundary
		"-map", "0:"+stream, // Select the subtitle track explicitly
		"-f", "webvtt", // Output text envelope profile format
		"-", // Output straight to standard output pipe
	)

	// Attach memory buffers
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// Run the execution block
	err := cmd.Run()
	if err != nil {
		// If FFmpeg returns a non-zero exit code, capture the stderr log trace
		if stderrBuf.Len() > 0 {
			return "", fmt.Errorf("ffmpeg execution failed: %v, stderr: %s", err, stderrBuf.String())
		}
		return "", fmt.Errorf("ffmpeg execution failed: %w", err)
	}

	return stdoutBuf.String(), nil
}
