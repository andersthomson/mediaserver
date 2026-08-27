package vttextract

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/encoder"
)

// ExtractSubtitlesFromContainer calls the local ffmpeg binary to extract the
// first subtitle track as a WebVTT data stream completely in memory.
func extractSubtitlesFromContainer(ctx context.Context, videoPath string, stream string, durationUs int64) (string, error) {
	// Set a 30-second processing deadline safety context so a stuck file can't stall your backend

	execCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	pr, pw, err := os.Pipe()
	if err != nil {
		return "", err
	}
	defer pr.Close()

	cmd := exec.CommandContext(execCtx, "ffmpeg",
		"-y",
		"-progress", "pipe:3", // Progress isolated here
		"-i", videoPath,
		"-map", "0:"+stream,
		"-f", "webvtt",
		"-", // Subtitles flow through stdout
	)
	cmd.ExtraFiles = []*os.File{pw}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	meta := encoder.ExecutionMetadata{
		LogIdentifier:   "FfmpegSubtitleExtract",
		TargetID:        videoPath,
		TotalDurationUs: durationUs,
	}

	if err := cmd.Start(); err != nil {
		pw.Close()
		return "", err
	}
	pw.Close()

	// Works out of the box!
	res, err := encoder.RunPreStartedFFmpegCmd(execCtx, cmd, pr, meta, &stdoutBuf, &stderrBuf)
	return res.Stdout, err // Your subtitles are clean and intact here

}
