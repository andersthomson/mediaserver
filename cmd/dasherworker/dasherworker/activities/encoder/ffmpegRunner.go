package encoder

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared/throttledLogger"
	"go.temporal.io/sdk/activity"
	"golang.org/x/time/rate"
)

// ExecutionMetadata consolidates telemetry tracking markers.
type ExecutionMetadata struct {
	LogIdentifier   string // e.g., "FfmpegLocalEncode" or "FfmpegRemoteEncode"
	TargetID        string // e.g., working directory path or SSH connection signature
	TotalDurationUs int64
}

// EncodeResult archives execution outputs for posterity.
type EncodeResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// runPreStartedFFmpegCmd orchestrates tracing streams, heartbeats, and lifecycle teardown.
// The caller MUST have already called cmd.Start() and handled initial process creation errors.
func RunPreStartedFFmpegCmd(
	ctx context.Context,
	cmd *exec.Cmd,
	progressReader io.Reader,
	meta ExecutionMetadata,
	stdoutBuf *bytes.Buffer,
	stderrBuf *bytes.Buffer,
) (EncodeResult, error) {
	var result EncodeResult
	progressDone := make(chan struct{})

	// Handle background telemetry scanning
	go func() {
		defer close(progressDone)
		if progressReader == nil {
			return
		}

		// Use a fixed max buffer size limit to prevent memory exhaustion if noise bleeds in
		scanner := bufio.NewScanner(progressReader)
		tlogger := throttledLogger.New(rate.Every(5*time.Second), 3)
		var currentFPS float64
		var currentSpeed string = "0.00x"

		for scanner.Scan() {
			line := scanner.Text()

			// Defense against random lines/noise: Skip lines lacking properties
			if !strings.Contains(line, "=") {
				continue
			}

			// Split safely around the first assignment matrix token
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := parts[0]
			value := strings.TrimSpace(parts[1])

			//spew.Dump(parts)
			switch key {
			case "speed":
				currentSpeed = value
			case "out_time_ms":
				percent := 0.0
				if meta.TotalDurationUs != 0 {
					currentUs, _ := strconv.ParseInt(value, 10, 64)
					percent = (float64(currentUs) / float64(meta.TotalDurationUs)) * 100
				}
				activity.RecordHeartbeat(ctx, fmt.Sprintf("%4.1f%% completed", percent))

				// Conditionally log FPS only if it's a video stream (currentFPS > 0)
				if currentFPS > 0 {
					tlogger.Info("Progress",
						"F", meta.LogIdentifier,
						"idOrWorkdir", meta.TargetID,
						"percent", percent,
						"fps", currentFPS,
						"speed", currentSpeed,
					)
				} else {
					tlogger.Info("Progress",
						"F", meta.LogIdentifier,
						"idOrWorkdir", meta.TargetID,
						"percent", percent,
						"speed", currentSpeed,
					)
				}

			}
		}
	}()

	// Await running terminal runtime states
	err := cmd.Wait()
	<-progressDone

	// Structural payload mirroring for posterity records
	result.Stdout = stdoutBuf.String()
	result.Stderr = stderrBuf.String()

	// Intercept and bubble contextual abort states safely (Temporal cancellation)
	if ctx.Err() != nil {
		return result, ctx.Err()
	}

	if result.Stderr != "" {
		slog.Error(fmt.Sprintf("%s diagnostic payload", meta.LogIdentifier), "stderr", result.Stderr)
	}

	// Structural interpretation of system exit states
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		} else {
			result.ExitCode = -1
		}
	} else {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}

	return result, err
}
