package dasherworker

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"go.temporal.io/sdk/activity"
	"golang.org/x/time/rate"
)

// RunMP4Box executes MP4Box with full stdout/stderr separation and real-time progress parsing
func MP4Box(ctx context.Context, dir string, args []string) (bytes.Buffer, bytes.Buffer, error) {
	slog.Info("MP4Box", "dir", dir, "args", args)
	cmd := exec.CommandContext(ctx, "/usr/bin/MP4Box", args...)
	cmd.Dir = dir

	// 🖥️ Force MP4Box to run in interactive/TTY mode despite standard piping
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"FORCE_TTY=true",
	)

	// 🔗 Create distinct, independent pipes
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return bytes.Buffer{}, bytes.Buffer{}, Fatal("stdout pipe allocation failure", "err", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return bytes.Buffer{}, bytes.Buffer{}, Fatal("stderr pipe allocation failure", "err", err)
	}

	if err := cmd.Start(); err != nil {
		return bytes.Buffer{}, bytes.Buffer{}, Fatal("failed to start MP4Box", "args", args, "err", err)
	}

	// 🗄️ Buffers to securely capture independent data streams
	var stdoutBuffer bytes.Buffer
	var stderrBuffer bytes.Buffer

	// Coordinate asynchronous processing steps safely
	stdoutDone := make(chan struct{})
	stderrDone := make(chan struct{})

	// 1. Read Stdout in background goroutine
	go func() {
		defer close(stdoutDone)
		_, _ = io.Copy(&stdoutBuffer, stdoutPipe)
	}()

	re := regexp.MustCompile(`MPD\s+[\d\.]+\s*s\s+(\d+)\s*%`)
	logger := NewThrottledLogger(rate.Every(3*time.Second), 1)
	fname := filepath.Base(args[len(args)-1])

	// 2. Read, log, and parse Stderr in background goroutine
	go func() {
		defer close(stderrDone)

		// Duplicate stderr to our in-memory buffer while the scanner processes it
		teeStderr := io.TeeReader(stderrPipe, &stderrBuffer)
		scanner := bufio.NewScanner(teeStderr)

		// Split on BOTH \n and \r so interactive updates trigger regex evaluations instantly
		scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
			if atEOF && len(data) == 0 {
				return 0, nil, nil
			}
			for i := 0; i < len(data); i++ {
				if data[i] == '\n' || data[i] == '\r' {
					return i + 1, data[0:i], nil
				}
			}
			if atEOF {
				return len(data), data, nil
			}
			return 0, nil, nil
		})

		for scanner.Scan() {
			line := scanner.Text()
			if match := re.FindStringSubmatch(line); match != nil {
				// 📈 Insert your throttled percentage logging logic here
				// Example: password.logger.LogProgress(match[1])
				logger.Info("MP4Box Progress", "file", fname, "percentage", match[1])
				activity.RecordHeartbeat(ctx, fmt.Sprintf("MP4Box %s: %v%% done", fname, match[1]))

			}
		}
	}()

	// 3. Wait until both independent reading threads flush their data
	<-stdoutDone
	<-stderrDone

	// 4. Reap the final system process status code
	if err := cmd.Wait(); err != nil {
		return stdoutBuffer, stderrBuffer, Error("MP4Box process failed execution", "args", args, "error", err,
			"stdout", stdoutBuffer.String(),
			"stderr", stderrBuffer.String(),
		)
	}
	return stdoutBuffer, stderrBuffer, nil
}
