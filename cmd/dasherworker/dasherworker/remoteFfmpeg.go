package dasherworker

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"

	"github.com/kballard/go-shellquote"
	"go.temporal.io/sdk/activity"
)

func FfmpegRemoteEncode(ctx context.Context, args FfmpegEncodeArgs, user, host string, port int) (FfmpegEncodeResp, error) {
	var resp FfmpegEncodeResp

	// 1. Construct the remote command
	// We force '-progress -' to send progress data to stdout
	// We use '-nostats' to keep stdout clean of the usual messy progress bar
	remoteCmd := fmt.Sprintf("cd '%s' && %s %s -progress - -nostats",
		args.Workdir,
		args.Ffmpeg,
		shellquote.Join(args.Args...),
	)
	slog.Info("FfmpegRemoteEncode", "remoteCmd", remoteCmd)
	// 2. Prepare SSH command
	var cmd *exec.Cmd
	if user != "" {
		cmd = exec.CommandContext(ctx, "ssh", "-p", strconv.Itoa(port), fmt.Sprintf("%s@%s", user, host), remoteCmd)
	} else {
		cmd = exec.CommandContext(ctx, "ssh", "-p", strconv.Itoa(port), fmt.Sprintf("%s", host), remoteCmd)
	}

	// Separate buffers for Stderr (logs)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// Create pipe for Stdout (where progress now lives)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return resp, err
	}

	if err := cmd.Start(); err != nil {
		return resp, err
	}

	// 3. Progress Parser (Reading from SSH Stdout)
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			line := scanner.Text()

			// Same logic as your local function
			if strings.HasPrefix(line, "out_time_ms=") && args.TotalDurationUs != 0 {
				parts := strings.Split(line, "=")
				if len(parts) == 2 {
					currentUs, _ := strconv.ParseInt(parts[1], 10, 64)
					percent := (float64(currentUs) / float64(args.TotalDurationUs)) * 100
					str := fmt.Sprintf("%4.1f%% completed", percent)
					slog.Info("ffmpeg", "host", host, "port", port, "value", str)
					activity.RecordHeartbeat(ctx, str)
				}
			}
		}
	}()

	err = cmd.Wait()

	// 4. Populate Response
	resp.Stderr = stderr.String()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			resp.Exitcode = exitError.ExitCode()
		} else {
			resp.Exitcode = -1
		}
	}
	if resp.Stderr != "" {
		slog.Error("RemoteFFmpeg error", "stderr", resp.Stderr)
	}

	return resp, err
}
