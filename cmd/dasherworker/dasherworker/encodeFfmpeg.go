package dasherworker

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/kballard/go-shellquote"
	"go.temporal.io/sdk/activity"
)

type FfmpegEncodeArgs struct {
	Ffmpeg          string
	Args            []string
	Workdir         string
	TotalDurationUs int64
}

type FfmpegEncodeResp struct {
	Exitcode int
	Stdout   string
	Stderr   string
}

func FfmpegLocalEncode(ctx context.Context, args FfmpegEncodeArgs) (FfmpegEncodeResp, error) {
	var resp FfmpegEncodeResp

	// Create an extra pipe for progress only
	pr, pw, _ := os.Pipe()
	defer pr.Close()

	var newArgs []string
	if args.TotalDurationUs != 0 {
		newArgs = append(args.Args, []string{"-progress", "pipe:3"}...)
	} else {
		newArgs = args.Args
	}
	cmd := exec.CommandContext(ctx, args.Ffmpeg, newArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.ExtraFiles = []*os.File{pw}
	cmd.Dir = args.Workdir

	// 3. Start progress parser in background
	if args.TotalDurationUs != 0 {
		go func() {
			defer pw.Close() // Ensure the write-end closes so scanner finishes
			scanner := bufio.NewScanner(pr)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "out_time_ms=") {
					parts := strings.Split(line, "=")
					if len(parts) == 2 {
						currentUs, _ := strconv.ParseInt(parts[1], 10, 64)
						percent := (float64(currentUs) / float64(args.TotalDurationUs)) * 100
						activity.RecordHeartbeat(ctx, fmt.Sprintf("%4.1f percent complete", percent))
					}
				}
			}
		}()
	}

	// Run() starts the command and waits for it to finish
	err := cmd.Run()

	// 5. Handle Early Closure / Cancellation
	if ctx.Err() != nil {
		// Temporal canceled the context. cmd.Run() usually returns an error here.
		return resp, ctx.Err()
	}

	// Capture outputs
	resp.Stdout = stdout.String()
	resp.Stderr = stderr.String()

	// Get Exit Code
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			// This happens if the command couldn't start at all (e.g., binary not found)
			exitCode = -1
		}
	} else {
		exitCode = cmd.ProcessState.ExitCode()
	}
	resp.Exitcode = exitCode
	return resp, nil
}

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
