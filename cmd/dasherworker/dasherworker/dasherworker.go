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
	"time"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/workflow"
)

type EncodingWorkflowArgs struct {
	InputFilePath    string
	FfmpegEncodeArgs FfmpegEncodeArgs
}

type EncodingWorkflowResp struct {
	FfmpegEncodeResp FfmpegEncodeResp
}

func EncodingWorkflow(ctx workflow.Context, args EncodingWorkflowArgs) (EncodingWorkflowResp, error) {
	// Step 1: Probe
	ctx1 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
	})
	err := workflow.ExecuteActivity(ctx1, GetVideoDurationUsec, args.InputFilePath).Get(ctx, &args.FfmpegEncodeArgs.TotalDurationUs)
	if err != nil {
		return EncodingWorkflowResp{}, err
	}

	ctx2 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Hour * 5,
		TaskQueue:           "encodingQueue",
		HeartbeatTimeout:    10 * time.Second,
	})
	var result FfmpegEncodeResp
	err = workflow.ExecuteActivity(ctx2, FfmpegEncode, args.FfmpegEncodeArgs).Get(ctx, &result)
	if err != nil {
		slog.Error("activity failed", "err", err.Error())
		return EncodingWorkflowResp{}, err
	}
	return EncodingWorkflowResp{
		FfmpegEncodeResp: result,
	}, nil
}

type FfmpegEncodeArgs struct {
	Args            []string
	Workdir         string
	TotalDurationUs int64
}

type FfmpegEncodeResp struct {
	Exitcode int
	Stdout   string
	Stderr   string
}

func FfmpegEncode(ctx context.Context, args FfmpegEncodeArgs) (FfmpegEncodeResp, error) {
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
	cmd := exec.CommandContext(ctx, "/usr/bin/ffmpeg", newArgs...)
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

type RsyncArgs struct {
}

func Rsync(ctx context.Context, args RsyncArgs) (string, error) {
	return "", nil
}
