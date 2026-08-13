package dasherworker

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	"go.temporal.io/sdk/activity"
)

type FFProbeArgs struct {
	SessionID string
	Args      []string
}

type FFProbeResp struct {
	Stdout   string
	Stderr   string
	Exitcode int
}

func FFProbe(ctx context.Context, args FFProbeArgs) (FFProbeResp, error) {
	slog.Info("Start ffprobe", "args", args.Args)
	defer slog.Info("Stop ffprobe", "args", args.Args)

	var resp FFProbeResp
	cmd := exec.CommandContext(ctx, "/usr/bin/ffprobe", args.Args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// If needed, map to your session directory helper: l.workDir(args.SessionID, ...)
	cmd.Dir = ""

	// 1. Start a background ticker to send Temporal heartbeats while ffprobe runs
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		startTime := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-heartbeatDone:
				return
			case <-ticker.C:
				elapsed := time.Since(startTime).Round(time.Second)
				// Record heartbeat to notify Temporal that the probe operation is still alive
				activity.RecordHeartbeat(ctx, fmt.Sprintf("FFProbe activity: %s elapsed, args %v", elapsed, args.Args))
				slog.Info("FFProbe actvity", "elapsed", elapsed, "args", args.Args)
			}
		}
	}()

	// 2. Execute ffprobe and block until completion
	err := cmd.Run()

	// 3. Stop the heartbeat routine safely
	heartbeatDone <- struct{}{}

	// 4. Handle context cancellation or timeouts triggered by Temporal
	if ctx.Err() != nil {
		return resp, ctx.Err()
	}

	// 5. Populate response data
	resp.Stdout = stdout.String()
	resp.Stderr = stderr.String()

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			resp.Exitcode = exitError.ExitCode()
		} else {
			resp.Exitcode = -1
		}
		slog.Error("LocalFFprobe error", "stderr", resp.Stderr, "err", err)
		return resp, err
	}

	resp.Exitcode = cmd.ProcessState.ExitCode()
	return resp, nil
}
