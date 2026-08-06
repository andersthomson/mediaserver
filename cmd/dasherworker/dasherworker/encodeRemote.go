package dasherworker

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kballard/go-shellquote"
	"go.temporal.io/sdk/activity"
	"golang.org/x/time/rate"
)

var _ Encoder = &RemoteEncode{}

type RemoteEncode struct {
	Hostname string
	Port     int
	Dir      string
	Username string
	Ffmpeg   string
}

func (r RemoteEncode) remoteDir(ctx context.Context, fname string) string {
	return r.Dir + "/" + fname + "-" + activity.GetInfo(ctx).WorkflowExecution.ID
}

func (r *RemoteEncode) EncodePrelude(ctx context.Context, args EncodePreludeArgs) (EncodePreludeResp, error) {
	slog.Info("Start", "A", "RemoteEncode/Prelude", "id", r.Username+"@"+r.Hostname+"#"+strconv.Itoa(r.Port), "inputFname", args.FfmpegArgs.InputFname)
	defer slog.Info("Stop ", "A", "RemoteEncode/Prelude", "id", r.Username+"@"+r.Hostname+"#"+strconv.Itoa(r.Port), "inputFname", args.FfmpegArgs.InputFname)
	//slog.Info("Remote/Prelude", "host", r.Hostname, "username", r.Username, "args", args)
	localPath := filepath.Join(args.FfmpegArgs.InputDir, args.FfmpegArgs.InputFname)
	remotePath := filepath.Join(r.remoteDir(ctx, args.FfmpegArgs.InputFname), args.FfmpegArgs.InputFname)
	if err := RsyncActivity(ctx, localPath, remotePath, r.Username, r.Hostname, r.Port, true); err != nil {
		return EncodePreludeResp{}, err
	}
	return EncodePreludeResp{
		FfmpegArgs: args.FfmpegArgs,
	}, nil
}

func (r *RemoteEncode) Encode(ctx context.Context, args EncodeArgs) (EncodeResp, error) {
	slog.Info("Start", "A", "RemoteEncode/Encode", "id", r.Username+"@"+r.Hostname+"#"+strconv.Itoa(r.Port), "inputFname", args.FfmpegArgs.InputFname)
	defer slog.Info("Stop ", "A", "RemoteEncode/Encode", "id", r.Username+"@"+r.Hostname+"#"+strconv.Itoa(r.Port), "inputFname", args.FfmpegArgs.InputFname)
	//slog.Info("Remote/Encode", "host", r.Hostname, "args", args)
	/*
	   	_, err := FfmpegRemoteEncode(ctx, FfmpegEncodeArgs{
	   		Ffmpeg:          r.Ffmpeg,
	   		Args:            args.FfmpegArgs.Args,
	   		Workdir:         r.remoteDir(ctx, args.FfmpegArgs.InputFname),
	   		TotalDurationUs: args.TotalDurationUs,
	   	}, r.Username, r.Hostname, r.Port)
	   	if err != nil {
	   		return EncodeResp{}, fmt.Errorf("Remote ffmpeg failed: %+v", err)
	   	}
	   func FfmpegRemoteEncode(ctx context.Context, args FfmpegEncodeArgs, user, host string, port int) (FfmpegEncodeResp, error) {
	*/
	var resp EncodeResp

	// 1. Construct the remote command
	// We force '-progress -' to send progress data to stdout
	// We use '-nostats' to keep stdout clean of the usual messy progress bar
	remoteCmd := fmt.Sprintf("cd '%s' && %s %s -progress - -nostats",
		r.remoteDir(ctx, args.FfmpegArgs.InputFname),
		r.Ffmpeg,
		shellquote.Join(args.FfmpegArgs.Args...),
	)
	slog.Info("FfmpegRemoteEncode", "remoteCmd", remoteCmd)
	// 2. Prepare SSH command
	var cmd *exec.Cmd
	if r.Username != "" {
		cmd = exec.CommandContext(ctx, "ssh", "-p", strconv.Itoa(r.Port), fmt.Sprintf("%s@%s", r.Username, r.Hostname), remoteCmd)
	} else {
		cmd = exec.CommandContext(ctx, "ssh", "-p", strconv.Itoa(r.Port), fmt.Sprintf("%s", r.Hostname), remoteCmd)
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
		tlogger := NewThrottledLogger(rate.Every(5*time.Second), 3)

		for scanner.Scan() {
			line := scanner.Text()
			// Same logic as the local function
			if strings.HasPrefix(line, "out_time_ms=") && args.TotalDurationUs != 0 {
				parts := strings.Split(line, "=")
				if len(parts) == 2 {
					currentUs, _ := strconv.ParseInt(parts[1], 10, 64)
					percent := (float64(currentUs) / float64(args.TotalDurationUs)) * 100
					str := fmt.Sprintf("%4.1f%% completed", percent)
					activity.RecordHeartbeat(ctx, str)
					tlogger.Info("Progress", "F", "FfmpegRemoteEncode", "id", fmt.Sprintf("%s@%s#%d", r.Username, r.Hostname, r.Port), "workdir", r.remoteDir(ctx, args.FfmpegArgs.InputFname), "percent", percent)
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

	return EncodeResp{}, err
}

func (r *RemoteEncode) EncodePostlude(ctx context.Context, args EncodePostludeArgs) (EncodePostludeResp, error) {
	slog.Info("Start", "A", "RemoteEncode/Postlude", "id", r.Username+"@"+r.Hostname+"#"+strconv.Itoa(r.Port), "inputFname", args.FfmpegArgs.InputFname)
	defer slog.Info("Stop ", "A", "RemoteEncode/Postlude", "id", r.Username+"@"+r.Hostname+"#"+strconv.Itoa(r.Port), "inputFname", args.FfmpegArgs.InputFname)

	//slog.Info("Remote/postlude", "host", r.Hostname, "args", args)
	localPath := filepath.Join(args.FfmpegArgs.OutputDir, args.FfmpegArgs.OutputFname+"-"+args.SessionID)
	localTmpPath := localPath + "-" + args.SessionID
	remotePath := filepath.Join(r.remoteDir(ctx, args.FfmpegArgs.InputFname), args.FfmpegArgs.OutputFname)
	if err := RsyncActivity(ctx, localTmpPath, remotePath, r.Username, r.Hostname, r.Port, false); err != nil {
		return EncodePostludeResp{}, fmt.Errorf("Rsync to remote failed: %+v", err)
	}
	if err := os.Rename(localTmpPath, localPath); err != nil {
		return EncodePostludeResp{}, Fatal("Failed to rename ffmpeg result file into place", "localTmpPath", localTmpPath, "localPath", localPath, "err", err)
	}
	return EncodePostludeResp{
		FfmpegArgs: args.FfmpegArgs,
	}, nil
}
