package remoteEncode

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

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared/throttledLogger"
	"github.com/kballard/go-shellquote"
	"go.temporal.io/sdk/activity"
	"golang.org/x/time/rate"
)

var _ shared.Encoder = &RemoteEncode{}

type RemoteEncode struct {
	Hostname string
	Port     int
	Dir      string
	Username string
	Ffmpeg   string

	Storage *storage.Storage
}

func (r RemoteEncode) remoteDir(ctx context.Context, fname string) string {
	return r.Dir + "/" + fname + "-" + activity.GetInfo(ctx).WorkflowExecution.ID
}

func (r *RemoteEncode) EncodePrelude(ctx context.Context, args shared.EncodePreludeArgs) (shared.EncodePreludeResp, error) {
	slog.Info("Start", "A", "RemoteEncode/Prelude", "id", r.Username+"@"+r.Hostname+"#"+strconv.Itoa(r.Port), "inputFname", args.FfmpegArgs.InputFname)
	defer slog.Info("Stop ", "A", "RemoteEncode/Prelude", "id", r.Username+"@"+r.Hostname+"#"+strconv.Itoa(r.Port), "inputFname", args.FfmpegArgs.InputFname)
	if err := os.MkdirAll(r.Storage.ProdDir(args.ESA.InputID), os.ModePerm); err != nil {
		return shared.EncodePreludeResp{}, err
	}
	//slog.Info("Remote/Prelude", "host", r.Hostname, "username", r.Username, "args", args)
	//localPath := filepath.Join(args.FfmpegArgs.InputDir, args.FfmpegArgs.InputFname)
	localPath := r.Storage.ResolveInputNumber(args.ESA.InputID, args.ESA.InputNo)
	remotePath := filepath.Join(r.remoteDir(ctx, args.FfmpegArgs.InputFname), filepath.Base(localPath))
	if err := Rsync(ctx, localPath, remotePath, r.Username, r.Hostname, r.Port, true); err != nil {
		return shared.EncodePreludeResp{}, err
	}
	return shared.EncodePreludeResp{
		FfmpegArgs: args.FfmpegArgs,
	}, nil
}

func (r *RemoteEncode) Encode(ctx context.Context, args shared.EncodeArgs) (shared.EncodeResp, error) {
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
	var resp shared.EncodeResp

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
		tlogger := throttledLogger.New(rate.Every(5*time.Second), 3)

		// Track rolling processing performance safely across lines inside the loop matrix
		var currentFPS float64 = 0.0

		for scanner.Scan() {
			line := scanner.Text()

			// Capture the processing speed token (e.g., "fps=145.2" or "fps=0")
			if strings.HasPrefix(line, "fps=") {
				parts := strings.Split(line, "=")
				if len(parts) == 2 {
					currentFPS, _ = strconv.ParseFloat(parts[1], 64)
				}
			}

			// Same logic as the local function
			if strings.HasPrefix(line, "out_time_ms=") && args.TotalDurationUs != 0 {
				parts := strings.Split(line, "=")
				if len(parts) == 2 {
					currentUs, _ := strconv.ParseInt(parts[1], 10, 64)
					percent := (float64(currentUs) / float64(args.TotalDurationUs)) * 100
					str := fmt.Sprintf("%4.1f%% completed", percent)
					activity.RecordHeartbeat(ctx, str)
					tlogger.Info("Progress", "F", "FfmpegRemoteEncode", "id", fmt.Sprintf("%s@%s#%d", r.Username, r.Hostname, r.Port), "workdir", r.remoteDir(ctx, args.FfmpegArgs.InputFname), "percent", percent, "fps", currentFPS)
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

	return shared.EncodeResp{}, err
}

func (r *RemoteEncode) EncodePostlude(ctx context.Context, args shared.EncodePostludeArgs) (shared.EncodePostludeResp, error) {
	slog.Info("Start", "A", "RemoteEncode/Postlude", "id", r.Username+"@"+r.Hostname+"#"+strconv.Itoa(r.Port), "inputFname", args.FfmpegArgs.InputFname)
	defer slog.Info("Stop ", "A", "RemoteEncode/Postlude", "id", r.Username+"@"+r.Hostname+"#"+strconv.Itoa(r.Port), "inputFname", args.FfmpegArgs.InputFname)

	//slog.Info("Remote/postlude", "host", r.Hostname, "args", args)
	localPath := r.Storage.TranscodedRepresentationFilePath(args.ESA)
	localTmpPath := filepath.Join(filepath.Dir(localPath), "."+filepath.Base(localPath)+"-"+args.SessionID)
	remotePath := filepath.Join(r.remoteDir(ctx, args.FfmpegArgs.InputFname), filepath.Base(localPath))
	if err := Rsync(ctx, localTmpPath, remotePath, r.Username, r.Hostname, r.Port, false); err != nil {
		return shared.EncodePostludeResp{}, fmt.Errorf("Rsync to remote failed: %+v", err)
	}
	if err := os.Rename(localTmpPath, localPath); err != nil {
		return shared.EncodePostludeResp{}, shared.Fatal("Failed to rename ffmpeg result file into place", "localTmpPath", localTmpPath, "localPath", localPath, "err", err)
	}
	return shared.EncodePostludeResp{
		FfmpegArgs: args.FfmpegArgs,
	}, nil
}
