package remoteEncode

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/encoder"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
	"github.com/kballard/go-shellquote"
	"go.temporal.io/sdk/activity"
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
	sshTarget := fmt.Sprintf("%s@%s#%d", r.Username, r.Hostname, r.Port)
	slog.Info("Start", "A", "RemoteEncode/Encode", "id", sshTarget, "inputFname", args.FfmpegArgs.InputFname)
	defer slog.Info("Stop ", "A", "RemoteEncode/Encode", "id", sshTarget, "inputFname", args.FfmpegArgs.InputFname)

	// Force nostats to prevent terminal graph corruption on the stdout line stream
	remoteCmd := fmt.Sprintf("cd '%s' && %s %s -progress - -nostats",
		r.remoteDir(ctx, args.FfmpegArgs.InputFname),
		r.Ffmpeg,
		shellquote.Join(args.FfmpegArgs.Args...),
	)
	slog.Info("FfmpegRemoteEncode", "remoteCmd", remoteCmd)

	var cmd *exec.Cmd
	if r.Username != "" {
		cmd = exec.CommandContext(ctx, "ssh", "-p", strconv.Itoa(r.Port), fmt.Sprintf("%s@%s", r.Username, r.Hostname), remoteCmd)
	} else {
		cmd = exec.CommandContext(ctx, "ssh", "-p", strconv.Itoa(r.Port), r.Hostname, remoteCmd)
	}

	// Prepare data preservation matrices
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	stdoutStream, err := cmd.StdoutPipe()
	if err != nil {
		return shared.EncodeResp{}, err
	}

	// Mirror traffic: Write to stdoutBuf for posterity while simultaneously piping to progress scanner
	progressReader := io.TeeReader(stdoutStream, &stdoutBuf)

	meta := encoder.ExecutionMetadata{
		LogIdentifier:   "FfmpegRemoteEncode",
		TargetID:        sshTarget,
		TotalDurationUs: args.TotalDurationUs,
	}

	// Trigger command context allocation execution over network wire topology
	if err := cmd.Start(); err != nil {
		return shared.EncodeResp{}, err
	}

	// Delegate processing logic down to the unified engine
	res, err := encoder.RunPreStartedFFmpegCmd(ctx, cmd, progressReader, meta, &stdoutBuf, &stderrBuf)

	resp := shared.EncodeResp{
		Exitcode: res.ExitCode,
		Stderr:   res.Stderr,
	}
	return resp, err
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
