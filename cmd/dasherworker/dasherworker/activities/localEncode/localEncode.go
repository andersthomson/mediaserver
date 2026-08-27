package localEncode

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/encoder"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
)

var _ shared.Encoder = &LocalEncode{}

type LocalEncode struct {
	Storage *storage.Storage
}

// Gives the workdir for a local ffmpeg encode.
func (l *LocalEncode) workDir(sessionID string, ESA shared.EncodeStreamArgs) string {
	p := l.Storage.ProdDir(ESA.InputID)
	return filepath.Join(p, ".sessionID-"+sessionID)
}

func (l LocalEncode) makeWorkDir(sessionID string, ESA shared.EncodeStreamArgs) string {
	wd := l.workDir(sessionID, ESA)
	if err := os.Mkdir(wd, 0755); err != nil {
		slog.Error("Failed to create ffmpeg working dir", "err", err)
	} else {
		slog.Info("Created ffmpeg workdir", "dir", wd)
	}
	return wd
}

func (l *LocalEncode) inputSymlink(sessionID string, ESA shared.EncodeStreamArgs, ffmpegargs shared.FFMpegArgs) string {
	return filepath.Join(l.workDir(sessionID, ESA), filepath.Base(l.Storage.ResolveInputNumber(ESA.InputID, ESA.InputNo)))
}

func (l *LocalEncode) EncodePrelude(ctx context.Context, args shared.EncodePreludeArgs) (shared.EncodePreludeResp, error) {
	_, m := l.Storage.ResolveInput(args.ESA.InputID)
	inputFname := m.Inputs[args.ESA.InputNo].Filename
	slog.Info("Start", "A", "LocalEncode/Prelude", "inputFname", inputFname)
	defer slog.Info("Stop ", "A", "LocalEncode/Prelude", "inputFname", inputFname)
	//slog.Info("local/prelude", "args", args)
	if err := os.MkdirAll(l.Storage.ProdDir(args.ESA.InputID), os.ModePerm); err != nil {
		return shared.EncodePreludeResp{}, err
	}
	slog.Info("local/prelude: symlinking input file")
	_ = l.makeWorkDir(args.SessionID, args.ESA)
	newName := l.inputSymlink(args.SessionID, args.ESA, args.FfmpegArgs)
	oldName := l.Storage.ResolveInputNumber(args.ESA.InputID, args.ESA.InputNo)
	//oldName := filepath.Join(args.FfmpegArgs.InputDir, args.FfmpegArgs.InputFname)

	if err := os.Symlink(oldName, newName); err != nil {
		return shared.EncodePreludeResp{}, shared.Error("Failed to symlink input file", "oldname", oldName, "newname", newName, "err", err)
	}
	return shared.EncodePreludeResp{
		FfmpegArgs: args.FfmpegArgs,
	}, nil
}
func (l *LocalEncode) Encode(ctx context.Context, args shared.EncodeArgs) (shared.EncodeResp, error) {
	_, m := l.Storage.ResolveInput(args.ESA.InputID)
	inputFname := m.Inputs[args.ESA.InputNo].Filename

	slog.Info("Start", "A", "LocalEncode/Prelude", "inputFname", inputFname)
	defer slog.Info("Stop ", "A", "LocalEncode/Prelude", "inputFname", inputFname)
	slog.Info("local/Encode", "args", args)

	pr, pw, err := os.Pipe()
	if err != nil {
		return shared.EncodeResp{}, err
	}
	defer pr.Close()

	var finalArgs []string
	if args.TotalDurationUs != 0 {
		finalArgs = append(args.FfmpegArgs.Args, "-progress", "pipe:3")
	} else {
		finalArgs = args.FfmpegArgs.Args
	}

	cmd := exec.CommandContext(ctx, "/usr/bin/ffmpeg", finalArgs...)
	cmd.ExtraFiles = []*os.File{pw}
	cmd.Dir = l.workDir(args.SessionID, args.ESA)

	// Prepare data preservation matrices
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	meta := encoder.ExecutionMetadata{
		LogIdentifier:   "FfmpegLocalEncode",
		TargetID:        l.workDir(args.SessionID, args.ESA),
		TotalDurationUs: args.TotalDurationUs,
	}

	// Trigger command context allocation execution
	if err := cmd.Start(); err != nil {
		pw.Close()
		return shared.EncodeResp{}, err
	}

	// CRITICAL: Close parent reference immediately so reader loop can cleanly parse EOF on execution end
	pw.Close()

	// Delegate processing logic down to the unified engine
	res, err := encoder.RunPreStartedFFmpegCmd(ctx, cmd, pr, meta, &stdoutBuf, &stderrBuf)

	resp := shared.EncodeResp{
		Exitcode: res.ExitCode,
		Stderr:   res.Stderr,
	}
	return resp, err
}

func (l *LocalEncode) EncodePostlude(ctx context.Context, args shared.EncodePostludeArgs) (shared.EncodePostludeResp, error) {
	_, m := l.Storage.ResolveInput(args.ESA.InputID)
	inputFname := m.Inputs[args.ESA.InputNo].Filename
	slog.Info("Start", "A", "LocalEncode/Prelude", "inputFname", inputFname)
	defer slog.Info("Stop ", "A", "LocalEncode/Prelude", "inputFname", inputFname)

	//slog.Info("local/postlude", "args", args)
	//slog.Info("local/postlude: removing input symlink")
	inputSymlink := l.inputSymlink(args.SessionID, args.ESA, args.FfmpegArgs)
	workDir := l.workDir(args.SessionID, args.ESA)
	targetOutputPath := l.Storage.TranscodedRepresentationFilePath(args.ESA)
	outputPath := filepath.Join(workDir, filepath.Base(targetOutputPath))
	if err := os.Remove(inputSymlink); err != nil {
		return shared.EncodePostludeResp{}, shared.Error("Failed to remove symlink to input file", "file", inputSymlink, "err", err)
	}
	if err := os.Rename(outputPath, targetOutputPath); err != nil {
		return shared.EncodePostludeResp{}, shared.Error("Failed to rename ffmpeg result file into place", "outputPath", outputPath, "targetOutputPath", targetOutputPath, "err", err)
	}
	if err := os.Remove(workDir); err != nil {
		return shared.EncodePostludeResp{}, shared.Error("Failed to remove ffmpeg workdir", "workdir", workDir, "err", err)
	}
	return shared.EncodePostludeResp{
		FfmpegArgs: args.FfmpegArgs,
	}, nil
}

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
