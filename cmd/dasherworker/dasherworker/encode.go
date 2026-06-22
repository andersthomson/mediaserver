package dasherworker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"

	"go.temporal.io/sdk/activity"
)

type DirFile struct {
	Dir   string
	Fname string
}

type InputDirFile DirFile
type OutputDirFile DirFile

func NewDirFile(dir, fname string) DirFile {
	return DirFile{
		Dir:   dir,
		Fname: fname,
	}
}

func (d DirFile) String() string {
	return filepath.Join(d.Dir, d.Fname)
}

type FFMpegArgs struct {
	InputDir       string
	InputFname     string
	Args           []string
	OutputDir      string
	OutputFname    string
	OutputDirFiles []OutputDirFile
}

func NewFFMpegArgs(s []any) FFMpegArgs {
	res := FFMpegArgs{}
	res.Args = make([]string, len(s))
	for idx, _ := range s {
		switch x := s[idx].(type) {
		case string:
			res.Args[idx] = x
		case DirFile:
			res.Args[idx] = x.Fname
			if res.InputFname == "" {
				res.InputFname = x.Fname
				res.InputDir = x.Dir
				continue
			}
			if res.OutputFname == "" {
				res.OutputFname = x.Fname
				res.OutputDir = x.Dir
				continue
			}
			slog.Error("Found more than 2 DirFile:s in the ffmpeg args", "args", s)
		case OutputDirFile:
			res.Args[idx] = x.Fname
			res.OutputDirFiles = append(res.OutputDirFiles, x)
		default:
			slog.Error("NewFFMpegArgs/Unsupported type", "type", fmt.Sprintf("%T", x))
		}
	}
	//Secure that we have input and output (by checking that output is set)
	if res.OutputFname == "" {
		slog.Error("input and output not identified", "args", s)
	}
	return res
}

type EncodePreludeArgs struct {
	SessionID  string
	FfmpegArgs FFMpegArgs
}

type EncodePreludeResp struct {
	FfmpegArgs FFMpegArgs
}

type EncodeArgs struct {
	SessionID       string
	FfmpegArgs      FFMpegArgs
	TotalDurationUs int64
}

type EncodeResp struct {
	FfmpegArgs FFMpegArgs
}

type EncodePostludeArgs struct {
	SessionID  string
	FfmpegArgs FFMpegArgs
}

type EncodePostludeResp struct {
	FfmpegArgs FFMpegArgs
}

type Encoder interface {
	EncodePrelude(ctx context.Context, args EncodePreludeArgs) (EncodePreludeResp, error)
	Encode(ctx context.Context, args EncodeArgs) (EncodeResp, error)
	EncodePostlude(ctx context.Context, args EncodePostludeArgs) (EncodePostludeResp, error)
}

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

	_, err := FfmpegRemoteEncode(ctx, FfmpegEncodeArgs{
		Ffmpeg:          r.Ffmpeg,
		Args:            args.FfmpegArgs.Args,
		Workdir:         r.remoteDir(ctx, args.FfmpegArgs.InputFname),
		TotalDurationUs: args.TotalDurationUs,
	}, r.Username, r.Hostname, r.Port)
	if err != nil {
		return EncodeResp{}, fmt.Errorf("Remote ffmpeg failed: %+v", err)
	}

	return EncodeResp{
		FfmpegArgs: args.FfmpegArgs,
	}, err
}

func (r *RemoteEncode) EncodePostlude(ctx context.Context, args EncodePostludeArgs) (EncodePostludeResp, error) {
	slog.Info("Start", "A", "RemoteEncode/Postlude", "id", r.Username+"@"+r.Hostname+"#"+strconv.Itoa(r.Port), "inputFname", args.FfmpegArgs.InputFname)
	defer slog.Info("Stop ", "A", "RemoteEncode/Postlude", "id", r.Username+"@"+r.Hostname+"#"+strconv.Itoa(r.Port), "inputFname", args.FfmpegArgs.InputFname)

	//slog.Info("Remote/postlude", "host", r.Hostname, "args", args)
	localPath := filepath.Join(args.FfmpegArgs.OutputDir, args.FfmpegArgs.OutputFname)
	remotePath := filepath.Join(r.remoteDir(ctx, args.FfmpegArgs.InputFname), args.FfmpegArgs.OutputFname)
	if err := RsyncActivity(ctx, localPath, remotePath, r.Username, r.Hostname, r.Port, false); err != nil {
		return EncodePostludeResp{}, fmt.Errorf("Rsync to remote failed: %+v", err)
	}
	return EncodePostludeResp{
		FfmpegArgs: args.FfmpegArgs,
	}, nil
}

var _ Encoder = &LocalEncode{}

type LocalEncode struct {
}

// Gives the workdir for a local ffmpeg encode.
func (_ LocalEncode) workDir(sessionID string, FfmpegArgs FFMpegArgs) string {
	wd := FfmpegArgs.OutputDir + "/" + ".sessionID-" + sessionID
	if err := os.Mkdir(wd, 0755); err != nil {
		slog.Error("Failed to create ffmpeg working dir", "err", err)
	} else {
		slog.Info("Created ffmpeg workdir", "dir", wd)
	}
	return wd
}

func (l LocalEncode) inputSymlink(sessionID string, ffmpegargs FFMpegArgs) string {
	return filepath.Join(l.workDir(sessionID, ffmpegargs), ffmpegargs.InputFname)
}

func (l *LocalEncode) EncodePrelude(ctx context.Context, args EncodePreludeArgs) (EncodePreludeResp, error) {
	slog.Info("Start", "A", "LocalEncode/Prelude", "inputFname", args.FfmpegArgs.InputFname)
	defer slog.Info("Stop ", "A", "LocalEncode/Prelude", "inputFname", args.FfmpegArgs.InputFname)
	//slog.Info("local/prelude", "args", args)
	slog.Info("local/prelude: symlinking input file")
	newName := l.inputSymlink(args.SessionID, args.FfmpegArgs)
	oldName := filepath.Join(args.FfmpegArgs.InputDir, args.FfmpegArgs.InputFname)

	if err := os.Symlink(oldName, newName); err != nil {
		slog.Error("Failed to symlink input file", "oldname", oldName, "newname", newName, "err", err)
		return EncodePreludeResp{}, fmt.Errorf("Failed to symlink input file (%s): %s", args.FfmpegArgs.InputFname, err)
	}
	return EncodePreludeResp{
		FfmpegArgs: args.FfmpegArgs,
	}, nil
}
func (l *LocalEncode) Encode(ctx context.Context, args EncodeArgs) (EncodeResp, error) {
	slog.Info("Start", "A", "LocalEncode/Encode", "inputFname", args.FfmpegArgs.InputFname)
	defer slog.Info("Stop ", "A", "LocalEncode/Encode", "inputFname", args.FfmpegArgs.InputFname)
	slog.Info("local/Encode", "args", args)
	_, err := FfmpegLocalEncode(ctx, FfmpegEncodeArgs{
		Ffmpeg:          "/usr/bin/ffmpeg",
		Args:            args.FfmpegArgs.Args,
		Workdir:         l.workDir(args.SessionID, args.FfmpegArgs),
		TotalDurationUs: args.TotalDurationUs,
	})
	return EncodeResp{
		FfmpegArgs: args.FfmpegArgs,
	}, err
}
func (l *LocalEncode) EncodePostlude(ctx context.Context, args EncodePostludeArgs) (EncodePostludeResp, error) {
	slog.Info("Start", "A", "LocalEncode/Postlude", "inputFname", args.FfmpegArgs.InputFname)
	defer slog.Info("Stop ", "A", "LocalEncode/Postlude", "inputFname", args.FfmpegArgs.InputFname)

	//slog.Info("local/postlude", "args", args)
	//slog.Info("local/postlude: removing input symlink")
	inputSymlink := l.inputSymlink(args.SessionID, args.FfmpegArgs)
	workDir := l.workDir(args.SessionID, args.FfmpegArgs)
	outputPath := filepath.Join(workDir, args.FfmpegArgs.OutputFname)
	targetOutputPath := filepath.Join(args.FfmpegArgs.OutputDir, args.FfmpegArgs.OutputFname)
	if err := os.Remove(inputSymlink); err != nil {
		return EncodePostludeResp{}, Error("Failed to remove symlink to input file", "file", inputSymlink, "err", err)
	}
	if err := os.Rename(outputPath, targetOutputPath); err != nil {
		return EncodePostludeResp{}, Error("Failed to rename ffmpeg result file into place", "outputPath", outputPath, "targetOutputPath", targetOutputPath, "err", err)
	}
	if err := os.Remove(workDir); err != nil {
		return EncodePostludeResp{}, Error("Failed to remove ffmpeg workdir", "workdir", workDir, "err", err)
	}
	return EncodePostludeResp{
		FfmpegArgs: args.FfmpegArgs,
	}, nil
}
