package dasherworker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"go.temporal.io/sdk/activity"
)

type DirFile struct {
	Dir   string
	Fname string
}

func File(dir, fname string) DirFile {
	return DirFile{
		Dir:   dir,
		Fname: fname,
	}
}

type FFMpegArgs struct {
	InputDir    string
	InputFname  string
	Args        []string
	OutputDir   string
	OutputFname string
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
			panic(fmt.Sprintf("Found more than 2 DirFile:s in the ffmpeg args %+v", s))
		default:
			panic(fmt.Sprintf("Unsupported type %T", x))
		}
	}
	//Secure that we have input and output (by checkinng that output is set)
	if res.OutputFname == "" {
		panic(fmt.Sprintf("input and output not identified: %+v", s))
	}
	return res
}

type EncodePreludeArgs struct {
	FfmpegArgs FFMpegArgs
}

type EncodePreludeResp struct {
	FfmpegArgs FFMpegArgs
}

type EncodeArgs struct {
	FfmpegArgs      FFMpegArgs
	TotalDurationUs int64
}

type EncodeResp struct {
	FfmpegArgs FFMpegArgs
}

type EncodePostludeArgs struct {
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
	slog.Info("Remote/Prelude", "host", r.Hostname, "username", r.Username, "args", args)
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
	slog.Info("Remote/Encode", "host", r.Hostname, "args", args)

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

	slog.Info("Remote/postlude", "host", r.Hostname, "args", args)
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

func (l *LocalEncode) EncodePrelude(ctx context.Context, args EncodePreludeArgs) (EncodePreludeResp, error) {
	slog.Info("local/prelude", "args", args)
	slog.Info("local/prelude: symlinking input file")
	if err := os.Symlink(args.FfmpegArgs.InputDir+"/"+args.FfmpegArgs.InputFname, args.FfmpegArgs.OutputDir+"/"+args.FfmpegArgs.InputFname); err != nil {
		return EncodePreludeResp{}, fmt.Errorf("Failed to symlink inpout file (%s): %s", args.FfmpegArgs.InputFname, err)
	}
	return EncodePreludeResp{
		FfmpegArgs: args.FfmpegArgs,
	}, nil
}
func (l *LocalEncode) Encode(ctx context.Context, args EncodeArgs) (EncodeResp, error) {
	slog.Info("local/Encode", "args", args)
	_, err := FfmpegLocalEncode(ctx, FfmpegEncodeArgs{
		Ffmpeg:          "/usr/bin/ffmpeg",
		Args:            args.FfmpegArgs.Args,
		Workdir:         args.FfmpegArgs.OutputDir,
		TotalDurationUs: args.TotalDurationUs,
	})
	return EncodeResp{
		FfmpegArgs: args.FfmpegArgs,
	}, err
}
func (l *LocalEncode) EncodePostlude(ctx context.Context, args EncodePostludeArgs) (EncodePostludeResp, error) {
	slog.Info("local/postlude", "args", args)
	slog.Info("local/postlude: removing input symlink")
	if err := os.Remove(args.FfmpegArgs.OutputDir + "/" + args.FfmpegArgs.InputFname); err != nil {
		return EncodePostludeResp{}, fmt.Errorf("Failed to remove symlink to inpout file (%s): %s", args.FfmpegArgs.OutputDir+"/"+args.FfmpegArgs.InputFname, err)
	}
	return EncodePostludeResp{
		FfmpegArgs: args.FfmpegArgs,
	}, nil
}
