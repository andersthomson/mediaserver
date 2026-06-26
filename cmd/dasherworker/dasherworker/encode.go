package dasherworker

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
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
	Stderr   string
	Exitcode int
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
