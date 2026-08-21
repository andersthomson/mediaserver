package dasherworker

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"

	"go.temporal.io/sdk/workflow"
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

type FFMpegArgKind string

const (
	KindString  FFMpegArgKind = "STRING"
	KindDirFile FFMpegArgKind = "DIRFILE"
)

type FFMpegArg struct {
	Kind    FFMpegArgKind
	Payload json.RawMessage
}

func NewFFMpegArg(kind FFMpegArgKind, v any) FFMpegArg {
	bytes, _ := json.Marshal(v) // Pre-serialize so it traverses Temporal safely
	return FFMpegArg{Kind: kind, Payload: bytes}
}

type FFMpegArgs struct {
	InputDir    string
	InputFname  string
	Args        []string
	OutputDir   string
	OutputFname string
}

func CallNewFFMpegArgs(ctx workflow.Context, s []FFMpegArg) (FFMpegArgs, error) {
	return CallActivityIO[[]FFMpegArg, FFMpegArgs](ctx, NewFFMpegArgs, s)
}

func NewFFMpegArgs(ctx context.Context, s []FFMpegArg) (FFMpegArgs, error) {
	res := FFMpegArgs{}
	res.Args = make([]string, len(s))
	for idx, x := range s {
		switch x.Kind {
		case KindString:
			var str string
			if err := json.Unmarshal(x.Payload, &str); err != nil {
				return res, Fatal("json unmarshal failed", "err", err)
			}
			res.Args[idx] = str
		case KindDirFile:
			var df DirFile
			if err := json.Unmarshal(x.Payload, &df); err != nil {
				return res, Fatal("json unmarshal failed", "err", err)
			}
			res.Args[idx] = df.Fname

			if res.InputFname == "" {
				res.InputFname = df.Fname
				res.InputDir = df.Dir
				continue
			}
			if res.OutputFname == "" {
				res.OutputFname = df.Fname
				res.OutputDir = df.Dir
				continue
			}
			slog.Error("Found more than 2 DirFile:s in the ffmpeg args", "args", s)
		default:
			slog.Error("unsupported FFMpegArgKind", "value", x.Kind)
		}
	}
	//Secure that we have input and output (by checking that output is set)
	if res.OutputFname == "" {
		return res, Fatal("input anhd output not identified", "args", s)
	}
	return res, nil
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
