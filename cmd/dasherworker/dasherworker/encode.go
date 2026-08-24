package dasherworker

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
	"go.temporal.io/sdk/workflow"
)

type TranscodedRepesentationFilePath struct {
	ESA shared.EncodeStreamArgs
}

type InputFilePath struct {
	Id     string
	Number int
}

type FFMpegArgKind string

const (
	KindString                          FFMpegArgKind = "STRING"
	KindTranscodedRepesentationFilePath FFMpegArgKind = "TranscodedRepesentationFilePath"
	KindInputFilePath                   FFMpegArgKind = "INPUTFILEPATH"
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
		case KindTranscodedRepesentationFilePath:
			var v TranscodedRepesentationFilePath
			if err := json.Unmarshal(x.Payload, &v); err != nil {
				return res, Fatal("json unmarshal failed", "err", err)
			}
			p := storage.TranscodedRepresentationFilePath(v.ESA)
			res.Args[idx] = filepath.Base(p)
		case KindInputFilePath:
			var v InputFilePath
			if err := json.Unmarshal(x.Payload, &v); err != nil {
				return res, Fatal("json unmarshal failed", "err", err)
			}
			p := storage.ResolveInputNumber(v.Id, v.Number)
			res.Args[idx] = filepath.Base(p)
		default:
			slog.Error("unsupported FFMpegArgKind", "value", x.Kind)
		}
	}
	return res, nil
}

type EncodePreludeArgs struct {
	SessionID  string
	FfmpegArgs FFMpegArgs
	ESA        shared.EncodeStreamArgs
}

type EncodePreludeResp struct {
	FfmpegArgs FFMpegArgs
}

type EncodeArgs struct {
	SessionID       string
	FfmpegArgs      FFMpegArgs
	ESA             shared.EncodeStreamArgs
	TotalDurationUs int64
}

type EncodeResp struct {
	Stderr   string
	Exitcode int
}

type EncodePostludeArgs struct {
	SessionID  string
	FfmpegArgs FFMpegArgs
	ESA        shared.EncodeStreamArgs
}

type EncodePostludeResp struct {
	FfmpegArgs FFMpegArgs
}

type Encoder interface {
	EncodePrelude(ctx context.Context, args EncodePreludeArgs) (EncodePreludeResp, error)
	Encode(ctx context.Context, args EncodeArgs) (EncodeResp, error)
	EncodePostlude(ctx context.Context, args EncodePostludeArgs) (EncodePostludeResp, error)
}
