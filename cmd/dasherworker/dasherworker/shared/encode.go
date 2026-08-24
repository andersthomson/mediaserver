package shared

import (
	"context"
)

type FFMpegArgs struct {
	InputDir    string
	InputFname  string
	Args        []string
	OutputFname string
}

type EncodePreludeArgs struct {
	SessionID  string
	FfmpegArgs FFMpegArgs
	ESA        EncodeStreamArgs
}

type EncodePreludeResp struct {
	FfmpegArgs FFMpegArgs
}

type EncodeArgs struct {
	SessionID       string
	FfmpegArgs      FFMpegArgs
	ESA             EncodeStreamArgs
	TotalDurationUs int64
}

type EncodeResp struct {
	Stderr   string
	Exitcode int
}

type EncodePostludeArgs struct {
	SessionID  string
	FfmpegArgs FFMpegArgs
	ESA        EncodeStreamArgs
}

type EncodePostludeResp struct {
	FfmpegArgs FFMpegArgs
}

type Encoder interface {
	EncodePrelude(ctx context.Context, args EncodePreludeArgs) (EncodePreludeResp, error)
	Encode(ctx context.Context, args EncodeArgs) (EncodeResp, error)
	EncodePostlude(ctx context.Context, args EncodePostludeArgs) (EncodePostludeResp, error)
}
