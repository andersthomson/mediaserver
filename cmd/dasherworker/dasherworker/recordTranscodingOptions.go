package dasherworker

import (
	"context"
	"os"

	"github.com/davecgh/go-spew/spew"
	"go.temporal.io/sdk/workflow"
)

func CallRecordTranscodingOptions(ctx workflow.Context, args EncodeStreamArgs, ffmpegargs FFMpegArgs, stderr string) error {
	_, err := CallActivityFast[any, string](ctx, RecordTranscodingOptions, args, ffmpegargs, stderr)
	return err
}

func RecordTranscodingOptions(_ context.Context, args EncodeStreamArgs, ffmpegargs FFMpegArgs, stderr string) (string, error) {
	type Log struct {
		EncodeStream EncodeStreamArgs
		Ffmpegargs   FFMpegArgs
		Stderr       string
	}
	log := Log{
		EncodeStream: args,
		Ffmpegargs:   ffmpegargs,
		Stderr:       stderr,
	}
	buf := spew.Sdump(log)
	return "", os.WriteFile(storage.DasherReadyRepresentationTranscodingLogFilePath(args), []byte(buf), 0600)
}
