package dasherworker

import (
	"context"
	"os"

	"github.com/davecgh/go-spew/spew"
)

type RecordTranscodingOptionsArgs struct {
	Args       EncodeStreamArgs
	Ffmpegargs FFMpegArgs
}

func RecordTranscodingOptions(_ context.Context, a RecordTranscodingOptionsArgs) (string, error) {
	buf := spew.Sdump(a.Ffmpegargs)
	return "", os.WriteFile(storage.DasherReadyRepresentationTranscodingLogFilePath(a.Args), []byte(buf), 0600)
}
