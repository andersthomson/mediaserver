package dasherworker

import (
	"context"
	"os"

	"github.com/pkg/errors"
	"go.temporal.io/sdk/workflow"
)

type Invocation struct {
	Dir      string
	Args     []string
	Stdout   string
	Stderr   string
	ExitCode int
}
type TranscodingOptionsRecord struct {
	EncodeStream        EncodeStreamArgs
	Ffmpegargs          FFMpegArgs
	Stderr              string
	MP4BoxDashReadyArgs MP4BoxDashReadyArgs
	MP4Box              Invocation
}

func CallRecordTranscodingOptions(ctx workflow.Context, t TranscodingOptionsRecord) error {
	_, err := CallActivityFast[any, string](ctx, RecordTranscodingOptions, t)
	return err
}

func RecordTranscodingOptions(_ context.Context, t TranscodingOptionsRecord) (string, error) {
	return "", SaveStructToJSON(storage.DasherReadyRepresentationTranscodingLogFilePath(t.EncodeStream), t)
}

func CallLoadTranscodingOptions(ctx workflow.Context, e EncodeStreamArgs) (*TranscodingOptionsRecord, error) {
	return CallActivityFast[EncodeStreamArgs, *TranscodingOptionsRecord](ctx, LoadTranscodingOptions, e)
}

func LoadTranscodingOptions(_ context.Context, e EncodeStreamArgs) (*TranscodingOptionsRecord, error) {
	var t TranscodingOptionsRecord
	err := LoadJSONToStruct(storage.DasherReadyRepresentationTranscodingLogFilePath(e), &t)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, Fatal(err.Error())
	}
	return &t, err
}
