package dasherworker

import (
	"context"

	"go.temporal.io/sdk/workflow"
)

type TranscodingOptionsRecord struct {
	EncodeStream EncodeStreamArgs
	Ffmpegargs   FFMpegArgs
	Stderr       string
}

func CallRecordTranscodingOptions(ctx workflow.Context, t TranscodingOptionsRecord) error {
	_, err := CallActivityFast[any, string](ctx, RecordTranscodingOptions, t)
	return err
}

func RecordTranscodingOptions(_ context.Context, t TranscodingOptionsRecord) (string, error) {
	return "", SaveStructToJSON(storage.DasherReadyRepresentationTranscodingLogFilePath(t.EncodeStream), t)
}

func CallLoadTranscodingOptions(ctx workflow.Context, e EncodeStreamArgs) (TranscodingOptionsRecord, error) {
	return CallActivityFast[EncodeStreamArgs, TranscodingOptionsRecord](ctx, LoadTranscodingOptions, e)
}

func LoadTranscodingOptions(_ context.Context, e EncodeStreamArgs) (TranscodingOptionsRecord, error) {
	var t TranscodingOptionsRecord
	err := LoadJSONToStruct(storage.DasherReadyRepresentationTranscodingLogFilePath(e), &t)
	return t, err
}
