package dasherworker

import (
	"context"
	"os"
	"path/filepath"
	"time"

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
	stamp := time.Now().Format("20060102150405")
	base := storage.DasherReadyRepresentationTranscodingLogFilePath(t.EncodeStream)
	fname := base + "-" + stamp

	err := SaveStructToJSON(fname, t)
	if err != nil {
		return "", FatalError(err)
	}
	// Intentional: OK if the name does not exist.
	_ = os.Remove(base)

	if err := os.Symlink(filepath.Base(fname), base); err != nil {
		return "", FatalError(err)
	}
	return "", nil
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
