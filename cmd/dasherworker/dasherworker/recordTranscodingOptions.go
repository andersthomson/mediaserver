package dasherworker

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
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
	EncodeStream        shared.EncodeStreamArgs
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
	_ = os.Rename(base, base+".old")

	if err := os.Symlink(filepath.Base(fname), base); err != nil {
		return "", FatalError(err)
	}
	return "", nil
}

func CallLoadTranscodingOptions(ctx workflow.Context, e shared.EncodeStreamArgs) (*TranscodingOptionsRecord, error) {
	return CallActivityFast[shared.EncodeStreamArgs, *TranscodingOptionsRecord](ctx, LoadTranscodingOptions, e)
}

func LoadTranscodingOptions(_ context.Context, e shared.EncodeStreamArgs) (*TranscodingOptionsRecord, error) {
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
