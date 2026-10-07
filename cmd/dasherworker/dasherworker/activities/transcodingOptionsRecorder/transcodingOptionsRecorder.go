package transcodingOptionsRecorder

import (
	"context"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/mp4boxDashReady"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
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
	MP4BoxDashReadyArgs mp4boxDashReady.MP4BoxDashReadyArgs
	Ffmpeg              Invocation
	MP4Box              Invocation
}

type TranscodingOptionsRecorder struct {
	Storage *storage.Storage
}

func (t *TranscodingOptionsRecorder) RecordTranscodingOptions(ctx context.Context, tr TranscodingOptionsRecord) (string, error) {
	base := t.Storage.DasherReadyRepresentationTranscodingLogFilePath(tr.EncodeStream)
	return shared.RecordOptions(ctx, base, tr)
}

func (t *TranscodingOptionsRecorder) LoadTranscodingOptions(ctx context.Context, e shared.EncodeStreamArgs) (*TranscodingOptionsRecord, error) {
	var tr TranscodingOptionsRecord
	err := shared.LoadOptions(ctx, t.Storage.DasherReadyRepresentationTranscodingLogFilePath(e), &tr)
	return &tr, err
}
