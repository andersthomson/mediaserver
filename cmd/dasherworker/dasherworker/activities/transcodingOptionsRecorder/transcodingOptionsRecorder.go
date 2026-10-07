package transcodingOptionsRecorder

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/mp4boxDashReady"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
	"github.com/pkg/errors"
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

func (t *TranscodingOptionsRecorder) RecordTranscodingOptions(_ context.Context, tr TranscodingOptionsRecord) (string, error) {
	stamp := time.Now().Format("20060102150405")
	base := t.Storage.DasherReadyRepresentationTranscodingLogFilePath(tr.EncodeStream)
	fname := base + "-" + stamp

	err := shared.SaveStructToJSON(fname, tr)
	if err != nil {
		return "", shared.FatalError(err)
	}
	// Intentional: OK if the name does not exist.
	_ = os.Rename(base, base+".old")

	if err := os.Symlink(filepath.Base(fname), base); err != nil {
		return "", shared.FatalError(err)
	}
	return "", nil
}

func (t *TranscodingOptionsRecorder) LoadTranscodingOptions(_ context.Context, e shared.EncodeStreamArgs) (*TranscodingOptionsRecord, error) {
	var tr TranscodingOptionsRecord
	err := shared.LoadJSONToStruct(t.Storage.DasherReadyRepresentationTranscodingLogFilePath(e), &tr)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, shared.Fatal(err.Error())
	}
	return &tr, err
}
