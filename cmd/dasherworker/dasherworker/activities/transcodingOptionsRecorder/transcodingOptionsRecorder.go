package transcodingOptionsRecorder

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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
	Ffmpegargs          shared.FFMpegArgs
	Stderr              string
	MP4BoxDashReadyArgs mp4boxDashReady.MP4BoxDashReadyArgs
	MP4Box              Invocation
}

type TranscodingOptionsRecorder struct {
	Storage *storage.Storage
}

func (t *TranscodingOptionsRecorder) RecordTranscodingOptions(_ context.Context, tr TranscodingOptionsRecord) (string, error) {
	stamp := time.Now().Format("20060102150405")
	base := t.Storage.DasherReadyRepresentationTranscodingLogFilePath(tr.EncodeStream)
	fname := base + "-" + stamp

	err := SaveStructToJSON(fname, tr)
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
	err := LoadJSONToStruct(t.Storage.DasherReadyRepresentationTranscodingLogFilePath(e), &tr)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, shared.Fatal(err.Error())
	}
	return &tr, err
}

func SaveStructToJSON(filename string, data interface{}) error {
	// 1. Convert struct to pretty-printed JSON bytes
	// MarshallIndent adds spacing and line breaks for readability on disk
	jsonData, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal struct to JSON: %w", err)
	}

	// 2. Write bytes to disk
	err = os.WriteFile(filename, jsonData, 0600)
	if err != nil {
		return fmt.Errorf("failed to write JSON file to disk: %w", err)
	}

	return nil
}

func LoadJSONToStruct(filename string, target interface{}) error {
	// 1. Read the raw bytes from the file
	jsonData, err := os.ReadFile(filename)
	if err != nil {
		// Provide a helpful error if the file simply doesn't exist
		if errors.Is(err, os.ErrNotExist) {
			slog.Info("File not found", "filename", filename)
		}
		return err
	}

	// 2. Parse the bytes into the struct pointer
	err = json.Unmarshal(jsonData, target)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return nil
}
