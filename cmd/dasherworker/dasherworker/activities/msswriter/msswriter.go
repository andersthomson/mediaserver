package msswriter

import (
	"context"
	"encoding/json"
	"os"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
	"github.com/andersthomson/mediaserver/scrape"
)

type MssWriter struct {
	Storage *storage.Storage
}

// StitchSubtitle injects an external WebVTT subtitle track into an existing DASH manifest
func (m *MssWriter) MssWrite(ctx context.Context, inputID string, mss scrape.Mss) error {
	path := m.Storage.MssFilePath(inputID)

	buf, err := json.MarshalIndent(mss, "", "    ")
	if err != nil {
		return shared.FatalError(err)
	}
	buf = append(buf, '\n')
	err = os.WriteFile(path, buf, 0644)
	if err != nil {
		return shared.FatalError(err)
	}
	return nil
}
