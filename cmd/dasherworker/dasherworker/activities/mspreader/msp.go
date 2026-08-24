package mspreader

import (
	"context"
	"path/filepath"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
	"github.com/andersthomson/mediaserver/scrape"
)

func Read(ctx context.Context, dir string, mspFile string) (scrape.Msp, error) {
	M, err := scrape.ReadMspFromFile(filepath.Join(dir, mspFile))
	if err != nil {
		return M, shared.FatalError(err)
	}
	return M, nil
}
