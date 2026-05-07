package dasherworker

import (
	"context"
	"path/filepath"

	"github.com/andersthomson/mediaserver/scrape"
)

func ReadMspFile(ctx context.Context, dir string, mspFile string) (scrape.Msp, error) {
	return scrape.ReadMspFromFile(filepath.Join(dir, mspFile))
}
