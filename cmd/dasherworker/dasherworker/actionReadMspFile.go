package dasherworker

import (
	"context"
	"path/filepath"

	"github.com/andersthomson/mediaserver/scrape"
	"go.temporal.io/sdk/workflow"
)

func CallReadMspFile(ctx workflow.Context, mspPath string) (scrape.Msp, error) {
	return CallActivityIO[string, scrape.Msp](ctx, ReadMspFile, filepath.Dir(mspPath), filepath.Base(mspPath))
}
func ReadMspFile(ctx context.Context, dir string, mspFile string) (scrape.Msp, error) {
	M, err := scrape.ReadMspFromFile(filepath.Join(dir, mspFile))
	if err != nil {
		return M, FatalError(err)
	}
	return M, nil
}
