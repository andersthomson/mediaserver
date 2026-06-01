package dasherworker

import (
	"log/slog"
	"path/filepath"
	"slices"
	"time"

	"github.com/andersthomson/mediaserver/scrape"
	"github.com/davecgh/go-spew/spew"
	"go.temporal.io/sdk/workflow"
)

func HLSProdDir(m scrape.Msp) string {
	return "/var/cache/mediacache/" + m.ShortName + "-" + m.Id + "/hls"
}

var HLSRelevantExtensions = []string{".ts", ".m3u8"}

// Symlink all inputs which are .ts or .m3u8
func LinkHLSSources(ctx workflow.Context, m scrape.Msp, dir string) error {
	spew.Dump(m)
	for _, input := range m.Inputs {
		ext := filepath.Ext(input.Filename)
		slog.Info("Testing", input.Filename)
		if slices.Contains(HLSRelevantExtensions, ext) {
			_, err := CallActivity[string, string](ctx, LinkSrcMedia, 10*time.Minute, filepath.Join(dir, input.Filename), filepath.Join(HLSProdDir(m), input.Filename))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func LinkHLSSourcesWF(ctx workflow.Context, m scrape.Msp, dir string) (string, error) {
	return "", LinkHLSSources(ctx, m, dir)
}
