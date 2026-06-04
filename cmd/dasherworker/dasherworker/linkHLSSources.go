package dasherworker

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andersthomson/mediaserver/scrape"
	"go.temporal.io/sdk/workflow"
)

func HLSProdDir(m scrape.Msp) string {
	return "/var/cache/mediacache/" + m.ShortName + "-" + m.Id + "/hls"
}

var HLSRelevantExtensions = []string{".ts", ".m3u8"}

// Symlink all inputs which are .ts or .m3u8
func LinkHLSSources(ctx workflow.Context, m scrape.Msp, dir string) error {
	//spew.Dump(m)
	for _, input := range m.Inputs {
		ext := filepath.Ext(input.Filename)
		if slices.Contains(HLSRelevantExtensions, ext) {
			if _, err := CallActivityFast[string, string](ctx, LinkSrcMedia, filepath.Join(dir, input.Filename), filepath.Join(HLSProdDir(m), input.Filename)); err != nil {
				return err
			}
		}
	}
	for _, input := range m.Inputs {
		ext := filepath.Ext(input.Filename)
		if before, ok := strings.CutSuffix(input.Filename, ext); ok {
			if err := GenerateHLSLanguageFile(ctx, input, filepath.Join(HLSProdDir(m), before+".language")); err != nil {
				return err
			}
		}
	}
	return nil
}

func LinkHLSSourcesWF(ctx workflow.Context, m scrape.Msp, dir string) (string, error) {
	return "", LinkHLSSources(ctx, m, dir)
}

func GenerateHLSLanguageFile(ctx workflow.Context, input scrape.InputT, outputPath string) error {
	if input.Language != "" {
		_, err := CallActivityFast[string, string](ctx, GenerateHLSLanguageFileActivity, input.Language, outputPath)
		return err
	}
	return nil
}

func GenerateHLSLanguageFileActivity(ctx context.Context, lang string, outputPath string) (string, error) {
	return "", os.WriteFile(outputPath, []byte(lang), 0644)
}
