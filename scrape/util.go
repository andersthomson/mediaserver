package scrape

import (
	"log/slog"
	"os"

	"github.com/andersthomson/mediaserver/datasource"
)

type scrapeer interface {
	Scrape(dir, fname string)
	datasource.DataSource
}

func fileExists(fname string) bool {
	_, err := os.Stat(fname)
	return err == nil
}

func readFileIfExists(fname string) string {
	if fname == "" {
		return ""
	}
	buf, err := os.ReadFile(fname)
	if err != nil {
		slog.Warn("Plotfile gone from under me", "fname", fname, "err", err)
		return ""
	}
	return string(buf)
}

func replaceSuffix(s string, oldSuffix string, newSuffix string) string {
	return s[:len(s)-len(oldSuffix)] + newSuffix
}
