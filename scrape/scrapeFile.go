package scrape

import (
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/andersthomson/mediaserver/datasource"
)

func toScraper(dir string, fname string) scrapeer {
	if strings.HasSuffix(fname, ".mp4") {
		if strings.HasSuffix(fname, "-svtplay.mp4") {
			return &SvtplayItem{}
		}
		return NewItem()
	}
	return nil
}

func ScrapeFile(dir string, fname string) datasource.DataSource {
	ffdata, err := FFProbe(filepath.Join(dir, fname))
	if err != nil {
		slog.Error("FFProbe", fname, filepath.Join(dir, fname), "error", err)
		panic(13)
	}

	if res, ok := NewTMDBMovie(dir, fname, ffdata); ok {
		return res
	}
	if res, ok := NewTMDBTVEpisode(dir, fname, ffdata); ok {
		return res
	}
	itm := toScraper(dir, fname)
	if itm == nil {
		slog.Info("No suitable scraper found", "dir", dir, "fname", fname)
		return nil
	}
	//slog.Info("Scraping", "dir", dir, "file", fname)
	itm.Scrape(dir, fname)
	return itm
}
