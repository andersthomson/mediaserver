package scrape

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/andersthomson/mediaserver/datasource"
)

func toScraper(dir string, fname string) scrapeer {
	if strings.HasSuffix(fname, ".mp4") {
		if strings.HasSuffix(fname, "-svtplay.mp4") {
			return &svtplayItem{}
		}
		defaultAttrs := []slog.Attr{}
		level := &slog.LevelVar{}
		level.Set(slog.LevelInfo)
		handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}).WithAttrs(defaultAttrs)
		logger := slog.New(handler)
		return NewItem(logger)
	}
	return nil
}

func ScrapeFile(logger *slog.Logger, dir string, fname string) datasource.DataSource {
	ffdata, err := FFProbe(filepath.Join(dir, fname))
	if err != nil {
		slog.Error("FFProbe", fname, filepath.Join(dir, fname), "error", err)
		panic(13)
	}

	/*
		defaultAttrs := []slog.Attr{}
		level := &slog.LevelVar{}
		level.Set(slog.LevelInfo)
		handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}).WithAttrs(defaultAttrs)
		logger := slog.New(handler)
	*/
	if res, ok := NewTMDBMovie(logger, dir, fname, ffdata); ok {
		return res
	}
	if res, ok := NewTMDBTVEpisode(logger, dir, fname, ffdata); ok {
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
