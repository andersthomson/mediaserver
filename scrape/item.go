package scrape

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type ItemData struct {
	logger       *slog.Logger
	id           string
	media        string
	showName     string
	title        string
	episodetitle string
	SubsFile     string
	posterFile   string
	plotFile     string
	plot         string
	episode      int
	season       int
	tags         map[string][]string
}

func NewItem(logger *slog.Logger) *ItemData {
	return &ItemData{
		logger: logger,
		tags:   make(map[string][]string, 4),
	}
}
func (i ItemData) OpenMedia() (io.ReadSeekCloser, error) {
	x, err := os.Open(i.media)
	return x, err
}

func (i ItemData) Title() string {
	return i.title
}

func (i ItemData) ShowName() string {
	return i.showName
}

func (i ItemData) Tags() map[string][]string {
	return i.tags
}

func (i ItemData) ID() string {
	return i.id
}

func (i ItemData) Episode() int {
	return i.episode
}

func (i ItemData) Season() int {
	return i.season
}
func (i ItemData) Plot() string {
	if i.plot != "" {
		return i.plot
	}
	if i.plotFile == "" {
		return ""
	}
	buf, err := os.ReadFile(i.plotFile)
	if err != nil {
		slog.Warn("Plotfile gone from under me", "fname", i.plotFile, "err", err)
		return ""
	}
	return string(buf)
}

func (i ItemData) OpenSubs() (io.ReadSeekCloser, error) {
	x, err := os.Open(i.SubsFile)
	if err != nil {
		return nil, fmt.Errorf("open of %s failed: %w", i.SubsFile, err)
	}
	return x, nil
}

func (i ItemData) OpenPoster() (io.ReadSeekCloser, error) {
	x, err := os.Open(i.posterFile)
	return x, err
}

func (_ ItemData) deriveID(fname string) string {
	return fname
}

func (_ ItemData) derivePlot(fname string, dir string) string {
	plotFname := filepath.Join(dir, strings.TrimSuffix(fname, ".mp4")+"-plot.txt")
	_, err := os.Stat(plotFname)
	if err != nil {
		//slog.Info("ItemDatar/derivePlot", "err", err)
		return ""
	}
	//slog.Info("ItemDatar/derivePlot", "file", err)
	return plotFname
}

func (_ ItemData) deriveSubs(basedir string, fname string) []string {
	basename := strings.TrimSuffix(fname, ".mp4")
	target := filepath.Join(basedir, basename+"-subtitles_sv.vtt")
	if !fileExists(target) {
		//slog.Info("ItemData/deriveSubs", "ENOFILE", target)
		return []string{}
	}
	//slog.Info("ItemDatar/deriveSubs", "found file", target)
	return []string{target}
}

func scrapeAsIndividualmp4tags(logger *slog.Logger, itm *ItemData, ffdata FFProbeRoot) bool {
	if ffdata.Format.Tags.Title != "" {
		itm.title = ffdata.Format.Tags.Title
		logger.Info("", "source", "mp4 Format.Tags.Title", "title", itm.title)
	}
	if ffdata.Format.Tags.Description != "" {
		logger.Info("", "source", "mp4 Format.Tags.Description", "plot", itm.plot)
		itm.plot = ffdata.Format.Tags.Description
	}
	if ffdata.Format.Tags.Genre != "" {
		splits := strings.Split(ffdata.Format.Tags.Genre, "/")
		for _, s := range splits {
			itm.tags["genre"] = append(itm.tags["genre"], strings.TrimSpace(s))
			logger.Info("", "source", "mp4 Format.Tags.Genre", "genre+=", strings.TrimSpace(s))
		}
	}
	if ffdata.Format.Tags.Season != "" {
		d, err := strconv.Atoi(strings.TrimSpace(ffdata.Format.Tags.Season))
		if err != nil {
			logger.Warn("strconv.Atoi failed", "data", ffdata.Format.Tags.Season, "err", err)
		} else {
			itm.episode = d
			logger.Info("", "source", "mp4 Format.Tags.Season", "season", itm.season)
		}
	}
	if ffdata.Format.Tags.Episode_id != "" {
		d, err := strconv.Atoi(strings.TrimSpace(ffdata.Format.Tags.Episode_id))
		if err != nil {
			logger.Warn("strconv.Atoi failed", "data", ffdata.Format.Tags.Episode_id, "err", err)
		} else {
			itm.episode = d
			logger.Info("", "source", "mp4 Format.Tags.Episode_id", "episode_id", itm.episode)
		}
	}
	return true
}

func (itm *ItemData) Scrape(dir, fname string) {
	logger := itm.logger.With(
		slog.String("scraper", "item"),
		slog.String("file", filepath.Join(dir, fname)))
	var ffdata FFProbeRoot
	var err error
	if ffdata, err = ffprobe(filepath.Join(dir, fname)); err != nil {
		slog.Info("ffprobe", fname, filepath.Join(dir, fname), "error", err)
		panic(33)
	}
	itm.id = itm.deriveID(fname)
	itm.media = dir + "/" + fname
	i := itm.deriveSubs(dir, fname)
	if len(i) > 0 {
		itm.SubsFile = i[0]
	}

	basename := strings.TrimSuffix(fname, ".mp4")
	target := filepath.Join(dir, basename+"-poster.jpg")
	if fileExists(target) {
		itm.posterFile = target
		logger.Info("", "source", "filename", "posterfile", itm.posterFile)
	}

	scrapeAsIndividualmp4tags(logger, itm, ffdata)
	if itm.title == "" {
		itm.title = strings.TrimSuffix(fname, ".mp4")
		logger.Info("", "source", "filename", "title", itm.title)
	}
	target = filepath.Join(dir, basename+"-plot.txt")
	if itm.plot == "" && fileExists(target) {
		itm.plotFile = target
		logger.Info("", "source", "filename", "plotFile", itm.plotFile)
	}

	if ffdata.Format.Tags.Grouping != "" {
		itm.tags["grouping"] = append(itm.tags["grouping"], strings.TrimSpace(ffdata.Format.Tags.Grouping))
		logger.Info("", "source", "mp4 Format.Tags.Grouping", "grouping", ffdata.Format.Tags.Grouping)
	}
	itm.tags["dir"] = append(itm.tags["dir"], filepath.Base(dir))
	itm.tags["fulldir"] = append(itm.tags["fulldir"], (dir))
	itm.tags["scraper"] = append(itm.tags["scraper"], "ItemData")
}
