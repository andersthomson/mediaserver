package scrape

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	tmdb "github.com/cyruzin/golang-tmdb"
)

type TMDBMovie struct {
	SubsFileHandler
	logger       *slog.Logger
	id           string
	media        string
	title        string
	episodetitle string
	SubsFile     string
	posterFile   string
	backdropFile string
	plotFile     string
	plot         string
	overview     string
	episode      int
	season       int
	tags         map[string][]string
}

func (i TMDBMovie) OpenMedia() (io.ReadSeekCloser, error) {
	x, err := os.Open(i.media)
	return x, err
}

func (i TMDBMovie) Title() string {
	return i.title
}

func (i TMDBMovie) Overview() string {
	return i.overview
}

func (i TMDBMovie) Tags() map[string][]string {
	return i.tags
}

func (i TMDBMovie) ID() string {
	return i.id
}

func (i TMDBMovie) Episode() int {
	return i.episode
}

func (i TMDBMovie) Season() int {
	return i.season
}
func (i TMDBMovie) XPlot() string {
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

func (i TMDBMovie) OpenPoster() (io.ReadSeekCloser, error) {
	x, err := os.Open(i.posterFile)
	return x, err
}

func (i TMDBMovie) OpenBackdrop() (io.ReadSeekCloser, error) {
	x, err := os.Open(i.backdropFile)
	return x, err
}

func (_ TMDBMovie) deriveID(fname string) string {
	return fname
}

func (_ TMDBMovie) derivePlot(fname string, dir string) string {
	plotFname := filepath.Join(dir, strings.TrimSuffix(fname, ".mp4")+"-plot.txt")
	_, err := os.Stat(plotFname)
	if err != nil {
		//slog.Info("TMDBMovier/derivePlot", "err", err)
		return ""
	}
	//slog.Info("TMDBMovier/derivePlot", "file", err)
	return plotFname
}

func (_ TMDBMovie) deriveSubs(basedir string, fname string) []string {
	basename := strings.TrimSuffix(fname, ".mp4")
	target := filepath.Join(basedir, basename+"-subtitles_sv.vtt")
	if !fileExists(target) {
		//slog.Info("TMDBMovie/deriveSubs", "ENOFILE", target)
		return []string{}
	}
	//slog.Info("TMDBMovier/deriveSubs", "found file", target)
	return []string{target}
}

func scrapeAsTMDBMovie(logger *slog.Logger, itm *TMDBMovie, ffdata FFProbeRoot) bool {
	if ffdata.Format.Tags.TmdbMovie == "" {
		return false
	}
	id, err := strconv.Atoi(ffdata.Format.Tags.TmdbMovie)
	if err != nil {
		logger.Warn("Unexpected MP4 tag. Skipping", "ffdata.Format.Tags.TmdbMovie", ffdata.Format.Tags.TmdbMovie)
		return false

	}
	movie, err := TMDBMovieDetails(id)
	if err != nil {
		logger.Warn("TMDBTVMovie failed. Skipping", "err", err)
		return false
	}
	//Given all the data, complete the itm record.
	itm.title = movie.Title
	itm.tags["Movie"] = []string{itm.title}
	itm.plot = movie.Overview
	itm.overview = movie.Overview
	if fname, err := TMDBImage(movie.PosterPath, tmdb.W500); err == nil {
		itm.posterFile = fname
	}
	if fname, err := TMDBImage(movie.BackdropPath, tmdb.W1280); err == nil {
		itm.backdropFile = fname
	}
	for _, genre := range movie.Genres {
		itm.tags["genre"] = append(itm.tags["genre"], strings.TrimSpace(genre.Name))
	}
	return true
}
func NewTMDBMovie(logger *slog.Logger, dir string, fname string, ffdata FFProbeRoot) (*TMDBMovie, bool) {
	res := &TMDBMovie{
		logger: logger,
		tags:   make(map[string][]string, 4),
	}
	logger = res.logger.With(
		slog.String("scraper", "TMDBMovie"),
		slog.String("file", filepath.Join(dir, fname)))

	if !scrapeAsTMDBMovie(logger, res, ffdata) {
		return nil, false
	}
	res.id = res.deriveID(fname)
	res.media = dir + "/" + fname
	i := res.deriveSubs(dir, fname)
	if len(i) > 0 {
		res.SubsFileHandler.Filename = i[0]
	}

	basename := strings.TrimSuffix(fname, ".mp4")
	target := filepath.Join(dir, basename+"-poster.jpg")
	if fileExists(target) {
		res.posterFile = target
		logger.Info("", "source", "filename", "posterfile", res.posterFile)
	}

	if ffdata.Format.Tags.Grouping != "" {
		res.tags["grouping"] = append(res.tags["grouping"], strings.TrimSpace(ffdata.Format.Tags.Grouping))
		logger.Info("", "source", "mp4 Format.Tags.Grouping", "grouping", ffdata.Format.Tags.Grouping)
	}
	res.tags["dir"] = append(res.tags["dir"], filepath.Base(dir))
	res.tags["fulldir"] = append(res.tags["fulldir"], (dir))
	res.tags["scraper"] = append(res.tags["scraper"], "TMDBMovie")
	return res, true
}
