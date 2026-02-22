package scrape

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	tmdb "github.com/cyruzin/golang-tmdb"
)

type TMDBMovie struct {
	//SubsFileHandler
	SubsFileHandlerSlice
	PosterServer
	logger       *slog.Logger
	id           string
	media        string
	language     string
	title        string
	tagline      string
	backdropFile string
	overview     string
	tags         map[string][]string
}

func (i TMDBMovie) OpenMedia() (io.ReadSeekCloser, error) {
	x, err := os.Open(i.media)
	return x, err
}

func (i TMDBMovie) Title() string {
	return i.title
}

func (i TMDBMovie) Tagline() string {
	return i.tagline
}

func (i TMDBMovie) Overview() string {
	return i.overview
}

func (i TMDBMovie) Language() string {
	return i.language
}

func (i TMDBMovie) Tags() map[string][]string {
	return i.tags
}

func (i TMDBMovie) ID() string {
	return i.id
}

func (i TMDBMovie) OpenBackdrop() (io.ReadSeekCloser, error) {
	x, err := os.Open(i.backdropFile)
	return x, err
}

func (_ TMDBMovie) deriveID(fname string) string {
	return fname
}

func (i TMDBMovie) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	i.logger.Info("tmdbmovie serving", "Url", r.URL.String())
	switch r.URL.Path {
	case i.PosterURLPath():
		i.PosterServer.ServeHTTP(w, r, i.logger)
	}
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
	itm.overview = movie.Overview
	if fname, err := TMDBImage(movie.PosterPath, tmdb.W500); err == nil {
		itm.PosterFile = fname
	}
	if movie.BackdropPath != "" {
		if fname, err := TMDBImage(movie.BackdropPath, tmdb.W1280); err == nil {
			itm.backdropFile = fname
		}
	} else {
		logger.Warn("Has no backdrop image", "id", id, "title", movie.Title)
	}
	for _, genre := range movie.Genres {
		itm.tags["genre"] = append(itm.tags["genre"], strings.TrimSpace(genre.Name))
	}
	itm.tagline = movie.Tagline
	if movie.BelongsToCollection.ID != 0 {
		collection, err := TMDBCollectionDetails(int(movie.BelongsToCollection.ID))
		if err != nil {
			logger.Warn("TMDBTVMovie failed to fetch collection data. Skipping", "err", err)
			return false
		}
		itm.tags["collection"] = []string{collection.Name}
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

	res.SubsFileHandlerSlice = NewSubsFileHandlers(dir, fname)

	basename := strings.TrimSuffix(fname, ".mp4")
	target := filepath.Join(dir, basename+"-poster.jpg")
	if fileExists(target) {
		res.PosterFile = target
		logger.Info("", "source", "filename", "posterfile", res.PosterFile)
	}

	for idx := range ffdata.Streams {
		if ffdata.Streams[idx].CodecType == "audio" {
			res.language = ffdata.Streams[idx].Tags.Language
			break
		}
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
