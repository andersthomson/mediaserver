package scrape

import (
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	tmdb "github.com/cyruzin/golang-tmdb"
	"github.com/davecgh/go-spew/spew"
)

type TMDBMovie struct {
	MediaServer
	DashServer
	SubsServer
	PosterServer
	BackdropServer
	logger   *slog.Logger
	id       string
	uuid     string
	language string
	title    string
	genres   []string
	tagline  string
	overview string
	tags     map[string][]string
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
	if i.tags != nil {
		return i.tags
	}
	return make(map[string][]string, 0)
}

func (i TMDBMovie) ID() string {
	return i.id + "-" + i.uuid
}

func (i TMDBMovie) UUID() string {
	return i.uuid
}

func (_ TMDBMovie) deriveID(fname string) string {
	return fname
}

func (i TMDBMovie) Genres() []string {
	return i.genres
}

func (i TMDBMovie) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	i.logger.Info("tmdbmovie serving", "Url", r.URL.String())
	w.Header().Add("Cache-Control", "no-cache, private, max-age=0")
	switch {
	case r.URL.Path == "/"+i.MediaURLPath():
		i.MediaServer.ServeHTTP(w, r, i.logger)
	case strings.HasPrefix(r.URL.String(), "/dash/"):
		i.DashServer.ServeHTTP(w, r, i.logger)
	case r.URL.Path == i.PosterURLPath():
		i.PosterServer.ServeHTTP(w, r, i.logger)
	case r.URL.Path == i.BackdropURLPath():
		i.BackdropServer.ServeHTTP(w, r, i.logger)
	case strings.HasPrefix(r.URL.String(), i.SubsURLPath()):
		i.SubsServer.ServeHTTP(w, r, i.logger)
	default:
		i.logger.ErrorContext(r.Context(), "Unsupported URLPathFragment", "URLPathFrag", r.URL.Path)
		w.WriteHeader(404)
		return
	}
}

func getTMDBMovieIdFromFFdata(logger *slog.Logger, ffdata FFProbeRoot) (int, bool) {
	if ffdata.Format.Tags.TmdbMovie == "" {
		return 0, false
	}
	id, err := strconv.Atoi(ffdata.Format.Tags.TmdbMovie)
	if err != nil {
		logger.Warn("Unexpected MP4 tag. Skipping", "ffdata.Format.Tags.TmdbMovie", ffdata.Format.Tags.TmdbMovie, "err", err)
		return 0, false

	}
	return id, true
}
func extractTMDBMovieData(logger *slog.Logger, itm *TMDBMovie, tmdbId int) bool {
	movie, err := TMDBMovieDetails(tmdbId)
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
			itm.BackdropFile = fname
		}
	} else {
		logger.Warn("Has no backdrop image", "id", tmdbId, "title", movie.Title)
	}
	for _, genre := range movie.Genres {
		itm.tags["genre"] = append(itm.tags["genre"], strings.TrimSpace(genre.Name))
		itm.genres = append(itm.genres, strings.TrimSpace(genre.Name))
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
	for _, lang := range iso639_1_Order {
		if movie.MovieTranslationsAppend != nil {
			if movie.MovieTranslationsAppend.Translations != nil {
				for _, translation := range movie.MovieTranslationsAppend.Translations.Translations {
					//logger.Info("trans", translation.Iso639_1, "lang", lang)
					if translation.Iso639_1 == lang {
						if translation.Data.Overview != "" && itm.overview == "" {
							itm.overview = translation.Data.Overview
							//logger.Info("hit", itm.plot)
						}
						if translation.Data.Name != "" && itm.title == "" {
							itm.title = translation.Data.Name
							//logger.Info("hit", itm.title)
						}
						if translation.Data.Tagline != "" && itm.tagline == "" {
							itm.tagline = translation.Data.Tagline
							//logger.Info("hit", itm.tagline)
						}
					}
				}
			}
		}
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

	id, ok := getTMDBMovieIdFromFFdata(logger, ffdata)
	if !ok {
		return nil, false
	}
	if !extractTMDBMovieData(logger, res, id) {
		return nil, false
	}
	res.id = res.deriveID(fname)
	res.MediaFile = dir + "/" + fname

	res.SubsServer.AddSubsFromMP4Filename(dir, fname)

	for idx := range ffdata.Streams {
		if ffdata.Streams[idx].CodecType == "audio" {
			res.language = ffdata.Streams[idx].Tags.Language
			break
		}
	}
	res.tags["dir"] = append(res.tags["dir"], filepath.Base(dir))
	res.tags["fulldir"] = append(res.tags["fulldir"], (dir))
	res.tags["scraper"] = append(res.tags["scraper"], "TMDBMovie")
	return res, true
}

func basename(orig string) string {
	for _, suffix := range []string{"-orig.mkv", "-orig.mp4", "-orig.avi", "-orig.mpg"} {
		if s, ok := strings.CutSuffix(orig, suffix); ok {
			return s
		}
	}
	return orig
}

func TMDBMovieFromGenerate(logger *slog.Logger, caches []string, g map[string]string, dir string) (*TMDBMovie, bool) {
	res := &TMDBMovie{
		logger: logger,
		tags:   make(map[string][]string, 4),
	}
	logger = res.logger.With(
		slog.String("scraper", "TMDBMovie"),
		slog.String("dir", dir),
		slog.String("INPUT", g["INPUT"]))

	id, err := strconv.Atoi(g["TMDBMOVIE"])
	if err != nil {
		logger.Warn("Unexpected TMDBMOVIE in .generate file. Skipping", "err", err)
		return nil, false

	}

	if !extractTMDBMovieData(logger, res, id) {
		return nil, false
	}
	res.uuid = g["INPUTID"]
	res.id = res.deriveID(g["INPUT"])

	methods, ok := g["methods"]
	if !ok {
		logger.Warn("no serving method(s) defined. Skipping", "dir", dir, "input", g["INPUT"])
		return nil, false
	}
	for _, method := range strings.Split(methods, ",") {
		switch method {
		//case "mp4":
		//	res.MediaFile = caches[0] + "/" + res.ID() + "/mp4/" + basename(g["INPUT"]) + ".mp4"
		case "dash":
			res.MpdFile = caches[0] + "/" + res.ID() + "/dash/" + "manifest.mpd"
		default:
			logger.Warn("unsupported serving method. Skipping", "dir", dir, "input", g["INPUT"], "method", method)
			return nil, false
		}
	}
	res.SubsServer.AddSubsFromMP4Filename(caches[0]+"/"+res.ID()+"/mp4/", basename(g["INPUT"]+".mp4"))

	res.language = g["AUDIOLANGUAGE"]
	res.tags["dir"] = append(res.tags["dir"], filepath.Base(dir))
	res.tags["fulldir"] = append(res.tags["fulldir"], (dir))
	res.tags["scraper"] = append(res.tags["scraper"], "TMDBMovie")
	spew.Dump(res)
	return res, true

}
