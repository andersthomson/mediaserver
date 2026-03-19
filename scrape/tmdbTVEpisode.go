package scrape

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	tmdb "github.com/cyruzin/golang-tmdb"
)

type TMDBTVEpisode struct {
	MediaServer
	PosterServer
	BackdropServer
	SubsServer
	logger       *slog.Logger
	id           string
	showName     string
	title        string
	tagline      string
	episodetitle string
	posterFile   string
	backdropFile string
	overview     string
	episode      int
	season       int
	tags         map[string][]string
}

func (i TMDBTVEpisode) Title() string {
	return i.title
}

func (i TMDBTVEpisode) Tagline() string {
	return i.tagline
}

func (i TMDBTVEpisode) ShowName() string {
	return i.showName
}

func (i TMDBTVEpisode) Tags() map[string][]string {
	return i.tags
}

func (i TMDBTVEpisode) ID() string {
	return i.id
}

func (i TMDBTVEpisode) Episode() int {
	return i.episode
}

func (i TMDBTVEpisode) Season() int {
	return i.season
}
func (i TMDBTVEpisode) Overview() string {
	return i.overview
}

func (_ TMDBTVEpisode) deriveID(fname string) string {
	return fname
}

func (_ TMDBTVEpisode) derivePlot(fname string, dir string) string {
	plotFname := filepath.Join(dir, strings.TrimSuffix(fname, ".mp4")+"-plot.txt")
	_, err := os.Stat(plotFname)
	if err != nil {
		//slog.Info("TMDBTVEpisoder/derivePlot", "err", err)
		return ""
	}
	//slog.Info("TMDBTVEpisoder/derivePlot", "file", err)
	return plotFname
}

func (i TMDBTVEpisode) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	i.logger.Info("tmdbtvepisode serving", "Url", r.URL.String())
	switch {
	case r.URL.Path == i.MediaURLPath():
		i.MediaServer.ServeHTTP(w, r, i.logger)
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

func getFirstString(strings ...*string) *string {
	for _, s := range strings {
		if *s != "" {
			return s
		}
	}
	return nil
}

func scrapeAsTMDBTVEpisode(logger *slog.Logger, itm *TMDBTVEpisode, ffdata FFProbeRoot) bool {
	if ffdata.Format.Tags.TmdbSeries == "" {
		return false
	}
	id, err := strconv.Atoi(ffdata.Format.Tags.TmdbSeries)
	if err != nil {
		logger.Warn("Unexpected MP4 tag. Skipping", "ffdata.Format.Tags.TmdbSeries", ffdata.Format.Tags.TmdbSeries)
		return false
	}
	episode, err := strconv.Atoi(ffdata.Format.Tags.Episode_id)
	if err != nil {
		logger.Warn("Unexpected MP4 tag. Skipping", "ffdata.Format.Tags.Episode_id", ffdata.Format.Tags.Episode_id)
		return false
	}
	season, err := strconv.Atoi(ffdata.Format.Tags.Season)
	if err != nil {
		logger.Warn("Unexpected MP4 tag. Skipping", "ffdata.Format.Tags.Season", ffdata.Format.Tags.Season)
		return false
	}
	tvEpisodeDetails, err := TMDBTVEpisodeDetails(id, season, episode)
	if err != nil {
		logger.Warn("TMDBTVEpisodeDetails failed. Skipping", "err", err)
		return false
	}
	tvSeasonDetails, err := TMDBTVSeasonDetails(id, season)
	if err != nil {
		logger.Warn("TMDBTVSeasonDetails failed. Skipping", "err", err)
		return false
	}
	tvDetails, err := TMDBTVDetails(id)
	if err != nil {
		logger.Warn("TMDBTVDetails failed. Skipping", "err", err)
		return false
	}
	//Given all the data, complete the itm record.
	itm.showName = tvDetails.Name
	itm.tagline = tvDetails.Tagline
	itm.tags["TV Show"] = []string{itm.showName}
	for _, lang := range iso639_1_Order {
		if tvEpisodeDetails == nil {
			panic(66)
		}
		if tvEpisodeDetails.TVEpisodeTranslationsAppend != nil {
			for _, translation := range tvEpisodeDetails.Translations.Translations {
				//logger.Info("trans", translation.Iso639_1, "lang", lang)
				if translation.Iso639_1 == lang {
					if translation.Data.Overview != "" && itm.overview == "" {
						itm.overview = translation.Data.Overview
						//logger.Info("hit", itm.overview)
					}
					if translation.Data.Name != "" && itm.title == "" {
						itm.title = translation.Data.Name
						//logger.Info("hit", itm.title)
					}
					if translation.Data.Tagline != "" && itm.tagline == "" {
						itm.tagline = translation.Data.Tagline
						//logger.Info("hit", itm.title)
					}
				}
			}
		}
	}
	itm.episode = episode
	itm.season = season
	if p := getFirstString(&tvEpisodeDetails.StillPath, &tvSeasonDetails.PosterPath); p != nil {
		if fname, err := TMDBImage(*p, tmdb.W500); err == nil {
			itm.PosterFile = fname
		}
	}
	if p := getFirstString(&tvDetails.BackdropPath); p != nil {
		if fname, err := TMDBImage(*p, tmdb.W500); err == nil {
			itm.BackdropFile = fname
		}
	}

	for _, genre := range tvDetails.Genres {
		itm.tags["genre"] = append(itm.tags["genre"], strings.TrimSpace(genre.Name))
	}
	return true
}

func NewTMDBTVEpisode(logger *slog.Logger, dir string, fname string, ffdata FFProbeRoot) (*TMDBTVEpisode, bool) {
	res := &TMDBTVEpisode{
		logger: logger,
		tags:   make(map[string][]string, 4),
	}

	logger = res.logger.With(
		slog.String("scraper", "TVMDBTVEpisode"),
		slog.String("file", filepath.Join(dir, fname)))
	if !scrapeAsTMDBTVEpisode(logger, res, ffdata) {
		return nil, false
	}
	res.id = res.deriveID(fname)
	res.MediaFile = dir + "/" + fname

	res.SubsServer.AddSubsFromMP4Filename(dir, fname)

	basename := strings.TrimSuffix(fname, ".mp4")
	target := filepath.Join(dir, basename+"-poster.jpg")
	if fileExists(target) {
		res.PosterFile = target
		logger.Info("", "source", "filename", "posterfile", res.PosterFile)
	}

	if ffdata.Format.Tags.Grouping != "" {
		res.tags["grouping"] = append(res.tags["grouping"], strings.TrimSpace(ffdata.Format.Tags.Grouping))
		logger.Info("", "source", "mp4 Format.Tags.Grouping", "grouping", ffdata.Format.Tags.Grouping)
	}
	res.tags["dir"] = append(res.tags["dir"], filepath.Base(dir))
	res.tags["fulldir"] = append(res.tags["fulldir"], (dir))
	res.tags["scraper"] = append(res.tags["scraper"], "TMDBTVEpisode")
	return res, true
}
