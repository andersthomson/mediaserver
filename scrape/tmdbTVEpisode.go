package scrape

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	tmdb "github.com/cyruzin/golang-tmdb"
)

type TMDBTVEpisode struct {
	logger       *slog.Logger
	id           string
	media        string
	showName     string
	title        string
	episodetitle string
	SubsFile     string
	posterFile   string
	backdropFile string
	plotFile     string
	plot         string
	episode      int
	season       int
	tags         map[string][]string
}

func (i TMDBTVEpisode) OpenMedia() (io.ReadSeekCloser, error) {
	x, err := os.Open(i.media)
	return x, err
}

func (i TMDBTVEpisode) Title() string {
	return i.title
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
func (i TMDBTVEpisode) Plot() string {
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

func (i TMDBTVEpisode) OpenSubs() (io.ReadSeekCloser, error) {
	x, err := os.Open(i.SubsFile)
	if err != nil {
		return nil, fmt.Errorf("open of %s failed: %w", i.SubsFile, err)
	}
	return x, nil
}

func (i TMDBTVEpisode) OpenPoster() (io.ReadSeekCloser, error) {
	x, err := os.Open(i.posterFile)
	return x, err
}

func (i TMDBTVEpisode) OpenBackdrop() (io.ReadSeekCloser, error) {
	x, err := os.Open(i.backdropFile)
	return x, err
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

func (_ TMDBTVEpisode) deriveSubs(basedir string, fname string) []string {
	basename := strings.TrimSuffix(fname, ".mp4")
	target := filepath.Join(basedir, basename+"-subtitles_sv.vtt")
	if !fileExists(target) {
		//slog.Info("TMDBTVEpisode/deriveSubs", "ENOFILE", target)
		return []string{}
	}
	//slog.Info("TMDBTVEpisoder/deriveSubs", "found file", target)
	return []string{target}
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
	itm.tags["TV Show"] = []string{itm.showName}
	for _, lang := range iso639_1_Order {
		if tvEpisodeDetails == nil {
			panic(66)
		}
		if tvEpisodeDetails.TVEpisodeTranslationsAppend != nil {
			for _, translation := range tvEpisodeDetails.Translations.Translations {
				//logger.Info("trans", translation.Iso639_1, "lang", lang)
				if translation.Iso639_1 == lang {
					if translation.Data.Overview != "" && itm.plot == "" {
						itm.plot = translation.Data.Overview
						//logger.Info("hit", itm.plot)
					}
					if translation.Data.Name != "" && itm.title == "" {
						itm.title = translation.Data.Name
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
			itm.posterFile = fname
		}
	}
	if p := getFirstString(&tvDetails.BackdropPath); p != nil {
		if fname, err := TMDBImage(*p, tmdb.W500); err == nil {
			itm.backdropFile = fname
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
	res.media = dir + "/" + fname
	i := res.deriveSubs(dir, fname)
	if len(i) > 0 {
		res.SubsFile = i[0]
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
	res.tags["scraper"] = append(res.tags["scraper"], "TMDBTVEpisode")
	return res, true
}
