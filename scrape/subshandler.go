package scrape

import (
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/andersthomson/mediaserver/datasource"
	iso639_3 "github.com/barbashov/iso639-3"
)

type langURL struct {
	Language string
	SubsFile string
}

type SubsServer struct {
	Subs []langURL
}

// Helper function
func (s *SubsServer) AddSubsFromMP4Filename(dir string, fname string) {
	basename := strings.TrimSuffix(fname, ".mp4")
	for _, code := range slices.Sorted(maps.Keys(iso639_3.LanguagesPart1)) {
		targetFname := filepath.Join(dir, basename+"-subtitles_"+code+".vtt")
		if !fileExists(targetFname) {
			continue
		}
		s.AddSubs(targetFname, code)
	}
}

// Canonical constructor for urlPathFrag
func (_ SubsServer) urlPathFrag(language string, fname string) string {
	return "subs/subtitles-" + language + ".vtt"
}

func (s *SubsServer) AddSubs(fname string, language string) {

	s.Subs = append(s.Subs, langURL{
		Language: language,
		SubsFile: fname,
	})
}

func (s SubsServer) SubsURLSlice(ds datasource.DataSource, webroot string) []datasource.Subs {
	res := make([]datasource.Subs, len(s.Subs), 0)
	for idx := range s.Subs {
		res = append(res, datasource.Subs{
			Language:    s.Subs[idx].Language,
			URLPathFrag: s.urlPathFrag(s.Subs[idx].Language, s.Subs[idx].SubsFile),
		})
	}
	return res
}

func (_ SubsServer) SubsURLPath() string {
	return "subs/"
}

func (s *SubsServer) ServeHTTP(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	logger.Info("SubsServer got", "urlfrag", r.URL.String())
	idx := slices.IndexFunc(s.Subs, func(x langURL) bool {
		return s.urlPathFrag(x.Language, x.SubsFile) == r.URL.String()
	})
	if idx == -1 {
		w.WriteHeader(http.StatusNotFound)
		logger.Error("SubsServer unknown URLPath", "URLPath", r.URL.String())
		return
	}
	content, err := os.Open(s.Subs[idx].SubsFile)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		logger.Error("SubsServer os.Open failed", "name", s.Subs[idx].SubsFile, "error", err.Error())
	}
	http.ServeContent(w, r, "", time.Time{}, content)
}
