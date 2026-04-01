package scrape

import (
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/davecgh/go-spew/spew"
)

type MediaServer struct {
	MediaFile string
}

func (m MediaServer) MediaURLPath() string {
	if m.MediaFile != "" {
		return "media"
	}
	return ""
}

func (m MediaServer) ServeHTTP(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	/*
		content, err := os.Open(m.MediaFile)
		if err != nil {
			logger.ErrorContext(r.Context(), "read of media", "failed", err)
			w.WriteHeader(404)
			return
		}
		http.ServeContent(w, r, "foo.mp4", time.Time{}, content)
	*/
	/*
		ctx := r.Context()
		itm := r.PathValue("item")
		ds := allRepos.DataSourceByID(itm)
		if ds == nil {
			errorHandler(ctx, w, r, http.StatusNotFound)
			logger.WarnContext(ctx, "datasource unknown", "id", itm)
			return
		}*/
	spew.Dump(r)
	//hdlr := http.StripPrefix("/", http.FileServer(http.Dir(filepath.Dir(m.MediaFile))))

}

type DashServer struct {
	MpdFile string
}

func (d DashServer) DashURLPath() string {
	if d.MpdFile != "" {
		return "dash/manifest.mpd"
	}
	return ""
}
func (d DashServer) ServeHTTP(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	//We expect r.URL.Path to host e.g. "/dash/manifest.mpd"
	splits := strings.SplitN(r.URL.Path, "/", 3)
	r.URL.Path = splits[2]
	logger.Info("Serving  dash", "splits", splits, "got 2", r.URL.Path, "file location", d.MpdFile)
	hdlr := http.FileServer(http.Dir(filepath.Dir(d.MpdFile)))
	hdlr.ServeHTTP(w, r)
}
