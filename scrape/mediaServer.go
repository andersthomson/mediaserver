package scrape

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
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

func (m MediaServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	content, err := os.Open(m.MediaFile)
	if err != nil {
		Logger.ErrorContext(r.Context(), "read of media", "failed", err)
		w.WriteHeader(404)
		return
	}
	http.ServeContent(w, r, "foo.mp4", time.Time{}, content)
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
func (d DashServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//We expect r.URL.Path to host e.g. "/dash/manifest.mpd"
	splits := strings.SplitN(r.URL.Path, "/", 3)
	r.URL.Path = splits[2]
	Logger.Info("Serving  dash", "splits", splits, "got 2", r.URL.Path, "file location", d.MpdFile)
	hdlr := http.FileServer(http.Dir(filepath.Dir(d.MpdFile)))
	hdlr.ServeHTTP(w, r)
}
