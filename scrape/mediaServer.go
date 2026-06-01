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

type HLSServer struct {
	MpdFile string
}

func (h HLSServer) HLSURLPath() string {
	if h.MpdFile != "" {
		return "hls/master.m3u8"
	}
	return ""
}
func (h HLSServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.MpdFile == "" {
		Logger.Error("Dash server started without setting MpdFile")
		w.WriteHeader(500)
		return
	}
	Logger.Info("HLSServer", "Serving File", h.MpdFile, "r.URL", r.URL, "Range", r.Header.Get("Range"))
	//We expect r.URL.Path to host e.g. "/hls/master.m3u8"
	splits := strings.SplitN(r.URL.Path, "/", 3)
	r.URL.Path = splits[2]
	//Hack for shaka HLS??
	r.Header.Del("If-Modified-Since")
	Logger.Info("Serving  hls", "splits", splits, "got 2", r.URL.Path, "file location", h.MpdFile, "Range", r.Header.Get("Range"))
	hdlr := http.FileServer(http.Dir(filepath.Dir(h.MpdFile)))
	hdlr.ServeHTTP(w, r)
}

type DashServer struct {
	MpdFile string
}

func (d DashServer) DashURLPath() string {
	if d.MpdFile != "" {
		//return "dash/manifest.mpd"
		return "dash/master.m3u8"
	}
	return ""
}
func (d DashServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if d.MpdFile == "" {
		Logger.Error("Dash server started without setting MpdFile")
		w.WriteHeader(500)
		return
	}
	Logger.Info("DashServer", "Serving File", d.MpdFile, "r.URL", r.URL, "Range", r.Header.Get("Range"))
	//We expect r.URL.Path to host e.g. "/dash/manifest.mpd"
	splits := strings.SplitN(r.URL.Path, "/", 3)
	r.URL.Path = splits[2]
	//Hack for shaka HLS??
	r.Header.Del("If-Modified-Since")
	Logger.Info("Serving  dash", "splits", splits, "got 2", r.URL.Path, "file location", d.MpdFile, "Range", r.Header.Get("Range"))
	hdlr := http.FileServer(http.Dir(filepath.Dir(d.MpdFile)))
	hdlr.ServeHTTP(w, r)
}
