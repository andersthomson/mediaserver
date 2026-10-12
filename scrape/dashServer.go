package scrape

import (
	"net/http"
	"path/filepath"
	"strings"
)

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
