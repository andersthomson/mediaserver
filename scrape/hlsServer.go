package scrape

import (
	"net/http"
	"path/filepath"
	"strings"
)

// THIS STUFF NEEDS FIXING
type HLSServer struct {
	M3U8File string
}

func (h HLSServer) HLSURLPath() string {
	if h.M3U8File != "" {
		return "hls/master.m3u8"
	}
	return ""
}
func (h HLSServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.M3U8File == "" {
		//Logger.Error("HLS server started without setting M3U8File")
		w.WriteHeader(500)
		return
	}
	//Logger.Info("HLSServer", "Serving File", h.M3U8File, "r.URL", r.URL, "Range", r.Header.Get("Range"))
	//We expect r.URL.Path to host e.g. "/hls/master.m3u8"
	splits := strings.SplitN(r.URL.Path, "/", 3)
	r.URL.Path = splits[2]
	//Hack for shaka HLS??
	r.Header.Del("If-Modified-Since")
	//	Logger.Info("Serving  hls", "splits", splits, "got 2", r.URL.Path, "file location", h.M3U8File, "Range", r.Header.Get("Range"))
	hdlr := http.FileServer(http.Dir(filepath.Dir(h.M3U8File)))
	hdlr.ServeHTTP(w, r)
}
