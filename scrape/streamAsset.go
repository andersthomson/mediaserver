package scrape

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type StreamAsset struct {
	DashServer DashServer
	HLSServer
	id        string
	shortName string
	TmdbView
}

func (s StreamAsset) ID() string {
	return s.id
}

func (s StreamAsset) ShortName() string {
	return s.shortName
}

func (s StreamAsset) PrettyID() string {
	return s.ShortName() + "-" + s.ID()
}
func (s StreamAsset) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	Logger.Info("StreamAsset serving", "Url", r.URL.Path)
	w.Header().Add("Cache-Control", "no-cache, private, max-age=0")

	// Fetch the unmutated raw path string context from the headers.
	// If r.URL.RawPath is empty (meaning the URL contains zero special characters),
	// we naturally fall back to the standard pre-cleaned r.URL.Path.
	currentRawPath := r.URL.RawPath
	if currentRawPath == "" {
		currentRawPath = r.URL.Path
	}

	//if !strings.HasPrefix(currentRawPath, "/") {
	//	currentRawPath = "/" + currentRawPath
	//}

	switch {
	//case r.URL.Path == "/"+i.MediaURLPath():
	//	s.MediaServer.ServeHTTP(w, r)
	case strings.HasPrefix(r.URL.String(), "/dash/"):
		s.DashServer.ServeHTTP(w, r)
	//case strings.HasPrefix(r.URL.String(), "/hls/"):
	//	s.HLSServer.ServeHTTP(w, r)
	///case r.URL.Path == "/"+i.BackdropURLPath():
	//	s.BackdropServer.ServeHTTP(w, r)
	//case strings.HasPrefix(r.URL.String(), i.SubsURLPath()):
	//	s.SubsServer.ServeHTTP(w, r)
	default:
		Logger.ErrorContext(r.Context(), "Unsupported URLPathFragment", "URLPathFrag", r.URL.Path)
		w.WriteHeader(404)
		return
	}
}

func StreamAssetFromMss(streamDir string, m Mss) (*StreamAsset, bool) {
	res := &StreamAsset{}
	res.id = m.Id
	res.shortName = m.ShortName

	if m.Playouts.HasDASHManifest {
		u := filepath.Join(streamDir, res.PrettyID(), "/dash/", "manifest.mpd")
		if _, err := os.Stat(u); err == nil {
			res.DashServer.DashResolver = &DashResolver{}
		}

	}
	if m.Playouts.HasHLSMaster {
		u := filepath.Join(streamDir, res.PrettyID(), "/hls/", "master.m3u8")
		if _, err := os.Stat(u); err == nil {
			res.M3U8File = u
		}
	}
	res.MovieId = m.Tmdb.MovieId

	return res, true
}
