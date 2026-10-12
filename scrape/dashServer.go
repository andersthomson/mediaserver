package scrape

import (
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
)

type DashServer struct {
	DashResolver *DashResolver
}

func (d DashServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	val := ctx.Value("ItmId")
	if val == nil {
		slog.Error("Failed to find itmid")
		w.WriteHeader(500)
		return
	}
	itemID := val.(string)

	state, err := d.DashResolver.ResolveDashState(itemID)
	if err != nil {
		slog.Error("DasherServer failed to resolve dash state", "err", err)
		w.WriteHeader(500)
		return
	}
	if !state.HasDash {
		slog.Info("Dasher server called, but item has no dash manifest", "itemid", itemID)
		w.WriteHeader(404)
		return
	}

	Logger.Info("DashServer", "Serving File", state.ManifestPath, "r.URL", r.URL, "Range", r.Header.Get("Range"))
	//We expect r.URL.Path to host e.g. "/dash/manifest.mpd"
	splits := strings.SplitN(r.URL.Path, "/", 3)
	r.URL.Path = splits[2]
	//Hack for shaka HLS??
	r.Header.Del("If-Modified-Since")
	hdlr := http.FileServer(http.Dir(filepath.Dir(state.ManifestPath)))
	hdlr.ServeHTTP(w, r)
}
