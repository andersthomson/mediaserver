package scrape

import (
	"log/slog"
	"net/http"
)

type MP4Server struct {
	MP4Resolver *MP4Resolver
	Logger      *slog.Logger
}

func (d MP4Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	val := ctx.Value("ItmId")
	if val == nil {
		d.Logger.Error("Failed to find itmid")
		w.WriteHeader(500)
		return
	}
	itemID := val.(string)

	state, err := d.MP4Resolver.ResolveMP4State(itemID)
	if err != nil {
		d.Logger.ErrorContext(ctx, "MP4Server failed to resolve mp4 state", "err", err)
		w.WriteHeader(500)
		return
	}
	if !state.HasMP4 {
		d.Logger.InfoContext(ctx, "MP4Server called, but item has no mp4", "itemid", itemID)
		w.WriteHeader(404)
		return
	}

	d.Logger.InfoContext(ctx, "MP4Server", "Serving File", state.FilePath, "r.URL", r.URL, "Range", r.Header.Get("Range"))
	http.ServeFile(w, r, state.FilePath)
}
