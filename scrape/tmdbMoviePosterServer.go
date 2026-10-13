package scrape

import (
	"log/slog"
	"net/http"
	"os"
	"time"
)

type PosterServer struct {
	PosterResolver *PosterResolver
}

func (p PosterServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	val := ctx.Value("ItmId")
	if val == nil {
		slog.Error("Failed to find itmid")
		w.WriteHeader(500)
		return
	}
	itemID := val.(string)

	metadata, err := p.PosterResolver.ResolvePosterState(itemID)
	if err != nil || !metadata.HasPoster {
		slog.WarnContext(r.Context(), "Poster route hit but no valid file mapped in cache parameters", "id", itemID)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	content, err := os.Open(metadata.LocalDiskPath)
	if err != nil {
		Logger.ErrorContext(r.Context(), "read of poster", "failed", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	slog.InfoContext(r.Context(), "Serving poster", "id", itemID, "fromFile", metadata.LocalDiskPath)
	http.ServeContent(w, r, "", time.Time{}, content)
}
