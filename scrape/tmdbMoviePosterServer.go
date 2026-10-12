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

	val2 := ctx.Value("MssCacheCtx")
	if val2 == nil {
		slog.Error("Failed to find MssCacheCtx")
		w.WriteHeader(500)
		return
	}
	mssCache := val2.(*MssCache)

	pr := &PosterResolver{
		MssCache: mssCache,
	}
	metadata, err := pr.ResolvePosterState(itemID)
	if err != nil || !metadata.HasPoster {
		slog.Warn("Poster route hit but no valid file mapped in cache parameters", "id", itemID)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	content, err := os.Open(metadata.LocalDiskPath)
	if err != nil {
		Logger.ErrorContext(r.Context(), "read of poster", "failed", err)
		w.WriteHeader(404)
		return
	}
	slog.Info("Serving poster", "id", ItemID, "fromFile", metadata.LocalDiskPath)
	http.ServeContent(w, r, "", time.Time{}, content)
}
