package scrape

import (
	"log/slog"
	"net/http"
	"os"
	"time"
)

type BackdropServer struct {
	BackdropResolver *BackdropResolver
	Logger           *slog.Logger
}

func (p BackdropServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	val := ctx.Value("ItmId")
	if val == nil {
		p.Logger.Error("Failed to find itmid")
		w.WriteHeader(500)
		return
	}
	itemID := val.(string)

	metadata, err := p.BackdropResolver.ResolveBackdropState(itemID)
	if err != nil || !metadata.HasBackdrop {
		p.Logger.WarnContext(ctx, "Backdrop route hit but no valid file mapped in cache parameters", "id", itemID)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	content, err := os.Open(metadata.LocalDiskPath)
	if err != nil {
		p.Logger.ErrorContext(ctx, "read of backdrop", "failed", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	p.Logger.InfoContext(ctx, "Serving backdrop", "id", itemID, "fromFile", metadata.LocalDiskPath)
	http.ServeContent(w, r, "", time.Time{}, content)
}
