package scrape

import (
	"log/slog"
	"net/http"
	"os"
	"time"
)

type PosterServer struct {
	PosterFile string
}

func (p PosterServer) PosterURLPath() string {
	if p.PosterFile != "" {
		return "poster"
	}
	return ""
}

func (p PosterServer) ServeHTTP(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	content, err := os.Open(p.PosterFile)
	if err != nil {
		logger.ErrorContext(r.Context(), "read of poster", "failed", err)
		w.WriteHeader(404)
		return
	}
	http.ServeContent(w, r, "", time.Time{}, content)
}
