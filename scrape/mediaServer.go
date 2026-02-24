package scrape

import (
	"log/slog"
	"net/http"
	"os"
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

func (m MediaServer) ServeHTTP(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	content, err := os.Open(m.MediaFile)
	if err != nil {
		logger.ErrorContext(r.Context(), "read of media", "failed", err)
		w.WriteHeader(404)
		return
	}
	http.ServeContent(w, r, "foo.mp4", time.Time{}, content)
}
