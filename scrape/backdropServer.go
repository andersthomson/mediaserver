package scrape

import (
	"log/slog"
	"net/http"
	"os"
	"time"
)

type BackdropServer struct {
	BackdropFile string
}

func (b BackdropServer) BackdropURLPath() string {
	if b.BackdropFile != "" {
		return "poster"
	}
	return ""
}

func (b BackdropServer) ServeHTTP(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	content, err := os.Open(b.BackdropFile)
	if err != nil {
		logger.ErrorContext(r.Context(), "read of backdrop", "failed", err)
		w.WriteHeader(404)
		return
	}
	http.ServeContent(w, r, "", time.Time{}, content)
}
