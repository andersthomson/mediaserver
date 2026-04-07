package scrape

import (
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

func (b BackdropServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	content, err := os.Open(b.BackdropFile)
	if err != nil {
		Logger.ErrorContext(r.Context(), "read of backdrop", "failed", err)
		w.WriteHeader(404)
		return
	}
	http.ServeContent(w, r, "", time.Time{}, content)
}
