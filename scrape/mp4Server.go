package scrape

import (
	"net/http"
	"os"
	"time"
)

type MP4Server struct {
	MediaFile string
}

func (m MP4Server) MediaURLPath() string {
	if m.MediaFile != "" {
		return "media"
	}
	return ""
}

func (m MP4Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	content, err := os.Open(m.MediaFile)
	if err != nil {
		Logger.ErrorContext(r.Context(), "read of media", "failed", err)
		w.WriteHeader(404)
		return
	}
	http.ServeContent(w, r, "foo.mp4", time.Time{}, content)
}
