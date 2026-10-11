package scrape

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	tmdb "github.com/cyruzin/golang-tmdb"
)

type PosterServer struct {
	//PosterFile string
}

func (p PosterServer) PosterURLPath() string {
	//if p.PosterFile != "" {
	return "poster"
	//}
	//return ""
}

func (p PosterServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	val := ctx.Value("ItmId")
	if val == nil {
		slog.Error("Failed to find itmid")
		w.WriteHeader(500)
		return
	}
	id := val.(string)
	slog.Info("SHOULD STream poster", "id", val.(string))

	val2 := ctx.Value("MssCacheCtx")
	if val2 == nil {
		slog.Error("Failed to find MssCacheCtx")
		w.WriteHeader(500)
		return
	}
	mssCache := val2.(*MssCache)
	movieId, ok := mssCache.MovieId(id)
	if !ok {
		slog.Info("Is NOT MOVIE", "id", id)
		w.WriteHeader(404)
		return
	}
	slog.Info("Should poster movie", "modvieid", movieId)

	movieDetails, err := TMDBMovieDetails(movieId)
	if err != nil {
		slog.Error("Failed to read movie details", "err", err)
		w.WriteHeader(500)
		return
	}

	posterPath := TmdbMoviePosterPath(movieDetails)
	if posterPath == "" {
		slog.Info("No posterPath found")
		w.WriteHeader(404)
		return
	}
	fname, err := TMDBImage(posterPath, tmdb.W500)
	if err != nil {
		slog.Error("Failed to download poster", "err", err)
		w.WriteHeader(500)
		return
	}

	content, err := os.Open(fname)
	if err != nil {
		Logger.ErrorContext(r.Context(), "read of poster", "failed", err)
		w.WriteHeader(404)
		return
	}
	slog.Info("Serving poster", "fromFile", fname)
	http.ServeContent(w, r, "", time.Time{}, content)
}
