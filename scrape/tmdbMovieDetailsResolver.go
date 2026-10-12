package scrape

import (
	"log/slog"
	"strings"
	"sync"

	tmdb "github.com/cyruzin/golang-tmdb"
)

type TmdbView struct {
	Tmdb
	movieDetails     *tmdb.MovieDetails
	movieDetailsOnce sync.Once
}

func (t *TmdbView) readMovieDetails() {
	movie, err := TMDBMovieDetails(*t.MovieId)
	if err != nil {
		Logger.Error("TMDBMovieDetails failed. Skipping", "tmdbId", *t.MovieId, "err", err)
	}
	t.movieDetails = movie
}

func (t *TmdbView) Tagline() (string, bool) {
	switch {
	case t.MovieId != nil:
		t.movieDetailsOnce.Do(t.readMovieDetails)
		return t.movieDetails.Tagline, true
	case t.SeriesId != nil:
		///TODO
		slog.Warn("NEED IMPLEMENTING")
	}
	return "", false
}

func (t *TmdbView) Overview() (string, bool) {
	switch {
	case t.MovieId != nil:
		t.movieDetailsOnce.Do(t.readMovieDetails)
		return t.movieDetails.Overview, true
	case t.SeriesId != nil:
		///TODO
		slog.Warn("NEED IMPLEMENTING")
	}
	return "", false
}

func (t *TmdbView) Title() (string, bool) {
	switch {
	case t.MovieId != nil:
		t.movieDetailsOnce.Do(t.readMovieDetails)
		return t.movieDetails.Title, true
	case t.SeriesId != nil:
		///TODO
		slog.Warn("NEED IMPLEMENTING")
	}
	return "", false
}

func (t *TmdbView) Genres() ([]string, bool) {
	switch {
	case t.MovieId != nil:
		t.movieDetailsOnce.Do(t.readMovieDetails)

		if len(t.movieDetails.Genres) == 0 {
			return []string{}, false
		}
		res := make([]string, 0, len(t.movieDetails.Genres))
		for _, genre := range t.movieDetails.Genres {
			res = append(res, strings.TrimSpace(genre.Name))
		}
		return res, true
	case t.SeriesId != nil:
		///TODO
		slog.Warn("NEED IMPLEMENTING")
	}
	return nil, false
}
