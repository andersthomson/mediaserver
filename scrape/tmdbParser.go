package scrape

import (
	"strings"

	tmdb "github.com/cyruzin/golang-tmdb"
)

func TmdbMoviePosterPath(t *tmdb.MovieDetails) string {
	return t.PosterPath
}

func TmdbMovieBackdropPath(t *tmdb.MovieDetails) string {
	return t.BackdropPath
}
func TmdbMovieTitle(t *tmdb.MovieDetails) string {
	return t.Title
}

func TmdbMovieGenres(t *tmdb.MovieDetails) []string {
	var res []string
	for _, genre := range t.Genres {
		res = append(res, strings.TrimSpace(genre.Name))
	}
	return res
}
func TmdbMovieTagline(t *tmdb.MovieDetails) string {
	return t.Tagline
}
func TmdbMovieOverview(t *tmdb.MovieDetails) string {
	return t.Overview
}

func TmdbMovieCollectionID(t *tmdb.MovieDetails) int {
	return int(t.BelongsToCollection.ID)
}
