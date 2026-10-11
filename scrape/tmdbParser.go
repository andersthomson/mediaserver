package scrape

import tmdb "github.com/cyruzin/golang-tmdb"

func TmdbMoviePosterPath(t *tmdb.MovieDetails) string {
	return t.PosterPath
}
