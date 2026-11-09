package scrape

import (
	"fmt"
	"path"

	tmdb "github.com/cyruzin/golang-tmdb"
)

// PosterMetadata tracks the definitive outcome of evaluating a movie record.
type PosterMetadata struct {
	HasPoster        bool
	LocalDiskPath    string
	TargetPosterFile string // The file name token exposed to the web router
}

type PosterResolverTmdbSource interface {
	Image(posterPath string, size string) (string, error)
	MovieDetails(MovieID) (*tmdb.MovieDetails, error)
}

type PosterResolverMssSource interface {
	MovieId(id string) (MovieID, bool)
}

type PosterResolver struct {
	MssCache  PosterResolverMssSource
	TmdbCache PosterResolverTmdbSource
}

// ResolvePosterState handles all your heavy cache, API, and image fetching logic in ONE place.
func (pr *PosterResolver) ResolvePosterState(id string) (PosterMetadata, error) {
	movieID, ok := pr.MssCache.MovieId(id)
	if !ok {
		return PosterMetadata{HasPoster: false}, fmt.Errorf("Id %s not in mss cache", id)
	}

	movieDetails, err := pr.TmdbCache.MovieDetails(movieID)
	if err != nil {
		return PosterMetadata{HasPoster: false}, fmt.Errorf("tmdb breakdown: %w", err)
	}

	posterPath := TmdbMoviePosterPath(movieDetails)
	if posterPath == "" {
		return PosterMetadata{HasPoster: false}, fmt.Errorf("No posterpath found")
	}

	localFilename, err := pr.TmdbCache.Image(posterPath, "w500")
	if err != nil {
		return PosterMetadata{HasPoster: false}, fmt.Errorf("image fetch breakdown: %w", err)
	}

	// Extract the plain filename token out of the disk path to pass across routers
	baseFile := path.Base(localFilename)

	return PosterMetadata{
		HasPoster:        true,
		LocalDiskPath:    localFilename,
		TargetPosterFile: baseFile,
	}, nil
}
