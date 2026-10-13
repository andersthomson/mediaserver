package scrape

import (
	"fmt"
	"path"
)

// BackdropMetadata tracks the definitive outcome of evaluating a movie record.
type BackdropMetadata struct {
	HasBackdrop        bool
	LocalDiskPath      string
	TargetBackdropFile string // The file name token exposed to the web router
}

type BackdropResolver struct {
	MssCache *MssCache
}

// ResolveBackdropState handles all your heavy cache, API, and image fetching logic in ONE place.
func (pr *BackdropResolver) ResolveBackdropState(id string) (BackdropMetadata, error) {
	movieID, ok := pr.MssCache.MovieId(id)
	if !ok {
		return BackdropMetadata{HasBackdrop: false}, fmt.Errorf("Id %s not i mss cache", id)
	}

	movieDetails, err := TMDBMovieDetails(movieID)
	if err != nil {
		return BackdropMetadata{HasBackdrop: false}, fmt.Errorf("tmdb breakdown: %w", err)
	}

	backdropPath := TmdbMovieBackdropPath(movieDetails)
	if backdropPath == "" {
		return BackdropMetadata{HasBackdrop: false}, fmt.Errorf("No posterpath found")
	}

	localFilename, err := TMDBImage(backdropPath, "w500")
	if err != nil {
		return BackdropMetadata{HasBackdrop: false}, fmt.Errorf("image fetch breakdown: %w", err)
	}

	// Extract the plain filename token out of the disk path to pass across routers
	baseFile := path.Base(localFilename)

	return BackdropMetadata{
		HasBackdrop:        true,
		LocalDiskPath:      localFilename,
		TargetBackdropFile: baseFile,
	}, nil
}
