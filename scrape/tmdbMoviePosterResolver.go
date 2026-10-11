package scrape

import (
	"fmt"
	"path"
)

// PosterMetadata tracks the definitive outcome of evaluating a movie record.
type PosterMetadata struct {
	HasPoster        bool
	LocalDiskPath    string
	TargetPosterFile string // The file name token exposed to the web router
}

type PosterResolver struct {
	MssCache *MssCache
}

// ResolvePosterState handles all your heavy cache, API, and image fetching logic in ONE place.
func (pr *PosterResolver) ResolvePosterState(id string) (PosterMetadata, error) {
	movieID, ok := pr.MssCache.MovieId(id)
	if !ok {
		return PosterMetadata{HasPoster: false}, fmt.Errorf("Id %s not i mss cache", id)
	}

	movieDetails, err := TMDBMovieDetails(movieID)
	if err != nil {
		return PosterMetadata{HasPoster: false}, fmt.Errorf("tmdb breakdown: %w", err)
	}

	posterPath := TmdbMoviePosterPath(movieDetails)
	if posterPath == "" {
		return PosterMetadata{HasPoster: false}, fmt.Errorf("No posterpath found")
	}

	localFilename, err := TMDBImage(posterPath, "w500")
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

/*
func Xmain() {
	// Startup configuration setup (Run once at server launch)
	cachePool := &MssCache{
		movies: map[string]string{
			"id_normal":    "movie_inception",
			"id_no_poster": "movie_no_poster", // Explicitly hits the no-poster validation track
		},
	}
	resolverService := &PosterResolver{Cache: cachePool}
	presenterFactory := &PresenterFactory{WebRootPath: "/app", PosterResolver: resolverService}
	imageStreamingServer := PosterServer{PosterResolver: resolverService}

	mockDatabaseSearchRows := []SearchRow{
		{ID: "id_normal", Title: "Inception (4K UHD)"},
		{ID: "id_no_poster", Title: "Obscure Indie Documentary"},
	}

	searchHandler := HandleSearchConstructor(presenterFactory, mockDatabaseSearchRows)

	mux := http.NewServeMux()

	// Dynamic Go 1.22+ structural subtree wildcard layout routing
	mux.Handle("GET /app/item/{item}/part/poster/{subPath...}", imageStreamingServer)
	mux.Handle("GET /search", searchHandler)

	// ------------------------------------------------------------------------
	// SIMULATE RENDERING THE HTML INTERFACE PAGE
	// ------------------------------------------------------------------------
	fmt.Println("--- SIMULATING HTML SEARCH PAGE SOURCE GENERATION ---")
	mockRequestA, _ := http.NewRequest("GET", "/search", nil)
	mockResponseA := &mockResponseWriter{}
	searchHandler.ServeHTTP(mockResponseA, mockRequestA)
	fmt.Println(strings.TrimSpace(mockResponseA.builder.String()))

	// ------------------------------------------------------------------------
	// SIMULATE CHROMIUM BROWSER STREAMING THE RENDERED IMAGE URL
	// ------------------------------------------------------------------------
	fmt.Println("\n--- SIMULATING BROWSER STREAMING THE GENERATED IMG SRC LINK ---")
	mockRequestB, _ := http.NewRequest("GET", "/app/item/id_normal/part/poster/w500_inceptions_artwork_path.jpg", nil)
	mockResponseB := &mockResponseWriter{}
	mux.ServeHTTP(mockResponseB, mockRequestB)
	fmt.Println(strings.TrimSpace(mockResponseB.builder.String()))
}

type mockResponseWriter struct {
	builder strings.Builder
	h       http.Header
}

func (m *mockResponseWriter) Header() http.Header {
	if m.h == nil {
		m.h = make(http.Header)
	}
	return m.h
}
func (m *mockResponseWriter) Write(b []byte) (int, error) { return m.builder.Write(b) }
func (m *mockResponseWriter) WriteHeader(s int)           {}

*/
