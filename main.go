package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/andersthomson/mediaserver/scrape"
)

func main() {
	setupLogger()
	var sessions *SessionStore
	rand.Seed(time.Now().UnixNano())
	Config.ReadFromFile("config")
	tmdbClient, err := scrape.TmdbInit(Config.Tmdb.ApiKey, Config.Tmdb.CacheDir)
	if err != nil {
		slog.Error("Failed to initn tmdb client", "err", err)
		os.Exit(1)
	}
	sessions = NewSessionStoreFromFile(Config.SessionFile)

	webRootURL, err := url.Parse(Config.WebRoot)
	if err != nil {
		panic(err)
	}
	mssCache := scrape.NewMssCache()

	IDPRoot := webRootURL.Path + "/auth"
	idpManager := NewIDPManager()
	if slices.Contains(Config.IDProviders, "GoogleOAuth") {
		googleIDP := NewGoogleIDP(sessions, Config.GoogleOAuth.ClientID, Config.GoogleOAuth.ClientSecret, Config.WebRoot, IDPRoot)
		idpManager.Register(googleIDP)
	}
	if slices.Contains(Config.IDProviders, "InternalIDP") {
		internalIDP := NewInternalIDP(Config.WebRoot, IDPRoot)
		idpManager.Register(internalIDP)
	}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan // Block until a signal is received
		fmt.Printf("\nReceived signal: %v\n", sig)
		if maxDur, err := time.ParseDuration(Config.MaxSessionAge); err == nil {
			sessions.PruneOldSessions(maxDur)
		}
		b := sessions.ToJson()
		if err := os.WriteFile(Config.SessionFile, b, 0644); err != nil {
			logger.Error("Failed to write sessionfile", "err", err)
		}
		os.Exit(0)
	}()

	wt, err := NewWatcherThingy()
	if err != nil {
		panic(err)
	}
	sDirs := NewSourceDirectories(wt, mssCache)
	for _, d := range Config.Directories {
		//addDir(mssCache, d.Name)
		err = sDirs.Add(d.Name)
		if err != nil {
			panic(err)
		}
	}
	tmdbCache := &scrape.TmdbCache{
		Client: tmdbClient,
		Path:   Config.Tmdb.CacheDir,
	}

	sDirs.StartMonitor(context.TODO())
	posterResolver := &scrape.PosterResolver{
		MssCache:  mssCache,
		TmdbCache: tmdbCache,
	}

	posterServer := &scrape.PosterServer{
		PosterResolver: posterResolver,
	}

	backdropResolver := &scrape.BackdropResolver{
		MssCache:  mssCache,
		TmdbCache: tmdbCache,
	}

	backdropServer := &scrape.BackdropServer{
		BackdropResolver: backdropResolver,
	}

	dashResolver := &scrape.DashResolver{
		MssCache: mssCache,
	}

	dashServer := &scrape.DashServer{
		DashResolver: dashResolver,
	}

	mp4Resolver := &scrape.MP4Resolver{
		MssCache: mssCache,
	}

	mp4Server := &scrape.MP4Server{
		MP4Resolver: mp4Resolver,
	}
	orchestrator := &MetadataOrchestrator{
		PosterResolver:   posterResolver,
		BackdropResolver: backdropResolver,
		DashResolver:     dashResolver,
		MP4Resolver:      mp4Resolver,
		MssCache:         mssCache,
		TmdbCache:        tmdbCache,
	}
	viewModelGenerator := &ViewModelGenerator{
		Orchestrator: orchestrator,
		MssCache:     mssCache,
	}

	mux := http.NewServeMux()

	//mux.Handle(webRootURL.Path+"/auth/google/login", Chain(LoggingMiddleware)(http.HandlerFunc(googleIDP.googleLoginHandler)))
	//mux.Handle(webRootURL.Path+"/auth/google/callback", Chain(LoggingMiddleware)(http.HandlerFunc(googleIDP.googleOAuthCallbackHandler)))

	//mux.Handle(webRootURL.Path+"/auth/google/", http.StripPrefix(webRootURL.Path+"/auth/google", googleIDP.ServeMux()))
	//mux.Handle(webRootURL.Path+"/auth/internalIDP/", http.StripPrefix(webRootURL.Path+"/auth/internalIDP", internalIDP.ServeMux()))
	mux.Handle(webRootURL.Path+"/auth/", http.StripPrefix(webRootURL.Path+"/auth", idpManager.ServeMux()))
	mux.Handle(webRootURL.Path+"/auth/login", Chain(LoggingMiddleware)(idpManager))

	mux.Handle("GET "+path.Join(webRootURL.Path, "view/cast/{item}"), Chain(LoggingMiddleware, SessionStoreToContext(sessions), AuthMiddleware, CORS)(HandleCast(viewModelGenerator)))
	mux.Handle("GET "+path.Join(webRootURL.Path, "/view/html5/{item}"), Chain(LoggingMiddleware, SessionStoreToContext(sessions), AuthMiddleware, CORS)(HandleHtml5(viewModelGenerator)))
	mux.Handle("GET "+path.Join(webRootURL.Path, "/view/shaka/{item}"), Chain(LoggingMiddleware, SessionStoreToContext(sessions), AuthMiddleware, CORS)(HandleShaka(viewModelGenerator)))

	mux.Handle("GET "+path.Join(webRootURL.Path, "/item/{item}/part/{subPath...}"), Chain(LoggingMiddleware, SessionStoreToContext(sessions), CORS)(&dataSourceServer{mssCache, posterServer, backdropServer, dashServer, mp4Server}))

	mux.Handle("POST "+path.Join(webRootURL.Path, "/search"), Chain(LoggingMiddleware, SessionStoreToContext(sessions), AuthMiddleware, CORS)(HandleSearch(viewModelGenerator)))
	mux.Handle(webRootURL.Path+"/", Chain(LoggingMiddleware, SessionStoreToContext(sessions), AuthMiddleware, CORS)(HandleIndex(viewModelGenerator)))

	listenaddr := Config.IP_Address + ":" + strconv.Itoa(int(Config.Port))
	logger.Info("Started", "Listening at", listenaddr)
	err = http.ListenAndServe(listenaddr, mux)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
