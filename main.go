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

type Application struct {
	WebRootURLPath     string
	Sessions           *SessionStore
	DataSourceServer   *DataSourceServer
	ViewModelGenerator *ViewModelGenerator
	IDPManager         *IDPManager
	Router             *http.ServeMux
}

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
		googleIDP := NewGoogleIDP(logger, sessions, Config.GoogleOAuth.ClientID, Config.GoogleOAuth.ClientSecret, Config.WebRoot, IDPRoot)
		idpManager.Register(googleIDP)
	}
	if slices.Contains(Config.IDProviders, "InternalIDP") {
		internalIDP := NewInternalIDP(logger, Config.WebRoot, IDPRoot)
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
		WebRoot:      Config.WebRoot,
		Orchestrator: orchestrator,
		MssCache:     mssCache,
	}

	dataSourceServer := &DataSourceServer{
		PosterServer:   posterServer,
		BackdropServer: backdropServer,
		DashServer:     dashServer,
		MP4Server:      mp4Server,
	}

	app := Application{
		Sessions:           sessions,
		WebRootURLPath:     webRootURL.Path,
		ViewModelGenerator: viewModelGenerator,
		DataSourceServer:   dataSourceServer,
		IDPManager:         idpManager,
		Router:             http.NewServeMux(),
	}

	app.routes()

	listenaddr := Config.IP_Address + ":" + strconv.Itoa(int(Config.Port))
	logger.Info("Started", "Listening at", listenaddr)
	err = http.ListenAndServe(listenaddr, app.Router)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

func (app *Application) routes() {
	logMW := LoggingMiddleware(logger)
	sessMW := SessionStoreToContext(app.Sessions)
	authMW := AuthMiddleware(logger)

	app.Router.Handle(app.WebRootURLPath+"/auth/", http.StripPrefix(app.WebRootURLPath+"/auth", app.IDPManager.ServeMux()))
	app.Router.Handle(app.WebRootURLPath+"/auth/login", Chain(logMW)(app.IDPManager))

	app.Router.Handle("GET "+path.Join(app.WebRootURLPath, "view/cast/{item}"), Chain(logMW, sessMW, authMW, CORS)(HandleCast(app.ViewModelGenerator)))
	app.Router.Handle("GET "+path.Join(app.WebRootURLPath, "/view/html5/{item}"), Chain(logMW, sessMW, authMW, CORS)(HandleHtml5(app.ViewModelGenerator)))
	app.Router.Handle("GET "+path.Join(app.WebRootURLPath, "/view/shaka/{item}"), Chain(logMW, sessMW, authMW, CORS)(HandleShaka(app.ViewModelGenerator)))

	app.Router.Handle("GET "+path.Join(app.WebRootURLPath, "/item/{item}/part/{subPath...}"), Chain(logMW, sessMW, CORS)(app.DataSourceServer))

	app.Router.Handle("POST "+path.Join(app.WebRootURLPath, "/search"), Chain(logMW, sessMW, authMW, CORS)(HandleSearch(app.ViewModelGenerator)))
	app.Router.Handle(app.WebRootURLPath+"/", Chain(logMW, sessMW, authMW, CORS)(HandleIndex(app.ViewModelGenerator)))
}
