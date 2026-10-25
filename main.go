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
	slogctx "github.com/veqryn/slog-context"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop() // Restores default OS signal behavior if called twice

	logger := slog.New(slogctx.NewHandler(slog.Default().Handler(), nil))
	rand.Seed(time.Now().UnixNano())
	Config, err := ReadConfigFromFile("config")
	if err != nil {
		panic(err)
	}
	sessions := NewSessionStoreFromFile(logger, Config.SessionFile)
	if maxDur, err := time.ParseDuration(Config.MaxSessionAge); err == nil {
		go sessions.StartPeriodicPruning(ctx, maxDur, 15*time.Minute)
	}

	webRootURL, err := url.Parse(Config.WebRoot)
	if err != nil {
		panic(err)
	}
	mssCache := scrape.NewMssCache()

	IDPRoot := webRootURL.Path + "/auth"
	idpManager := NewIDPManager()
	if slices.Contains(Config.IDProviders, "GoogleOAuth") {
		googleIDP := NewGoogleIDP(logger, sessions, Config.GoogleOAuth.ClientID, Config.GoogleOAuth.ClientSecret, Config.WebRoot, IDPRoot, Config.GoogleOAuth.AllowedUsers, Config.WebRoot+"/auth/login", Config.WebRoot)
		idpManager.Register(googleIDP)
	}
	if slices.Contains(Config.IDProviders, "InternalIDP") {
		internalIDP := NewInternalIDP(logger, sessions, Config.WebRoot, IDPRoot, Config.InternalIDP, Config.WebRoot+"/auth/login")
		idpManager.Register(internalIDP)
	}
	wt, err := NewWatcherThingy()
	if err != nil {
		panic(err)
	}
	sDirs := NewSourceDirectories(logger, wt, mssCache)
	for _, d := range Config.Directories {
		err = sDirs.Add(d.Name)
		if err != nil {
			panic(err)
		}
	}
	sDirs.StartMonitor(ctx)

	maxSessionAgeDur, err := time.ParseDuration(Config.MaxSessionAge)
	if err != nil {
		panic(err)
	}
	if maxSessionAgeDur <= 0 {
		fmt.Printf("Too small duration: %v\n", maxSessionAgeDur)
		os.Exit(1)
	}

	//Adaptors to the Application
	tmdbClient, err := scrape.TmdbInit(Config.Tmdb.ApiKey)
	if err != nil {
		slog.Error("Failed to initn tmdb client", "err", err)
		os.Exit(1)
	}
	tmdbCache := &scrape.TmdbCache{
		Client: tmdbClient,
		Path:   Config.Tmdb.CacheDir,
	}

	authMW := AuthMiddleware(logger, sessions, Config.WebRoot+"/auth/login", maxSessionAgeDur)
	app := BuildApp(logger, tmdbCache, mssCache, webRootURL.Path, idpManager, authMW, Config.WebRoot)

	listenaddr := Config.IP_Address + ":" + strconv.Itoa(int(Config.Port))
	logger.Info("Starting", "Listening at", listenaddr)
	// 3. Define the explicit HTTP server
	srv := &http.Server{
		Addr:    listenaddr,
		Handler: app.Router,
	}

	// 4. Create an error channel to catch immediate boot errors (e.g., port already in use)
	serverErrors := make(chan error, 1)

	// 5. Fire up the server inside a background goroutine so it doesn't block main
	go func() {
		logger.Info("HTTP server listening", "address", listenaddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed { // Filter out normal close errors
			serverErrors <- err
		}
	}()

	// 6. Block the main thread here and wait for EITHER a fatal boot error OR a Ctrl+C signal
	select {
	case err := <-serverErrors:
		fmt.Printf("Fatal server startup error: %v", err)

	case <-ctx.Done(): // Ctrl+C or kill signal was intercepted
		logger.Info("Shutdown signal received. Starting graceful offboarding...")

		// 7. Give the in-flight web requests 5 seconds to wrap up cleanly before pulling the plug
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Info("HTTP server forced to close", "err", err)
			_ = srv.Close() // Hard close the network sockets if it times out
		}
	}

	// 8. THE FLUSH ZONE: Now that the server is completely dark and traffic has stopped,
	// execute your synchronous disk sync safely.
	logger.Info("HTTP server completely stopped. Syncing data structures to disk...")
	/*if maxDur, err := time.ParseDuration(Config.MaxSessionAge); err == nil {
		sessions.PruneOldSessions(maxDur)
	}
	b := sessions.ToJson()
	if err := os.WriteFile(Config.SessionFile, b, 0644); err != nil {
		logger.Error("Failed to write sessionfile", "err", err)
	}*/
	if err := sessions.Flush(); err != nil {
		logger.Error("Critical: Error flushing data during exit: %v", err)
		os.Exit(1)
	}

	logger.Info("Application exited cleanly.")
}

type Application struct {
	WebRootURLPath     string
	DataSourceServer   *DataSourceServer
	ViewModelGenerator *ViewModelGenerator
	IDPManager         *IDPManager
	Router             *http.ServeMux
	Logger             *slog.Logger
	AuthMW             Middleware
}

func BuildApp(logger *slog.Logger, tmdbCache *scrape.TmdbCache, mssCache *scrape.MssCache, webRootURLPath string, idpManager *IDPManager, authMW Middleware, webRoot string) *Application {

	posterResolver := &scrape.PosterResolver{
		MssCache:  mssCache,
		TmdbCache: tmdbCache,
	}

	posterServer := &scrape.PosterServer{
		PosterResolver: posterResolver,
		Logger:         logger,
	}

	backdropResolver := &scrape.BackdropResolver{
		MssCache:  mssCache,
		TmdbCache: tmdbCache,
	}

	backdropServer := &scrape.BackdropServer{
		BackdropResolver: backdropResolver,
		Logger:           logger,
	}

	dashResolver := &scrape.DashResolver{
		MssCache: mssCache,
	}

	dashServer := &scrape.DashServer{
		DashResolver: dashResolver,
		Logger:       logger,
	}

	mp4Resolver := &scrape.MP4Resolver{
		MssCache: mssCache,
	}

	mp4Server := &scrape.MP4Server{
		MP4Resolver: mp4Resolver,
		Logger:      logger,
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
		Logger:       logger,
		WebRoot:      webRoot,
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
		WebRootURLPath:     webRootURLPath,
		ViewModelGenerator: viewModelGenerator,
		DataSourceServer:   dataSourceServer,
		IDPManager:         idpManager,
		Router:             http.NewServeMux(),
		Logger:             logger,
		AuthMW:             authMW,
	}

	app.routes()
	return &app
}

func (app *Application) routes() {
	logMW := LoggingMiddleware(app.Logger)
	corsMW := CORS(app.Logger)
	authMW := app.AuthMW

	app.Router.Handle(app.WebRootURLPath+"/auth/", http.StripPrefix(app.WebRootURLPath+"/auth", app.IDPManager.ServeMux()))
	app.Router.Handle(app.WebRootURLPath+"/auth/login", Chain(logMW)(app.IDPManager))

	app.Router.Handle("GET "+path.Join(app.WebRootURLPath, "view/cast/{item}"), Chain(logMW, authMW, corsMW)(HandleCast(app.ViewModelGenerator)))
	app.Router.Handle("GET "+path.Join(app.WebRootURLPath, "/view/html5/{item}"), Chain(logMW, authMW, corsMW)(HandleHtml5(app.ViewModelGenerator)))
	app.Router.Handle("GET "+path.Join(app.WebRootURLPath, "/view/shaka/{item}"), Chain(logMW, authMW, corsMW)(HandleShaka(app.ViewModelGenerator)))

	app.Router.Handle("GET "+path.Join(app.WebRootURLPath, "/item/{item}/part/{subPath...}"), Chain(logMW, corsMW)(app.DataSourceServer))

	app.Router.Handle("POST "+path.Join(app.WebRootURLPath, "/search"), Chain(logMW, authMW, corsMW)(HandleSearch(app.ViewModelGenerator)))
	app.Router.Handle(app.WebRootURLPath+"/", Chain(logMW, authMW, corsMW)(HandleIndex(app.ViewModelGenerator)))
}
