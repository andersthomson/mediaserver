package main

import (
	"cmp"
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/andersthomson/mediaserver/datasource"
	"github.com/andersthomson/mediaserver/scrape"
	"github.com/davecgh/go-spew/spew"
	slogctx "github.com/veqryn/slog-context"
)

type Tagser interface {
	Tags() map[string][]string
}

type Seasoner interface {
	Season() int
}

type Episoder interface {
	Episode() int
}
type ShowNamer interface {
	ShowName() string
}

type EpisodeTitler interface {
	EpisodeTitle() string
}

// Global OAuth2 config
var googleIDP *GoogleIDP
var internalIDP *InternalIDP

var sessions *SessionStore

var logger *slog.Logger
var Config config

func ScanDir(dir string) []datasource.DataSource {
	//slog.Info("Scanning", "dir", dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		logger.Warn("ScanDir/os.ReadDir failed", "dir", dir, "err", err)
		return nil
	}
	res := make([]datasource.DataSource, 0, len(entries))
	for _, d := range entries {
		if strings.HasSuffix(d.Name(), ".mp4") {
			if itm := scrape.ScrapeFile(logger, dir, d.Name()); itm != nil {
				res = append(res, itm)
			}
		}
	}
	return res
}

type repo interface {
	AllDataSources() []datasource.DataSource
}
type allReposT struct {
	repos   []repo
	reposMu sync.Mutex
}

func (a *allReposT) Add(r repo) {
	a.reposMu.Lock()
	a.repos = append(a.repos, r)
	a.reposMu.Unlock()
}

func (a *allReposT) Delete(r repo) {
	a.reposMu.Lock()
	slices.DeleteFunc(a.repos, func(x repo) bool {
		return x == r
	})
	a.reposMu.Unlock()
}

func (a allReposT) AllDataSources() []datasource.DataSource {
	res := make([]datasource.DataSource, 0, 1024)
	a.reposMu.Lock()
	for _, r := range a.repos {
		if r != nil {
			res = append(res, r.AllDataSources()...)
		}
	}
	a.reposMu.Unlock()
	return res
}
func (a allReposT) DataSourceByID(id string) datasource.DataSource {
	a.reposMu.Lock()
	defer a.reposMu.Unlock()
	for _, r := range a.repos {
		if r != nil {
			for _, src := range r.AllDataSources() {
				if src.ID() == id {
					return src
				}
			}
		}
	}
	return nil
}

var allRepos allReposT

type backdropServer struct {
}

func (_ backdropServer) partName() string {
	return "backdrop"
}
func (p backdropServer) BackdropURL(id string) string {
	ds := allRepos.DataSourceByID(id)
	if ds == nil {
		return ""
	}
	dsT, ok := ds.(datasource.OpenBackdroper)
	if !ok {
		logger.Warn("ds does not support backdrops", "id", ds.ID())
		return ""
	}
	content, err := dsT.OpenBackdrop()
	if err != nil {
		return ""
	}
	content.Close()
	return Config.WebRoot + "/item/" + url.PathEscape(id) + "/part/" + p.partName()
}

func (p *backdropServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	itm := r.PathValue("item")
	ds := allRepos.DataSourceByID(itm)
	if ds == nil {
		errorHandler(ctx, w, r, http.StatusNotFound)
		logger.WarnContext(ctx, "datasource unkown", "id", itm)
		return
	}
	dsT, ok := ds.(datasource.OpenBackdroper)
	if !ok {
		errorHandler(ctx, w, r, http.StatusNotFound)
		logger.WarnContext(ctx, "ds does not support backdrops", "id", ds.ID())
		return
	}
	content, err := dsT.OpenBackdrop()
	if err != nil {
		errorHandler(ctx, w, r, http.StatusNotFound)
		logger.WarnContext(ctx, "read of backdrop", "failed", err)
		return
	}
	http.ServeContent(w, r, "", time.Time{}, content)
	content.Close()
}

type posterServer struct {
}

func (_ posterServer) partName() string {
	return "poster"
}
func (p posterServer) PosterURL(id string) string {
	ds := allRepos.DataSourceByID(id)
	if ds == nil {
		return ""
	}
	content, err := ds.OpenPoster()
	if err != nil {
		return ""
	}
	content.Close()
	return Config.WebRoot + "/item/" + url.PathEscape(id) + "/part/" + p.partName()
}

func (p *posterServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	itm := r.PathValue("item")
	ds := allRepos.DataSourceByID(itm)
	if ds == nil {
		errorHandler(ctx, w, r, http.StatusNotFound)
		logger.WarnContext(ctx, "datasource unkown", "id", itm)
		return
	}
	content, err := ds.OpenPoster()
	if err != nil {
		errorHandler(ctx, w, r, http.StatusNotFound)
		logger.WarnContext(ctx, "read of poster", "failed", err)
		return
	}
	http.ServeContent(w, r, "", time.Time{}, content)
	content.Close()
}

type mediaServer struct {
}

func (_ mediaServer) partName() string {
	return "media"
}
func (p mediaServer) MediaURL(id string) string {
	return Config.WebRoot + "/item/" + url.PathEscape(id) + "/part/" + p.partName()
}

func (p *mediaServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	itm := r.PathValue("item")
	ds := allRepos.DataSourceByID(itm)
	if ds == nil {
		errorHandler(ctx, w, r, http.StatusNotFound)
		logger.WarnContext(ctx, "datasource unkown", "id", itm)
		return
	}
	content, err := ds.OpenMedia()
	if err != nil {
		errorHandler(ctx, w, r, http.StatusNotFound)
		logger.InfoContext(ctx, "media not found", "ds", ds.ID())
		return
	}
	logger.InfoContext(ctx, "Serving", "URL", r.URL)
	http.ServeContent(w, r, "foo.mp4", time.Time{}, content)
	content.Close()
	return
}

type subsServer struct {
}

func (_ subsServer) partName() string {
	return "subs.vtt"
}
func (s subsServer) SubsURL(id string) string {
	ds := allRepos.DataSourceByID(id)
	content, err := ds.OpenSubs()
	if err == nil {
		content.Close()
		return Config.WebRoot + "/item/" + url.PathEscape(id) + "/part/" + s.partName()
	}
	return ""
}

func (_ *subsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	itm := r.PathValue("item")
	ds := allRepos.DataSourceByID(itm)
	if ds == nil {
		errorHandler(ctx, w, r, http.StatusNotFound)
		logger.WarnContext(ctx, "datasource unkown", "id", itm)
		return
	}
	content, err := ds.OpenSubs()
	if err != nil {
		errorHandler(ctx, w, r, http.StatusNotFound)
		logger.InfoContext(ctx, "read of subs", "failed", err)
		return
	}
	http.ServeContent(w, r, "foo.vtt", time.Time{}, content)
	content.Close()
	return
}

type html5Server struct {
}

func (_ html5Server) partName() string {
	return "html5"
}
func (h html5Server) Html5URL(id string) string {
	return Config.WebRoot + "/item/" + url.PathEscape(id) + "/part/" + h.partName()
}

func (_ *html5Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	itm := r.PathValue("item")
	ds := allRepos.DataSourceByID(itm)
	if ds == nil {
		errorHandler(ctx, w, r, http.StatusNotFound)
		logger.WarnContext(ctx, "datasource unkown", "id", itm)
		return
	}
	serveItemHtml5(ctx, w, r, ds)
	return
}

type castServer struct {
}

func (_ castServer) partName() string {
	return "cast"
}
func (h castServer) CastURL(id string) string {
	return Config.WebRoot + "/item/" + url.PathEscape(id) + "/part/" + h.partName()
}

func (_ *castServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	itm := r.PathValue("item")
	ds := allRepos.DataSourceByID(itm)
	if ds == nil {
		errorHandler(ctx, w, r, http.StatusNotFound)
		logger.WarnContext(ctx, "datasource unkown", "id", itm)
		return
	}
	serveItemCast(ctx, w, r, ds)
	return
}

func errorHandler(ctx context.Context, w http.ResponseWriter, r *http.Request, status int, args ...any) {
	w.WriteHeader(status)
	logger.With(
		slog.String("url", r.URL.String()),
		slog.Int("status", status)).InfoContext(ctx, "Http error", args...)
}

func addDir(dir string) {
	dr := directoryRepo{
		dir: dir,
	}
	dr.Refresh()
	allRepos.Add(&dr)
}

func recurseDir(dir string) {
	addDir(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		//panic(err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			recurseDir(path.Join(dir, e.Name()))
		}
	}
}
func setupLogger() {
	/*
		baseHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			//AddSource: true,
		})*/
	customHandler := slogctx.NewHandler(slog.Default().Handler(), nil)
	logger = slog.New(customHandler)
}
func BruteLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := r.Context()
		reqid := NewRequestid()
		ctx = slogctx.Append(ctx, "Brutereqid", reqid)
		logger.InfoContext(ctx, "Brute Started", "URL", r.URL.Path)
		next.ServeHTTP(w, r.WithContext(ctx))
		logger.InfoContext(ctx, "Brute Completed", "URL", r.URL.Path, "time", time.Since(start))
	})
}
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := r.Context()
		reqid := NewRequestid()
		ctx = slogctx.Append(ctx, "reqid", reqid)
		//ctx = slogctx.Append(ctx, "agent", r.Header.Get("User-Agent"))
		logger.InfoContext(ctx, "start req",
			"clientAddr", r.Header.Get("X-Forwarded-For"),
			"Agent", r.Header.Get("User-Agent"),
			"URL", r.URL.String())
		next.ServeHTTP(w, r.WithContext(ctx))
		logger.InfoContext(ctx, "end req", "time", time.Since(start))
	})
}
func GetUserSession(r *http.Request) (User, bool) {
	sessionID, err := getSessionCookie(r)
	if err != nil {
		logger.Info("No session cookie", "err", err)
		return nil, false
	}
	sessions.RLock()
	u, ok := sessions.m[sessionID]
	sessions.RUnlock()
	if !ok {
		logger.Info("Invalid session")
		return nil, false
	}
	return u.User, true
}

type userCtxKey struct{}

func setSessionCookie(w http.ResponseWriter, sessionID string) {
	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // Set to true in production (HTTPS)
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

func getSessionCookie(r *http.Request) (string, error) {
	c, err := r.Cookie("session_id")
	if err != nil || c.Value == "" {
		return "", fmt.Errorf("missing session cookie")
	}
	return c.Value, nil
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		sessionID, err := getSessionCookie(r)
		if err != nil {
			logger.Error("No session cookie", "err", err)
			http.Redirect(w, r, Config.WebRoot+"/auth/login", http.StatusFound)
			return
		}
		se, hasSession := sessions.GetSessionEntry(sessionID)
		if !hasSession {
			http.Redirect(w, r, Config.WebRoot+"/auth/login", http.StatusFound)
			return
		}
		if maxAge, err := time.ParseDuration(Config.MaxSessionAge); err == nil {
			if maxAge.Abs() > 0 && se.LastUsed.Add(maxAge).Before(time.Now()) {
				sessions.DeleteSessionEntry(sessionID)
				http.Redirect(w, r, Config.WebRoot+"/auth/login", http.StatusFound)
				return
			}
		}
		//We are good! Proceed to use the session
		sessions.TouchLastUsed(sessionID)
		// Add user data to the request context
		ctx = context.WithValue(ctx, userCtxKey{}, se.User)
		logger.InfoContext(ctx, "Has Session", "userID", se.User.UserID(), "idp", se.User.IDProvider())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		//w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight request quickly
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		logger.InfoContext(r.Context(), "Adding cors")
		next.ServeHTTP(w, r)
	})
}

// Middleware defines a function to process middleware.
type Middleware func(http.Handler) http.Handler

// Chain applies a list of middlewares to an http.Handler.
// The first middleware in the list will be the outermost.
func Chain(middlewares ...Middleware) Middleware {
	return func(final http.Handler) http.Handler {
		// Apply in reverse order so that the first middleware wraps the rest
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

func serveTopIndex(w http.ResponseWriter, r *http.Request) {
	webRootURL, err := url.Parse(Config.WebRoot)
	if err != nil {
		panic(err)
	}
	serveIndex(r.Context(), w, r, allRepos.AllDataSources(), webRootURL.Path+"/")
}

func main() {
	setupLogger()
	rand.Seed(time.Now().UnixNano())
	Config.ReadFromFile("config")
	scrape.TmdbInit(Config.Tmdb.ApiKey, Config.Tmdb.CacheDir, Config.Tmdb.Iso6391Order)
	sessions = NewSessionStoreFromFile("./sessions.json")

	webRootURL, err := url.Parse(Config.WebRoot)
	if err != nil {
		panic(err)
	}
	IDPRoot := webRootURL.Path + "/auth"
	idpManager := NewIDPManager()
	if slices.Contains(Config.IDProviders, "GoogleOAuth") {
		googleIDP = NewGoogleIDP(sessions, Config.GoogleOAuth.ClientID, Config.GoogleOAuth.ClientSecret, Config.WebRoot, IDPRoot)
		idpManager.Register(googleIDP)
	}
	if slices.Contains(Config.IDProviders, "InternalIDP") {
		internalIDP = NewInternalIDP(Config.WebRoot, IDPRoot)
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
		if err := os.WriteFile("./sessions.json", b, 0644); err != nil {
			logger.Error("Failed to write sessionfile", "err", err)
		}
		os.Exit(0)
	}()

	for _, d := range Config.Directories {
		if d.Method == "faNotify" {
			dr := NewFaNotifyDirectoryRepo(d.Name, d.Recursive)
			dr.Refresh()
			allRepos.Add(dr)

		} else {
			if d.Recursive {
				recurseDir(d.Name)
			} else {
				addDir(d.Name)
			}
		}
	}
	mux := http.NewServeMux()

	//mux.Handle(webRootURL.Path+"/auth/google/login", Chain(LoggingMiddleware)(http.HandlerFunc(googleIDP.googleLoginHandler)))
	//mux.Handle(webRootURL.Path+"/auth/google/callback", Chain(LoggingMiddleware)(http.HandlerFunc(googleIDP.googleOAuthCallbackHandler)))

	//mux.Handle(webRootURL.Path+"/auth/google/", http.StripPrefix(webRootURL.Path+"/auth/google", googleIDP.ServeMux()))
	//mux.Handle(webRootURL.Path+"/auth/internalIDP/", http.StripPrefix(webRootURL.Path+"/auth/internalIDP", internalIDP.ServeMux()))
	mux.Handle(webRootURL.Path+"/auth/", http.StripPrefix(webRootURL.Path+"/auth", idpManager.ServeMux()))

	mux.Handle(webRootURL.Path+"/auth/login", Chain(LoggingMiddleware)(idpManager))

	mux.Handle(webRootURL.Path+"/item/{item}/part/"+mediaServer{}.partName(), Chain(LoggingMiddleware, CORS)(&mediaServer{}))
	mux.Handle(webRootURL.Path+"/item/{item}/part/"+posterServer{}.partName(), Chain(LoggingMiddleware, AuthMiddleware, CORS)(&posterServer{}))
	mux.Handle(webRootURL.Path+"/item/{item}/part/"+backdropServer{}.partName(), Chain(LoggingMiddleware, AuthMiddleware, CORS)(&backdropServer{}))
	mux.Handle(webRootURL.Path+"/item/{item}/part/"+subsServer{}.partName(), Chain(LoggingMiddleware, CORS)(&subsServer{}))
	mux.Handle(webRootURL.Path+"/item/{item}/part/"+html5Server{}.partName(), Chain(LoggingMiddleware, AuthMiddleware, CORS)(&html5Server{}))
	mux.Handle(webRootURL.Path+"/item/{item}/part/"+castServer{}.partName(), Chain(LoggingMiddleware, AuthMiddleware, CORS)(&castServer{}))

	mux.Handle(webRootURL.Path+"/", Chain(LoggingMiddleware, AuthMiddleware, CORS)(http.HandlerFunc(serveTopIndex)))

	logger.Info("Listening...")
	err = http.ListenAndServe(":3000", mux)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

func serveItemCast(ctx context.Context, w http.ResponseWriter, r *http.Request, ds datasource.DataSource) {
	type dataT struct {
		Title     string
		PosterURL string
		MediaURL  string
		SubsURL   string
		Tagline   string
	}
	data := dataT{
		Title:     datasource.TitleOrZero(ds),
		PosterURL: posterServer{}.PosterURL(ds.ID()),
		MediaURL:  mediaServer{}.MediaURL(ds.ID()),
		SubsURL:   subsServer{}.SubsURL(ds.ID()),
		Tagline:   datasource.TaglineOrZero(ds),
	}
	html2templ := `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Chromecast Movie Demo</title>

    <!-- Load Cast Framework -->
    <script
      type="text/javascript"
      src="https://www.gstatic.com/cv/js/sender/v1/cast_sender.js?loadCastFramework=1"
    ></script>

    <style>
      body {
        font-family: system-ui, sans-serif;
        background: #f8f9fa;
        text-align: center;
        padding: 3rem;
      }
      google-cast-launcher {
        --disconnected-color: #555;
        --connected-color: #4285f4;
        width: 48px;
        height: 48px;
        cursor: pointer;
      }
      button {
        margin-top: 2rem;
        padding: 0.8rem 1.4rem;
        font-size: 1rem;
        border: none;
        border-radius: 8px;
        background: #4285f4;
        color: white;
        cursor: pointer;
      }
      button:hover {
        background: #3367d6;
      }
      .controls {
            margin-top: 1rem;
       }
    #progress-container {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          margin-top: 1rem;
   }
   #progress {
          flex: 1;
          width: 100%;
   }
    </style>

  </head>
  <body>
    <h1>🎥 Chromecast Movie Demo</h1>
    <p>Click the Cast button, then press “Play Movie” below.</p>

    <!-- Cast button provided by the framework -->
    <google-cast-launcher></google-cast-launcher>

    <br />
    <button onclick="startCasting({{.MediaURL}},{{.PosterURL}},{{.SubsURL}},{{.Title}},{{.Tagline}})">Play Movie</button>
    <div id="log">Log messages will appear here...</div>
     <div>
	    <button id="load">Load Media</button>
	    <button id="play">Play ▶️</button>
	    <button id="pause">Pause ⏸️</button>
	    <button id="stop">Stop ⏹️</button>
	    <button id="skip">Skip +30s ⏩</button>
	    <button id="rewind">Rewind -10s ⏪</button>
	    <button id="mute">Mute 🔇</button>
	    <button id="unmute">Unmute 🔊</button>
     </div>
    <div id="progress-container">
       <span id="currentTime">0:00</span>
        <input type="range" id="progress" min="0" max="100" value="0">
       <span id="duration">0:00</span>
    </div>
	       
   <script>
	function waitForCastApi() {
	    if (window.cast && window.cast.framework) {
	        initializeCast();
	    } else {
	        console.log("Waiting for Cast API...");
	        setTimeout(waitForCastApi, 500);
	    }
	}
	waitForCastApi();

	function initializeCast() {
	    //logmessage("Cast Framework initialized");
	    const context = cast.framework.CastContext.getInstance();
	    context.setOptions({
	        receiverApplicationId: chrome.cast.media.DEFAULT_MEDIA_RECEIVER_APP_ID,
	        autoJoinPolicy: chrome.cast.AutoJoinPolicy.ORIGIN_SCOPED,
	    });
	    console.log("Cast Framework initialized");

	    // ===== Modern Progress Updater (RemotePlayer API) =====
	    player = new cast.framework.RemotePlayer();
	    controller = new cast.framework.RemotePlayerController(player);
	    setupPlayerListeners();
	}

	async function startCasting(mediaURL, posterURL, subsURL, title, tagline) {
	    const context = cast.framework.CastContext.getInstance();

	    // Ensure a Cast session exists
	    await context.requestSession();
	    const session = context.getCurrentSession();

	    // Define media
	    const mediaInfo = new chrome.cast.media.MediaInfo(mediaURL, "video/mp4");

	    // Attach movie metadata (this is what shows up in Google Home!)
	    const metadata = new chrome.cast.media.MovieMediaMetadata();
	    metadata.title = title;
	    metadata.subtitle = tagline;
	    metadata.studio = "Blender Studio";
	    metadata.images = [
	        new chrome.cast.Image(
	            "posterURL"
	        ),
	    ];
	    mediaInfo.metadata = metadata;
	    if (subsURL.length > 0) {
	        const tracks = [
	            new chrome.cast.media.Track(1, chrome.cast.media.TrackType.TEXT),
	        ];
	        tracks[0].trackContentId = subsURL;
	        tracks[0].trackContentType = "text/vtt";
	        tracks[0].subtype = chrome.cast.media.TextTrackType.SUBTITLES;
	        tracks[0].name = "Swedish";
	        tracks[0].language = "sv";
	        mediaInfo.tracks = tracks;
	    }

	    // Load media
	    const request = new chrome.cast.media.LoadRequest(mediaInfo);
	    request.autoplay = true;
	    if (subsURL.length > 0) {
	        request.activeTrackIds = [1]; // enable subtitles
	    }

	    try {
	        await session.loadMedia(request);
	        console.log("Media loaded successfully!");
	    } catch (err) {
	        console.error("Error loading media:", err);
	    }
	}
	// --- Helper to get media session ---
	function getMedia() {
	    const session = cast.framework.CastContext.getInstance().getCurrentSession();
	    if (!session) {
	        alert("No cast session.");
	        return null;
	    }
	    return session.getMediaSession();
	}

	// --- Controls ---
	function play() {
	    const media = getMedia();
	    if (media) media.play(null,
	        () => console.log("▶️ Playing"),
	        err => console.error("play() failed", err)
	    );
	}

	function pause() {
	    const media = getMedia();
	    if (media) media.pause(null,
	        () => console.log("⏸️ Paused"),
	        err => console.error("pause() failed", err)
	    );
	}

	function stop() {
	    const media = getMedia();
	    if (media) media.stop(null,
	        () => console.log("⏹️ Stopped"),
	        err => console.error("stop() failed", err)
	    );
	}

	function skipForward() {
	    const media = getMedia();
	    if (!media) return;
	    const seek = new chrome.cast.media.SeekRequest();
	    seek.currentTime = media.currentTime + 30;
	    media.seek(seek);
	}

	function rewind() {
	    const media = getMedia();
	    if (!media) return;
	    const seek = new chrome.cast.media.SeekRequest();
	    seek.currentTime = Math.max(media.currentTime - 10, 0);
	    media.seek(seek);
	}

	function mute() {
	    const session = cast.framework.CastContext.getInstance().getCurrentSession();
	    if (session) session.setMute(true);
	}

	function unmute() {
	    const session = cast.framework.CastContext.getInstance().getCurrentSession();
	    if (session) session.setMute(false);
	}

	function formatTime(seconds) {
	    if (!seconds || isNaN(seconds)) return "0:00";
	    const m = Math.floor(seconds / 60);
	    const s = Math.floor(seconds % 60);
	    return ` + "`${m}: ${s.toString().padStart(2, \"0\")}`" + `;
	}

	function setupPlayerListeners() {
	    controller.addEventListener(
	        cast.framework.RemotePlayerEventType.CURRENT_TIME_CHANGED,
	        () => {
	            document.getElementById("progress").value = player.currentTime;
	            document.getElementById("currentTime").textContent = formatTime(player.currentTime);
	        }
	    );

	    controller.addEventListener(
	        cast.framework.RemotePlayerEventType.DURATION_CHANGED,
	        () => {
	            document.getElementById("progress").max = player.duration;
	            document.getElementById("duration").textContent = formatTime(player.duration);
	        }
	    );

	    controller.addEventListener(
	        cast.framework.RemotePlayerEventType.PLAYER_STATE_CHANGED,
	        () => {
	            const playBtn = document.getElementById("play");
	            const pauseBtn = document.getElementById("pause");

	            if (player.playerState === chrome.cast.media.PlayerState.PLAYING) {
	                playBtn.disabled = true;
	                pauseBtn.disabled = false;
	            } else if (player.playerState === chrome.cast.media.PlayerState.PAUSED) {
	                playBtn.disabled = false;
	                pauseBtn.disabled = true;
	            } else {
	                playBtn.disabled = false;
	                pauseBtn.disabled = false;
	            }
	        }
	    );

	};


	// --- Wire buttons ---
	document.getElementById("play").onclick = play;
	document.getElementById("pause").onclick = pause;
	document.getElementById("stop").onclick = stop;
	document.getElementById("skip").onclick = skipForward;
	document.getElementById("rewind").onclick = rewind;
	document.getElementById("mute").onclick = mute;
	document.getElementById("unmute").onclick = unmute;

	// ===== Scrubbing =====
	document.getElementById("progress").addEventListener("input", (e) => {
	    player.currentTime = parseFloat(e.target.value);
	    controller.seek();
	});
    </script>
  </body>
</html>
`

	htmltempl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTML5 Video Player with Chromecast Support</title>
    
    <!-- Google Cast SDK -->
    <script src="https://www.gstatic.com/cv/js/sender/v1/cast_sender.js"></script>
<script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
        }
        video {
            max-width: 100%;
            height: auto;
            display: block;
            margin: 20px auto;
        }
        #castButton {
            display: inline-block;
            background-color: #ff4d00;
            color: white;
            padding: 10px 20px;
            cursor: pointer;
            border-radius: 5px;
            font-size: 16px;
        }
        #log {
            margin-top: 20px;
            background-color: #f0f0f0;
            padding: 10px;
            border-radius: 5px;
            max-height: 200px;
            overflow-y: auto;
            font-family: Consolas, monospace;
            font-size: 14px;
        }
    </style>
</head>
<body>

    <h1>HTML5 Video Player with Chromecast Support</h1>

    <!-- Chromecast Cast Button -->
    <div id="castButton" onclick="initializeCast()">Cast to TV</div>
    <div id="castButton" onclick="playOnChromeCast()">Cast to TV2</div>

    <!-- Video Player -->
    <!-- Log Display -->
    <div id="log">Log messages will appear here...</div>

<script>
class ChromeCastService {
  constructor() {
    this.castSession = null;

    this.sessionRequest = new chrome.cast.SessionRequest(chrome.cast.media.DEFAULT_MEDIA_RECEIVER_APP_ID);
    const apiConfig = new chrome.cast.ApiConfig(
      this.sessionRequest,
      (session) => { // sessionListener
        console.log('Received ChromeCast session', session)
        this.castSession = session;
      },
      (receiverAvailability) => { // receiverListener
        if (receiverAvailability === chrome.cast.ReceiverAvailability.AVAILABLE) {
          console.log('Chromecast receivers are available')
        } else if (receiverAvailability === chrome.cast.ReceiverAvailability.NAVAILABLE) {
          console.log('No Chromecast receiver available')
        }
      }
    );
    chrome.cast.initialize(
      apiConfig,
      () => {
        console.log('Successful ChromeCast initialization');
      },
      (error) => {
        console.log('ChromeCast initialization failed', error);
      }
    );
  }

  // Lets the user select a ChromeCast and opens the player on the big screen
  selectDevice() {
    console.log('Opening ChromeCast device selection prompt')
      return new Promise((resolve, reject) => {
        chrome.cast.requestSession(
        (session) => {
          // ChromeCast should now show an empty media player on the screen. You're ready to stream
          console.log('Successfully connected to ChromeCast', session);
          this.castSession = session;
          resolve(this.castSession);
        },
        (error) => {
          console.log('Connection to ChromeCast failed', error);
          reject(error);
        }, 
        this.sessionRequest
      );
    });
  }

  isConnectedToDevice() {
    return this.castSession && this.castSession.status === "connected";
  }

  setMedia(mediaUrl, subtitlesUrl, contentType) {
    const mediaInfo = new chrome.cast.media.MediaInfo(mediaUrl, contentType);
    const metadata = new chrome.cast.media.MovieMediaMetadata();
    let subtitlesPreparationPromise = Promise.resolve();
    if (subtitlesUrl) { // Check if the subs exist
      subtitlesPreparationPromise = axios.head(subtitlesUrl).then(
        () => {
          const subtitles = new chrome.cast.media.Track(1, chrome.cast.media.TrackType.TEXT);
          subtitles.trackContentId = subtitlesUrl;
          subtitles.trackContentType = 'text/vtt';
          subtitles.subtype = chrome.cast.media.TextTrackType.SUBTITLES;
          subtitles.name = 'English Subtitles'; // Can be in any language
          subtitles.language = 'en-US'; // Can be in any language
          subtitles.customData = null;
          mediaInfo.tracks = [subtitles];

	metadata.title = "AB";
	metadata.subtitle = "A mind-bending thriller";
	metadata.studio = "Warner Bros";
	mediaInfo.metadata = metadata;

          mediaInfo.activeTrackIds = [1];
        },
        () => {}
      );
    }

    subtitlesPreparationPromise.then(() => {
      const loadRequest = new chrome.cast.media.LoadRequest(mediaInfo);
      this.castSession.loadMedia(
        loadRequest,
        (media) => {
          console.log('Media loaded successfully');
          logMessage('Media loaded successfully');
          const tracksInfoRequest = new chrome.cast.media.EditTracksInfoRequest([1]);
          media.editTracksInfo(tracksInfoRequest, s => console.log('Subtitles loaded'), e => console.log(e));
        },
        (errorCode) => { console.error(errorCode); }
      );
    })
  }
}
 let ChromeCast = null;
window['__onGCastApiAvailable'] = function(isAvailable) {
  if (isAvailable) {
    ChromeCast = new ChromeCastService();
  }
};

</script>
    <script>
    function playOnChromeCast(episode) {
     //const mediaUrl = episode.videoUrl;
      mediaUrl = {{.MediaURL}}
      subtitlesUrl = {{.SubsURL}}
      metadataTitle = {{.Title}}
        const loadMedia = () => {
          ChromeCast.setMedia(mediaUrl, subtitlesUrl,"video/mp4");
      }

      //if(!ChromeCast.isConnectedToDevice()) {
        ChromeCast.selectDevice().then(loadMedia);
      //} else {
      //  loadMedia();
      //}
    }
    </script>

    <script>
        // Function to log messages to the on-screen log
        function logMessage(message) {
            const logElement = document.getElementById('log');
            logElement.innerHTML += message + '<br>';
            logElement.scrollTop = logElement.scrollHeight; // Scroll to bottom
        }

        // Initialize the Cast API
        function initializeCast() {
            //logMessage('Initializing Cast session...');

            if (!cast || !cast.framework) {
                logMessage('Google Cast SDK is not available.');
                return;
            }

            const castContext = cast.framework.CastContext.getInstance();

            if (!castContext) {
                //logMessage('Cast Context is not ready.');
                return;
            }

            castContext.setOptions({
                receiverApplicationId: chrome.cast.media.DEFAULT_MEDIA_RECEIVER_APP_ID,
                autoJoinPolicy: chrome.cast.AutoJoinPolicy.ORIGIN_SCOPED
            });

            castContext.addEventListener(cast.framework.CastContextEventType.CAST_STATE_CHANGED, function(event) {
                logMessage('Cast State Changed: ' + event.castState);
            });

            logMessage('Requesting Cast session...');
            castContext.requestSession().then(function() {
                logMessage('Cast session started.');
                startCasting();
            }).catch(function(error) {
                logMessage('Error starting Cast session: ' + error);
            });
        }

        // Start casting the video to the Chromecast device
        function startCasting() {
            const castContext = cast.framework.CastContext.getInstance();
            const videoElement = document.getElementById('video');

            logMessage('Creating media info...');
            const mediaInfo = new chrome.cast.media.MediaInfo(videoElement.src, 'video/mp4');

            // Explicitly define subtitle tracks for Chromecast with fully qualified URLs
            const subtitleTracks = [
                new chrome.cast.media.TextTrack('subtitles_en.vtt', 'en', 'English', chrome.cast.media.TextTrackType.SUBTITLES),
                new chrome.cast.media.TextTrack('subtitles_es.vtt', 'es', 'Spanish', chrome.cast.media.TextTrackType.SUBTITLES)
            ];

            mediaInfo.tracks = subtitleTracks;

            // Create a LoadRequest for the media
            const request = new chrome.cast.media.LoadRequest(mediaInfo);

            logMessage('Sending media to Cast device...');
            castContext.getCurrentSession().loadMedia(request).then(function() {
                logMessage('Media is loaded and playing on the Chromecast device.');
            }).catch(function(error) {
                logMessage('Error loading media on Chromecast: ' + error);
            });
        }

        // Initialize cast context when the page loads
        window.onload = function() {
            logMessage('Page loaded, initializing Cast context...');
            if (cast.framework.CastContext.getInstance()) {
                cast.framework.CastContext.getInstance().setOptions({
                    receiverApplicationId: chrome.cast.media.DEFAULT_MEDIA_RECEIVER_APP_ID,
                    autoJoinPolicy: chrome.cast.AutoJoinPolicy.ORIGIN_SCOPED
                });
            }
        };
    </script>

</body>
</html>
	`
	_ = htmltempl
	_ = html2templ
	templ := template.Must(template.New("foo").Parse(html2templ))
	if err := templ.Execute(w, data); err != nil {
		logger.WarnContext(ctx, "Temaplate error", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// seasonEpisode returns a SxxExx format string, or ""
func seasonEpisode(ds datasource.DataSource) string {
	var res string
	if dss, ok := ds.(Seasoner); ok {
		if s := dss.Season(); s != 0 {
			res = fmt.Sprintf("S%02d", s)
		}
	}
	if dss, ok := ds.(Episoder); ok {
		if e := dss.Episode(); e != 0 {
			res = res + fmt.Sprintf("E%02d", e)
		}
	}
	return res
}

func tags(ds datasource.DataSource) string {
	x, ok := ds.(Tagser)
	if !ok {
		return ""
	}
	var tags []string
	for k, v := range x.Tags() {
		tags = append(tags, "\t"+k+": "+strings.Join(v, ", "))
	}
	return strings.Join(tags, "\n")
}

func serveItemHtml5(ctx context.Context, w http.ResponseWriter, r *http.Request, ds datasource.DataSource) {
	type dataT struct {
		MediaURL      string
		SubsURL       string
		Title         string
		SeasonEpisode string
		Plot          string
		Overview      string
	}
	//itm := r.PathValue("item")
	data := dataT{}
	data.MediaURL = mediaServer{}.MediaURL(ds.ID())
	data.SubsURL = subsServer{}.SubsURL(ds.ID())
	data.SeasonEpisode = seasonEpisode(ds)
	data.Overview = datasource.OverviewOrZero(ds)
	data.Title = datasource.TitleOrZero(ds)
	data.Plot = datasource.PlotOrZero(ds)
	//spew.Dump(ds)

	htmltempl := `<!DOCTYPE html>
        <html lang="en" dir="ltr">
                <head>
                        <meta charset="utf-8">
                        <meta name="viewport"
                                content="width=device-width, initial-scale=1, shrink-to-fit=no">
                        <meta name="description" content="Simple file server">
                        <!-- prevent favicon requests -->
                        <link rel="icon" type="image/png" href="data:image/png;base64,iVBORw0KGgo=">
                        <title>{{ .Title }}</title>
                        <style>
                                tbody tr:nth-child(odd) {
                                        background-color: #eeeeee;
                                }
                                @media (min-width:960px) {
                                        .upload-form {
                                                max-width: 40%;
                                        }
                                }
                        </style>
                </head>
                <body>
    <video id="video" controls>
        <source src="{{.MediaURL}}" type="video/mp4">
	{{ if .SubsURL }}
        	<track src="{{.SubsURL}}" kind="subtitles" srclang="sv" label="Swedish">
	{{ end }}
        Your browser does not support the video tag.
    </video>
    <p>
{{ if .SeasonEpisode }}
	{{.SeasonEpisode }}<br>
{{ end }}
{{ if .Overview }}
	Overview: {{ .Overview}}<br>
{{ end }}
{{ if .Plot }}
    Plot {{.Plot}}<br>
 {{ end }}
    </body>
    </html>
`
	templ := template.Must(template.New("foo").Parse(htmltempl))
	if err := templ.Execute(w, data); err != nil {
		logger.WarnContext(ctx, "Template error", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func hasSetTag(ds datasource.DataSource, filterTags map[string]map[string]bool) bool {
	dss, ok := ds.(Tagser)
	if !ok {
		return false
	}
	dsTags := dss.Tags()

	for filterTagClass, x := range filterTags {
		for filterTagKey, filterTagValue := range x {
			//slog.Info("Testing Filter", "Class", filterTagClass, "Key", filterTagKey, "val", filterTagValue)
			for dsClass, dsValSlice := range dsTags {
				if dsClass == filterTagClass {
					if slices.Contains(dsValSlice, filterTagKey) {
						if filterTagValue == true {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
func sortSources(datasources []datasource.DataSource) {
	title := func(c1, c2 datasource.DataSource) bool {
		return datasource.TitleOrZero(c1) < datasource.TitleOrZero(c2)
	}
	showname := func(c1, c2 datasource.DataSource) bool {
		c1T, ok := c1.(ShowNamer)
		if !ok {
			return false
		}
		c2T, ok := c2.(ShowNamer)
		if !ok {
			return false
		}
		return c1T.ShowName() < c2T.ShowName()
	}
	season := func(c1, c2 datasource.DataSource) bool {
		c1T, ok := c1.(Seasoner)
		if !ok {
			return false
		}
		c2T, ok := c2.(Seasoner)
		if !ok {
			return false
		}
		return c1T.Season() < c2T.Season()
	}
	episode := func(c1, c2 datasource.DataSource) bool {
		c1T, ok := c1.(Episoder)
		if !ok {
			return false
		}
		c2T, ok := c2.(Episoder)
		if !ok {
			return false
		}
		return c1T.Episode() < c2T.Episode()
	}

	// Simple use: Sort by title.
	datasource.OrderedBy(showname, season, episode, title).Sort(datasources)
}

type ListItem struct {
	Movie  *scrape.TMDBMovie
	Marked bool
}
type Collection struct {
	Name   string
	Open   bool
	Titles []ListItem
}

type movieListItem struct {
	Title      *ListItem
	Collection *Collection
}

type groupedMovies struct {
	MovieListItems []movieListItem
}

func groupMovies(dss []datasource.DataSource, r *http.Request) *groupedMovies {
	queries := r.URL.Query()
	markedMovies := make([]string, 0, len(queries))
	for key, _ := range queries {
		splits := strings.Split(key, ".")
		tag := splits[0]
		val := splits[1]
		if tag == "Movie" {
			markedMovies = append(markedMovies, val)
		}
	}

	collections := make(map[string][]ListItem, 64)
	titles := make([]ListItem, 0, len(dss))
	for _, ds := range dss {
		dsT, ok := ds.(*scrape.TMDBMovie)
		if !ok {
			continue
		}
		tags := dsT.Tags()
		if collectionName, ok := tags["collection"]; ok {
			if collections[collectionName[0]] == nil {
				collections[collectionName[0]] = make([]ListItem, 0, 4)
			}
			collections[collectionName[0]] = append(collections[collectionName[0]], ListItem{
				Movie:  dsT,
				Marked: slices.Contains(markedMovies, dsT.Title()),
			})
		} else {
			titles = append(titles, ListItem{
				Movie:  dsT,
				Marked: slices.Contains(markedMovies, dsT.Title()),
			})
		}
	}
	//sort each collection
	for _, v := range collections {
		slices.SortFunc(v, func(a, b ListItem) int {
			return cmp.Compare(a.Movie.Title(), b.Movie.Title())
		})
	}
	res := &groupedMovies{}
	res.MovieListItems = make([]movieListItem, 0, len(titles)+len(collections))
	//Add individual titles to the result slice
	for _, t := range titles {
		res.MovieListItems = append(res.MovieListItems, movieListItem{
			Title:      &t,
			Collection: nil,
		})
	}
	//Add individual collections to the result slice
	for cName, cList := range collections {
		if len(cList) > 1 {
			res.MovieListItems = append(res.MovieListItems, movieListItem{
				Title: nil,
				Collection: &Collection{
					Name:   cName,
					Titles: cList,
					Open: slices.ContainsFunc(cList, func(i ListItem) bool {
						return i.Marked
					}),
				},
			})
		} else {
			res.MovieListItems = append(res.MovieListItems, movieListItem{
				Title:      &cList[0],
				Collection: nil,
			})
		}

	}
	//sort the listItems
	slices.SortFunc(res.MovieListItems, func(a, b movieListItem) int {
		switch {
		case a.Title != nil && b.Title != nil:
			return cmp.Compare(a.Title.Movie.Title(), b.Title.Movie.Title())
		case a.Collection != nil && b.Title != nil:
			return cmp.Compare(a.Collection.Name, b.Title.Movie.Title())
		case a.Title != nil && b.Collection != nil:
			return cmp.Compare(a.Title.Movie.Title(), b.Collection.Name)
		case a.Collection != nil && b.Collection != nil:
			return cmp.Compare(a.Collection.Name, b.Collection.Name)
		}
		panic(45)
		return 0
	})
	/*
		for _, m := range res.MovieListItems {
			switch {
			case m.Title != nil:
				fmt.Printf("%s\n", m.Title.Movie.Title())
			case m.Collection != nil:
				fmt.Printf("Collection %s\n", m.Collection.Name)
				for _, ct := range m.Collection.Titles {
					fmt.Printf("\t%s\n", ct.Movie.Title())
				}
			}
		}
	*/
	return res
}

func serveIndex(ctx context.Context, w http.ResponseWriter, r *http.Request, dss []datasource.DataSource, formActionURL string) {
	logger.InfoContext(ctx, "Serving", "url", r.URL.String())
	//Find all tags
	FilterTags := map[string]map[string]bool{}
	for _, ds := range dss {
		dsT, ok := ds.(Tagser)
		if !ok {
			continue
		}
		for k, v := range dsT.Tags() {
			//if k == "dir" {
			for _, vv := range v {
				if FilterTags[k] == nil {
					FilterTags[k] = map[string]bool{}
				}
				FilterTags[k][vv] = false
			}
			//}
		}
	}

	//	spew.Dump(r.Header)
	queries := r.URL.Query()
	for key, value := range queries {
		fmt.Printf("  %v ===== %v\n", key, value)
		splits := strings.Split(key, ".")
		tag := splits[0]
		val := splits[1]
		if _, ok := FilterTags[tag][val]; ok {
			FilterTags[tag][val] = true
		}
	}
	type object struct {
		MediaURL      string
		PosterURL     string
		BackdropURL   string
		Title         string
		Language      string
		Overview      string
		ShowName      string
		EpisodeTitle  string
		Html5URL      string
		CastURL       string
		Plot          string
		SeasonEpisode string
		Tags          map[string][]string
		BackingStruct string
	}

	o := make([]object, 0, len(dss))
	sortSources(dss)
	for _, ds := range dss {
		if hasSetTag(ds, FilterTags) {
			dsObject := object{
				MediaURL:      mediaServer{}.MediaURL(ds.ID()),
				PosterURL:     posterServer{}.PosterURL(ds.ID()),
				BackdropURL:   backdropServer{}.BackdropURL(ds.ID()),
				Title:         datasource.TitleOrZero(ds),
				Html5URL:      html5Server{}.Html5URL(ds.ID()),
				CastURL:       castServer{}.CastURL(ds.ID()),
				Overview:      datasource.OverviewOrZero(ds),
				Plot:          datasource.PlotOrZero(ds),
				Language:      datasource.LanguageOrZero(ds),
				SeasonEpisode: seasonEpisode(ds),
				BackingStruct: spew.Sdump(ds),
			}
			if dsT, ok := ds.(EpisodeTitler); ok {
				dsObject.EpisodeTitle = dsT.EpisodeTitle()
			}
			if dsT, ok := ds.(ShowNamer); ok {
				dsObject.ShowName = dsT.ShowName()
			}
			if dsT, ok := ds.(Tagser); ok {
				dsObject.Tags = dsT.Tags()
			}
			o = append(o, dsObject)
		}
	}
	type dataT struct {
		User          string
		GroupedMovies *groupedMovies
		FilterTags    map[string]map[string]bool
		Objects       []object
		FormActionURL string
	}
	data := dataT{
		User:          ctx.Value(userCtxKey{}).(User).UserID(),
		GroupedMovies: groupMovies(dss, r),
		FilterTags:    FilterTags,
		Objects:       o,
		FormActionURL: formActionURL,
	}
	htmltempl := `<!DOCTYPE html>
	<html lang="en" dir="ltr">
		<head>
			<meta charset="utf-8">
			<meta name="description" content="Simple file server">
			<!-- prevent favicon requests -->
			<link rel="icon" type="image/png" href="data:image/png;base64,iVBORw0KGgo=">
			<title>TITLE</title>
			<style>
				#navigation a {
    background-color: #999;
}

#navigation .current {
    background-color: #000;
}
				fieldset {
					border: none;          /* removes the border */
				}
				tbody tr:nth-child(odd) {
					background-color: #eeeeee;
			  	}
				.poster {
					max-width:33%;
                                        height: auto;
				}
				ul {
					column-width: 200px;
				}
				.plot {
					max-height: 100pt;
					overflow: auto;
					white-space: pre-line;
				}
				@media only screen and (max-width: 600px) {
					  body {
					    background-color: lightblue;
					  }
					.poster {
						max-width:100%;
                	                        height: auto;
					}
				}
			</style>
		</head>
		<body>
				<h1>Welcome {{.User}}</h1>
				<form action="{{.FormActionURL}}">
				<ul>
				{{range $itm := .GroupedMovies.MovieListItems }}
					{{ if $itm.Title }}
						<input type="checkbox" id="Movie" name="Movie.{{$itm.Title.Movie.Title}}" {{if eq $itm.Title.Marked true}} checked {{end}}>
						<label for="Movie.{{$itm.Title.Movie.Title}}">{{$itm.Title.Movie.Title}}</label><br>
					{{ end}}
					{{ if $itm.Collection }}
					      <details {{ if eq $itm.Collection.Open true}} open {{end}}>
					      <summary>{{ $itm.Collection.Name }}</summary>
					      <fieldset>
						{{ range $t := $itm.Collection.Titles }}
							<input type="checkbox" id="Movie" name="Movie.{{$t.Movie.Title}}" {{if eq $t.Marked true}} checked {{end}}>
							<label for="Movie.{{$t.Movie.Title}}">{{$t.Movie.Title}}</label><br>
						{{ end}}
						</fieldset>
					      </details>
					{{ end }}
				{{end}}
				</ul>
				{{range $tag,$vals := .FilterTags}}
					{{ $tag }}<p>
					{{range $val,$set := $vals}}
						<input type="checkbox" id="{{$tag}}" name="{{$tag}}.{{$val}}" {{if eq $set true}} checked {{end}}>
						<label for="{{$tag}}.{{$val}}">{{$val}}</label>
					{{end}} <p>
				{{end}}
				<input type="submit" value="Submit">
				</form>
				{{range .Objects }} 
						<div>
						{{ if .BackdropURL }}
						<div style="background-image:  
									linear-gradient(rgba(0, 0, 0, 0.6), rgba(0, 0, 0, 0.6)),
									url('{{ .BackdropURL }}');
									background-size: cover;
									color: white;
									width:100% ; 
									height: 100%; ">
						{{ end }}
						<div style="
						  display: flex;
						  align-items: center;
						  gap: 20px;
						">
						{{ if .PosterURL}}
							<img src="{{.PosterURL}}" class="poster"><br>
						{{end}}

						<div>
						{{ if .ShowName }}
							ShowName: {{.ShowName}}<br>
						{{ end }}
						{{ if .Title }}
							Title: {{.Title}}<br>
						{{ end }}
						{{ if .EpisodeTitle }}
							EpisodeTitle: {{.EpisodeTitle}}<br>
						{{ end }}
						{{ if .Language }}
							Language: {{.Language}}<br>
						{{ end }}
						{{ if .Tags }}
							Tags:<br>
							{{ range $tag, $value := .Tags }} 
								----{{$tag }}: 
									{{ range $x := $value }}
									{{ $x }} 
									{{ end}}<br>
							{{ end }}
						{{ end }}
						{{ if .SeasonEpisode }}
							{{.SeasonEpisode }}<br>
						{{ end }}
						{{ if .Overview }}
							<div class="plot">
							{{.Overview}}
							</div>
						{{ end }}
						{{ if .Plot }}
							<div class="plot">
							{{.Plot}}
							</div>
						{{ end }}
						<p>
						<div id="navigation">
						<a href="{{.MediaURL}}">&lt;Download&gt;</a>
						<a href="{{ .Html5URL}}">&lt;Play in browser&gt;</a>
						<a href="{{ .CastURL}}">&lt;Play on ChromeCast&gt;</a><br> 
						</div>
						</div>
						</div>
						{{if .BackdropURL }}
						</div>
						{{ end }}
						</div>
				{{ end }}
		</body>
	</html>
`
	templ := template.Must(template.New("foo").Parse(htmltempl))
	if err := templ.Execute(w, data); err != nil {
		logger.Warn("template error", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
