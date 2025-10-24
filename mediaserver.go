package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/andersthomson/mediaserver/datasource"
	"github.com/andersthomson/mediaserver/scrape"
	"github.com/davecgh/go-spew/spew"
	slogctx "github.com/veqryn/slog-context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type User struct {
	IDProvider string
	Email      string
	Name       string
	GivenName  string
	FamilyName string
	LastUsed   time.Time
}

var (
	// Global OAuth2 config
	oauthConfig *oauth2.Config
	// In-memory session store: sessionID -> email
	sessions Sessions
)

var logger *slog.Logger
var Config config

type MediaOrigin struct {
	Format string
}

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

type directoryRepo struct {
	dsLck sync.Mutex
	ds    []datasource.DataSource
	dir   string
}

func (d *directoryRepo) Refresh() {
	go func() {
		for {
			i := ScanDir(d.dir)
			d.dsLck.Lock()
			d.ds = i
			d.dsLck.Unlock()
			time.Sleep(time.Minute)
		}
	}()
}

func (d *directoryRepo) AllDataSources() []datasource.DataSource {
	var r []datasource.DataSource
	d.dsLck.Lock()
	r = d.ds
	d.dsLck.Unlock()
	if r == nil {
		return []datasource.DataSource{}
	}
	return r
}

func IsMP4File(s string) bool {
	switch {
	case filepath.Ext(s) == ".mp4":
		return true
	case filepath.Ext(s) == ".MP4":
		return true
	default:
		return false
	}
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

var allRepos allReposT

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

type DataSourceServer struct {
}

func (d DataSourceServer) allItms() []datasource.DataSource {
	return allRepos.AllDataSources()
}

func (d DataSourceServer) dataSourceByID(id string) datasource.DataSource {
	itms := d.allItms()
	idx := slices.IndexFunc(itms, func(ds datasource.DataSource) bool {
		return ds.ID() == id
	})
	if idx != -1 {
		return itms[idx]
	}
	return nil
}

func (_ DataSourceServer) partNameMedia() string {
	return "media.mp4"
}
func (_ DataSourceServer) partNameSubs() string {
	return "subs.vtt"
}
func (_ DataSourceServer) partNamePoster() string {
	return "poster"
}
func (_ DataSourceServer) partNameBackdrop() string {
	return "backdrop"
}
func (_ DataSourceServer) partNameHtml5() string {
	return "html5"
}
func (_ DataSourceServer) partNameChromeCast() string {
	return "cast"
}

func (d *DataSourceServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, hasSession := GetUserSession(r)
	if hasSession {
		ctx = slogctx.Append(ctx, "idp", user.IDProvider)
		ctx = slogctx.Append(ctx, "user", user.Email)
	}
	itms := d.allItms()
	itm := r.PathValue("item")
	part := r.PathValue("part")
	if itm == "" {
		logger.InfoContext(ctx, "No item exists", "itm", itm)
		serveIndex(ctx, w, r, itms, "/") //FIXME: proper action URL
		return
	}
	ds := d.dataSourceByID(itm)
	if ds == nil {
		slog.InfoContext(ctx, "No ds exists", "itm", itm)
		errorHandler(ctx, w, r, http.StatusNotFound)
		return
	}
	enableCors(&w)
	switch part {
	case d.partNameMedia():
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
	default:
		if !hasSession {
			logger.Info("No session go to login")
			LoginPage(w, r)
			return
		}
		logger.InfoContext(ctx, "Serving", "URL", r.URL)
		switch part {
		case d.partNameSubs():
			content, err := ds.OpenSubs()
			if err != nil {
				errorHandler(ctx, w, r, http.StatusNotFound)
				logger.InfoContext(ctx, "read of subs", "failed", err)
				return
			}
			http.ServeContent(w, r, "foo.vtt", time.Time{}, content)
			content.Close()
			return
		case d.partNamePoster():
			content, err := ds.OpenPoster()
			if err != nil {
				errorHandler(ctx, w, r, http.StatusNotFound)
				logger.InfoContext(ctx, "read of poster", "failed", err)
				return
			}
			http.ServeContent(w, r, "", time.Time{}, content)
			content.Close()
		case d.partNameBackdrop():
			dsT, ok := ds.(datasource.OpenBackdroper)
			if !ok {
				errorHandler(ctx, w, r, http.StatusNotFound)
				logger.InfoContext(ctx, "ds does not support backdrops", "id", ds.ID())
				return
			}
			content, err := dsT.OpenBackdrop()
			if err != nil {
				errorHandler(ctx, w, r, http.StatusNotFound)
				logger.InfoContext(ctx, "read of backdrop", "failed", err)
				return
			}
			http.ServeContent(w, r, "", time.Time{}, content)
			content.Close()
		case d.partNameHtml5():
			serveItemHtml5(ctx, w, r, ds)
			return
		case d.partNameChromeCast():
			serveItemCast(ctx, w, r, ds)
			return

		default:
			logger.InfoContext(ctx, "Unsupported request", "part", part, "URL", r.URL, "header", r.Header)
		}
	}
}

func (d DataSourceServer) MediaURL(id string) string {
	return Config.WebRoot + "/item/" + url.PathEscape(id) + "/part/" + d.partNameMedia()
}
func (d DataSourceServer) SubsURL(id string) string {
	ds := d.dataSourceByID(id)
	content, err := ds.OpenSubs()
	if err == nil {
		content.Close()
		return Config.WebRoot + "/item/" + url.PathEscape(id) + "/part/" + d.partNameSubs()
	}
	return ""
}
func (d DataSourceServer) PosterURL(id string) string {
	ds := d.dataSourceByID(id)
	content, err := ds.OpenPoster()
	if err == nil {
		content.Close()
		return Config.WebRoot + "/item/" + url.PathEscape(id) + "/part/" + d.partNamePoster()
	}
	return ""
}
func (d DataSourceServer) BackdropURL(id string) string {
	ds := d.dataSourceByID(id)
	dsT, ok := ds.(datasource.OpenBackdroper)
	if !ok {
		return ""
	}
	content, err := dsT.OpenBackdrop()
	if err == nil {
		content.Close()
		return Config.WebRoot + "/item/" + url.PathEscape(id) + "/part/" + d.partNameBackdrop()
	}
	return ""
}
func (d DataSourceServer) Html5URL(id string) string {
	return Config.WebRoot + "/item/" + url.PathEscape(id) + "/part/" + d.partNameHtml5()
}
func (d DataSourceServer) ChromeCastURL(id string) string {
	return Config.WebRoot + "/item/" + url.PathEscape(id) + "/part/" + d.partNameChromeCast()
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
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
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Started %s %s", r.Method, r.URL.Path)

		next.ServeHTTP(w, r)

		log.Printf("Completed %s in %v", r.URL.Path, time.Since(start))
	})
}

func ChainMiddleware(handler http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
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
	oauthConfig = &oauth2.Config{
		ClientID:     Config.GoogleOAuth.ClientID,
		ClientSecret: Config.GoogleOAuth.ClientSecret,
		RedirectURL:  "https://media.famthomson.se/ms/auth/google/callback",
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}
	sessions = Sessions{}
	sessions.m = make(map[string]User, 16)
	buf, err := os.ReadFile("./sessions")
	if err != nil {
		logger.Warn("Failed to read sesson file", "err", err)
	} else {
		sessions.FromJson(buf)
	}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan // Block until a signal is received
		fmt.Printf("\nReceived signal: %v\n", sig)
		b := sessions.ToJson()
		if err := os.WriteFile("./sessions", b, 0644); err != nil {
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

	webRootURL, err := url.Parse(Config.WebRoot)
	if err != nil {
		panic(err)
	}
	mux.Handle(webRootURL.Path+"/login", ChainMiddleware(http.HandlerFunc(loginHandler), LoggingMiddleware))
	mux.Handle(webRootURL.Path+"/auth/google/callback", ChainMiddleware(http.HandlerFunc(callbackHandler), LoggingMiddleware))

	mux.Handle(webRootURL.Path+"/item/{item}/part/{part}", &DataSourceServer{})

	mux.Handle(webRootURL.Path+"/", ChainMiddleware(http.HandlerFunc(serveTopIndex), LoggingMiddleware, AuthMiddleware))

	logger.Info("Listening...")
	err = http.ListenAndServe(":3000", mux)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

func LoginPage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<html><h2>Welcome</h2><a href=\""+"/ms"+"/login\">Login with Google</a></html>")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	url := oauthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code", http.StatusBadRequest)
		logger.Info("Missing code")
		return
	}

	ctx := context.Background()
	token, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Fetch user info from Google's userinfo endpoint
	client := oauthConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "Userinfo request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var user struct {
		Email      string `json:"email"`
		Name       string `json:"name"`
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		http.Error(w, "Failed to decode userinfo: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !slices.Contains(Config.GoogleOAuth.AllowedUsers, user.Email) {
		LoginPage(w, r)
		logger.Warn("User not authorized", "user", user)
		return
	}
	logger.Info("Authorized user", "user", user)
	// Create a new session
	sessionID := randomString(32)
	setSessionCookie(w, sessionID)

	// Store session -> user mapping
	sessions.Lock()
	sessions.m[sessionID] = User{
		IDProvider: "google",
		Email:      user.Email,
		Name:       user.Name,
		GivenName:  user.GivenName,
		FamilyName: user.FamilyName,
		LastUsed:   time.Now(),
	}
	sessions.Unlock()

	http.Redirect(w, r, Config.WebRoot, http.StatusFound)
}
func GetUserSession(r *http.Request) (User, bool) {
	sessionID, err := getSessionCookie(r)
	if err != nil {
		logger.Info("No session cookie", "err", err)
		return User{}, false
	}
	sessions.RLock()
	u, ok := sessions.m[sessionID]
	sessions.RUnlock()
	if !ok {
		logger.Info("Invalid session")
		return User{}, false
	}
	return u, true
}

func MustGetUserSession(w http.ResponseWriter, r *http.Request) (User, bool) {
	u, ok := GetUserSession(r)
	if !ok {
		LoginPage(w, r)
		return User{}, false
	}
	return u, true
}

type userKey struct{}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, hasSession := MustGetUserSession(w, r)
		if !hasSession {
			return
		}

		// Add user data to the request context
		ctx := context.WithValue(r.Context(), userKey{}, user)
		ctx = slogctx.Append(ctx, "idp", user.IDProvider)
		ctx = slogctx.Append(ctx, "user", user.Email)
		logger.InfoContext(ctx, "USER AUTHED")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

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

func serveItemCast(ctx context.Context, w http.ResponseWriter, r *http.Request, ds datasource.DataSource) {
	type dataT struct {
		DS       datasource.DataSource
		MediaURL string
		SubsURL  string
	}
	data := dataT{
		DS:       ds,
		MediaURL: DataSourceServer{}.MediaURL(ds.ID()),
		SubsURL:  DataSourceServer{}.SubsURL(ds.ID()),
	}
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
        const loadMedia = () => {
          ChromeCast.setMedia(mediaUrl, subtitlesUrl);
      }

      if(!ChromeCast.isConnectedToDevice()) {
        ChromeCast.selectDevice().then(loadMedia);
      } else {
        loadMedia();
      }
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
            logMessage('Initializing Cast session...');

            if (!cast || !cast.framework) {
                logMessage('Google Cast SDK is not available.');
                return;
            }

            const castContext = cast.framework.CastContext.getInstance();

            if (!castContext) {
                logMessage('Cast Context is not ready.');
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
	templ := template.Must(template.New("foo").Parse(htmltempl))
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
	data.MediaURL = DataSourceServer{}.MediaURL(ds.ID())
	data.SubsURL = DataSourceServer{}.SubsURL(ds.ID())
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
				MediaURL:      DataSourceServer{}.MediaURL(ds.ID()),
				PosterURL:     DataSourceServer{}.PosterURL(ds.ID()),
				BackdropURL:   DataSourceServer{}.BackdropURL(ds.ID()),
				Title:         datasource.TitleOrZero(ds),
				Html5URL:      DataSourceServer{}.Html5URL(ds.ID()),
				CastURL:       DataSourceServer{}.ChromeCastURL(ds.ID()),
				Overview:      datasource.OverviewOrZero(ds),
				Plot:          datasource.PlotOrZero(ds),
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
		Objects       []object
		FilterTags    map[string]map[string]bool
		FormActionURL string
	}
	data := dataT{
		Objects:       o,
		FilterTags:    FilterTags,
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
				tbody tr:nth-child(odd) {
					background-color: #eeeeee;
			  	}
				.poster {
					max-width:33%;
                                        height: auto;
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
				<form action="{{.FormActionURL}}">
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
						<a href="{{.MediaURL}}">&lt;Download&gt;</a>
						<a href="{{ .Html5URL}}">&lt;Play in browser&gt;</a>
						<a href="{{ .CastURL}}">&lt;Play on ChromeCast&gt;</a><br> 
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
