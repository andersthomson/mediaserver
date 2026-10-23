package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/a-h/templ"
	"github.com/andersthomson/mediaserver/scrape"
	"github.com/felixge/httpsnoop"
	slogctx "github.com/veqryn/slog-context"
)

var logger *slog.Logger
var Config config

type PrettyID struct {
	Id        string
	ShortName string
}

func (p PrettyID) String() string {
	return p.ShortName + "-" + p.Id
}

func NewPrettyIDFromString(s string) (PrettyID, error) {
	const uuidLen = 36

	// A valid <randomchars>-<uuid> must be at least 38 chars long
	// (minimum 1 char for random + 1 char for separator '-' + 36 chars for UUID)
	if len(s) < uuidLen+2 {
		return PrettyID{}, errors.New("string too short to contain random chars and a UUID")
	}

	// Calculate the exact split index right before the UUID
	splitIdx := len(s) - uuidLen - 1

	// Validate that the separator right before the UUID is a hyphen
	if s[splitIdx] != '-' {
		return PrettyID{}, errors.New("malformed format: missing hyphen separator before UUID")
	}

	shortName := s[:splitIdx]
	id := s[len(s)-uuidLen:]

	return NewPrettyID(id, shortName), nil
}

func NewPrettyID(id, shortName string) PrettyID {
	return PrettyID{
		Id:        id,
		ShortName: shortName,
	}
}

type dataSourceServer struct {
	mssCache       *scrape.MssCache
	PosterServer   *scrape.PosterServer
	BackdropServer *scrape.BackdropServer
	DashServer     *scrape.DashServer
	MP4Server      *scrape.MP4Server
}

const ItmId = "ItmId"

func (p *dataSourceServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	itm := r.PathValue("item")
	prettyID, err := NewPrettyIDFromString(itm)
	if err != nil {
		slog.Error("Failed to derive ID", "err", err)
		return
	}
	ctx = context.WithValue(ctx, ItmId, prettyID.Id)
	r = r.WithContext(ctx)

	subRequest := r.Clone(r.Context())

	// Pull the raw, raw unescaped remaining tail path segment safely
	subPathTail := r.PathValue("subPath")
	subRequest.URL.Path = "/" + path.Clean(subPathTail)

	if subRequest.URL.Path == "/poster" {
		p.PosterServer.ServeHTTP(w, subRequest)
		return
	}
	if strings.HasPrefix(subRequest.URL.Path, "/mp4/") {
		p.MP4Server.ServeHTTP(w, subRequest)
		return
	}
	if subRequest.URL.Path == "/backdrop" {
		p.BackdropServer.ServeHTTP(w, subRequest)
		return
	}
	if strings.HasPrefix(subRequest.URL.Path, "/dash/") {
		p.DashServer.ServeHTTP(w, subRequest)
		return
	}

	slog.Error("SHOULD NOT BE HERE")
	w.WriteHeader(500)
	return
}

func MssCacheAddFile(mssCache *scrape.MssCache, path string) {
	dir := filepath.Dir(path)
	name := filepath.Base(path)
	if name != "mediaserver.mss" {
		return
	}

	jsonFile, err := os.Open(path)
	// if os.Open returns an error then handle it
	if err != nil {
		slog.Error("Open failed", "err", err)
		return
	}
	defer jsonFile.Close()
	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		slog.Error("Error reading file", "path", path, "err", err)
		return
	}
	var mss scrape.Mss
	err = json.Unmarshal(byteValue, &mss)
	if err != nil {
		slog.Error("Error unmarshalling JSON", "path", path, "err", err)
		return
	}
	mssCache.Add(dir, mss)
}

func MssCacheRemoveFile(mssCache *scrape.MssCache, path string) {
	//Expect a path of the firm /a/b/c/shortName-id/dash/mediaserver.mss
	if filepath.Base(path) != "mediaserver.mss" {
		return
	}
	name := filepath.Dir(path) //gets ..../'dash'
	name = filepath.Dir(name)  //gets ..../'shortname-id'
	name = filepath.Base(name) //gets 'shortname-id'
	prettyId, err := NewPrettyIDFromString(name)
	if err != nil {
		slog.Error("Failed to derive a prettyId from string", "path", path, "err", err)
		return
	}
	mssCache.Remove(prettyId.Id)
}

type SourceDirectories struct {
	sync.Mutex
	WT       *WatcherThingy
	MssCache *scrape.MssCache
}

func NewSourceDirectories(wt *WatcherThingy, mssCache *scrape.MssCache) *SourceDirectories {
	s := &SourceDirectories{}
	s.WT = wt
	s.MssCache = mssCache
	return s
}
func (s *SourceDirectories) Add(dir string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	s.Lock()
	defer s.Unlock()

	if err := s.WT.addWatchRecursive(absDir); err != nil {
		return fmt.Errorf("Failed to add watch dir=%s err=%w", err, absDir, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("os.ReadDir failed dir=%s err=%w", dir, err)
	}
	for _, entry := range entries {
		mssName := filepath.Join(dir, entry.Name(), "dash/mediaserver.mss")
		MssCacheAddFile(s.MssCache, mssName)
	}
	return nil
}

func (s *SourceDirectories) StartMonitor(ctx context.Context) {
	go func() {
		ch := s.WT.Events()
		for {
			select {
			case ce := <-ch:
				fmt.Printf("GOT %v\n", ce)
				switch ce.Event {
				case "CLOSE":
					MssCacheAddFile(s.MssCache, ce.Path)
				case "REMOVE":
					MssCacheRemoveFile(s.MssCache, ce.Path)
				}
			case <-ctx.Done():
				return
			}
		}
		slog.Info("Exiting filesystem polling loop")
	}()
}

func setupLogger() {
	/*
		baseHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			//AddSource: true,
		})*/
	customHandler := slogctx.NewHandler(slog.Default().Handler(), nil)
	logger = slog.New(customHandler)
	scrape.Logger = slog.New(customHandler)
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
func xSnoopingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := httpsnoop.CaptureMetrics(next, w, r)
		logger.Info("Snoop", "Code", m.Code, "URL", r.URL)
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
		m := httpsnoop.CaptureMetrics(next, w, r.WithContext(ctx))
		logger.InfoContext(ctx, "end req", "code", m.Code, "url", r.URL, "range", r.Header.Get("Range"), "time", time.Since(start))
	})
}

func SessionStoreFromContext(ctx context.Context) *SessionStore {
	if ss := ctx.Value("sessionStore"); ss != nil {
		return ss.(*SessionStore)
	}
	return nil
}

func SessionStoreToContext(sessions *SessionStore) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		f := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, "sessionStore", sessions)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(f)
	}
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
		sessions := SessionStoreFromContext(ctx)
		if sessions == nil {
			logger.Error("No sessionStore in context")
			http.Error(w, err.Error(), http.StatusInternalServerError)
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
		//Write the to session log (per user data)
		se.Logger.Info("Serving", "url", r.URL.String(), "range", r.Header.Get("Range"))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetUserSession(r *http.Request) (User, bool) {
	sessionID, err := getSessionCookie(r)
	if err != nil {
		logger.Info("No session cookie", "err", err)
		return nil, false
	}
	sessions := SessionStoreFromContext(r.Context())
	if sessions == nil {
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

func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		//w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Range")

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

type MediaKind string

const KindUnknown MediaKind = "mediakind.unknown"
const KindMovie MediaKind = "mediakind.movie"
const KindTVshow MediaKind = "mediakind.tvshow"

// MediaManifest is the "Aggregate Root". It holds the raw, unformatted
// data state of the entity across ALL sources before path composition happens.
type MediaManifest struct {
	ID         string
	ShortName  string
	Title      string
	Genres     []string
	Collection string
	Tagline    string
	Overview   string
	HasDash    bool
	HasMP4     bool
	ShowName   string
	Season     int
	Episode    int
	Kind       MediaKind
	Poster     scrape.PosterMetadata
	Backdrop   scrape.BackdropMetadata
	Dash       scrape.DashMetadata
	MP4        scrape.MP4Metadata
	Tags       map[string][]string
}

type MetadataOrchestrator struct {
	PosterResolver   *scrape.PosterResolver
	BackdropResolver *scrape.BackdropResolver
	DashResolver     *scrape.DashResolver
	MP4Resolver      *scrape.MP4Resolver
	MssCache         *scrape.MssCache
	TmdbCache        *scrape.TmdbCache
}

func (m *MetadataOrchestrator) GetUnifiedManifest(id string) (MediaManifest, error) {
	// Consolidate background system lookups into a single execution pass
	var res MediaManifest
	var err error
	var ok bool
	res.ID = id
	res.ShortName, ok = m.MssCache.ShortName(id)
	if !ok {
		return MediaManifest{}, fmt.Errorf("ID %s not in msscache", id)
	}
	res.HasDash, ok = m.MssCache.HasDashManifest(id)
	if !ok {
		return MediaManifest{}, fmt.Errorf("ID %s not in msscache", id)
	}
	res.HasMP4, ok = m.MssCache.HasMP4(id)

	if tmdbMovieID, ok := m.MssCache.MovieId(id); ok {
		res.Kind = KindMovie
		movieDetails, err := m.TmdbCache.MovieDetails(tmdbMovieID)
		if err != nil {
			return MediaManifest{}, fmt.Errorf("tmdb breakdown: %w", err)
		}
		res.Title = scrape.TmdbMovieTitle(movieDetails)
		res.Genres = scrape.TmdbMovieGenres(movieDetails)
		res.Tags = make(map[string][]string)
		res.Tags["genre"] = slices.Clone(res.Genres)
		res.Tags["Movie"] = []string{res.Title}
		res.Tagline = scrape.TmdbMovieTagline(movieDetails)
		res.Overview = scrape.TmdbMovieOverview(movieDetails)
		if cid := scrape.TmdbMovieCollectionID(movieDetails); cid != 0 {
			collectionDetails, err := m.TmdbCache.CollectionDetails(cid)
			if err != nil {
				return MediaManifest{}, fmt.Errorf("tmdb breakdown: %w", err)
			}
			res.Collection = collectionDetails.Name
			res.Tags["collection"] = []string{res.Collection}
		}
	}
	res.Poster, err = m.PosterResolver.ResolvePosterState(id)
	if err != nil {
		return MediaManifest{}, fmt.Errorf("orchestrator poster matching crash: %w", err)
	}

	res.Backdrop, err = m.BackdropResolver.ResolveBackdropState(id)
	if err != nil {
		return MediaManifest{}, fmt.Errorf("orchestrator backdrop matching crash: %w", err)
	}

	res.Dash, err = m.DashResolver.ResolveDashState(id)
	if err != nil {
		return MediaManifest{}, fmt.Errorf("orchestrator dash matching crash: %w", err)
	}

	res.MP4, err = m.MP4Resolver.ResolveMP4State(id)
	if err != nil {
		return MediaManifest{}, fmt.Errorf("orchestrator mp4 matching crash: %w", err)
	}
	return res, nil
}

type ViewModelGenerator struct {
	WebRoot      string
	Orchestrator *MetadataOrchestrator
	MssCache     *scrape.MssCache
}

func (g *ViewModelGenerator) posterURL(manifest MediaManifest) string {
	if manifest.Poster.HasPoster {
		return g.WebRoot + "/item/" + url.PathEscape(NewPrettyID(manifest.ID, manifest.ShortName).String()) + "/part/" + "poster"
	}
	return ""
}

func (g *ViewModelGenerator) backdropURL(manifest MediaManifest) string {
	if manifest.Backdrop.HasBackdrop {
		return g.WebRoot + "/item/" + url.PathEscape(NewPrettyID(manifest.ID, manifest.ShortName).String()) + "/part/" + "backdrop"
	}
	return ""
}
func (g *ViewModelGenerator) shakaURL(manifest MediaManifest, id string) string {
	if manifest.HasDash {
		return g.WebRoot + "/view/shaka/" + url.PathEscape(NewPrettyID(id, manifest.ShortName).String())
	}
	return ""
}

func (g *ViewModelGenerator) html5URL(manifest MediaManifest) string {
	if manifest.HasMP4 {
		return g.WebRoot + "/view/html5/" + url.PathEscape(NewPrettyID(manifest.ID, manifest.ShortName).String())
	}
	return ""
}

func (g *ViewModelGenerator) mp4URL(manifest MediaManifest) string {
	if manifest.HasMP4 {
		return g.WebRoot + "/item/" + url.PathEscape(NewPrettyID(manifest.ID, manifest.ShortName).String()) + "/part/" + "mp4/media.mp4"
	}
	return ""
}

func (g *ViewModelGenerator) dashURL(manifest MediaManifest) string {
	if manifest.HasDash {
		return g.WebRoot + "/item/" + url.PathEscape(NewPrettyID(manifest.ID, manifest.ShortName).String()) + "/part/" + "dash/manifest.mpd"
	}
	return ""
}
func (g *ViewModelGenerator) thumbnailsURL(manifest MediaManifest) string {
	if manifest.HasDash {
		return g.WebRoot + "/item/" + url.PathEscape(NewPrettyID(manifest.ID, manifest.ShortName).String()) + "/part/" + "dash/thumbnails.vtt"
	}
	return ""
}

func (g *ViewModelGenerator) seasonEpisode(manifest MediaManifest) string {
	s := fmt.Sprintf("S%02d", manifest.Season)
	e := fmt.Sprintf("E%02d", manifest.Episode)
	var res string
	if manifest.Season > 0 {
		res = s
	}
	if manifest.Episode > 0 {
		res += e
	}
	return res
}

type object struct {
	Html5URL string
	MP4URL   string
	ShakaURL string
	//HLSURL        string
	//CastURL       string
	PosterURL     string
	BackdropURL   string
	Title         string
	Language      string
	Overview      string
	ShowName      string
	EpisodeTitle  string
	Plot          string
	SeasonEpisode string
	Tags          map[string][]string
	BackingStruct string
	SubsLanguages []string
}
type IndexViewModel struct {
	User          string
	GroupedMovies *groupedMovies
	FilterTags    map[string]map[string]bool
	Objects       []object
	FormActionURL string
	SearchURL     string
}

func (g *ViewModelGenerator) AssembleIndex(ctx context.Context, enabledTags map[string][]string) (IndexViewModel, error) {
	webRootURL, err := url.Parse(g.WebRoot)
	if err != nil {
		panic(err)
	}
	ids := g.MssCache.AllIDs()
	manifests := make([]MediaManifest, 0, len(ids))
	for _, id := range ids {
		manifest, err := g.Orchestrator.GetUnifiedManifest(id)
		if err != nil {
			return IndexViewModel{}, err
		}
		manifests = append(manifests, manifest)
	}

	formActionURL := webRootURL.Path + "/"
	searchURL := webRootURL.Path + "/search"

	//Find all tags
	FilterTags := map[string]map[string]bool{}

	for _, mfest := range manifests {
		for k, v := range mfest.Tags {
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

	for tag, vals := range enabledTags {
		for _, val := range vals {
			//F the value already exists, enable it (thus not accepting non-exisiting values)
			if _, ok := FilterTags[tag][val]; ok {
				FilterTags[tag][val] = true
			}
		}
	}
	sortSources(manifests)
	movs := groupMovies(manifests, enabledTags)

	o := make([]object, 0, len(manifests))
	for _, manifest := range manifests {
		if hasSetTag(manifest.Tags, FilterTags) {
			Object := object{
				Title:       manifest.Title,
				PosterURL:   g.posterURL(manifest),
				BackdropURL: g.backdropURL(manifest),
				Overview:    manifest.Overview,
				ShakaURL:    g.shakaURL(manifest, manifest.ID),
				Html5URL:    g.html5URL(manifest),
				MP4URL:      g.mp4URL(manifest),
				Tags:        manifest.Tags,
			}
			o = append(o, Object)
		}
	}
	return IndexViewModel{
		User:          ctx.Value(userCtxKey{}).(User).UserID(),
		GroupedMovies: movs,
		FilterTags:    FilterTags,
		Objects:       o,
		FormActionURL: formActionURL,
		SearchURL:     searchURL,
	}, nil

}

type SearchCardViewModel struct {
	ID        string
	Title     string
	PosterURL string
	Tagline   string
	Genres    []string
	Overview  string
	MP4URL    string
	CastURL   string
	Html5URL  string
	ShakaURL  string
}

type SearchViewModel map[string][]SearchCardViewModel

func (g *ViewModelGenerator) AssembleSearchViewModel(ctx context.Context, searchTerm string) (SearchViewModel, error) {
	ids := g.MssCache.AllIDs()
	manifests := make([]MediaManifest, 0, len(ids))
	for _, id := range ids {
		manifest, err := g.Orchestrator.GetUnifiedManifest(id)
		if err != nil {
			return SearchViewModel{}, err
		}
		manifests = append(manifests, manifest)
	}

	var res []MediaManifest
	for _, mFest := range manifests {
		if strings.Contains(strings.ToLower(mFest.Title), searchTerm) {
			res = append(res, mFest)
			continue
		}
		if strings.Contains(strings.ToLower(mFest.Title), searchTerm) {
			res = append(res, mFest)
		}
	}
	sortSources(res)
	splits := SplitByGenre(res)
	logger.InfoContext(ctx, "serving search", "SearchTerm", searchTerm, "num datasources", len(res))
	//templ.Handler(Cards4Datasources(splits)).ServeHTTP(w, r)

	sID := map[string][]SearchCardViewModel{}
	for genre, genreSlice := range splits {
		for _, mFest := range genreSlice {
			scvm := SearchCardViewModel{
				Title:     mFest.Title,
				PosterURL: g.posterURL(mFest),
				Tagline:   mFest.Tagline,
				Genres:    mFest.Genres,
				Overview:  mFest.Overview,
				MP4URL:    g.mp4URL(mFest),
				CastURL:   "",
				Html5URL:  g.html5URL(mFest),
				ShakaURL:  g.shakaURL(mFest, mFest.ID),
			}

			sID[genre] = append(sID[genre], scvm)
		}
	}
	return sID, nil
}

type ShakaViewModel struct {
	ManifestURL   string
	ThumbnailsURL string
}

func (g *ViewModelGenerator) AssembleShakaViewModel(ctx context.Context, id string) (ShakaViewModel, error) {
	manifest, err := g.Orchestrator.GetUnifiedManifest(id)
	if err != nil {
		slog.Error("Failed to get manifest", "id", id, "err", err)
		return ShakaViewModel{}, fmt.Errorf("Failed to get manifest", "id", id, "err", err)
	}

	data := ShakaViewModel{
		ManifestURL:   g.dashURL(manifest),
		ThumbnailsURL: g.thumbnailsURL(manifest),
	}
	return data, nil
}

type Html5ViewModel struct {
	MP4URL string
	//SubsURLs      []datasource.Subs
	Title         string
	SeasonEpisode string
	Overview      string
}

func (g *ViewModelGenerator) AssembleHtml5ViewModel(ctx context.Context, id string) (Html5ViewModel, error) {
	manifest, err := g.Orchestrator.GetUnifiedManifest(id)
	if err != nil {
		slog.Error("Failed to get manifest", "id", id, "err", err)
		return Html5ViewModel{}, fmt.Errorf("Failed to get manifest", "id", id, "err", err)
	}

	data := Html5ViewModel{
		MP4URL: g.mp4URL(manifest),
		//SubsURLs:      nil, //TODO
		Title:         manifest.Title,
		SeasonEpisode: g.seasonEpisode(manifest),
		Overview:      manifest.Overview,
	}
	return data, nil
}

type CastViewModel struct {
	Title     string
	PosterURL string
	MediaURL  string
	SubsURL   string
	//SubsURLs  []datasource.Subs
	Tagline string
}

func (g *ViewModelGenerator) AssembleCastViewModel(ctx context.Context, id string) (CastViewModel, error) {
	manifest, err := g.Orchestrator.GetUnifiedManifest(id)
	if err != nil {
		slog.Error("Failed to get manifest", "id", id, "err", err)
		return CastViewModel{}, fmt.Errorf("Failed to get manifest", "id", id, "err", err)
	}

	data := CastViewModel{
		Title:     manifest.Title,
		MediaURL:  "", //TODO
		PosterURL: g.posterURL(manifest),
		Tagline:   manifest.Tagline,
	}
	return data, nil
}

func HandleSearch(viewModelGenerator *ViewModelGenerator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract the 'search' value from the POST request
		searchTerm := strings.ToLower(r.FormValue("search"))
		sID, err := viewModelGenerator.AssembleSearchViewModel(r.Context(), searchTerm)
		if err != nil {
			slog.Error("Failed to generate SearchViewModel", "err", err)
		}
		templ.Handler(Cards4IDs(sID)).ServeHTTP(w, r)
	}
}

func SplitByGenre(manifests []MediaManifest) map[string][]MediaManifest {
	res := map[string][]MediaManifest{}

	for _, mFest := range manifests {
		for _, genre := range mFest.Genres {
			res[genre] = append(res[genre], mFest)
		}
		if len(mFest.Genres) == 0 {
			res["generic"] = append(res["generic"], mFest)
		}
	}
	return res
}

func HandleCast(viewModelGenerator *ViewModelGenerator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		pretty := r.PathValue("item")
		prettyID, err := NewPrettyIDFromString(pretty)
		if err != nil {
			slog.Error("Failed to split prettyID", "prettyID", pretty, "err", err)
			return
		}
		data, err := viewModelGenerator.AssembleCastViewModel(ctx, prettyID.Id)
		if err != nil {
			slog.Error("Failed to assemble CastViewModel", "err", err)
			return
		}
		html2templ := `
		<!DOCTYPE html>
<html>
<head>
    <title>Simple Chromecast Sender</title>
    <style>
        body { font-family: sans-serif; display: flex; flex-direction: column; align-items: center; padding-top: 50px; }
        #castBtn { padding: 10px 20px; font-size: 16px; cursor: pointer; background: #4285f4; color: white; border: none; border-radius: 4px; }
        #playBtn { padding: 10px 20px; font-size: 16px; margin-top: 10px; background: #34a853; color: white; border: none; border-radius: 4px; }
        #status { margin-top: 20px; color: #666; }
    </style>
</head>
<body>

    <h2>Chromecast MP4 Player</h2>

    <!-- Custom button to trigger the Cast dialog -->
    <button id="castBtn">Choose Cast Device</button>
    <button id="playBtn" style="display:none;">Start Video</button>
    <div id="status">Ready</div>

    <script>
        // 1. Define the callback BEFORE loading the script
        window['__onGCastApiAvailable'] = function(isAvailable) {
            if (isAvailable) {
                initializeCastApi();
            } else {
                document.getElementById('status').innerText = "Cast SDK not available.";
            }
        };

        function initializeCastApi() {
            const context = cast.framework.CastContext.getInstance();
            context.setOptions({
                receiverApplicationId: chrome.cast.media.DEFAULT_MEDIA_RECEIVER_APP_ID,
                autoJoinPolicy: chrome.cast.AutoJoinPolicy.ORIGIN_SCOPED
            });

            // Monitor state changes
            context.addEventListener(cast.framework.CastContextEventType.SESSION_STATE_CHANGED, (event) => {
                const state = event.sessionState;
                if (state === cast.framework.SessionState.SESSION_STARTED) {
                    document.getElementById('status').innerText = "Connected!";
                    document.getElementById('playBtn').style.display = "block";
                    document.getElementById('castBtn').style.display = "none";
                }
            });
        }

        // 2. Manual trigger for the Cast Dialog
        document.getElementById('castBtn').addEventListener('click', () => {
            cast.framework.CastContext.getInstance().requestSession()
                .catch(err => console.log("User cancelled or error: ", err));
        });

        // 3. Playback Logic
        document.getElementById('playBtn').addEventListener('click', () => {
            const castSession = cast.framework.CastContext.getInstance().getCurrentSession();
            const mediaInfo = new chrome.cast.media.MediaInfo(
                'https://media.famthomson.se/ms-beta/item/2040%20-%20framtidsfilmen.mp4/part/media',
                    'video/mp4'
            );
            const request = new chrome.cast.media.LoadRequest(mediaInfo);
            castSession.loadMedia(request).then(
                () => { document.getElementById('status').innerText = "Playing on TV..."; },
                (err) => { document.getElementById('status').innerText = "Error: " + err; }
            );
        });
    </script>

    <!-- The Cast Framework SDK -->
    <script src="https://www.gstatic.com/cv/js/sender/v3/cast_sender.js?loadCastFramework=1"></script>
</body>
</html>

`

		_ = html2templ
		templ := template.Must(template.New("foo").Parse(html2templ))
		if err := templ.Execute(w, data); err != nil {
			logger.WarnContext(ctx, "Temaplate error", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func HandleHtml5(viewModelGenerator *ViewModelGenerator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		pretty := r.PathValue("item")
		prettyID, err := NewPrettyIDFromString(pretty)
		if err != nil {
			slog.Error("Failed to split prettyID", "prettyID", pretty, "err", err)
			return
		}
		data, err := viewModelGenerator.AssembleHtml5ViewModel(ctx, prettyID.Id)
		if err != nil {
			slog.Error("Failed to assemble Html5ViewModel", "err", err)
			return
		}
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
        <source src="{{.MP4URL}}" type="video/mp4">
        Your browser does not support the video tag.
    </video>
    <p>
{{ if .SeasonEpisode }}
        {{.SeasonEpisode }}<br>
{{ end }}
{{ if .Overview }}
        Overview: {{ .Overview}}<br>
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
}

func HandleShaka(viewModelGenerator *ViewModelGenerator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		pretty := r.PathValue("item")
		prettyID, err := NewPrettyIDFromString(pretty)
		if err != nil {
			slog.Error("Failed to split prettyID", "prettyID", pretty, "err", err)
			return
		}
		data, err := viewModelGenerator.AssembleShakaViewModel(ctx, prettyID.Id)
		if err != nil {
			slog.Error("Failed to assemble ShakaViewModel", "err", err)
			return
		}
		htmltempl := `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Minimal Shaka Cast/CC</title>
  <!-- Full URL Paths for UI and Engine -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/shaka-player/4.7.0/controls.min.css">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/shaka-player/4.7.0/shaka-player.ui.min.js"></script>
  <script defer src="https://gstatic.com/cv/js/sender/v1/cast_sender.js"></script>
  <style>
    body { margin: 0; background: #000; display: flex; justify-content: center; align-items: center; height: 100vh; }
    .video-container { width: 800px; }
  </style>
</head>
<body>

  <!-- Container with Shaka Demo Receiver ID -->
  <div class="video-container" 
       data-shaka-player-container 
       data-shaka-player-cast-receiver-id="07AEE832">
    <video data-shaka-player id="video" style="width:100%; height:100%"></video>
  </div>

<script>
  const manifestUri = '{{.ManifestURL}}';
  //const captionUri = 'https://googleapis.com/shaka-demo-assets/angel-one/subs_en.vtt';

  async function initPlayer() {
    shaka.polyfill.installAll();

    const video = document.getElementById('video');
    const ui = video['ui'];
    const player = ui.getControls().getPlayer();

    // Configure UI for Cast and CC visibility
    ui.configure({
      'controlPanelElements': ['play_pause', 'time_and_duration', 'spacer', 'mute', 'volume','captions', 'cast', 'fullscreen']
    });

    try {
      await player.load(manifestUri);
      // Explicitly add a CC track for the UI menu to pick up
     // await player.addTextTrackAsync(captionUri, 'en', 'captions', 'text/vtt');
    } catch (e) {
      console.error('Error loading:', e);
    }
  try {
  await player.addThumbnailsTrack('{{.ThumbnailsURL}}');
   } catch (e) {
      console.error('Error loading vtt:', e);
    }
  }

  // Initialized via Shaka UI event
  document.addEventListener('shaka-ui-loaded', initPlayer);
</script>

</body>
</html>
`

		templ := template.Must(template.New("foo").Parse(htmltempl))
		if err := templ.Execute(w, data); err != nil {
			logger.WarnContext(ctx, "Template error", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
func hasSetTag(dsTags map[string][]string, filterTags map[string]map[string]bool) bool {
	//slog.Info("hasSetTag", "dsTags", dsTags, "filterTags", filterTags)
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

// cmpFunc is a 3-way comparison function generic over any type T.
// It returns:
//
//	-1 if a < b
//	 0 if a == b
//	 1 if a > b
type cmpFunc[T any] func(a, b T) int

// OrderedBy chains multiple 3-way comparison functions into one.
// It stops executing functions the moment a tie is broken.
func OrderedBy[T any](comparators ...cmpFunc[T]) func(a, b T) int {
	return func(a, b T) int {
		for _, compare := range comparators {
			if res := compare(a, b); res != 0 {
				return res // Tie broken! Return -1 or 1 immediately.
			}
		}
		return 0 // All criteria found the elements to be perfectly identical.
	}
}

func sortSources(mms []MediaManifest) {
	title := func(c1, c2 MediaManifest) int {
		return cmp.Compare(c1.Title, c2.Title)
	}
	showname := func(c1, c2 MediaManifest) int {
		return cmp.Compare(c1.ShowName, c2.ShowName)
	}
	season := func(c1, c2 MediaManifest) int {
		return cmp.Compare(c1.Season, c2.Season)
	}
	episode := func(c1, c2 MediaManifest) int {
		return cmp.Compare(c1.Episode, c2.Episode)
	}
	slices.SortFunc(mms, OrderedBy(showname, season, episode, title))
}

type ListItem struct {
	Movie  MediaManifest
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

func groupMovies(mms []MediaManifest, enabledTags map[string][]string) *groupedMovies {
	markedMovies := enabledTags["Movie"]

	collections := make(map[string][]ListItem, 64)
	titles := make([]ListItem, 0, len(mms))
	for _, mFest := range mms {
		tags := mFest.Tags
		if collectionName, ok := tags["collection"]; ok {
			if collections[collectionName[0]] == nil {
				collections[collectionName[0]] = make([]ListItem, 0, 4)
			}
			collections[collectionName[0]] = append(collections[collectionName[0]], ListItem{
				Movie:  mFest,
				Marked: slices.Contains(markedMovies, mFest.Title),
			})
		} else {
			titles = append(titles, ListItem{
				Movie:  mFest,
				Marked: slices.Contains(markedMovies, mFest.Title),
			})
		}
	}
	//sort each collection
	for _, v := range collections {
		slices.SortFunc(v, func(a, b ListItem) int {
			return cmp.Compare(a.Movie.Title, b.Movie.Title)
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
			return cmp.Compare(a.Title.Movie.Title, b.Title.Movie.Title)
		case a.Collection != nil && b.Title != nil:
			return cmp.Compare(a.Collection.Name, b.Title.Movie.Title)
		case a.Title != nil && b.Collection != nil:
			return cmp.Compare(a.Title.Movie.Title, b.Collection.Name)
		case a.Collection != nil && b.Collection != nil:
			return cmp.Compare(a.Collection.Name, b.Collection.Name)
		}
		return 0
	})
	return res
}

func HandleIndex(viewModelGenerator *ViewModelGenerator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		queries := r.URL.Query()
		enabledTags := map[string][]string{}
		for key, value := range queries {
			if value[0] != "on" {
				continue
			}
			splits := strings.SplitN(key, ".", 2)
			tag := splits[0]
			val := splits[1]
			enabledTags[tag] = append(enabledTags[tag], val)
		}

		data, err := viewModelGenerator.AssembleIndex(ctx, enabledTags)
		if err != nil {
			slog.Error("Failed to generate index vireModel", "err", err)
			return
		}
		logger.InfoContext(ctx, "Serving idx", "url", r.URL.String())
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
				.row-content {
				    display: flex;          /* Put cards in a single row */
				        overflow-x: auto;       /* Enable horizontal scrolling */
					    gap: 16px;              /* Space between cards */
					        padding: 10px 0;        /* Space for shadows/borders */
						    scrollbar-width: thin;  /* Optional: cleaner scrollbar for Firefox */
						    }

				.card {
				    border: 1px solid #ccc;
				        padding: 16px;
				    border-radius: 8px;
				        width: 250px;        /* Fixed width or use flex-basis */
				    background: #f9f9f9;
			   	 }
				 .card-container {
				     display: flex;     
					      flex-direction: column; /* Stack rows vertically */
					          gap: 40px;              /* Space between the "Trending", "Recommended" rows */
						      padding: 20px;
					     gap: 16px;           /* Space between the cards */
					     }
			.card img {
			    max-width: 100%;  /* Shrink to fit the card's width */
			        height: auto;     /* Maintain aspect ratio (don't stretch) */
				    display: block;   /* Removes the tiny gap at the bottom of images */
				        border-radius: 4px; /* Optional: matches the card style */
					}
			</style>
		<script src="https://cdnjs.cloudflare.com/ajax/libs/htmx/1.9.12/htmx.min.js"></script>
		</head>
		<body>
				<h1>Welcome {{.User}}</h1>
					<input class="form-control" 
					type="search" 
					name="search" 
					placeholder="Begin typing to search..." 
					hx-post="{{.SearchURL}}"
					hx-trigger="input changed delay:500ms, search" 
					hx-target="#searchresult">

				<div id="searchresult" class="card-container">
NADA
				</div>
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
						{{ if .SubsLanguages }}
							Subtitles:<br>
							{{ range $lang := .SubsLanguages }}
								{{ $lang }}
							{{ end }}<br>
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
						{{ if .MediaURL }}
							<a href="{{.MediaURL}}">&lt;Download&gt;</a>
							<a href="{{ .Html5URL}}">&lt;Play in browser&gt;</a>
						{{ end }}
						{{ if .ShakaURL }}
							<a href="{{ .ShakaURL}}">&lt;Play in Shaka&gt;</a>
						{{ end }}
						{{ if .HLSURL }}
							<a href="{{ .ShakaURL}}">&lt;Play in Shaka&gt;</a>
						{{ end }}
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
}
