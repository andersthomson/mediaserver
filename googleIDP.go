package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleUser struct {
	IDProvider_ string
	Email       string
	Name        string
	GivenName   string
	FamilyName  string
}

func (g GoogleUser) UserID() string {
	return g.Email
}

func (g GoogleUser) IDProvider() string {
	return g.IDProvider_
}

type GoogleIDP struct {
	sessionStore              *Sessions
	oauthConfig               *oauth2.Config
	postAuthenticateTargetURL string
	idpRoot                   string
}

func NewGoogleIDP(sessionStore *Sessions, oauthClientID string, oauthClientSecret string, postAuthenticateTargetURL string, IDPRoot string) *GoogleIDP {
	oauthConfig := &oauth2.Config{
		ClientID:     oauthClientID,
		ClientSecret: oauthClientSecret,
		RedirectURL:  Config.WebRoot + "/auth/google/callback",
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}
	return &GoogleIDP{
		sessionStore:              sessionStore,
		oauthConfig:               oauthConfig,
		postAuthenticateTargetURL: postAuthenticateTargetURL,
		idpRoot:                   IDPRoot,
	}
}

func (g GoogleIDP) IDPName() string {
	return "google"
}

func (g *GoogleIDP) LoginPageFragment(w http.ResponseWriter) {
	fmt.Fprintf(w, "<a href=\""+g.idpRoot+"/"+g.IDPName()+"/login\">Login with Google</a><p>\n")

}

func (g *GoogleIDP) ServeMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/login", Chain(LoggingMiddleware)(http.HandlerFunc(g.googleLoginHandler)))
	mux.Handle("/callback", Chain(LoggingMiddleware)(http.HandlerFunc(g.googleOAuthCallbackHandler)))
	return mux
}

func (g *GoogleIDP) googleLoginHandler(w http.ResponseWriter, r *http.Request) {
	url := g.oauthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	logger.Info("Returing redirect", "url", url)
	http.Redirect(w, r, url, http.StatusFound)
}

func (g *GoogleIDP) googleOAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code", http.StatusBadRequest)
		logger.Info("Missing code")
		return
	}

	ctx := context.Background()
	token, err := g.oauthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Fetch user info from Google's userinfo endpoint
	client := g.oauthConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "Userinfo request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var returnedUser struct {
		Email      string `json:"email"`
		Name       string `json:"name"`
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&returnedUser); err != nil {
		http.Error(w, "Failed to decode userinfo: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !slices.Contains(Config.GoogleOAuth.AllowedUsers, returnedUser.Email) {
		http.Redirect(w, r, Config.WebRoot+"/auth/login", http.StatusFound)
		logger.Warn("User not authorized", "user", returnedUser)
		return
	}
	// Create a new session
	sessionID := NewSessionID()
	setSessionCookie(w, sessionID)

	// Store session -> user mapping
	user := GoogleUser{
		IDProvider_: "googleIDP",
		Email:       returnedUser.Email,
		Name:        returnedUser.Name,
		GivenName:   returnedUser.GivenName,
		FamilyName:  returnedUser.FamilyName,
	}
	g.sessionStore.AddSessionEntry(sessionID, NewSessionEntry(user))
	logger.Info("Session created for", "user", returnedUser, "session", sessionID)

	http.Redirect(w, r, g.postAuthenticateTargetURL, http.StatusFound)
}
