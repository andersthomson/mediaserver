package main

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"slices"

	"golang.org/x/oauth2"
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

func googleLoginHandler(w http.ResponseWriter, r *http.Request) {
	url := oauthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func googleOAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
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

	var googleUser struct {
		Email      string `json:"email"`
		Name       string `json:"name"`
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		http.Error(w, "Failed to decode userinfo: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !slices.Contains(Config.GoogleOAuth.AllowedUsers, googleUser.Email) {
		LoginPage(w, r)
		logger.Warn("User not authorized", "user", googleUser)
		return
	}
	// Create a new session
	sessionID := randomString(32)
	setSessionCookie(w, sessionID)

	// Store session -> user mapping
	user := GoogleUser{
		IDProvider_: "googleIDP",
		Email:       googleUser.Email,
		Name:        googleUser.Name,
		GivenName:   googleUser.GivenName,
		FamilyName:  googleUser.FamilyName,
	}
	sessions.Add(sessionID, user)
	logger.Info("Session created for", "user", googleUser, "session", sessionID)

	http.Redirect(w, r, Config.WebRoot, http.StatusFound)
}
