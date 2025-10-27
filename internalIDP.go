package main

import (
	"net/http"
	"slices"
	"time"

	"github.com/davecgh/go-spew/spew"
)

type InternalIDPUser struct {
	IdProvider_ string
	Username    string
	LastUsed    time.Time
}

func (i InternalIDPUser) UserID() string {
	return i.Username
}

func (i InternalIDPUser) IDProvider() string {
	return i.IdProvider_
}

type internalIDP struct {
}

func (_ internalIDP) loginPage(postPath string) string {
	return `Local login<p><form action="` + postPath + `" method="post">
    <label for="username">Username:</label>
    <input
      type="text"
      id="username"
      name="username"
      autocomplete="username"
      required
    />
    <br>
    <label for="password">Password:</label>
    <input
      type="password"
      id="password"
      name="password"
      autocomplete="current-password"
      required
    />
    <br><br>

    <button type="submit">Log In</button>
  </form>`
}

func (_ internalIDP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	spew.Dump(r)
	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")
	ctx := r.Context()
	u := InternalIDPAccount{
		Username: username,
		Password: password,
	}
	if !slices.Contains(Config.InternalIDP, u) {
		LoginPage(w, r)
		logger.WarnContext(ctx, "User not found", "user", username, "password", password)
		return
	}
	sessionID := randomString(32)
	setSessionCookie(w, sessionID)

	// Store session -> user mapping
	user := InternalIDPUser{
		IdProvider_: "internalIDP",
		Username:    username,
		LastUsed:    time.Now(),
	}
	sessions.Add(sessionID, user)
	logger.Info("Session created for", "user", username, "session", sessionID)
	http.Redirect(w, r, Config.WebRoot, http.StatusFound)
}
