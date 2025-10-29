package main

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/davecgh/go-spew/spew"
)

type InternalIDPUser struct {
	IdProvider_ string
	Username    string
}

func (i InternalIDPUser) UserID() string {
	return i.Username
}

func (i InternalIDPUser) IDProvider() string {
	return i.IdProvider_
}

type InternalIDP struct {
	postAuthenticateTargetURL string
	idpRoot                   string
}

func NewInternalIDP(postAuthenticateTargetURL string, idpRoot string) *InternalIDP {
	return &InternalIDP{
		postAuthenticateTargetURL: postAuthenticateTargetURL,
		idpRoot:                   idpRoot,
	}
}

func (i InternalIDP) IDPName() string {
	return "internalIDP"
}

func (i *InternalIDP) ServeMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/Authenticate", Chain(LoggingMiddleware)(i))
	return mux
}

func (i *InternalIDP) LoginPageFragment(w http.ResponseWriter) {
	fmt.Fprintf(w, `Local login<p><form action="`+i.idpRoot+"/"+i.IDPName()+`/Authenticate" method="post">
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
  </form>`)
}

func (i *InternalIDP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
		http.Redirect(w, r, Config.WebRoot+"/auth/login", http.StatusFound)
		logger.WarnContext(ctx, "User not found", "user", username, "password", password)
		return
	}
	sessionID := randomString(32)
	setSessionCookie(w, sessionID)

	// Store session -> user mapping
	user := InternalIDPUser{
		IdProvider_: "internalIDP",
		Username:    username,
	}
	sessions.Add(sessionID, user)
	logger.Info("Session created for", "user", username, "session", sessionID)
	logger.Info("Redirecting to", "URL", i.postAuthenticateTargetURL)
	http.Redirect(w, r, i.postAuthenticateTargetURL, http.StatusFound)
}
