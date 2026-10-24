package main

import (
	"encoding/json"
	"log/slog"
	"os"
)

type Directory struct {
	Name      string
	Recursive bool
	Method    string
}
type Tmdb struct {
	ApiKey       string
	CacheDir     string
	Iso6391Order []string
}
type GoogleOAuth struct {
	ClientID     string
	ClientSecret string
	AllowedUsers []string
}

type InternalIDPAccount struct {
	Username string
	Password string
}

type config struct {
	WebRoot       string
	Port          int32
	IP_Address    string
	Tmdb          Tmdb
	Directories   []Directory
	Caches        []string
	GoogleOAuth   GoogleOAuth
	InternalIDP   []InternalIDPAccount
	IDProviders   []string
	MaxSessionAge string
	SessionFile   string
}

func ReadConfigFromFile(f string) (*config, error) {
	buf, err := os.ReadFile(f)
	if err != nil {
		slog.Info("Using DefaultConfig. Failed to read configfile", "filename", f, "error", err)
		return &DefaultConfig, nil
	}
	var c config
	if err := json.Unmarshal(buf, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

var DefaultConfig = config{
	WebRoot: "https://example.com/mymeda",
	Directories: []Directory{
		Directory{
			Name:      "dvd",
			Recursive: false,
		}},
}
