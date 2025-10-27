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
	WebRoot     string
	Tmdb        Tmdb
	Directories []Directory
	GoogleOAuth GoogleOAuth
	InternalIDP []InternalIDPAccount
	IDProviders []string
}

func (c *config) ReadFromFile(f string) {
	buf, err := os.ReadFile(f)
	if err != nil {
		slog.Info("Using DefaultConfig. Failed to read configfile", "filename", f, "error", err)
		*c = DefaultConfig
		return
	}
	if err := json.Unmarshal(buf, c); err != nil {
		panic(err)
	}
}

var DefaultConfig = config{
	WebRoot: "https://example.com/mymeda",
	Directories: []Directory{
		Directory{
			Name:      "dvd",
			Recursive: false,
		}},
}
