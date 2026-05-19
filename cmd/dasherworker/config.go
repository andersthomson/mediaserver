package main

import (
	"os"

	"github.com/BurntSushi/toml"
)

type remoteworker struct {
	Start    bool
	Name     string
	Hostname string
	Port     int
	Username string
	Dir      string
	Ffmpeg   string
	Id       string
}

type localworker struct {
	Start bool
}

type config struct {
	Remotes []remoteworker
	Local   localworker
}

func ReadConfigFromFile(f string) (config, error) {
	buf, err := os.ReadFile(f)
	if err != nil {
		return config{}, err
	}
	var res config
	_, err = toml.Decode(string(buf), &res)
	if err != nil {
		return config{}, err
	}
	return res, nil
}
