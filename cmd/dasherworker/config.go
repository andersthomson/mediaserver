package main

import (
	"os"

	"github.com/BurntSushi/toml"
)

type worker struct {
	Hostname string
	Port     int
	Username string
	Dir      string
	Ffmpeg   string
	Id       string
}

type config struct {
	Remotes []worker
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
