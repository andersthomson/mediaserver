package scrape

import (
	"os"

	"github.com/BurntSushi/toml"
	"github.com/andersthomson/mediaserver/datasource"
)

func readMspFromFile(f string) (Msp, error) {
	buf, err := os.ReadFile(f)
	if err != nil {
		return Msp{}, err
	}
	var res Msp
	_, err = toml.Decode(string(buf), &res)
	if err != nil {
		return Msp{}, err
	}
	return res, nil
}

func DataSourceFromMsp(caches []string, dir string, fname string) datasource.DataSource {
	m, err := readMspFromFile(dir + "/" + fname)
	if err != nil {
		Logger.Error("Parsing error", "file", dir+"/"+fname, "error", err)
		return nil
	}
	_ = m
	if m.Tmdb.MovieId != nil {
		if d, ok := TMDBMovieFromMsp(caches, m, dir); ok {
			return d
		}
	}
	return nil
}
