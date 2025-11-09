package scrape

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"

	tmdb "github.com/cyruzin/golang-tmdb"
	"golang.org/x/sync/singleflight"
)

var sf singleflight.Group
var tmdbClient *tmdb.Client
var cachePath = "./.tmdb/"
var iso639_1_Order []string

func TmdbInit(apiKey string, cacheDir string, iso639_1_order []string) {
	var err error
	tmdbClient, err = tmdb.InitV4(apiKey)
	if err != nil {
		panic(err)
	}
	tmdbClient.GetBaseURL()
	tmdbClient.SetClientAutoRetry()
	cachePath = cacheDir
	iso639_1_Order = slices.Clone(iso639_1_order)
	os.Mkdir(cachePath, 0700)
}
func DownloadFile(filepath string, url string) error {

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("URL not found %s: Code %d", url, resp.StatusCode)
	}
	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

func TMDBImage(key string, size string) (string, error) {
	fname := fmt.Sprintf("image-%s-%s", size, key)
	res, err, _ := sf.Do(fname, func() (any, error) {
		fnameLong := filepath.Join(cachePath, url.PathEscape(fname))
		if fileExists(fnameLong) {
			return fnameLong, nil
		}
		u := tmdb.GetImageURL(key, size)
		slog.Info("TMDB fetch", "type", "file", "url", u)
		if err := DownloadFile(fnameLong, u); err != nil {
			slog.Error("Download failed", "source", "tmdb", "err", err)
			return "", err
		}
		return fnameLong, nil
	})
	return res.(string), err
}

func TMDBCollectionDetails(id int) (*tmdb.CollectionDetails, error) {
	fname := fmt.Sprintf("Collection-%d", id)
	res, err, _ := sf.Do(fname, func() (any, error) {
		var resp *tmdb.CollectionDetails
		fnameLong := filepath.Join(cachePath, fname)
		body, err := os.ReadFile(fnameLong)
		if err == nil {
			var collection tmdb.CollectionDetails
			err := json.Unmarshal(body, &collection)
			if err != nil {
				return resp, err
			}
			return &collection, nil
		}
		options := map[string]string{
			"language":           "sv-SE",
			"append_to_response": "images,translations",
		}
		slog.Info("TMDB fetch", "type", "CollectionDetails", "id", id)
		resp, err = tmdbClient.GetCollectionDetails(id, options)
		if err != nil {
			return resp, err
		}
		body, err = json.MarshalIndent(resp, "", "    ")
		if err != nil {
			return resp, err
		}
		if os.WriteFile(fnameLong, body, 0644) != nil {
			return resp, err
		}
		return resp, err
	})
	return res.(*tmdb.CollectionDetails), err
}

func TMDBMovieDetails(id int) (*tmdb.MovieDetails, error) {
	fname := fmt.Sprintf("Movie-%d", id)
	res, err, _ := sf.Do(fname, func() (any, error) {
		var resp *tmdb.MovieDetails
		fnameLong := filepath.Join(cachePath, fname)
		body, err := os.ReadFile(fnameLong)
		if err == nil {
			var movie tmdb.MovieDetails
			err := json.Unmarshal(body, &movie)
			if err != nil {
				return resp, err
			}
			return &movie, nil
		}
		options := map[string]string{
			"language":           "sv-SE",
			"append_to_response": "images,translations",
		}
		slog.Info("TMDB fetch", "type", "MovieDetails", "id", id)
		resp, err = tmdbClient.GetMovieDetails(id, options)
		if err != nil {
			return resp, err
		}
		body, err = json.MarshalIndent(resp, "", "    ")
		if err != nil {
			return resp, err
		}
		if os.WriteFile(fnameLong, body, 0644) != nil {
			return resp, err
		}
		return resp, err
	})
	return res.(*tmdb.MovieDetails), err
}

func TMDBTVDetails(id int) (*tmdb.TVDetails, error) {
	fname := fmt.Sprintf("TVDetails-%d", id)
	res, err, _ := sf.Do(fname, func() (any, error) {
		var resp *tmdb.TVDetails
		fnameLong := filepath.Join(cachePath, fname)
		body, err := os.ReadFile(fnameLong)
		if err == nil {
			var tvDetails tmdb.TVDetails
			err := json.Unmarshal(body, &tvDetails)
			if err != nil {
				return resp, err
			}
			return &tvDetails, nil
		}
		options := map[string]string{
			"language":           "sv-SE",
			"append_to_response": "images,translations",
		}
		slog.Info("TMDB fetch", "type", "TVDetails", "id", id)
		resp, err = tmdbClient.GetTVDetails(id, options)
		if err != nil {
			return resp, err
		}
		body, err = json.MarshalIndent(resp, "", "    ")
		if err != nil {
			return resp, err
		}
		if os.WriteFile(fnameLong, body, 0644) != nil {
			return nil, err
		}
		return resp, err
	})
	return res.(*tmdb.TVDetails), err
}

func TMDBTVSeasonDetails(id int, seasonNumber int) (*tmdb.TVSeasonDetails, error) {
	fname := fmt.Sprintf("TVSeasonDetails-%d-%d", id, seasonNumber)
	res, err, _ := sf.Do(fname, func() (any, error) {
		var resp *tmdb.TVSeasonDetails
		fnameLong := filepath.Join(cachePath, fname)
		body, err := os.ReadFile(fnameLong)
		if err == nil {
			var tvSeasonDetails tmdb.TVSeasonDetails
			err := json.Unmarshal(body, &tvSeasonDetails)
			if err != nil {
				return resp, err
			}
			return &tvSeasonDetails, nil
		}
		options := map[string]string{
			"language":           "sv-SE",
			"append_to_response": "images,translations",
		}
		slog.Info("TMDB fetch", "type", "TVSeasonDetails", "id", id, "season", seasonNumber)
		resp, err = tmdbClient.GetTVSeasonDetails(id, seasonNumber, options)
		if err != nil {
			return resp, err
		}
		body, err = json.MarshalIndent(resp, "", "    ")
		if err != nil {
			return resp, err
		}
		if os.WriteFile(fnameLong, body, 0644) != nil {
			return resp, err
		}
		return resp, err
	})
	return res.(*tmdb.TVSeasonDetails), err
}

func TMDBTVEpisodeDetails(id int, seasonNumber int, episodeNumber int) (*tmdb.TVEpisodeDetails, error) {
	fname := fmt.Sprintf("TVEpisodeDetails-%d-%d-%d", id, seasonNumber, episodeNumber)
	res, err, _ := sf.Do(fname, func() (any, error) {
		var resp *tmdb.TVEpisodeDetails
		fnameLong := filepath.Join(cachePath, fname)
		body, err := os.ReadFile(fnameLong)
		if err == nil {
			var tvEpisodeDetails tmdb.TVEpisodeDetails
			err := json.Unmarshal(body, &tvEpisodeDetails)
			if err != nil {
				return resp, err
			}
			return &tvEpisodeDetails, nil
		}
		options := map[string]string{
			"language":           "sv-SE",
			"append_to_response": "images,translations",
		}
		slog.Info("TMDB fetch", "type", "TVEpisodeDetails", "id", id, "season", seasonNumber, "episode", episodeNumber)
		resp, err = tmdbClient.GetTVEpisodeDetails(id, seasonNumber, episodeNumber, options)
		if err != nil {
			return resp, err
		}
		body, err = json.MarshalIndent(resp, "", "    ")
		if err != nil {
			return resp, err
		}
		if os.WriteFile(fnameLong, body, 0644) != nil {
			return resp, err
		}
		return resp, err
	})
	return res.(*tmdb.TVEpisodeDetails), err
}
