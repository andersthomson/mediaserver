package scrape

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	tmdb "github.com/cyruzin/golang-tmdb"
	"golang.org/x/sync/singleflight"
)

func TmdbInit(apiKey string, cacheDir string) (*tmdb.Client, error) {
	tmdbClient, err := tmdb.InitV4(apiKey)
	if err != nil {
		panic(err)
	}
	dialer := &net.Dialer{
		// A negative value or 1ms forces the dialer to start IPv4
		// almost immediately after IPv6.
		FallbackDelay: -1 * time.Millisecond,
		Timeout:       30 * time.Second,
		KeepAlive:     30 * time.Second,
	}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	httpclient := http.Client{
		Transport: transport,
	}
	tmdbClient.SetClientConfig(httpclient)
	tmdbClient.GetBaseURL()
	tmdbClient.SetClientAutoRetry()
	return tmdbClient, nil
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
func fileExists(fname string) bool {
	_, err := os.Stat(fname)
	return err == nil
}

type TmdbCache struct {
	sf     singleflight.Group
	Client *tmdb.Client
	Path   string
}

func (t *TmdbCache) Image(key string, size string) (string, error) {
	fname := fmt.Sprintf("image-%s-%s", size, key)
	res, err, _ := t.sf.Do(fname, func() (any, error) {
		fnameLong := filepath.Join(t.Path, url.PathEscape(fname))
		if fileExists(fnameLong) {
			return fnameLong, nil
		}
		u := tmdb.GetImageURL(key, size)
		slog.Info("TMDB fetch", "type", "file", "url", u, "key", key, "size", size)
		if err := os.Mkdir(t.Path, 0700); err != nil {
			return nil, fmt.Errorf("Failed to create cache dir. dir=%s err=%w", t.Path, err)
		}
		if err := DownloadFile(fnameLong, u); err != nil {
			slog.Error("Download failed", "source", "tmdb", "err", err)
			return "", err
		}
		return fnameLong, nil
	})
	return res.(string), err
}

func (t *TmdbCache) CollectionDetails(id CollectionID) (*tmdb.CollectionDetails, error) {
	fname := fmt.Sprintf("Collection-%d", id)
	res, err, _ := t.sf.Do(fname, func() (any, error) {
		var resp *tmdb.CollectionDetails
		fnameLong := filepath.Join(t.Path, fname)
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
		resp, err = t.Client.GetCollectionDetails(int(id), options)
		if err != nil {
			return resp, err
		}
		body, err = json.MarshalIndent(resp, "", "    ")
		if err != nil {
			return resp, err
		}
		if err := os.Mkdir(t.Path, 0700); err != nil {
			return nil, fmt.Errorf("Failed to create cache dir. dir=%s err=%w", t.Path, err)
		}
		if os.WriteFile(fnameLong, body, 0644) != nil {
			return resp, err
		}
		return resp, err
	})
	return res.(*tmdb.CollectionDetails), err
}

func (t *TmdbCache) MovieDetails(id MovieID) (*tmdb.MovieDetails, error) {
	fname := fmt.Sprintf("Movie-%d", id)
	res, err, _ := t.sf.Do(fname, func() (any, error) {
		var resp *tmdb.MovieDetails
		fnameLong := filepath.Join(t.Path, fname)
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
		resp, err = t.Client.GetMovieDetails(int(id), options)
		if err != nil {
			return resp, err
		}
		body, err = json.MarshalIndent(resp, "", "    ")
		if err != nil {
			return resp, err
		}
		if err := os.Mkdir(t.Path, 0700); err != nil {
			return nil, fmt.Errorf("Failed to create cache dir. dir=%s err=%w", t.Path, err)
		}
		if os.WriteFile(fnameLong, body, 0644) != nil {
			return resp, err
		}
		return resp, err
	})
	return res.(*tmdb.MovieDetails), err
}

func (t *TmdbCache) TVDetails(id int) (*tmdb.TVDetails, error) {
	fname := fmt.Sprintf("TVDetails-%d", id)
	res, err, _ := t.sf.Do(fname, func() (any, error) {
		var resp *tmdb.TVDetails
		fnameLong := filepath.Join(t.Path, fname)
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
		resp, err = t.Client.GetTVDetails(id, options)
		if err != nil {
			return resp, err
		}
		body, err = json.MarshalIndent(resp, "", "    ")
		if err != nil {
			return resp, err
		}
		if err := os.Mkdir(t.Path, 0700); err != nil {
			return nil, fmt.Errorf("Failed to create cache dir. dir=%s err=%w", t.Path, err)
		}
		if os.WriteFile(fnameLong, body, 0644) != nil {
			return nil, err
		}
		return resp, err
	})
	return res.(*tmdb.TVDetails), err
}

func (t *TmdbCache) TVSeasonDetails(id int, seasonNumber int) (*tmdb.TVSeasonDetails, error) {
	fname := fmt.Sprintf("TVSeasonDetails-%d-%d", id, seasonNumber)
	res, err, _ := t.sf.Do(fname, func() (any, error) {
		var resp *tmdb.TVSeasonDetails
		fnameLong := filepath.Join(t.Path, fname)
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
		resp, err = t.Client.GetTVSeasonDetails(id, seasonNumber, options)
		if err != nil {
			return resp, err
		}
		body, err = json.MarshalIndent(resp, "", "    ")
		if err != nil {
			return resp, err
		}
		if err := os.Mkdir(t.Path, 0700); err != nil {
			return nil, fmt.Errorf("Failed to create cache dir. dir=%s err=%w", t.Path, err)
		}
		if os.WriteFile(fnameLong, body, 0644) != nil {
			return resp, err
		}
		return resp, err
	})
	return res.(*tmdb.TVSeasonDetails), err
}

func (t *TmdbCache) TVEpisodeDetails(id int, seasonNumber int, episodeNumber int) (*tmdb.TVEpisodeDetails, error) {
	fname := fmt.Sprintf("TVEpisodeDetails-%d-%d-%d", id, seasonNumber, episodeNumber)
	res, err, _ := t.sf.Do(fname, func() (any, error) {
		var resp *tmdb.TVEpisodeDetails
		fnameLong := filepath.Join(t.Path, fname)
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
		resp, err = t.Client.GetTVEpisodeDetails(id, seasonNumber, episodeNumber, options)
		if err != nil {
			return resp, err
		}
		body, err = json.MarshalIndent(resp, "", "    ")
		if err != nil {
			return resp, err
		}
		if err := os.Mkdir(t.Path, 0700); err != nil {
			return nil, fmt.Errorf("Failed to create cache dir. dir=%s err=%w", t.Path, err)
		}
		if os.WriteFile(fnameLong, body, 0644) != nil {
			return resp, err
		}
		return resp, err
	})
	return res.(*tmdb.TVEpisodeDetails), err
}
