package storage

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/mspreader"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
	"github.com/andersthomson/mediaserver/scrape"
)

type Storage struct {
	m     sync.RWMutex
	items map[string]struct {
		m   scrape.Msp
		dir string
	}
}

func New() *Storage {
	s := &Storage{}
	s.items = make(map[string]struct {
		m   scrape.Msp
		dir string
	})
	return s
}

func (s *Storage) add(dir string, m scrape.Msp) {
	s.m.Lock()
	defer s.m.Unlock()
	old, ok := s.items[m.Id] // Check if it exists
	if ok {
		if !reflect.DeepEqual(old.m, m) || old.dir != dir {
			slog.Error("Storage: Loading a new item with an EXISTING id!!!", "old", old.m, "new", m, "olddir", old.dir, "newdir", dir)
		} else {
			slog.Info("Storage: Reloading item", "id", m.Id, "shortname", m.ShortName)
		}
	}
	s.items[m.Id] = struct {
		m   scrape.Msp
		dir string
	}{
		m:   m,
		dir: dir,
	}
}

func (s *Storage) AddMspsFromTree(ctx context.Context, root string) error {
	suffix := "msp"
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		//slog.Info("Considering", "entry", path)
		// 1. Check if the context was cancelled before processing the next entry
		if err := ctx.Err(); err != nil {
			return err
		}

		// Handle directory read errors (like lost+found Permission Denied)
		if err != nil {
			if os.IsPermission(err) {
				slog.Warn("Skipping directory due to permission denied", "path", path)
				return filepath.SkipDir // Tells Go to skip this folder and keep going
			}
			return err // Return other critical system errors
		}

		// 2. Filter for files matching the suffix
		if !d.IsDir() && strings.HasSuffix(d.Name(), suffix) {
			M, err := mspreader.Read(ctx, filepath.Dir(path), d.Name())
			if err != nil {
				return err
			}
			s.add(filepath.Dir(path), M)
		}
		return nil
	})
	return err
}

// id is the uuid
func (s *Storage) ResolveInput(id string) (string, scrape.Msp) { //dir,msp
	s.m.RLock()
	x, ok := s.items[id]
	s.m.RUnlock()
	if !ok {
		slog.Info("Lazy load of item", "id", id)
		if err := s.AddMspsFromTree(context.TODO(), "/var/lib/media/"); err != nil {
			slog.Error("FATAL: Failed to load MSP tree", "err", err)
		}
		//Now check again
		s.m.RLock()
		x, ok := s.items[id]
		s.m.RUnlock()
		if ok {
			return x.dir, x.m
		}
		slog.Error("The freshly fetched tree did not have the item", "id", id)
		return "", scrape.Msp{}
	}
	return x.dir, x.m
}
func (s *Storage) ResolveInputNumber(id string, number int) string {
	dir, m := s.ResolveInput(id)
	return filepath.Join(dir, m.Inputs[number].Filename)
}

func (s *Storage) ProdDir(id string) string {
	s.m.RLock()
	x, ok := s.items[id]
	s.m.RUnlock()
	//spew.Dump(s)
	if !ok {
		if err := s.AddMspsFromTree(context.TODO(), "/var/lib/media/"); err != nil {
			slog.Error("FATAL: Failed to load MSP tree", "err", err)
		}
		s.m.RLock()
		x, ok := s.items[id]
		s.m.RUnlock()
		//spew.Dump(s)
		if ok {
			return "/var/cache/mediacache/" + x.m.ShortName + "-" + x.m.Id + "/dash"
		}
		return "ERROR IN LOOKUP OF PRODDIR"
	}
	return "/var/cache/mediacache/" + x.m.ShortName + "-" + x.m.Id + "/dash"
}

func (s *Storage) DasherReadyRepresentationTranscodingLogFilePath(args shared.EncodeStreamArgs) string {
	return filepath.Join(s.ProdDir(args.InputID), representation(args)+".mp4.transcodinglog")
}

func (s *Storage) DasherReadyRepresentationFilePath(args shared.EncodeStreamArgs) string {
	return filepath.Join(s.ProdDir(args.InputID), representation(args)+".mp4")
}
func (s *Storage) TranscodedRepresentationFilePath(args shared.EncodeStreamArgs) string {
	return filepath.Join(s.ProdDir(args.InputID), representation(args)+"-transcoded.mp4")
}

func (s *Storage) DasherReadyRepresentationManifestFilePath(args shared.EncodeStreamArgs) string {
	return filepath.Join(s.ProdDir(args.InputID), representation(args)+"-manifest.mpd")
}

// Interface to WFs
type ResolveInputResp struct {
	Dir string
	M   scrape.Msp
}

// Return an string uniquely representing this representation
func representation(args shared.EncodeStreamArgs) string {
	if shared.IsVideoCodec(args.Codec) {
		return fmt.Sprintf("%s-%s-%s", args.Codec, args.VideoFilters.MaxResolution, args.Profile)
	} else {
		return fmt.Sprintf("%s", args.Codec)
	}
}
