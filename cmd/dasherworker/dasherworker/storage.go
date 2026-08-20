package dasherworker

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/andersthomson/mediaserver/scrape"
	"go.temporal.io/sdk/workflow"
)

type Storage struct {
	items map[string]struct {
		m   scrape.Msp
		dir string
	}
}

var storage *Storage

func newStorage() *Storage {
	s := &Storage{}
	s.items = make(map[string]struct {
		m   scrape.Msp
		dir string
	})
	return s
}
func init() {
	storage = newStorage()
}

func (s *Storage) Add(dir string, m scrape.Msp) {
	old, ok := s.items[m.Id] // Check if it exists
	if ok {
		if !reflect.DeepEqual(old, m) {
			slog.Error("Storage: Loading a new item with an EXISTING id!!!", "old", old, "new", m)
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
		slog.Info("Considering", "entry", path)
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
			// Process the file. You can pass ctx down if parseJSONFile is slow/networked.
			slog.Info("Adding", "path", path)
			M, err := ReadMspFile(ctx, filepath.Dir(path), d.Name())
			if err != nil {
				return err
			}
			s.Add(d.Name(), M)
			slog.Info("Adding", "path", path, "done", 0)
		}
		return nil
	})

	return err
}

func StorageAddWF(ctx workflow.Context, mspPath string) (string, error) {
	M, err := CallReadMspFile(ctx, mspPath)
	if err != nil {
		return "", err
	}
	storage.Add(filepath.Dir(mspPath), M)
	return "", nil
}

// id is the uuid
func (s *Storage) ResolveInput(id string) (string, scrape.Msp) { //dir,msp
	x, ok := s.items[id]
	if !ok {
		slog.Error("Item does not exist", "id", id)
	}
	return x.dir, x.m
}

func (s *Storage) ResolveInputNumber(id string, number int) string {
	dir, m := s.ResolveInput(id)
	return filepath.Join(dir, m.Inputs[number].Filename)
}

func (s *Storage) ProdDir(id string) string {
	x, ok := s.items[id]
	//spew.Dump(s)
	if !ok {
		slog.Error("Item does not exist", "id", id)
	}
	return "/var/cache/mediacache/" + x.m.ShortName + "-" + x.m.Id + "/dash"
}
func (s *Storage) TranscodedRepresentationFilePath(args EncodeStreamArgs) string {
	return filepath.Join(s.ProdDir(args.InputID), representation(args)+"-transcoded.mp4")
}

func (s *Storage) DasherReadyRepresentationManifestFilePath(args EncodeStreamArgs) string {
	return filepath.Join(s.ProdDir(args.InputID), representation(args)+"-manifest.mpd")
}

func (s *Storage) DasherReadyRepresentationFilePath(args EncodeStreamArgs) string {
	return filepath.Join(s.ProdDir(args.InputID), representation(args)+".mp4")
}

func (s *Storage) DasherReadyRepresentationTranscodingLogFilePath(args EncodeStreamArgs) string {
	return filepath.Join(s.ProdDir(args.InputID), representation(args)+".mp4.transcodinglog")
}
