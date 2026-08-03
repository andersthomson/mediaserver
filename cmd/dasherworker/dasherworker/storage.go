package dasherworker

import (
	"log/slog"
	"path/filepath"

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
	_, ok := s.items[m.Id] // Check if it exists
	if ok {
		slog.Error("Item ID already exists!!!")
	}
	s.items[m.Id] = struct {
		m   scrape.Msp
		dir string
	}{
		m:   m,
		dir: dir,
	}
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
