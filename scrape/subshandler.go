package scrape

import (
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	iso639_3 "github.com/barbashov/iso639-3"
)

type SubsFileHandlerser interface {
	SubsFileHandlers() []SubsFileHandler
}

type SubsFileHandlerSlice []SubsFileHandler

func (s SubsFileHandlerSlice) SubsFileHandlers() []SubsFileHandler {
	return s
}

var _ SubsFileHandlerser = SubsFileHandlerSlice{}

func NewSubsFileHandlers(dir string, fname string) SubsFileHandlerSlice {
	res := []SubsFileHandler{}
	basename := strings.TrimSuffix(fname, ".mp4")
	for _, code := range slices.Sorted(maps.Keys(iso639_3.LanguagesPart1)) {
		targetFname := filepath.Join(dir, basename+"-subtitles_"+code+".vtt")
		if !fileExists(targetFname) {
			continue
		}
		res = append(res, SubsFileHandler{
			Filename: targetFname,
			Language: code,
		})
	}
	return res
}

type SubsFileHandler struct {
	Filename string
	Language string //iso639-1 code ("en" "sv" etc)
}

func (s SubsFileHandler) OpenSubs() (io.ReadSeekCloser, error) {
	x, err := os.Open(s.Filename)
	if err != nil {
		return nil, fmt.Errorf("open of %s failed: %w", s.Filename, err)
	}
	return x, nil
}
