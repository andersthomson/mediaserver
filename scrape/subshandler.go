package scrape

import (
	"fmt"
	"io"
	"os"
)

type OpenSubser interface {
	OpenSubs() (io.ReadSeekCloser, error)
}
type Subshandler interface {
	OpenSubser
}

type SubsFileHandler struct {
	Filename string
}

func (s SubsFileHandler) OpenSubs() (io.ReadSeekCloser, error) {
	x, err := os.Open(s.Filename)
	if err != nil {
		return nil, fmt.Errorf("open of %s failed: %w", s.Filename, err)
	}
	return x, nil
}
