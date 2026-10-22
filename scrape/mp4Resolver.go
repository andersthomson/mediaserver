package scrape

import (
	"fmt"
	"path/filepath"
)

// DashMetadata tracks the definitive outcome of evaluating a movie record.
type MP4Metadata struct {
	HasMP4   bool
	FilePath string
}

type MP4Resolver struct {
	MssCache *MssCache
}

// ResolveMP4State handles all your heavy cache, API, and fetching logic in ONE place.
func (d *MP4Resolver) ResolveMP4State(id string) (MP4Metadata, error) {
	dir, ok := d.MssCache.Dir(id)
	if !ok {
		return MP4Metadata{HasMP4: false}, fmt.Errorf("[MP4Resolver] MssCache has no directory record for id %s", id)
	}
	_, ok = d.MssCache.HasMP4(id)
	if !ok {
		return MP4Metadata{HasMP4: false}, nil
	}

	filePath := filepath.Join(dir, "media.mp4")

	return MP4Metadata{
		HasMP4:   true,
		FilePath: filePath,
	}, nil
}
