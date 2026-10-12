package scrape

import (
	"fmt"
	"path/filepath"
)

// DashMetadata tracks the definitive outcome of evaluating a movie record.
type DashMetadata struct {
	HasDash      bool
	ManifestPath string
}

type DashResolver struct {
	MssCache *MssCache
}

// ResolveDashState handles all your heavy cache, API, and fetching logic in ONE place.
func (d *DashResolver) ResolveDashState(id string) (DashMetadata, error) {
	dir, ok := d.MssCache.Dir(id)
	if !ok {
		return DashMetadata{HasDash: false}, fmt.Errorf("[DashResolver] MssCache has no directory record for id %s", id)
	}
	_, ok = d.MssCache.HasDashManifest(id)
	if !ok {
		return DashMetadata{HasDash: false}, nil
	}

	manifestPath := filepath.Join(dir, "manifest.mmpd")

	return DashMetadata{
		HasDash:      true,
		ManifestPath: manifestPath,
	}, nil
}
