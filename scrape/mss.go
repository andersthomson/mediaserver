package scrape

import "sync"

type Playouts struct {
	HasDASHManifest bool
	HasHLSMaster    bool
}

type Tmdb struct {
	MovieId  *int `json:",omitempty"`
	SeriesId *int `json:",omitempty"`
	Season   *int `json:",omitempty"`
	Episode  *int `json:",omitempty"`
}
type Mss struct {
	Id        string
	ShortName string
	Playouts  Playouts
	Tmdb      *Tmdb `json:",omitempty"`
}

type MssCache struct {
	m      map[string]Mss
	mssDir string
	sync.Mutex
}

func NewMssCache() *MssCache {
	return &MssCache{
		m: make(map[string]Mss, 64),
	}
}

func (m *MssCache) Add(dir string, mss Mss) {
	m.Lock()
	m.m[mss.Id] = mss
	m.mssDir = dir
	m.Unlock()
}

func (m *MssCache) MovieId(id string) (int, bool) {
	m.Lock()
	defer m.Unlock()
	itm, ok := m.m[id]
	if !ok {
		return 0, false
	}
	if itm.Tmdb == nil {
		return 0, false
	}
	if itm.Tmdb.MovieId == nil {
		return 0, false
	}
	return *itm.Tmdb.MovieId, true
}
