package scrape

type Mss struct {
	Id        string
	ShortName string
	Playouts  Playouts
	Tmdb      *Tmdb `json:",omitempty"`
}
type Playouts struct {
	HasDASHManifest bool
	HasHLSMaster    bool
	HasMP4          bool
}

type Tmdb struct {
	MovieId  *int `json:",omitempty"`
	SeriesId *int `json:",omitempty"`
	Season   *int `json:",omitempty"`
	Episode  *int `json:",omitempty"`
}
