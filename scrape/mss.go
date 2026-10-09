package scrape

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
