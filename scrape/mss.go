package scrape

type Playouts struct {
	HasDASHManifest bool
	HasHLSMaster bool
}

type Tmdb struct {
	MovieId *int
}
type Mss struct {
	Id string
	ShortName string
	Playouts Playouts
	Tmdb *Tmdb
}
