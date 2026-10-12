package scrape

type StreamAsset struct {
	id        string
	shortName string
	TmdbView
}

func (s StreamAsset) ID() string {
	return s.id
}

func (s StreamAsset) ShortName() string {
	return s.shortName
}

func (s StreamAsset) PrettyID() string {
	return s.ShortName() + "-" + s.ID()
}

func StreamAssetFromMss(streamDir string, m Mss) (*StreamAsset, bool) {
	res := &StreamAsset{}
	res.id = m.Id
	res.shortName = m.ShortName

	res.MovieId = m.Tmdb.MovieId

	return res, true
}
