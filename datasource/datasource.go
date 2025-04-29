package datasource

import "io"

type DataSource interface {
	ID() string //Gobally unique
	//Title() string
	OpenMedia() (io.ReadSeekCloser, error)
	OpenSubs() (io.ReadSeekCloser, error)
	OpenPoster() (io.ReadSeekCloser, error)
}
