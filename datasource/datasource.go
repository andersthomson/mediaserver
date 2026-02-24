package datasource

type DataSource interface {
	ID() string //Gobally unique
	//Title() string
	//OpenMedia() (io.ReadSeekCloser, error)
	//OpenPoster() (io.ReadSeekCloser, error)
}
