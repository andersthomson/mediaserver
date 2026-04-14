package datasource

type DataSource interface {
	ID() string       //Gobally unique
	PrettyID() string // Readable (short) name and globally unique
	//Title() string
	//OpenMedia() (io.ReadSeekCloser, error)
	//OpenPoster() (io.ReadSeekCloser, error)
}
