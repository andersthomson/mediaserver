package datasource

import "io"

type OpenBackdroper interface {
	OpenBackdrop() (io.ReadSeekCloser, error)
}

type Titler interface {
	Title() string
}

func TitleOrZero(x any) string {
	if xT, ok := x.(Titler); ok {
		return xT.Title()
	}
	return ""
}

type Overviewer interface {
	Overview() string
}

func OverviewOrZero(x any) string {
	if xT, ok := x.(Overviewer); ok {
		return xT.Overview()
	}
	return ""
}

type Ploter interface {
	Plot() string
}

func PlotOrZero(x any) string {
	if xT, ok := x.(Ploter); ok {
		return xT.Plot()
	}
	return ""
}
