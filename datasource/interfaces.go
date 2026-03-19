package datasource

import (
	"io"
)

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

type Genreser interface {
	Genres() []string
}

func GenresOrZero(x any) []string {
	if xT, ok := x.(Genreser); ok {
		return xT.Genres()
	}
	return []string{}
}

type Tagliner interface {
	Tagline() string
}

func TaglineOrZero(x any) string {
	if xT, ok := x.(Tagliner); ok {
		return xT.Tagline()
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

type Languager interface {
	Language() string
}

func LanguageOrZero(x any) string {
	if xT, ok := x.(Languager); ok {
		return xT.Language()
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

type PosterURLPather interface {
	PosterURLPath() string
}

func PosterURLPathOrZero(x any) string {
	if xT, ok := x.(PosterURLPather); ok {
		return xT.PosterURLPath()
	}
	return ""
}

type MediaURLPather interface {
	MediaURLPath() string
}

func MediaURLPathOrZero(x any) string {
	if xT, ok := x.(MediaURLPather); ok {
		return xT.MediaURLPath()
	}
	return ""
}

type BackdropURLPather interface {
	BackdropURLPath() string
}

func BackdropURLPathOrZero(x any) string {
	if xT, ok := x.(BackdropURLPather); ok {
		return xT.BackdropURLPath()
	}
	return ""
}

type Subs struct {
	Language    string
	URLPathFrag string
}
type SubsSlicer interface {
	SubsSlice() []Subs
}

func SubsSliceOrZero(x any) []Subs {
	if xT, ok := x.(SubsSlicer); ok {
		return xT.SubsSlice()
	}
	return []Subs{}
}
