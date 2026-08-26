package shared

import (
	"strconv"
)

type EncodeStreamArgs struct {
	InputID  string
	InputNo  int
	Stream   string //ffprobe y:z string
	Kind     string
	Language string

	Preset       Preset
	Profile      string
	Codec        string
	VideoFilters VideoFilterSettings

	DstProps CommonProperties
}

type Preset string

func (p Preset) String() string {
	return string(p)
}

type Resolution struct {
	Width  int
	Height int
}

func (r Resolution) String() string {
	return strconv.Itoa(r.Width) + "x" + strconv.Itoa(r.Height)
}

// Common industry standard clamps
var (
	Max480p  = Resolution{Width: 854, Height: 480}
	Max720p  = Resolution{Width: 1280, Height: 720}
	Max1080p = Resolution{Width: 1920, Height: 1080}
	Max4K    = Resolution{Width: 3840, Height: 2160}
)

type VideoFilterSettings struct {
	MaxResolution Resolution
}

// Return an string uniquely representing this representation
type CommonProperties struct {
	GopFrames int
	DashMs    string
}
