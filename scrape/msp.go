package scrape

import (
	"fmt"
)

type Msp struct {
	Version   int
	Id        string
	ShortName string
	Tmdb      TmdbT
	Inputs    []InputT
	InStreams []InStreamsT
	Dash      DashT
	Audio     Audio
}

type Msp3 struct {
	Version   int
	Id        string
	ShortName string
	Tmdb      TmdbT
	Inputs    []InputT3
	Dash      DashT3
}

type InputT3 struct {
	FileName string
	Streams  []StreamsT3
}

type StreamsT3 struct {
	Kind     string
	Language string
}

type DashT3 struct {
	Profile string
}

type TmdbT struct {
	MovieId  *int
	SeriesId *int
	Season   *int
	Episode  *int
}

type InStreamsT struct {
	Filename string
	Stream   string // "v:1" (ffprobe notation)
	Video    *VideoT
	Audio    *AudioT
}

type VideoT struct {
	Kind     string
	Language string
}

type AudioT struct {
	Language string
}

type InputT struct {
	Filename   string
	Interlaced bool
	Kind       string
	Language   string
}

type DashT struct {
	Subtitles []SubsT
	Streams   []StreamT
}

type Audio struct {
	Language string
}
type StreamT struct {
	ReferenceFile int    //zero based index of the input file used as ref (used as-is for a dash representation)
	Source        string // ffmpeg format
	Language      string // 3 letters
	Codec         string // "x264", "x265" or the sentinels "reference" to create a symlink to the source
	Profile       string // if Codec calls for encoding
	Tune          string
}

type SubsT struct {
	Language      string
	ReferenceFile int
}

func (t *TmdbT) UnmarshalTOML(in interface{}) error {
	m, ok := in.(map[string]any)
	if !ok {
		return fmt.Errorf("TmdbT unmarshal failed. Not a map[striing]any, is a %T", in)
	}
	if MovieId, ok := m["MovieId"]; ok {
		if len(m) != 1 {
			return fmt.Errorf("Inconsistent tmdb struct: %v", m)
		}
		i64, ok := MovieId.(int64)
		if !ok {
			return fmt.Errorf("Tmdb struct's MovieId %v is not an int64. Is %T", MovieId, MovieId)
		}
		i := int(i64)
		t.MovieId = &i
		return nil
	}
	if SeriesId, ok := m["SeriesId"]; ok {
		if len(m) != 3 {
			return fmt.Errorf("Inconsistent tmdb struct. SeriesId requires in total 3 entries. Has: %v", m)
		}
		SeriesId_i64, ok := SeriesId.(int64)
		if !ok {
			return fmt.Errorf("Tmdb struct's SeriesId %v is not an int64. Is %T", SeriesId, SeriesId)
		}
		SeriesId_i := int(SeriesId_i64)

		Season, ok := m["Season"]
		if !ok {
			return fmt.Errorf("Tmdb table for SeriesId misses a Season entry. Has: %v", in)
		}
		Season_i, ok := Season.(int)
		if !ok {
			fmt.Errorf("Tmdb struct's SeasonId %v is not an int. Is %T", Season, Season)
		}

		Episode, ok := m["Episode"]
		if !ok {
			return fmt.Errorf("Tmdb table for SeriesId misses an Episode entry. Has: %v", in)
		}
		Episode_i, ok := Episode.(int)
		if !ok {
			fmt.Errorf("Tmdb struct's EpisodeId %v is not an int. Is %T", Episode, Episode)
		}
		t.SeriesId = &SeriesId_i
		t.Season = &Season_i
		t.Episode = &Episode_i
		return nil
	}
	return fmt.Errorf("Inconsistent tmdb struct: %v", m)
}
