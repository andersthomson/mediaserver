package main

import (
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/andersthomson/mediaserver/scrape"
	"github.com/davecgh/go-spew/spew"
)

func indexOfCodecType(ffprobe scrape.FFProbeRoot, ct string) int {
	return slices.IndexFunc(ffprobe.Streams, func(s scrape.FFProbeStream) bool {
		return s.CodecType == ct
	})
}

func videocodec(ffprobe scrape.FFProbeRoot) string {
	idx := indexOfCodecType(ffprobe, "video")
	//fmt.Printf("index %v\n", idx)
	if idx != -1 {
		return fmt.Sprintf("%s/%s (%dx%d)", ffprobe.Streams[idx].CodecName, ffprobe.Streams[idx].Profile, ffprobe.Streams[idx].Width, ffprobe.Streams[idx].Height)
	}
	return ""
}

func audiocodec(ffprobe scrape.FFProbeRoot) string {
	//fmt.Printf("index %v\n", idx)
	res := make([]string, 0, 4)
	for _, strm := range ffprobe.Streams {
		if strm.CodecType != "audio" {
			continue
		}
		res = append(res, fmt.Sprintf("%s/%s (%d/%s)", strm.CodecName, strm.Profile, strm.Channels, strm.ChannelLayout))
	}
	return strings.Join(res, " ; ")
}

func tmdbMovie(ffprobe scrape.FFProbeRoot) string {
	return ffprobe.Format.Tags.TmdbMovie
}

func tmdbSeries(ffprobe scrape.FFProbeRoot) string {
	res := make([]string, 0, 3)
	if ffprobe.Format.Tags.TmdbSeries != "" {
		res = append(res, ffprobe.Format.Tags.TmdbSeries)
	}
	if ffprobe.Format.Tags.Season != "" {
		res = append(res, ffprobe.Format.Tags.Season)
	}
	if ffprobe.Format.Tags.Episode_id != "" {
		res = append(res, ffprobe.Format.Tags.Episode_id)
	}
	if len(res) > 0 {
		return fmt.Sprintf("(%s)", strings.Join(res, ","))
	}
	return ""
}

var doVideo bool
var doAudio bool
var doDump bool
var doTmdbMovie bool
var doTmdbSeries bool

func main() {
	flag.BoolVar(&doVideo, "video", true, "Dump video codec")
	flag.BoolVar(&doAudio, "audio", true, "Dump audio codec")
	flag.BoolVar(&doDump, "dump", false, "Dump ffprobe output")
	flag.BoolVar(&doTmdbMovie, "movie", true, "Dump tmdb movie id")
	flag.BoolVar(&doTmdbSeries, "series", true, "Dump tmdb series/season/episode ids")
	flag.Parse()
	for _, fname := range flag.Args() {
		ffprobe, err := scrape.FFProbe(fname)
		if err != nil {
			panic(err)
		}
		//spew.Dump(ffprobe)
		if doTmdbMovie {
			fmt.Printf(tmdbMovie(ffprobe) + "\t")
		}
		if doTmdbSeries {
			fmt.Printf(tmdbSeries(ffprobe) + "\t")
		}
		if doVideo {
			fmt.Printf(videocodec(ffprobe) + "\t")
		}
		if doAudio {
			fmt.Printf(audiocodec(ffprobe) + "\t")
		}
		if doDump {
			spew.Dump(ffprobe)
		}
		fmt.Printf(fname + "\n")
	}
}
