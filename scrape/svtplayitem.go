package scrape

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type svtplayItem struct {
	ID_           string
	Title_        string
	EpisodeTitle_ string
	Media         string
	SubsFile      string
	PosterFile_   string
	PlotFile_     string
	PlotString    string
	Episode_      int
	Season_       int
	Tags_         map[string][]string
}

func (_ svtplayItem) deriveID(fname string) string {
	return fname
}
func (s svtplayItem) OpenMedia() (io.ReadSeekCloser, error) {
	x, err := os.Open(s.Media)
	return x, err
}

func (s svtplayItem) Title() string {
	return s.Title_
}

func (s svtplayItem) Tags() map[string][]string {
	return s.Tags_
}

func (s svtplayItem) EpisodeTitle() string {
	return s.EpisodeTitle_
}

func (s svtplayItem) ID() string {
	return s.ID_
}

func (s svtplayItem) Episode() int {
	return s.Episode_
}

func (s svtplayItem) Season() int {
	return s.Season_
}
func (s svtplayItem) Plot() string {
	if s.PlotFile_ == "" {
		if s.PlotString != "" {
			return s.PlotString
		}
		return ""
	}
	buf, err := os.ReadFile(s.PlotFile_)
	if err != nil {
		slog.Warn("Plotfile gone from under me", "fname", s.PlotFile_, "err", err)
		return ""
	}
	return string(buf)
}

type nopCloser struct {
	io.ReadSeeker
}

func (r nopCloser) Close() error {
	return nil
}

func (s svtplayItem) OpenSubs() (io.ReadSeekCloser, error) {
	//slog.Info("Checking subs", "subs", s.SubsFile)
	if strings.HasSuffix(s.SubsFile, ".vtt") {
		x, err := os.Open(s.SubsFile)
		if err != nil {
			return nil, fmt.Errorf("open of %s failed: %w", s.SubsFile, err)
		}
		return x, nil
	}
	if strings.HasSuffix(s.SubsFile, ".srt") {
		ffmpegCmd := exec.Command("/usr/bin/ffmpeg", "-hide_banner", "-loglevel", "quiet", "-i", s.SubsFile, "-f", "webvtt", "-")
		ffmpegIn, _ := ffmpegCmd.StdinPipe()
		ffmpegOut, _ := ffmpegCmd.StdoutPipe()
		ffmpegErr, _ := ffmpegCmd.StderrPipe()
		ffmpegIn.Close()

		if err := ffmpegCmd.Start(); err != nil {
			slog.Info("svtplayItem/OpenSubs/ffmpeg start", "err", err)
			return nil, err
		}

		var errbuf []byte
		var errerr error
		var outbuf []byte
		var outerr error

		var stdwg sync.WaitGroup
		stdwg.Add(1)
		go func() {
			errbuf, errerr = io.ReadAll(ffmpegErr)
			stdwg.Done()
		}()
		stdwg.Add(1)
		go func() {
			outbuf, outerr = io.ReadAll(ffmpegOut)
			stdwg.Done()
		}()
		stdwg.Wait()
		if errerr != nil {
			slog.Info("svtplayItem/OpenSubs/ffmpeg stderr", "err", errerr)
			return nil, errerr
		}
		if len(errbuf) != 0 {
			slog.Info("svtplayItem/OpenSubs/ffmpeg stderr", "stderr", string(errbuf))
			return nil, errerr
		}

		if outerr != nil {
			slog.Info("svtplayItem/OpenSubs/ffmpeg stdout", "err", outerr)
			return nil, outerr
		}
		//slog.Info("stdout", "buf", string(outbuf), "err", err)
		ffmpegCmd.Wait()
		reader := bytes.NewReader(outbuf)

		return nopCloser{reader}, nil

	}
	slog.Warn("Unknown subs file extension", "filename", s.SubsFile)
	return nil, fmt.Errorf("error")

}

func (s svtplayItem) OpenPoster() (io.ReadSeekCloser, error) {
	x, err := os.Open(s.PosterFile_)
	return x, err
}

func (_ svtplayItem) derivePlot(dir, fname string) string {
	plotFname := filepath.Join(dir, strings.TrimSuffix(fname, ".mp4")+".plot.txt")
	_, err := os.Stat(plotFname)
	if err != nil {
		//slog.Info("svtplayItem/derivePlot", "err", err)
		return ""
	}
	//slog.Info("svtplayItem/derivePlot", "file", err)
	return plotFname
}

func (_ svtplayItem) _dropDotsDashesAndTrimSpaces(s string) string {
	res := strings.ReplaceAll(s, ".", " ")
	res = strings.ReplaceAll(res, "-", " ")
	res = strings.Trim(res, " ")
	return res
}
func (s *svtplayItem) _split(fname string) {
	parts := strings.Split(fname, "-")
	basename := strings.Join(parts[:len(parts)-2], "-")
	re := regexp.MustCompile("(.*)s([0-9][0-9])e([0-9][0-9])(.*)")
	splits := re.FindAllStringSubmatch(basename, -1)
	var err error
	if len(splits) < 1 {
		s.Title_ = s._dropDotsDashesAndTrimSpaces(basename)
	} else {
		s.Title_ = s._dropDotsDashesAndTrimSpaces(splits[0][1])
		s.Season_, err = strconv.Atoi(splits[0][2])
		if err != nil {
			panic(err)
			return
		}
		s.Episode_, err = strconv.Atoi(splits[0][3])
		if err != nil {
			panic(err)
			return
		}
		reEpisodeT := regexp.MustCompile(".*.[0-9]+.(.*)")
		splitsEpisodeT := reEpisodeT.FindAllStringSubmatch(splits[0][4], -1)
		if len(splitsEpisodeT) > 0 {
			s.EpisodeTitle_ = s._dropDotsDashesAndTrimSpaces(splitsEpisodeT[0][1])
		}
	}
	return
}

func (_ svtplayItem) deriveSubs(basedir string, fname string) string {
	target := replaceSuffix(filepath.Join(basedir, fname), ".mp4", ".vtt")
	if fileExists(target) {
		return target
	}
	target = replaceSuffix(filepath.Join(basedir, fname), ".mp4", ".srt")
	if fileExists(target) {
		return target
	}
	return ""
}

func (_ svtplayItem) derivePoster(basedir string, fname string) string {
	target := replaceSuffix(filepath.Join(basedir, fname), ".mp4", ".tbn")
	if !fileExists(target) {
		return ""
	}
	return target
}
func (s *svtplayItem) ScrapeNfo(nfoFname string) {
	type nfoT struct {
		ShowTitle string `xml:"showtitle"`
		Title     string `xml:"title"`
		Season    int    `xml:"season"`
		Episode   int    `xml:"episode"`
		Plot      string `xml:"plot"`
		Aired     string `xml:"aired"`
	}
	var nfo nfoT
	buf, err := os.ReadFile(nfoFname)
	if err != nil {
		slog.Info("Failed to read supposedly existing file", "nfoFname", nfoFname, "err", err)
		panic(err)
	}
	if err := xml.Unmarshal(buf, &nfo); err != nil {
		slog.Info("Failed to unmarshal", "err", err)
		panic(err)
	}
	s.Title_ = nfo.ShowTitle
	s.EpisodeTitle_ = nfo.Title
	s.PlotString = nfo.Plot
	s.Episode_ = nfo.Episode
	s.Season_ = nfo.Season
	return
}

func (s *svtplayItem) Scrape(dir, fname string) {
	s.ID_ = s.deriveID(fname)
	s.Media = filepath.Join(dir, fname)
	s.PosterFile_ = s.derivePoster(dir, fname)
	s.SubsFile = s.deriveSubs(dir, fname)
	if s.Tags_ == nil {
		s.Tags_ = map[string][]string{}
	}
	s.Tags_["dir"] = append(s.Tags_["dir"], filepath.Base(dir))
	s.Tags_["fulldir"] = append(s.Tags_["fulldir"], (dir))
	nfoFname := replaceSuffix(s.Media, ".mp4", ".nfo")
	if fileExists(nfoFname) {
		s.ScrapeNfo(nfoFname)
		s.Tags_["scraper"] = append(s.Tags_["scraper"], "svtplay/nfo")
		return
	}
	s._split(fname)
	s.Tags_["scraper"] = append(s.Tags_["scraper"], "svtplay/split")
	s.PlotFile_ = s.derivePlot(dir, fname)
}
