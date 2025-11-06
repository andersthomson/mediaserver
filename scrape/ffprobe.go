package scrape

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
)

type FFProbeRoot struct {
	Programs []FFProbeProgram `json:"programs"`
	Streams  []FFProbeStream  `json:"streams"`
	Chapters []FFProbeChapter `json:"chapters"`
	Format   FFProbeFormat    `json:"format"`
}

type FFProbeProgram struct {
	// Empty for now, define if structure is known
}

type FFProbeChapter struct {
	// Empty for now, define if structure is known
}

type FFProbeStream struct {
	Index              int                `json:"index"`
	CodecName          string             `json:"codec_name"`
	CodecLongName      string             `json:"codec_long_name"`
	Profile            string             `json:"profile"`
	CodecType          string             `json:"codec_type"`
	CodecTagString     string             `json:"codec_tag_string"`
	CodecTag           string             `json:"codec_tag"`
	Width              int                `json:"width,omitempty"`
	Height             int                `json:"height,omitempty"`
	CodedWidth         int                `json:"coded_width,omitempty"`
	CodedHeight        int                `json:"coded_height,omitempty"`
	ClosedCaptions     int                `json:"closed_captions"`
	FilmGrain          int                `json:"film_grain"`
	HasBFrames         int                `json:"has_b_frames,omitempty"`
	SampleAspectRatio  string             `json:"sample_aspect_ratio,omitempty"`
	DisplayAspectRatio string             `json:"display_aspect_ratio,omitempty"`
	PixFmt             string             `json:"pix_fmt,omitempty"`
	Level              int                `json:"level,omitempty"`
	ChromaLocation     string             `json:"chroma_location,omitempty"`
	FieldOrder         string             `json:"field_order,omitempty"`
	Refs               int                `json:"refs,omitempty"`
	IsAvc              string             `json:"is_avc,omitempty"`
	NalLengthSize      string             `json:"nal_length_size,omitempty"`
	ID                 string             `json:"id"`
	RFrameRate         string             `json:"r_frame_rate"`
	AvgFrameRate       string             `json:"avg_frame_rate"`
	TimeBase           string             `json:"time_base"`
	StartPts           int                `json:"start_pts"`
	StartTime          string             `json:"start_time"`
	DurationTs         int64              `json:"duration_ts"`
	Duration           string             `json:"duration"`
	BitRate            string             `json:"bit_rate"`
	BitsPerRawSample   string             `json:"bits_per_raw_sample,omitempty"`
	NBFrames           string             `json:"nb_frames"`
	ExtradataSize      int                `json:"extradata_size"`
	SampleFmt          string             `json:"sample_fmt,omitempty"`
	SampleRate         string             `json:"sample_rate,omitempty"`
	Channels           int                `json:"channels,omitempty"`
	ChannelLayout      string             `json:"channel_layout,omitempty"`
	BitsPerSample      int                `json:"bits_per_sample,omitempty"`
	InitialPadding     int                `json:"initial_padding,omitempty"`
	Disposition        FFProbeDisposition `json:"disposition"`
	Tags               FFProbeTags        `json:"tags"`
}

type FFProbeDisposition struct {
	Default         int `json:"default"`
	Dub             int `json:"dub"`
	Original        int `json:"original"`
	Comment         int `json:"comment"`
	Lyrics          int `json:"lyrics"`
	Karaoke         int `json:"karaoke"`
	Forced          int `json:"forced"`
	HearingImpaired int `json:"hearing_impaired"`
	VisualImpaired  int `json:"visual_impaired"`
	CleanEffects    int `json:"clean_effects"`
	AttachedPic     int `json:"attached_pic"`
	TimedThumbnails int `json:"timed_thumbnails"`
	NonDiegetic     int `json:"non_diegetic"`
	Captions        int `json:"captions"`
	Descriptions    int `json:"descriptions"`
	Metadata        int `json:"metadata"`
	Dependent       int `json:"dependent"`
	StillImage      int `json:"still_image"`
}

type FFProbeTags struct {
	Language    string `json:"language,omitempty"`
	HandlerName string `json:"handler_name,omitempty"`
	VendorID    string `json:"vendor_id,omitempty"`
	Encoder     string `json:"encoder,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Album       string `json:""album"`
	MajorBrand  string `json:"major_brand,omitempty"`
	MinorVer    string `json:"minor_version,omitempty"`
	Compatible  string `json:"compatible_brands,omitempty"`
	Comment     string `json:"comment,omitempty"`
	Genre       string `json:"genre,omitempty"`
	Grouping    string `json:'grouping,omitempty"`
	Episode_id  string `json:"episode_id,omitempty"`
	Season      string `json:"season,omitempty"`
	TmdbMovie   string `json:"tmdbMovie,omitempty"`
	TmdbSeries  string `json:"tmdbSeries,omitempty"`
}

type FFProbeFormat struct {
	Filename       string      `json:"filename"`
	NbStreams      int         `json:"nb_streams"`
	NbPrograms     int         `json:"nb_programs"`
	FormatName     string      `json:"format_name"`
	FormatLongName string      `json:"format_long_name"`
	StartTime      string      `json:"start_time"`
	Duration       string      `json:"duration"`
	Size           string      `json:"size"`
	BitRate        string      `json:"bit_rate"`
	ProbeScore     int         `json:"probe_score"`
	Tags           FFProbeTags `json:"tags"`
}

type Semaphore chan struct{}

func NewSemaphore(n int) Semaphore {
	return make(Semaphore, n)
}

// acquire n resources
func (s Semaphore) Acquire(n int) {
	e := struct{}{}
	for i := 0; i < n; i++ {
		s <- e
	}
}

// release n resources
func (s Semaphore) Release(n int) {
	for i := 0; i < n; i++ {
		<-s
	}
}

var ffprobeSem Semaphore

func init() {
	ffprobeSem = NewSemaphore(16)
}

func FFProbe(fname string) (FFProbeRoot, error) {
	defer ffprobeSem.Release(1)
	ffprobeSem.Acquire(1)

	ffmpegCmd := exec.Command("/usr/bin/ffprobe", "file:"+fname, "-hide_banner", "-loglevel", "fatal", "-show_error", "-show_format", "-show_streams", "-show_programs", "-show_chapters", "-show_private_data", "-print_format", "json", "-o", "-")
	ffmpegIn, err := ffmpegCmd.StdinPipe()
	if err != nil {
		panic(err)
	}
	ffmpegIn.Close()
	ffmpegOut, err := ffmpegCmd.StdoutPipe()
	if err != nil {
		panic(err)
	}
	ffmpegErr, err := ffmpegCmd.StderrPipe()
	if err != nil {
		panic(err)
	}
	if err := ffmpegCmd.Start(); err != nil {
		return FFProbeRoot{}, fmt.Errorf("ffprobe failed: %W", err)
	}
	_, _ = io.ReadAll(ffmpegErr)
	ffmpegErr.Close()
	//spew.Dump(err)
	//spew.Dump(errBuf)
	buf, err := io.ReadAll(ffmpegOut)
	if err != nil {
		return FFProbeRoot{}, fmt.Errorf("io.ReadAll failed: %W", err)
	}
	ffmpegCmd.Wait()
	ffmpegOut.Close()
	var b FFProbeRoot
	if len(buf) > 0 {
		if err := json.Unmarshal(buf, &b); err != nil {
			return FFProbeRoot{}, fmt.Errorf("json.Unmarshal failed: %w", err)
		}
	}
	return b, nil
}
