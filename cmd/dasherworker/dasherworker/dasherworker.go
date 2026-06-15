package dasherworker

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/andersthomson/mediaserver/scrape"
	"go.temporal.io/sdk/workflow"
)

type Storage struct {
	items map[string]struct {
		m   scrape.Msp
		dir string
	}
}

var storage *Storage

func NewStorage() *Storage {
	s := &Storage{}
	s.items = make(map[string]struct {
		m   scrape.Msp
		dir string
	})
	return s
}

func (s *Storage) Add(dir string, m scrape.Msp) {
	_, ok := s.items[m.Id] // Check if it exists
	if ok {
		slog.Error("Item ID already exists!!!")
	}
	s.items[m.Id] = struct {
		m   scrape.Msp
		dir string
	}{
		m:   m,
		dir: dir,
	}
}

func StorageAddWF(ctx workflow.Context, mspPath string) (string, error) {
	M, err := CallActivityIO[string, scrape.Msp](ctx, ReadMspFile, filepath.Dir(mspPath), filepath.Base(mspPath))
	if err != nil {
		return "", err
	}
	if storage == nil {
		storage = NewStorage()
	}
	storage.Add(filepath.Dir(mspPath), M)
	return "", nil
}

// id is the uuid
func (s *Storage) ResolveInput(id string) (string, scrape.Msp) { //dir,msp
	x, ok := s.items[id]
	if !ok {
		slog.Error("Item does not exist", "id", id)
	}
	return x.dir, x.m
}

func (s *Storage) ResolveInputNumber(id string, number int) string {
	dir, m := s.ResolveInput(id)
	return filepath.Join(dir, m.Inputs[number].Filename)
}

func (s *Storage) ProdDir(id string) string {
	x, ok := s.items[id]
	//spew.Dump(s)
	if !ok {
		slog.Error("Item does not exist", "id", id)
	}
	return "/var/cache/mediacache/" + x.m.ShortName + "-" + x.m.Id + "/dash"
}
func (s *Storage) TranscodedRepresentationFilePath(args EncodeStreamArgs) string {
	return filepath.Join(s.ProdDir(args.InputID), representation(args)+"-transcoded.mp4")
}

func (s *Storage) DasherReadyRepresentationManifestFilePath(args EncodeStreamArgs) string {
	return filepath.Join(s.ProdDir(args.InputID), representation(args)+"-manifest.mpd")
}

func (s *Storage) DasherReadyRepresentationFilePath(args EncodeStreamArgs) string {
	return filepath.Join(s.ProdDir(args.InputID), representation(args)+".mp4")
}

type AudioEncodingWorkflowArgs struct {
	Dir     string
	MspFile string
}

type AudioEncodingWorkflowResp struct {
}

func AudioEncodingWorkflow(ctx workflow.Context, args AudioEncodingWorkflowArgs) (AudioEncodingWorkflowResp, error) {
	slog.Info("Start", "W", "AudioEncoding", "msp", args.MspFile)
	defer slog.Info("Stop ", "W", "AudioEncoding", "msp", args.MspFile)

	M, err := CallActivityIO[string, scrape.Msp](ctx, ReadMspFile, args.Dir, args.MspFile)
	storage = NewStorage()

	storage.Add(args.Dir, M)
	idx := getFirstInputStreamWithPrefix(M.Inputs, "a")
	if idx == -1 {
		return AudioEncodingWorkflowResp{}, Error("Found no audio stream source specified", "input", M)
	}
	Eargs := NewEncodeStreamArgs(&EncodeStreamArgs{
		InputID: M.Id,
		InputNo: idx,
		Stream:  M.Inputs[idx].Stream,
		Codec:   "aac",
	})
	fname := storage.DasherReadyRepresentationFilePath(*Eargs)
	exists, err := CallActivityFast[string, bool](ctx, FileExists, fname)
	if err != nil {
		return AudioEncodingWorkflowResp{}, Error("failed to check for file existence", "err", err)
	}
	if exists {
		slog.Info("Skipping, representation exists", "shortName", M.ShortName, "representation", filepath.Base(fname))
		return AudioEncodingWorkflowResp{}, nil
	}
	slog.Info("Creating representation", "shortName", M.ShortName, "representation", filepath.Base(fname))
	if err := PipelineFactory(ctx, *Eargs).Process(ctx, *Eargs); err != nil {
		slog.Error("Pipeline processing failed", "err", err)
		return AudioEncodingWorkflowResp{}, err
	}
	return AudioEncodingWorkflowResp{}, nil
}

func getFirstInputStreamWithPrefix(inputs []scrape.InputT, prefix string) int {
	return slices.IndexFunc(inputs, func(i scrape.InputT) bool {
		return strings.HasPrefix(i.Stream, prefix)
	})
}

type Target struct {
	codec   string
	profile string
}

var targets = []Target{
	{"x264", "high"},
	{"x264", "low"},
	{"x265", "high"},
	{"x265", "low"},
}

type VideoEncodingWorkflowArgs struct {
	Dir     string
	MspFile string
	Fast    bool
}

type VideoEncodingWorkflowResp struct {
}

func VideoEncodingWorkflow(ctx workflow.Context, args VideoEncodingWorkflowArgs) (VideoEncodingWorkflowResp, error) {
	slog.Info("Start", "W", "VideoEncoding", "msp", args.MspFile)
	defer slog.Info("Stop ", "W", "VideoEncoding", "msp", args.MspFile)

	ctx1 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute,
		TaskQueue:           "dasherQueue",
		//HeartbeatTimeout:    1000 * time.Second,
	})
	var M scrape.Msp
	err := workflow.ExecuteActivity(ctx1, ReadMspFile, args.Dir, args.MspFile).Get(ctx1, &M)
	if err != nil {
		slog.Error("MSP read failed", "err", err)
	}
	storage = NewStorage()

	storage.Add(args.Dir, M)

	idx := getFirstInputStreamWithPrefix(M.Inputs, "v")
	if idx == -1 {
		return VideoEncodingWorkflowResp{}, Error("Found no video stream source specified", "input", M)
	}
	//Find the encoding needs
	for _, target := range targets {
		maxRes := WithMaxResolution(Max1080p)
		if target.profile == "low" {
			maxRes = WithMaxResolution(Max720p)
		}
		Eargs := NewEncodeStreamArgs(&EncodeStreamArgs{
			InputID: M.Id,
			InputNo: idx,
			Stream:  M.Inputs[idx].Stream,
			Kind:    M.Inputs[idx].Kind,
			Preset:  preset(args.Fast),
			Profile: target.profile,
			Codec:   target.codec,
		}, maxRes)
		fname := storage.DasherReadyRepresentationFilePath(*Eargs)
		exists, err := CallActivityFast[string, bool](ctx, FileExists, fname)
		if err != nil {
			slog.Error("XXX", "err", err)
		}
		if exists {
			slog.Info("Skipping, representation exists", "shortName", M.ShortName, "representation", filepath.Base(fname))
			continue
		}
		slog.Info("Creating representation", "shortName", M.ShortName, "representation", filepath.Base(fname))
		if err := PipelineFactory(ctx, *Eargs).Process(ctx, *Eargs); err != nil {
			slog.Error("Pipeline processing failed", "err", err)
			return VideoEncodingWorkflowResp{}, err
		}
	}
	return VideoEncodingWorkflowResp{}, nil

}
func FinalizeWF(ctx workflow.Context, args FinalizeArgs) (FinalizeResp, error) {
	return CallActivityIO[FinalizeArgs, FinalizeResp](ctx, Finalize, args)
}

type CommonProperties struct {
	GopFrames float64
	DashMs    float64
}

func crf(codec string, profile string) string {
	type crfTbl map[string]map[string]string
	crfT := crfTbl{
		"x264": {
			"high": "18",
			"low":  "18",
		},
		"x265": {
			"high": "21",
			"low":  "24",
		},
	}
	return crfT[codec][profile]
}

func crfMax(crf string) string {
	c, _ := strconv.Atoi(crf)
	return strconv.Itoa(c + 5)
}
func bufSize(bitrate string) string {
	c, _ := strconv.Atoi(bitrate)
	return strconv.Itoa(2 * c)
}
func interlaceIfNeeded(in, out string, filter string) string {
	return fmt.Sprintf("[%s]%s[%s]", in, filter, out)
}
func scaleIfNeeded(in, out string, filter string) string {
	return fmt.Sprintf("[%s]%s[%s]", in, filter, out)
}

func scaleFilter(args EncodeStreamArgs) string {
	if args.VideoFilters.MaxResolution.Width > 0 {
		return "scale='if(gt(iw,ih),min(" + strconv.Itoa(args.VideoFilters.MaxResolution.Width) + ",iw),-2)':'if(gt(iw,ih),-2,min(" + strconv.Itoa(args.VideoFilters.MaxResolution.Height) + ",ih))'"
	}
	return ""
}
func tune(codec string, kind string) []any {
	switch codec {
	case "x264":
		switch kind {
		case "animation":
			return []any{"-tune:v", "animation"}
		default:
			return []any{"-tune:v", "film"}
		}
	case "x265":
		switch kind {
		case "animation":
			return []any{"-tune:v", "animation"}
		}
	}
	return nil
}

func bitrate(codec string, profile string) string {
	type Tbl map[string]map[string]string
	T := Tbl{
		"x264": {
			"high": "6000",
			"low":  "800",
		},
		"x265": {
			"high": "2000",
			"low":  "800",
		},
	}
	return T[codec][profile]
}

func preset(fast bool) string {
	if fast {
		return "ultrafast"
	} else {
		return "slow"
	}
}

func inputDirFileStrategy(args EncodeStreamArgs) []any {
	return []any{
		//	"-itsoffset", fmt.Sprintf("%.3f", args.SrcProps.FirstPTS),
		"-i", DirFile{
			Dir:   filepath.Dir(storage.ResolveInputNumber(args.InputID, args.InputNo)),
			Fname: filepath.Base(storage.ResolveInputNumber(args.InputID, args.InputNo)),
		},
	}
}

func inputDirFileWithMapStrategy(args EncodeStreamArgs) []any {
	return []any{
		"-i", DirFile{
			Dir:   filepath.Dir(storage.ResolveInputNumber(args.InputID, args.InputNo)),
			Fname: filepath.Base(storage.ResolveInputNumber(args.InputID, args.InputNo)),
		},
		"-map", "0:" + args.Stream,
	}
}

func videoFilterStrategy(args EncodeStreamArgs, deinterlaceFilter string) []any {
	scaleFilter := scaleFilter(args)
	return []any{"-filter_complex",
		strings.Join([]string{
			interlaceIfNeeded("0:v:0", "postdeint", deinterlaceFilter),
			scaleIfNeeded("postdeint", "out", scaleFilter)}, ";"),
		"-map", "[out]"}
}

var DefaultGopFrames float64 = 100.0

func gopFrames(ctx workflow.Context, inputId string) float64 {
	props, _ := CallActivityIO[string, GetOneTargetsPropertiesResp](ctx, "GetOneTargetsProperties", storage.ProdDir(inputId))
	if !props.Found {
		slog.Info("Using GopFrames", "default", DefaultGopFrames)
		return DefaultGopFrames
	}
	slog.Info("Using GopFrames", "fromTarget", DefaultGopFrames)
	return props.Props.GopFrames
}

func nullStrategy(_ EncodeStreamArgs) []any {
	return []any{}
}
func x264EncodingStrategy(gopFrames float64, crf string, bitrate string) func(args EncodeStreamArgs) []any {
	gopFramesStr := strconv.FormatFloat(gopFrames, 'f', 0, 64)
	return func(args EncodeStreamArgs) []any {
		ffmpegArgs := []any{
			"-c:v", "libx264",
			"-profile:v", "high",
			"-level:v", "4.1",
			"-pix_fmt", "yuv420p",
			"-crf:v", crf,
			"-preset:v", args.Preset}
		ffmpegArgs = append(ffmpegArgs, tune("x264", args.Kind)...)
		ffmpegArgs = append(ffmpegArgs,
			"-x264-params:v", "keyint="+gopFramesStr+":min-keyint="+gopFramesStr+":scenecut=0:open-gop=0:vbv-maxrate="+bitrate+":vbv-bufsize="+bufSize(bitrate)+":crf-max="+crfMax(crf)+":no-deblock=0:cabac=1:8x8dct=1")

		return ffmpegArgs
	}
}
func x265EncodingStrategy(gopFrames float64, crf string, bitrate string) func(args EncodeStreamArgs) []any {
	gopFramesStr := strconv.FormatFloat(gopFrames, 'f', 0, 64)
	return func(args EncodeStreamArgs) []any {
		ffmpegArgs := []any{
			"-c:v", "libx265",
			"-profile:v", "main10",
			"-level:v", "5.1",
			"-pix_fmt", "yuv420p",
			"-crf:v", crf,
			"-preset:v", args.Preset,
		}
		ffmpegArgs = append(ffmpegArgs, tune("x265", args.Kind)...)
		ffmpegArgs = append(ffmpegArgs,
			"-tag:v", "hvc1",
			"-x265-params:v", "keyint="+gopFramesStr+":min-keyint="+gopFramesStr+":scenecut=0:open-gop=0:vbv-maxrate="+bitrate+":vbv-bufsize="+bufSize(bitrate))
		return ffmpegArgs
	}
}
func aac2cEncodingStrategy(args EncodeStreamArgs) []any {
	return []any{
		"-vn",
		"-c", "aac",
		"-aac_coder", "twoloop",
		"-frame_size", "960",
		"-b:a", "448k",
		"-ar", "48000",
		//FIXME: Keep mono as mono. Dont upsample
		"-ac", "2",
		"-af", "aresample=async=1",
	}
}

func copyStreamStrategy(args EncodeStreamArgs) []any {
	return []any{
		"-c", "copy",
	}
}

func HLSManifestStrategy(args EncodeStreamArgs) []any {
	return []any{
		"-map_chapters", "-1",
		"-map_metadata", "-1",
		"-movflags", "+faststart+disable_chpl",
		"-hls_time", "3.84", //FIXME
		"-hls_list_size", "0",
		"-hls_flags", "single_file",
		"-hls_playlist_type", "static",
		storage.DasherReadyRepresentationFilePath(args),
	}
}

func dashManifestStrategy(args EncodeStreamArgs) []any {
	return []any{
		"-map_chapters", "-1",
		"-map_metadata", "-1",
		//These are supposedly needed if ffmpeg does the dash packaging (not using e.g. mp4box)
		"-movflags", "frag_keyframe+empty_moov+default_base_moof",
		//"-movflags", "+faststart+disable_chpl",
		DirFile{
			Dir:   filepath.Dir(storage.TranscodedRepresentationFilePath(args)),
			Fname: filepath.Base(storage.TranscodedRepresentationFilePath(args)),
		},
	}
}

func rawOutputStrategy(args EncodeStreamArgs) []any {
	return []any{
		storage.DasherReadyRepresentationFilePath(args),
	}
}

type InputStrategy func(args EncodeStreamArgs) []any
type FilterStrategy func(args EncodeStreamArgs, deinterlaceFilter string) []any
type EncodingStrategy func(args EncodeStreamArgs) []any
type ManifestStrategy func(args EncodeStreamArgs) []any
type DurationDeriverUsec func(ctx workflow.Context, inputID string, inputNo int, stream string) (int64, error)
type QueueSelector func(args EncodeStreamArgs) string
type PackagingStrategy func(ctx workflow.Context, args EncodeStreamArgs, dashMs string) error

func BuildFfmpegArgs(args EncodeStreamArgs,
	applyInput InputStrategy,
	applyEncoding EncodingStrategy,
	applyManifest ManifestStrategy) []any {
	ffmpegArgs := []any{}
	return ffmpegArgs
}

func isVideoCodec(codec string) bool {
	switch codec {
	case "x264", "h264":
		return true
	case "x265", "h265":
		return true
	}
	return false
}
func durationDeriverFfmpeg(ctx workflow.Context, inputID string, inputNo int, stream string) (int64, error) {
	ctx1 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
	})
	var duration int64
	err := workflow.ExecuteActivity(ctx1, GetVideoDurationUsec, inputID, inputNo, stream).Get(ctx1, &duration)
	if err != nil {
		return 0, err
	}
	return duration, nil
}

func QueueSelectorLocal(args EncodeStreamArgs) string {
	/*
	   var queue string
	   	if isVideoEncode {
	   		queue = "encodingQueue"
	   	} else {
	   		queue = "dasherQueue"
	   	}
	*/
	return "dasherQueue"
}

func MP4BoxPackager(ctx workflow.Context, args EncodeStreamArgs, dashMs string) error {
	ctx3 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Minute * 50,
		TaskQueue:           "dasherQueue",
		HeartbeatTimeout:    3600 * time.Second,
	})

	var MP4BoxDashReadyResp MP4BoxDashReadyResp
	err := workflow.ExecuteActivity(ctx3, MP4BoxDashReady, MP4BoxDashReadyArgs{
		EncodeArgs: args,
		WorkDir:    storage.ProdDir(args.InputID),
		DashMs:     dashMs,
	}).Get(ctx3, &MP4BoxDashReadyResp)
	if err != nil {
		slog.Error("MP4BoxDashReady activity failed", "err", err.Error())
		return err
	}
	return nil
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
	Max720p  = Resolution{Width: 1280, Height: 720}
	Max1080p = Resolution{Width: 1920, Height: 1080}
	Max4K    = Resolution{Width: 3840, Height: 2160}
)

type VideoFilterSettings struct {
	MaxResolution Resolution
}

// Return an string uniquely representing this representation
func representation(args EncodeStreamArgs) string {
	if isVideoCodec(args.Codec) {
		return fmt.Sprintf("%s-%s-%s", args.Codec, args.VideoFilters.MaxResolution, args.Profile)
	} else {
		return fmt.Sprintf("%s", args.Codec)
	}
}

type EncodeStreamArgs struct {
	InputID string
	InputNo int
	Stream  string //ffprobe y:z string
	Kind    string

	Preset       string
	Profile      string
	Codec        string
	VideoFilters VideoFilterSettings

	DstProps CommonProperties
}

func NewEncodeStreamArgs(base *EncodeStreamArgs, opts ...TranscodeOption) *EncodeStreamArgs {
	for _, opt := range opts {
		opt(base)
	}

	return base
}

type TranscodeOption func(*EncodeStreamArgs)

func WithMaxResolution(maxx Resolution) TranscodeOption {
	return func(j *EncodeStreamArgs) {
		j.VideoFilters.MaxResolution = maxx
	}
}

func PipelineFactory(ctx workflow.Context, args EncodeStreamArgs) ManagedPipeline {
	res := ManagedPipeline{}
	switch args.Codec {
	case "x264":
		res.inputStrategy = inputDirFileStrategy
		res.encodingStrategy = x264EncodingStrategy(gopFrames(ctx, args.InputID), crf(args.Codec, args.Profile), bitrate(args.Codec, args.Profile))
		res.manifestStrategy = dashManifestStrategy
	case "x265":
		res.inputStrategy = inputDirFileStrategy
		res.encodingStrategy = x265EncodingStrategy(gopFrames(ctx, args.InputID), crf(args.Codec, args.Profile), bitrate(args.Codec, args.Profile))
		res.manifestStrategy = dashManifestStrategy
	case "aac":
		res.inputStrategy = inputDirFileWithMapStrategy
		res.encodingStrategy = aac2cEncodingStrategy
		res.manifestStrategy = dashManifestStrategy
	case "copy":
		res.inputStrategy = inputDirFileWithMapStrategy
		res.encodingStrategy = copyStreamStrategy
		res.manifestStrategy = rawOutputStrategy
	default:
		slog.Error("UNSUPPORTED CODEC", "codec", args.Codec)
		return ManagedPipeline{}
	}
	res.durationDeriver = durationDeriverFfmpeg
	res.encoderQueue = QueueSelectorLocal
	res.packager = MP4BoxPackager
	return res
}

type ManagedPipeline struct {
	inputStrategy    InputStrategy
	encodingStrategy EncodingStrategy
	manifestStrategy ManifestStrategy
	durationDeriver  DurationDeriverUsec
	encoderQueue     QueueSelector
	packager         PackagingStrategy
}

func (m ManagedPipeline) Process(ctx workflow.Context, args EncodeStreamArgs) error {

	if err := os.MkdirAll(storage.ProdDir(args.InputID), os.ModePerm); err != nil {
		return err
	}
	var ffmpegArgs []any
	ffmpegArgs = append(ffmpegArgs, m.inputStrategy(args)...)
	if isVideoCodec(args.Codec) {
		ctx1 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
			StartToCloseTimeout: 10 * time.Minute,
			TaskQueue:           "dasherQueue",
			//HeartbeatTimeout:    1000 * time.Second,
		})
		var MediaInterlaceAnalysis MediaInterlaceAnalysis
		err := workflow.ExecuteActivity(ctx1, AnalyzeMediaInterlace, AnalyzeMediaInterlaceArgs{
			//Dir:   args.Dir,
			InputID: args.InputID,
			InputNo: args.InputNo,
			Stream:  args.Stream,
		}).Get(ctx1, &MediaInterlaceAnalysis)
		if err != nil {
			return err
		}
		ffmpegArgs = append(ffmpegArgs, videoFilterStrategy(args, MediaInterlaceAnalysis.FilterRecommendation)...)
	}
	ffmpegArgs = append(ffmpegArgs, m.encodingStrategy(args)...)
	ffmpegArgs = append(ffmpegArgs, m.manifestStrategy(args)...)

	duration, err := m.durationDeriver(ctx, args.InputID, args.InputNo, args.Stream)
	if err != nil {
		return err
	}
	queue := m.encoderQueue(args)
	aoBase := workflow.ActivityOptions{
		TaskQueue: queue, // Necessary so CreateSession knows where to go
	}
	ctx = workflow.WithActivityOptions(ctx, aoBase)

	slog.Info("Creating session")
	sessionCtx, err := workflow.CreateSession(ctx, &workflow.SessionOptions{
		CreationTimeout:  24 * time.Hour,
		ExecutionTimeout: 24 * time.Hour,
	})
	if err != nil {
		return err
	}
	slog.Info("Created session")
	defer workflow.CompleteSession(sessionCtx)

	ctx2 := workflow.WithActivityOptions(sessionCtx, workflow.ActivityOptions{
		StartToCloseTimeout: 24 * time.Hour,
		HeartbeatTimeout:    20 * time.Second,
	})

	var encodePreludeResp EncodePreludeResp
	var a *LocalEncode
	//spew.Dump(ffmpegArgs)
	err = workflow.ExecuteActivity(ctx2, a.EncodePrelude, EncodePreludeArgs{
		FfmpegArgs: NewFFMpegArgs(ffmpegArgs),
	}).Get(ctx2, &encodePreludeResp)
	if err != nil {
		slog.Error(" FfmpegEncodePreludefailed", "err", err.Error())
		return err
	}

	var ffmpegEncodeResp EncodeResp
	err = workflow.ExecuteActivity(ctx2, a.Encode, EncodeArgs{
		FfmpegArgs:      encodePreludeResp.FfmpegArgs,
		TotalDurationUs: duration,
	}).Get(ctx2, &ffmpegEncodeResp)
	if err != nil {
		slog.Error("activity failed", "err", err.Error())
		return err
	}

	err = workflow.ExecuteActivity(ctx2, a.EncodePostlude, EncodePostludeArgs{
		FfmpegArgs: ffmpegEncodeResp.FfmpegArgs,
	}).Get(ctx2, nil)

	if err := MP4BoxPackager(ctx, args, strconv.FormatFloat(4000, 'f', 0, 64)); err != nil {
		slog.Error("MP4BoxPackager failed", "err", err)
		return err
	}
	return nil
}
