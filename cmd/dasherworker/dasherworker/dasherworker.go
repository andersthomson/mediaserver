package dasherworker

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/andersthomson/mediaserver/scrape"
	"go.temporal.io/sdk/workflow"
)

var targets = []Target{
	//	{"x264", "high"},
	{"x264", "low"},
	//	{"x265", "high"},
	{"x265", "low"},
}

type EnsureDashWFArgs struct {
	MspPath string
	Fast    bool
}

func EnsureDashWF(ctx workflow.Context, args EnsureDashWFArgs) (string, error) {
	M, err := CallActivityIO[string, scrape.Msp](ctx, ReadMspFile, filepath.Dir(args.MspPath), filepath.Base(args.MspPath))
	if err != nil {
		return "", err
	}

	storage.Add(filepath.Dir(args.MspPath), M)

	var futures []workflow.Future

	for _, target := range targets {
		childOptions := workflow.ChildWorkflowOptions{
			WorkflowID: "EnsureDash-child-for-" + M.ShortName + "-" + M.Id + "-" + target.String(), // Unique ID
		}
		ctx = workflow.WithChildOptions(ctx, childOptions)
		futures = append(futures, workflow.ExecuteChildWorkflow(ctx, VideoEncodingWorkflow, VideoEncodingWorkflowArgs{
			Dir:     filepath.Dir(args.MspPath),
			MspFile: filepath.Base(args.MspPath),
			Fast:    args.Fast,
			Target:  target,
		}))
	}
	childOptions := workflow.ChildWorkflowOptions{
		WorkflowID: "EnsureDash-child-for-" + M.ShortName + "-" + M.Id + "-" + "audio", // Unique ID
	}
	ctx = workflow.WithChildOptions(ctx, childOptions)
	futures = append(futures, workflow.ExecuteChildWorkflow(ctx, AudioEncodingWorkflow, AudioEncodingWorkflowArgs{
		Dir:     filepath.Dir(args.MspPath),
		MspFile: filepath.Base(args.MspPath),
	}))
	for _, future := range futures {
		if err := future.Get(ctx, nil); err != nil {
			return "", Error("Child WF execution failed", "err", err)
		}
	}

	CallFinalize(ctx, M.Id)
	return "", nil
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
	if err != nil {
		slog.Error("MSP read failed", "err", err)
	}

	storage.Add(args.Dir, M)
	idx := getFirstInputStreamWithPrefix(M.Inputs, "a")
	if idx == -1 {
		return AudioEncodingWorkflowResp{}, Error("Found no audio stream source specified", "input", M)
	}
	Eargs := NewEncodeStreamArgs(ctx, &EncodeStreamArgs{
		InputID:  M.Id,
		InputNo:  idx,
		Stream:   M.Inputs[idx].Stream,
		Language: M.Inputs[idx].Language,
		Codec:    "aac",
	})
	fname := storage.DasherReadyRepresentationFilePath(*Eargs)
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
	Codec   string
	Profile string
}

func (t Target) String() string {
	return fmt.Sprintf("%s-%s", t.Codec, t.Profile)
}

type VideoEncodingWorkflowArgs struct {
	Dir     string
	MspFile string
	Fast    bool
	Target  Target
}

type VideoEncodingWorkflowResp struct {
}

func VideoEncodingWorkflow(ctx workflow.Context, args VideoEncodingWorkflowArgs) (VideoEncodingWorkflowResp, error) {
	slog.Info("Start", "W", "VideoEncoding", "msp", args.MspFile)
	defer slog.Info("Stop ", "W", "VideoEncoding", "msp", args.MspFile)

	M, err := CallActivityIO[string, scrape.Msp](ctx, ReadMspFile, args.Dir, args.MspFile)
	if err != nil {
		slog.Error("MSP read failed", "err", err)
	}

	storage.Add(args.Dir, M)

	idx := getFirstInputStreamWithPrefix(M.Inputs, "v")
	if idx == -1 {
		return VideoEncodingWorkflowResp{}, Error("Found no video stream source specified", "input", M)
	}
	//Find the encoding needs
	var opts []TranscodeOption
	var maxRes TranscodeOption
	switch args.Target.Profile {
	case "high":
		maxRes = WithMaxResolution(Max1080p)
	case "low":
		maxRes = WithMaxResolution(Max720p)
	}
	opts = append(opts, maxRes)
	Eargs := NewEncodeStreamArgs(ctx, &EncodeStreamArgs{
		InputID: M.Id,
		InputNo: idx,
		Stream:  M.Inputs[idx].Stream,
		Kind:    M.Inputs[idx].Kind,
		Preset:  preset(args.Fast),
		Profile: args.Target.Profile,
		Codec:   args.Target.Codec,
	}, opts...)
	fname := storage.DasherReadyRepresentationFilePath(*Eargs)
	slog.Info("Creating representation", "shortName", M.ShortName, "representation", filepath.Base(fname))
	if err := PipelineFactory(ctx, *Eargs).Process(ctx, *Eargs); err != nil {
		slog.Error("Pipeline processing failed", "err", err)
		return VideoEncodingWorkflowResp{}, err
	}
	return VideoEncodingWorkflowResp{}, nil

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

func scaleFilter(ctx workflow.Context, args EncodeStreamArgs) string {
	if args.VideoFilters.MaxResolution.Width > 0 {
		//return "scale='if(gt(iw,ih),min(" + strconv.Itoa(args.VideoFilters.MaxResolution.Width) + ",iw),-2)':'if(gt(iw,ih),-2,min(" + strconv.Itoa(args.VideoFilters.MaxResolution.Height) + ",ih))'"
		width, height, SAR, err := CallGetStreamDimensions(ctx, args.InputID, args.InputNo, args.Stream)

		if err != nil {
			slog.Error("Failed to get Stream dimensions", "err", err)
			return ""
		}
		return scalingFilter(Resolution{Width: width, Height: height}, SAR, args.VideoFilters.MaxResolution)

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

type inputFileArgumentsStrategy interface {
	CanHandle(ctx workflow.Context, args EncodeStreamArgs) bool
	Process(ctx workflow.Context, args EncodeStreamArgs) []any
}

var inputFileArgumentsStrategies = []inputFileArgumentsStrategy{
	mpeg2videoWithBrokenPTS{},
}

type DefaultInputFileArgumentsStategy struct {
}

func (_ DefaultInputFileArgumentsStategy) CanHandle(ctx workflow.Context, args EncodeStreamArgs) bool {
	return true
}

func (_ DefaultInputFileArgumentsStategy) Process(ctx workflow.Context, args EncodeStreamArgs) []any {
	return []any{}
}

type mpeg2videoWithBrokenPTS struct {
}

func (m mpeg2videoWithBrokenPTS) CanHandle(ctx workflow.Context, args EncodeStreamArgs) bool {
	isBroken, err := CallIsMpeg2VideoWithBrokenDTS(ctx, args.InputID, args.InputNo, args.Stream)
	if err != nil {
		slog.Error("Failed to parse file", "err", err)
		return false
	}
	return isBroken
}
func (m mpeg2videoWithBrokenPTS) Process(ctx workflow.Context, args EncodeStreamArgs) []any {
	return []any{
		"-fflags",
		"+genpts+igndts",
		"-copyts",
		"-start_at_zero",
	}
}

func selectInputFileArgumentsStrategy(ctx workflow.Context, args EncodeStreamArgs) inputFileArgumentsStrategy {
	for _, strategy := range inputFileArgumentsStrategies {
		if strategy.CanHandle(ctx, args) {
			return strategy
		}
	}
	return DefaultInputFileArgumentsStategy{}
}

func inputDirFileStrategy(ctx workflow.Context, args EncodeStreamArgs) []any {
	inputArgsStrategy := selectInputFileArgumentsStrategy(ctx, args)
	return append(
		inputArgsStrategy.Process(ctx, args),
		"-i", DirFile{
			Dir:   filepath.Dir(storage.ResolveInputNumber(args.InputID, args.InputNo)),
			Fname: filepath.Base(storage.ResolveInputNumber(args.InputID, args.InputNo)),
		})
}

func inputDirFileWithMapStrategy(ctx workflow.Context, args EncodeStreamArgs) []any {
	return []any{
		//"-copyts",
		"-i", DirFile{
			Dir:   filepath.Dir(storage.ResolveInputNumber(args.InputID, args.InputNo)),
			Fname: filepath.Base(storage.ResolveInputNumber(args.InputID, args.InputNo)),
		},
		"-map", "0:" + args.Stream,
	}
}

func videoFilterStrategy(ctx workflow.Context, args EncodeStreamArgs, deinterlaceFilter string) []any {
	scaleFilter := scaleFilter(ctx, args)
	return []any{"-filter_complex",
		strings.Join([]string{
			interlaceIfNeeded("0:v:0", "postdeint", deinterlaceFilter),
			scaleIfNeeded("postdeint", "out", scaleFilter)}, ";"),
		"-map", "[out]"}
}

func dashMs2(gopFrames int, fps int) string {
	if fps == 0 || gopFrames == 0 {
		return "ILLEGAL GOPFRAMES OR FPS" // Guard against division by zero
	}

	// 1. Calculate the exact millisecond duration of ONE single GOP
	singleGopMs := (gopFrames * 1000) / fps

	// 2. Find out how many of these GOPs fit closest to our 4000ms target.
	// We add (singleGopMs / 2) to achieve perfect "round to nearest integer" math.
	gopCount := (4000 + (singleGopMs / 2)) / singleGopMs

	// 3. Prevent a count of 0 if a single GOP happens to be massive (e.g., 6 seconds)
	if gopCount == 0 {
		gopCount = 1
	}

	// 4. Return the combined duration of the stacked GOPs
	return fmt.Sprintf("%d", gopCount*singleGopMs)
}

var DefaultGopFrames int = 96

func gopFrames(ctx workflow.Context, inputId string) int {
	/*
		props, _ := CallActivityIO[string, GetOneTargetsPropertiesResp](ctx, "GetOneTargetsProperties", storage.ProdDir(inputId))
		if !props.Found {
			slog.Info("Using GopFrames", "default", DefaultGopFrames)
			return DefaultGopFrames
		}
		slog.Info("Using GopFrames", "fromTarget", DefaultGopFrames)
		return props.Props.GopFrames
	*/
	return DefaultGopFrames
}

func languageFromArgs(args EncodeStreamArgs) []any {
	if args.Language != "" {
		slog.Info("setting lang", "to", args.Language)
		return []any{
			"-metadata:s:0",
			"language=" + args.Language,
		}
	}
	slog.Info("NO language")
	return []any{}
}
func XnullStrategy(_ EncodeStreamArgs) []any {
	return []any{}
}
func x264EncodingStrategy(gopFrames int, crf string, bitrate string) func(args EncodeStreamArgs) []any {
	gopFramesStr := fmt.Sprintf("%d", gopFrames)
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

		ffmpegArgs = append(ffmpegArgs, []any{"-fps_mode", "cfr"}...)
		return ffmpegArgs
	}
}
func x265EncodingStrategy(gopFrames int, crf string, bitrate string) func(args EncodeStreamArgs) []any {
	gopFramesStr := fmt.Sprintf("%d", gopFrames)
	return func(args EncodeStreamArgs) []any {
		ffmpegArgs := []any{
			"-c:v", "libx265",
			"-profile:v", "main10",
			"-level:v", "5.1",
			"-pix_fmt", "yuv420p10le",
			"-crf:v", crf,
			"-preset:v", args.Preset,
		}
		ffmpegArgs = append(ffmpegArgs, tune("x265", args.Kind)...)
		ffmpegArgs = append(ffmpegArgs,
			"-tag:v", "hvc1",
			"-x265-params:v", "keyint="+gopFramesStr+":min-keyint="+gopFramesStr+":scenecut=0:open-gop=0:vbv-maxrate="+bitrate+":vbv-bufsize="+bufSize(bitrate))
		ffmpegArgs = append(ffmpegArgs, []any{"-fps_mode", "cfr"}...)
		return ffmpegArgs
	}
}
func aac2cEncodingStrategy(args EncodeStreamArgs) []any {
	return []any{
		"-vn",
		"-c", "aac",
		"-aac_coder", "twoloop",
		//"-frame_size", "960",
		"-b:a", "448k",
		"-ar", "48000",
		//FIXME: Keep mono as mono. Dont upsample
		"-ac", "2",
		//"-af", "aresample=async=1",
		"-af", "aresample=async=1:comp_duration=1:max_soft_comp=0.05",
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
		"-y",
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

type InputStrategy func(ctx workflow.Context, args EncodeStreamArgs) []any
type FilterStrategy func(args EncodeStreamArgs, deinterlaceFilter string) []any
type EncodingStrategy func(args EncodeStreamArgs) []any
type LanguageStrategy func(args EncodeStreamArgs) []any
type ManifestStrategy func(args EncodeStreamArgs) []any
type DurationDeriverUsec func(ctx workflow.Context, inputID string, inputNo int, stream string) (int64, error)
type QueueSelector func(args EncodeStreamArgs) string
type PackagingStrategy func(ctx workflow.Context, args MP4BoxDashReadyArgs) (MP4BoxDashReadyResp, error)

func MP4BoxDashReadyStrategy(args EncodeStreamArgs) MP4BoxDashReadyArgs {
	drFilePath := storage.DasherReadyRepresentationFilePath(args)
	drFname := filepath.Base(drFilePath)
	drDir := filepath.Dir(drFilePath)

	transcodedFilePath := storage.TranscodedRepresentationFilePath(args)
	transcodedFname := filepath.Base(transcodedFilePath)

	manifestFilePath := storage.DasherReadyRepresentationManifestFilePath(args)
	manifestFname := filepath.Base(manifestFilePath)

	boxArgs := []string{
		"-dash", args.DstProps.DashMs,
		"-rap",
		"-profile",
		"onDemand",
		"-segment-name", drFname,
		"-out", manifestFname,
		transcodedFname}

	return MP4BoxDashReadyArgs{
		EncodeArgs:         args,
		TranscodedFilePath: transcodedFilePath,
		ManifestFilePath:   manifestFilePath,
		DrFname:            drFname,
		DrDir:              drDir,
		DrFilePath:         drFilePath,
		WorkDir:            storage.ProdDir(args.InputID),
		DashMs:             args.DstProps.DashMs,
		MP4BoxArgs:         boxArgs,
	}
}
func MP4BoxPackager(ctx workflow.Context, args MP4BoxDashReadyArgs) (MP4BoxDashReadyResp, error) {
	ctx3 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Minute * 50,
		TaskQueue:           "dasherQueue",
		HeartbeatTimeout:    3600 * time.Second,
	})

	var MP4BoxDashReadyResp MP4BoxDashReadyResp
	err := workflow.ExecuteActivity(ctx3, MP4BoxDashReady, args).Get(ctx3, &MP4BoxDashReadyResp)
	if err != nil {
		slog.Error("MP4BoxDashReady activity failed", "err", err.Error())
	}
	return MP4BoxDashReadyResp, err
}

func isVideoCodec(codec string) bool {
	switch codec {
	case "x264", "h264":
		return true
	case "x265", "h265", "hevc":
		return true
	}
	return false
}
func QueueSelectorLocal(args EncodeStreamArgs) string {
	var queue string
	if isVideoCodec(args.Codec) {
		queue = "encodingQueue"
	} else {
		queue = "dasherQueue"
	}
	return queue
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

type CommonProperties struct {
	GopFrames int
	DashMs    string
}

type EncodeStreamArgs struct {
	InputID  string
	InputNo  int
	Stream   string //ffprobe y:z string
	Kind     string
	Language string

	Preset       string
	Profile      string
	Codec        string
	VideoFilters VideoFilterSettings

	DstProps CommonProperties
}

func NewEncodeStreamArgs(ctx workflow.Context, base *EncodeStreamArgs, opts ...TranscodeOption) *EncodeStreamArgs {
	//Apply provided functions
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
		res.languageStrategy = languageFromArgs
		res.manifestStrategy = dashManifestStrategy
	case "x265":
		res.inputStrategy = inputDirFileStrategy
		res.encodingStrategy = x265EncodingStrategy(gopFrames(ctx, args.InputID), crf(args.Codec, args.Profile), bitrate(args.Codec, args.Profile))
		res.languageStrategy = languageFromArgs
		res.manifestStrategy = dashManifestStrategy
	case "aac":
		res.inputStrategy = inputDirFileWithMapStrategy
		res.encodingStrategy = aac2cEncodingStrategy
		res.languageStrategy = languageFromArgs
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
	languageStrategy LanguageStrategy
	manifestStrategy ManifestStrategy
	durationDeriver  DurationDeriverUsec
	encoderQueue     QueueSelector
	packager         PackagingStrategy
}

func (m ManagedPipeline) Process(ctx workflow.Context, args EncodeStreamArgs) error {

	if err := os.MkdirAll(storage.ProdDir(args.InputID), os.ModePerm); err != nil {
		return err
	}
	args.DstProps.DashMs = dashMs2(gopFrames(ctx, args.InputID), 25)

	var ffmpegArgs []any
	ffmpegArgs = append(ffmpegArgs, m.inputStrategy(ctx, args)...)
	if isVideoCodec(args.Codec) {
		ctx1 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
			StartToCloseTimeout: 10 * time.Minute,
			TaskQueue:           "dasherQueue",
			//HeartbeatTimeout:    1000 * time.Second,
		})
		var MediaInterlaceAnalysis MediaInterlaceAnalysis
		err := workflow.ExecuteActivity(ctx1, AnalyzeMediaInterlace, AnalyzeMediaInterlaceArgs{
			InputID: args.InputID,
			InputNo: args.InputNo,
			Stream:  args.Stream,
		}).Get(ctx1, &MediaInterlaceAnalysis)
		if err != nil {
			return err
		}
		ffmpegArgs = append(ffmpegArgs, videoFilterStrategy(ctx, args, MediaInterlaceAnalysis.FilterRecommendation)...)
	}
	ffmpegArgs = append(ffmpegArgs, m.encodingStrategy(args)...)
	ffmpegArgs = append(ffmpegArgs, m.languageStrategy(args)...)
	ffmpegArgs = append(ffmpegArgs, m.manifestStrategy(args)...)

	ffmpegArgsExpanded := NewFFMpegArgs(ffmpegArgs)

	mp4boxargs := MP4BoxDashReadyStrategy(args)

	//If both ffmpeg and mp4box cmd lines have been executed before, skip processing.
	if t, err := CallLoadTranscodingOptions(ctx, args); err == nil && t != nil {
		//spew.Dump(t.Ffmpegargs)
		//spew.Dump(ffmpegArgsExpanded)
		//spew.Dump(t.MP4BoxDashReadyArgs)
		//spew.Dump(mp4boxargs)
		if reflect.DeepEqual(t.Ffmpegargs, ffmpegArgsExpanded) && reflect.DeepEqual(t.MP4BoxDashReadyArgs, mp4boxargs) {
			slog.Info("Already transcoded. Skipping", "inputID", args.InputID, "codec", args.Codec, "profile", args.Profile)
			return nil
		}
	}

	duration, err := m.durationDeriver(ctx, args.InputID, args.InputNo, args.Stream)
	if err != nil {
		return err
	}
	queue := m.encoderQueue(args)
	aoBase := workflow.ActivityOptions{
		TaskQueue: queue, // Necessary so CreateSession knows where to go
	}

	slog.Info("Creating session")
	sessionCtx, err := workflow.CreateSession(workflow.WithActivityOptions(ctx, aoBase), &workflow.SessionOptions{
		CreationTimeout:  24 * time.Hour,
		ExecutionTimeout: 24 * time.Hour,
	})
	if err != nil {
		return err
	}
	slog.Info("Created session")
	sessionID := workflow.GetSessionInfo(sessionCtx).SessionID
	defer workflow.CompleteSession(sessionCtx)

	ctx2 := workflow.WithActivityOptions(sessionCtx, workflow.ActivityOptions{
		StartToCloseTimeout: 24 * time.Hour,
		HeartbeatTimeout:    20 * time.Second,
	})

	var encodePreludeResp EncodePreludeResp
	var a *LocalEncode
	//spew.Dump(ffmpegArgs)
	err = workflow.ExecuteActivity(ctx2, a.EncodePrelude, EncodePreludeArgs{
		SessionID:  sessionID,
		FfmpegArgs: ffmpegArgsExpanded,
	}).Get(ctx2, &encodePreludeResp)
	if err != nil {
		slog.Error(" FfmpegEncodePreludefailed", "err", err.Error())
		return err
	}

	var ffmpegEncodeResp EncodeResp
	err = workflow.ExecuteActivity(ctx2, a.Encode, EncodeArgs{
		SessionID:       sessionID,
		FfmpegArgs:      ffmpegArgsExpanded,
		TotalDurationUs: duration,
	}).Get(ctx2, &ffmpegEncodeResp)
	if err != nil {
		slog.Error("activity failed", "err", err.Error())
		return err
	}

	err = workflow.ExecuteActivity(ctx2, a.EncodePostlude, EncodePostludeArgs{
		SessionID:  sessionID,
		FfmpegArgs: ffmpegArgsExpanded,
	}).Get(ctx2, nil)

	mp4boxresp, err := m.packager(ctx, mp4boxargs)
	if err != nil {
		return Error("Packager failed", "err", err)
	}

	t := TranscodingOptionsRecord{
		EncodeStream:        args,
		Ffmpegargs:          ffmpegArgsExpanded,
		Stderr:              ffmpegEncodeResp.Stderr,
		MP4BoxDashReadyArgs: mp4boxargs,
		MP4Box: Invocation{
			Dir:    mp4boxresp.Dir,
			Args:   mp4boxargs.MP4BoxArgs,
			Stdout: mp4boxresp.Stdout,
			Stderr: mp4boxresp.Stderr,
		},
	}
	if err := CallRecordTranscodingOptions(ctx, t); err != nil {
		return err
	}
	return nil
}
