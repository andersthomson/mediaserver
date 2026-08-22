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
	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"
	"go.temporal.io/sdk/workflow"
)

var targets = []Target{
	//	{"x264", "high"},
	{"x264", "low"},
	//	{"x265", "high"},
	{"x265", "low"},
	{"aac", ""},
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

	var VprobeRawData ProbeRawData
	for _, target := range targets {
		//if a target calls for video, probe the input source
		if isVideoCodec(target.Codec) {
			idx := getFirstInputStreamWithPrefix(M.Inputs, "v")
			if idx == -1 {
				return "", Error("Found no video stream source specified", "input", M)
			}
			VprobeRawData, err = CallExecuteProbes(ctx, M.Id, idx, M.Inputs[idx].Stream)
			if err != nil {
				return "", err
			}
			spew.Dump(EvaluateDashPassThrough(VprobeRawData))
			break
		}
	}
	var futures []workflow.Future

	for _, target := range targets {
		childOptions := workflow.ChildWorkflowOptions{
			WorkflowID: "EnsureDash-child-for-" + M.ShortName + "-" + M.Id + "-" + target.String(), // Unique ID
		}
		ctx = workflow.WithChildOptions(ctx, childOptions)
		futures = append(futures, workflow.ExecuteChildWorkflow(ctx, CreateRepresentation, CreateRepresentationArgs{
			Dir:          filepath.Dir(args.MspPath),
			MspFile:      filepath.Base(args.MspPath),
			Fast:         args.Fast,
			Target:       target,
			ProbeRawData: VprobeRawData, //Ok even if target is not video. it is input used for video flows
		}))
	}
	for _, future := range futures {
		if err := future.Get(ctx, nil); err != nil {
			return "", Error("Child WF execution failed", "err", err)
		}
	}

	_, err = CallFinalize(ctx, M.Id, true)
	return "", err
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

type CreateRepresentationArgs struct {
	Dir          string
	MspFile      string
	Fast         bool
	Target       Target
	ProbeRawData ProbeRawData
}

type CreateRepresentationResp struct {
}

func CreateRepresentation(ctx workflow.Context, args CreateRepresentationArgs) (CreateRepresentationResp, error) {
	slog.Info("Start", "W", "CreateRepresentation", "msp", args.MspFile)
	defer slog.Info("Stop ", "W", "CreateRepresentation", "msp", args.MspFile)

	M, err := CallActivityIO[string, scrape.Msp](ctx, ReadMspFile, args.Dir, args.MspFile)
	if err != nil {
		slog.Error("MSP read failed", "err", err)
	}

	//Find the encoding needs
	var opts []TranscodeOption

	var idx int
	if isVideoCodec(args.Target.Codec) {
		idx = getFirstInputStreamWithPrefix(M.Inputs, "v")
		if idx == -1 {
			return CreateRepresentationResp{}, Error("Found no video stream source specified", "input", M)
		}
		var maxRes TranscodeOption
		switch args.Target.Profile {
		case "high":
			maxRes = WithMaxResolution(Max1080p)
		case "low":
			maxRes = WithMaxResolution(Max720p)
		}
		opts = append(opts, maxRes)
		opts = append(opts, WithPreset(preset(args.Fast)))
	} else {
		idx = getFirstInputStreamWithPrefix(M.Inputs, "a")
		if idx == -1 {
			return CreateRepresentationResp{}, Error("Found no audio stream source specified", "input", M)
		}
	}

	Eargs := NewEncodeStreamArgs(ctx, &EncodeStreamArgs{
		InputID:  M.Id,
		InputNo:  idx,
		Stream:   M.Inputs[idx].Stream,
		Kind:     M.Inputs[idx].Kind,
		Language: M.Inputs[idx].Language,
		Profile:  args.Target.Profile,
		Codec:    args.Target.Codec,
	}, opts...)
	fname := DasherReadyRepresentationFilePath(ctx, *Eargs)
	slog.Info("Creating representation", "shortName", M.ShortName, "representation", filepath.Base(fname))
	factory := TranscodingPipelineFactory(ctx, *Eargs)
	ffmpegArgs, err := factory.FfmpegArgs(ctx, *Eargs, args.ProbeRawData)
	if err != nil {
		return CreateRepresentationResp{}, err
	}
	mp4boxArgs, err := factory.MP4BoxArgs(ctx, *Eargs)
	if err != nil {
		return CreateRepresentationResp{}, err
	}
	if t, err := CallLoadTranscodingOptions(ctx, *Eargs); err == nil && t != nil {
		//We have a history
		if diff := factory.NeedsProcessing(*t, ffmpegArgs, mp4boxArgs); diff == "" {
			slog.Info("Already processed", "ShortName", M.ShortName, "inputID", M.Id, "stream", M.Inputs[idx].Stream, "target", args.Target)
			return CreateRepresentationResp{}, nil
		} else {
			slog.Info("Need reprocessing", "ShortName", M.ShortName, "InputID", M.Id, "Stream", M.Inputs[idx].Stream, "target", args.Target, "new trancoding diff", diff)
		}
	}
	err = factory.Process(ctx, *Eargs, ffmpegArgs, mp4boxArgs)
	if err != nil {
		slog.Error("Pipeline processing failed", "ShortName", M.ShortName, "InputID", M.Id, "Stream", M.Inputs[idx].Stream, "target", args.Target, "err", err)
	}
	return CreateRepresentationResp{}, nil

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
func tune(codec string, kind string) []FFMpegArg {
	switch codec {
	case "x264":
		switch kind {
		case "animation":
			return []FFMpegArg{NewFFMpegArg(KindString, "-tune:v"), NewFFMpegArg(KindString, "animation")}
		default:
			return []FFMpegArg{NewFFMpegArg(KindString, "-tune:v"), NewFFMpegArg(KindString, "film")}
		}
	case "x265":
		switch kind {
		case "animation":
			return []FFMpegArg{NewFFMpegArg(KindString, "-tune:v"), NewFFMpegArg(KindString, "animation")}
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

type Preset string

func (p Preset) String() string {
	return string(p)
}

func preset(fast bool) Preset {
	if fast {
		return "ultrafast"
	} else {
		return "slow"
	}
}

type inputFileArgumentsStrategy interface {
	CanHandle(ctx workflow.Context, args EncodeStreamArgs) bool
	Process(ctx workflow.Context, args EncodeStreamArgs) []FFMpegArg
}

var inputFileArgumentsStrategies = []inputFileArgumentsStrategy{
	mpeg2videoWithBrokenPTS{},
}

type DefaultInputFileArgumentsStategy struct {
}

func (_ DefaultInputFileArgumentsStategy) CanHandle(ctx workflow.Context, args EncodeStreamArgs) bool {
	return true
}

func (_ DefaultInputFileArgumentsStategy) Process(ctx workflow.Context, args EncodeStreamArgs) []FFMpegArg {
	return []FFMpegArg{}
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
func (m mpeg2videoWithBrokenPTS) Process(ctx workflow.Context, args EncodeStreamArgs) []FFMpegArg {
	return []FFMpegArg{
		NewFFMpegArg(KindString, "-fflags"),
		NewFFMpegArg(KindString, "+genpts+igndts"),
		NewFFMpegArg(KindString, "-copyts"),
		NewFFMpegArg(KindString, "-start_at_zero"),
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

func inputDirFileStrategy(ctx workflow.Context, args EncodeStreamArgs) []FFMpegArg {
	inputArgsStrategy := selectInputFileArgumentsStrategy(ctx, args)
	return append(
		inputArgsStrategy.Process(ctx, args),
		NewFFMpegArg(KindString, "-i"), NewFFMpegArg(KindDirFile, DirFile{
			Dir:   filepath.Dir(ResolveInputNumber(ctx, args.InputID, args.InputNo)),
			Fname: filepath.Base(ResolveInputNumber(ctx, args.InputID, args.InputNo)),
		}))
}

func inputDirFileWithMapStrategy(ctx workflow.Context, args EncodeStreamArgs) []FFMpegArg {
	return []FFMpegArg{
		//"-copyts",
		NewFFMpegArg(KindString, "-i"), NewFFMpegArg(KindDirFile, DirFile{
			Dir:   filepath.Dir(ResolveInputNumber(ctx, args.InputID, args.InputNo)),
			Fname: filepath.Base(ResolveInputNumber(ctx, args.InputID, args.InputNo)),
		}),
		NewFFMpegArg(KindString, "-map"), NewFFMpegArg(KindString, "0:"+args.Stream),
	}
}

func videoFilterStrategy(ctx workflow.Context, args EncodeStreamArgs, deinterlaceFilter string) []FFMpegArg {
	scaleFilter := scaleFilter(ctx, args)
	return []FFMpegArg{NewFFMpegArg(KindString, "-filter_complex"),
		NewFFMpegArg(KindString, strings.Join([]string{
			interlaceIfNeeded("0:v:0", "postdeint", deinterlaceFilter),
			scaleIfNeeded("postdeint", "out", scaleFilter)}, ";")),
		NewFFMpegArg(KindString, "-map"), NewFFMpegArg(KindString, "[out]"),
	}
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

func languageFromArgs(args EncodeStreamArgs) []FFMpegArg {
	if args.Language != "" {
		slog.Info("setting lang", "to", args.Language)
		return []FFMpegArg{
			NewFFMpegArg(KindString, "-metadata:s:0"),
			NewFFMpegArg(KindString, "language="+args.Language),
		}
	}
	slog.Info("NO language")
	return []FFMpegArg{}
}
func XnullStrategy(_ EncodeStreamArgs) []FFMpegArg {
	return []FFMpegArg{}
}
func x264EncodingStrategy(gopFrames int, crf string, bitrate string) func(args EncodeStreamArgs) []FFMpegArg {
	gopFramesStr := fmt.Sprintf("%d", gopFrames)
	return func(args EncodeStreamArgs) []FFMpegArg {
		ffmpegArgs := []FFMpegArg{
			NewFFMpegArg(KindString, "-c:v"), NewFFMpegArg(KindString, "libx264"),
			NewFFMpegArg(KindString, "-profile:v"), NewFFMpegArg(KindString, "high"),
			NewFFMpegArg(KindString, "-level:v"), NewFFMpegArg(KindString, "4.1"),
			NewFFMpegArg(KindString, "-pix_fmt"), NewFFMpegArg(KindString, "yuv420p"),
			NewFFMpegArg(KindString, "-crf:v"), NewFFMpegArg(KindString, crf),
			NewFFMpegArg(KindString, "-preset:v"), NewFFMpegArg(KindString, args.Preset)}
		ffmpegArgs = append(ffmpegArgs, tune("x264", args.Kind)...)
		ffmpegArgs = append(ffmpegArgs,
			NewFFMpegArg(KindString, "-x264-params:v"), NewFFMpegArg(KindString, "keyint="+gopFramesStr+":min-keyint="+gopFramesStr+":scenecut=0:open-gop=0:strict-gop=1:b-pyramid=0:vbv-maxrate="+bitrate+":vbv-bufsize="+bufSize(bitrate)+":crf-max="+crfMax(crf)+":no-deblock=0:cabac=1:8x8dct=1"))

		ffmpegArgs = append(ffmpegArgs, []FFMpegArg{NewFFMpegArg(KindString, "-fps_mode"), NewFFMpegArg(KindString, "cfr")}...)
		return ffmpegArgs
	}
}
func x265EncodingStrategy(gopFrames int, crf string, bitrate string) func(args EncodeStreamArgs) []FFMpegArg {
	gopFramesStr := fmt.Sprintf("%d", gopFrames)
	return func(args EncodeStreamArgs) []FFMpegArg {
		ffmpegArgs := []FFMpegArg{
			NewFFMpegArg(KindString, "-c:v"), NewFFMpegArg(KindString, "libx265"),
			NewFFMpegArg(KindString, "-profile:v"), NewFFMpegArg(KindString, "main10"),
			NewFFMpegArg(KindString, "-level:v"), NewFFMpegArg(KindString, "5.1"),
			NewFFMpegArg(KindString, "-pix_fmt"), NewFFMpegArg(KindString, "yuv420p10le"),
			NewFFMpegArg(KindString, "-crf:v"), NewFFMpegArg(KindString, crf),
			NewFFMpegArg(KindString, "-preset:v"), NewFFMpegArg(KindString, args.Preset),
		}
		ffmpegArgs = append(ffmpegArgs, tune("x265", args.Kind)...)
		ffmpegArgs = append(ffmpegArgs,
			NewFFMpegArg(KindString, "-tag:v"), NewFFMpegArg(KindString, "hvc1"),
			NewFFMpegArg(KindString, "-x265-params:v"), NewFFMpegArg(KindString, "keyint="+gopFramesStr+":min-keyint="+gopFramesStr+":scenecut=0:open-gop=0:vbv-maxrate="+bitrate+":vbv-bufsize="+bufSize(bitrate)))
		ffmpegArgs = append(ffmpegArgs, []FFMpegArg{NewFFMpegArg(KindString, "-fps_mode"), NewFFMpegArg(KindString, "cfr")}...)
		return ffmpegArgs
	}
}
func aac2cEncodingStrategy(args EncodeStreamArgs) []FFMpegArg {
	return []FFMpegArg{
		NewFFMpegArg(KindString, "-vn"),
		NewFFMpegArg(KindString, "-c"), NewFFMpegArg(KindString, "aac"),
		NewFFMpegArg(KindString, "-aac_coder"), NewFFMpegArg(KindString, "twoloop"),
		//"-frame_size", "960",
		NewFFMpegArg(KindString, "-b:a"), NewFFMpegArg(KindString, "448k"),
		NewFFMpegArg(KindString, "-ar"), NewFFMpegArg(KindString, "48000"),
		//FIXME: Keep mono as mono. Dont upsample
		NewFFMpegArg(KindString, "-ac"), NewFFMpegArg(KindString, "2"),
		//"-af", "aresample=async=1",
		NewFFMpegArg(KindString, "-af"), NewFFMpegArg(KindString, "aresample=async=1:comp_duration=1:max_soft_comp=0.05"),
	}
}

func copyStreamStrategy(args EncodeStreamArgs) []FFMpegArg {
	return []FFMpegArg{
		NewFFMpegArg(KindString, "-c"), NewFFMpegArg(KindString, "copy"),
	}
}

/*
	func HLSManifestStrategy(args EncodeStreamArgs) []FFMpegArg {
		return []FFMpegArg{
			"-map_chapters", "-1",
			"-map_metadata", "-1",
			"-movflags", "+faststart+disable_chpl",
			"-hls_time", "3.84", //FIXME
			"-hls_list_size", "0",
			"-hls_flags", "single_file",
			"-hls_playlist_type", "static",
			DasherReadyRepresentationFilePath(args),
		}
	}
*/
func dashManifestStrategy(ctx workflow.Context, args EncodeStreamArgs) []FFMpegArg {
	return []FFMpegArg{
		NewFFMpegArg(KindString, "-map_chapters"), NewFFMpegArg(KindString, "-1"),
		NewFFMpegArg(KindString, "-map_metadata"), NewFFMpegArg(KindString, "-1"),
		//These are supposedly needed if ffmpeg does the dash packaging (not using e.g. mp4box)
		//"-movflags", "frag_keyframe+empty_moov+default_base_moof",
		NewFFMpegArg(KindString, "-movflags"), NewFFMpegArg(KindString, "faststart"),
		NewFFMpegArg(KindString, "-y"),
		/*
			NewFFMpegArg(KindDirFile, DirFile{
				Dir:   filepath.Dir(TranscodedRepresentationFilePath(ctx, args)),
				Fname: filepath.Base(TranscodedRepresentationFilePath(ctx, args)),
			}),*/
		NewFFMpegArg(KindTranscodedRepesentationFilePath, TranscodedRepesentationFilePath{ESA: args}),
	}
}

type InputStrategy func(ctx workflow.Context, args EncodeStreamArgs) []FFMpegArg
type EncodingStrategy func(args EncodeStreamArgs) []FFMpegArg
type LanguageStrategy func(args EncodeStreamArgs) []FFMpegArg
type ManifestStrategy func(ctx workflow.Context, args EncodeStreamArgs) []FFMpegArg
type DurationDeriverUsec func(ctx workflow.Context, inputID string, inputNo int, stream string) (int64, error)
type QueueSelector func(args EncodeStreamArgs) string

func CallMP4BoxDashReadyPrepare(ctx workflow.Context, args EncodeStreamArgs) (MP4BoxDashReadyArgs, error) {
	return CallActivityIO[EncodeStreamArgs, MP4BoxDashReadyArgs](ctx, MP4BoxDashReadyPrepare, args)
}

func CallMP4BoxDashReadyExecute(ctx workflow.Context, args MP4BoxDashReadyArgs) (MP4BoxDashReadyResp, error) {
	return CallActivityIO[MP4BoxDashReadyArgs, MP4BoxDashReadyResp](ctx, MP4BoxDashReadyExecute, args)
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

	Preset       Preset
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

func WithPreset(p Preset) TranscodeOption {
	return func(j *EncodeStreamArgs) {
		j.Preset = p
	}
}

func TranscodingPipelineFactory(ctx workflow.Context, args EncodeStreamArgs) TranscodingPipeline {
	res := TranscodingPipeline{}
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
	default:
		slog.Error("UNSUPPORTED CODEC", "codec", args.Codec)
		return TranscodingPipeline{}
	}
	res.durationDeriver = durationDeriverFfmpeg
	res.encoderQueue = QueueSelectorLocal
	return res
}

type TranscodingPipeline struct {
	inputStrategy    InputStrategy
	encodingStrategy EncodingStrategy
	languageStrategy LanguageStrategy
	manifestStrategy ManifestStrategy
	durationDeriver  DurationDeriverUsec
	encoderQueue     QueueSelector
}

func (m TranscodingPipeline) FfmpegArgs(ctx workflow.Context, args EncodeStreamArgs, probeRawData ProbeRawData) (FFMpegArgs, error) {
	var ffmpegArgs []FFMpegArg
	ffmpegArgs = append(ffmpegArgs, m.inputStrategy(ctx, args)...)
	if isVideoCodec(args.Codec) {
		filterRec := DeriveFilterRecommendation(probeRawData)
		ffmpegArgs = append(ffmpegArgs, videoFilterStrategy(ctx, args, filterRec.FilterRecommendation)...)
	}
	ffmpegArgs = append(ffmpegArgs, m.encodingStrategy(args)...)
	ffmpegArgs = append(ffmpegArgs, m.languageStrategy(args)...)
	ffmpegArgs = append(ffmpegArgs, m.manifestStrategy(ctx, args)...)

	return CallNewFFMpegArgs(ctx, ffmpegArgs)
}

func (m TranscodingPipeline) MP4BoxArgs(ctx workflow.Context, args EncodeStreamArgs) (MP4BoxDashReadyArgs, error) {
	args.DstProps.DashMs = dashMs2(gopFrames(ctx, args.InputID), 25)
	return CallMP4BoxDashReadyPrepare(ctx, args)
}

func (m TranscodingPipeline) NeedsProcessing(t TranscodingOptionsRecord, ffmpegArgsExpanded FFMpegArgs, dashReadyArgs MP4BoxDashReadyArgs) string {
	//If either of ffmpeg and mp4box cmd lines differ, we need (re)processing.
	var diffs []string
	if d := cmp.Diff(t.Ffmpegargs, ffmpegArgsExpanded); d != "" {
		diffs = append(diffs, d)
	}
	if d := cmp.Diff(t.MP4BoxDashReadyArgs.MP4BoxArgs, dashReadyArgs.MP4BoxArgs); d != "" {
		diffs = append(diffs, d)
	}
	return strings.Join(diffs, "\n")
}

func (m TranscodingPipeline) Process(ctx workflow.Context, args EncodeStreamArgs, ffmpegArgsExpanded FFMpegArgs, mp4boxargs MP4BoxDashReadyArgs) error {

	if err := os.MkdirAll(ProdDir(ctx, args.InputID), os.ModePerm); err != nil {
		return err
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
		ESA:        args,
	}).Get(ctx2, &encodePreludeResp)
	if err != nil {
		slog.Error(" FfmpegEncodePreludefailed", "err", err.Error())
		return err
	}

	var ffmpegEncodeResp EncodeResp
	err = workflow.ExecuteActivity(ctx2, a.Encode, EncodeArgs{
		SessionID:       sessionID,
		FfmpegArgs:      ffmpegArgsExpanded,
		ESA:             args,
		TotalDurationUs: duration,
	}).Get(ctx2, &ffmpegEncodeResp)
	if err != nil {
		slog.Error("activity failed", "err", err.Error())
		return err
	}

	err = workflow.ExecuteActivity(ctx2, a.EncodePostlude, EncodePostludeArgs{
		SessionID:  sessionID,
		FfmpegArgs: ffmpegArgsExpanded,
		ESA:        args,
	}).Get(ctx2, nil)

	mp4boxresp, err := CallMP4BoxDashReadyExecute(ctx, mp4boxargs)
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
