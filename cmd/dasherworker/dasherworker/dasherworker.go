package dasherworker

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/deinterlacer"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/localEncode"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/mp4boxDashReady"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/transcodingOptionsRecorder"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"
	"go.temporal.io/sdk/workflow"
)

var targets = []Target{
	//{"x264", "high"},
	{"x264", "low"},
	//{"x265", "high"},
	//{"x265", "low"},
	//{"aac", ""},
	{"vtt", ""},
}

type EnsureDashWFArgs struct {
	MspPath string
	Fast    bool
}

func EnsureDashWF(ctx workflow.Context, args EnsureDashWFArgs) (string, error) {
	M, err := CallReadMspFile(ctx, args.MspPath)
	if err != nil {
		return "", err
	}

	var VprobeRawData deinterlacer.ProbeRawData
	for _, target := range targets {
		//if a target calls for video, probe the input source
		if shared.IsVideoCodec(target.Codec) {
			idx := shared.GetFirstInputStreamWithPrefix(M.Inputs, "v")
			if idx == -1 {
				return "", shared.Error("Found no video stream source specified", "input", M)
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
	var languages []string
	for idx, future := range futures {
		switch {
		case shared.IsSubtitlesCodec(targets[idx].Codec):
			var resp CreateRepresentationResp
			if err := future.Get(ctx, &resp); err != nil {
				return "", shared.Error("Child WF execution failed", "err", err)
			}
			spew.Dump(resp)
			languages = append(languages, resp.Language)
		default:
			if err := future.Get(ctx, nil); err != nil {
				return "", shared.Error("Child WF execution failed", "err", err)
			}
		}
	}

	if _, err = CallFinalize(ctx, M.Id, true); err != nil {
		return "", err
	}
	if _, err := CallVttStitch(ctx, M.Id, languages); err != nil {
		return "", err
	}
	slog.Info("Sitched in languages", "languages", languages)
	return "", nil

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
	ProbeRawData deinterlacer.ProbeRawData
}

type CreateRepresentationResp struct {
	Language string //Returned by VttEx
}

func CreateRepresentation(ctx workflow.Context, args CreateRepresentationArgs) (CreateRepresentationResp, error) {
	slog.Info("Start", "W", "CreateRepresentation", "msp", args.MspFile, "target", args.Target)
	defer slog.Info("Stop ", "W", "CreateRepresentation", "msp", args.MspFile, "target", args.Target)

	M, err := CallReadMspFile(ctx, filepath.Join(args.Dir, args.MspFile))
	if err != nil {
		slog.Error("MSP read failed", "err", err)
	}

	//Find the encoding needs
	var opts []TranscodeOption

	var idx int
	switch {
	case shared.IsVideoCodec(args.Target.Codec):
		idx = shared.GetFirstInputStreamWithPrefix(M.Inputs, "v")
		if idx == -1 {
			return CreateRepresentationResp{}, shared.Error("Found no video stream source specified", "input", M)
		}
		var maxRes TranscodeOption
		switch args.Target.Profile {
		case "high":
			maxRes = WithMaxResolution(shared.Max1080p)
		case "low":
			maxRes = WithMaxResolution(shared.Max480p)
		}
		opts = append(opts, maxRes)
		opts = append(opts, WithPreset(preset(args.Fast)))
	case shared.IsAudioCodec(args.Target.Codec):
		idx = shared.GetFirstInputStreamWithPrefix(M.Inputs, "a")
		if idx == -1 {
			return CreateRepresentationResp{}, shared.Error("Found no audio stream source specified", "input", M)
		}
	case shared.IsSubtitlesCodec(args.Target.Codec):
		idx = shared.GetFirstInputStreamWithPrefix(M.Inputs, "s")
		if idx == -1 {
			return CreateRepresentationResp{}, nil
		}
		if lang, err := CallExtractVtt(ctx, M.Id, idx, M.Inputs[idx].Stream); err != nil {
			return CreateRepresentationResp{}, err
		} else {
			return CreateRepresentationResp{Language: lang}, nil
		}

		return CreateRepresentationResp{}, err
	default:
		return CreateRepresentationResp{}, shared.Fatal("Unsupported target codec", "codec", args.Target.Codec)
	}

	Eargs := NewEncodeStreamArgs(ctx, &shared.EncodeStreamArgs{
		InputID:  M.Id,
		InputNo:  idx,
		Stream:   M.Inputs[idx].Stream,
		Kind:     M.Inputs[idx].Kind,
		Language: M.Inputs[idx].Language,
		Profile:  args.Target.Profile,
		Codec:    args.Target.Codec,
	}, opts...)
	slog.Info("Creating representation", "shortName", M.ShortName, "codec", Eargs.Codec, "profile", Eargs.Profile)
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

func scaleFilter(ctx workflow.Context, args shared.EncodeStreamArgs) string {
	if args.VideoFilters.MaxResolution.Width > 0 {
		//return "scale='if(gt(iw,ih),min(" + strconv.Itoa(args.VideoFilters.MaxResolution.Width) + ",iw),-2)':'if(gt(iw,ih),-2,min(" + strconv.Itoa(args.VideoFilters.MaxResolution.Height) + ",ih))'"
		width, height, SAR, err := CallGetStreamDimensions(ctx, args.InputID, args.InputNo, args.Stream)

		if err != nil {
			slog.Error("Failed to get Stream dimensions", "err", err)
			return ""
		}
		return scalingFilter(shared.Resolution{Width: width, Height: height}, SAR, args.VideoFilters.MaxResolution)

	}
	return ""
}
func tune(codec string, kind string) []shared.FFMpegArg {
	switch codec {
	case "x264":
		switch kind {
		case "animation":
			return []shared.FFMpegArg{shared.NewFFMpegArg(shared.KindString, "-tune:v"), shared.NewFFMpegArg(shared.KindString, "animation")}
		default:
			return []shared.FFMpegArg{shared.NewFFMpegArg(shared.KindString, "-tune:v"), shared.NewFFMpegArg(shared.KindString, "film")}
		}
	case "x265":
		switch kind {
		case "animation":
			return []shared.FFMpegArg{shared.NewFFMpegArg(shared.KindString, "-tune:v"), shared.NewFFMpegArg(shared.KindString, "animation")}
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

func preset(fast bool) shared.Preset {
	if fast {
		return "ultrafast"
	} else {
		return "slow"
	}
}

type inputFileArgumentsStrategy interface {
	CanHandle(ctx workflow.Context, args shared.EncodeStreamArgs) bool
	Process(ctx workflow.Context, args shared.EncodeStreamArgs) []shared.FFMpegArg
}

var inputFileArgumentsStrategies = []inputFileArgumentsStrategy{
	mpeg2videoWithBrokenPTS{},
}

type DefaultInputFileArgumentsStategy struct {
}

func (_ DefaultInputFileArgumentsStategy) CanHandle(ctx workflow.Context, args shared.EncodeStreamArgs) bool {
	return true
}

func (_ DefaultInputFileArgumentsStategy) Process(ctx workflow.Context, args shared.EncodeStreamArgs) []shared.FFMpegArg {
	return []shared.FFMpegArg{}
}

type mpeg2videoWithBrokenPTS struct {
}

func (m mpeg2videoWithBrokenPTS) CanHandle(ctx workflow.Context, args shared.EncodeStreamArgs) bool {
	isBroken, err := CallIsMpeg2VideoWithBrokenDTS(ctx, args.InputID, args.InputNo, args.Stream)
	if err != nil {
		slog.Error("Failed to parse file", "err", err)
		return false
	}
	return isBroken
}
func (m mpeg2videoWithBrokenPTS) Process(ctx workflow.Context, args shared.EncodeStreamArgs) []shared.FFMpegArg {
	return []shared.FFMpegArg{
		shared.NewFFMpegArg(shared.KindString, "-fflags"),
		shared.NewFFMpegArg(shared.KindString, "+genpts+igndts"),
		shared.NewFFMpegArg(shared.KindString, "-copyts"),
		shared.NewFFMpegArg(shared.KindString, "-start_at_zero"),
	}
}

func selectInputFileArgumentsStrategy(ctx workflow.Context, args shared.EncodeStreamArgs) inputFileArgumentsStrategy {
	for _, strategy := range inputFileArgumentsStrategies {
		if strategy.CanHandle(ctx, args) {
			return strategy
		}
	}
	return DefaultInputFileArgumentsStategy{}
}

func inputDirFileStrategy(ctx workflow.Context, args shared.EncodeStreamArgs) []shared.FFMpegArg {
	inputArgsStrategy := selectInputFileArgumentsStrategy(ctx, args)
	return append(
		inputArgsStrategy.Process(ctx, args),
		shared.NewFFMpegArg(shared.KindString, "-i"), shared.NewFFMpegArg(shared.KindInputFilePath, shared.InputFilePath{Id: args.InputID, Number: args.InputNo}),
	)

}

func inputDirFileWithMapStrategy(ctx workflow.Context, args shared.EncodeStreamArgs) []shared.FFMpegArg {
	return []shared.FFMpegArg{
		shared.NewFFMpegArg(shared.KindString, "-i"), shared.NewFFMpegArg(shared.KindInputFilePath, shared.InputFilePath{Id: args.InputID, Number: args.InputNo}),
		shared.NewFFMpegArg(shared.KindString, "-map"), shared.NewFFMpegArg(shared.KindString, "0:"+args.Stream),
	}
}

func videoFilterStrategy(ctx workflow.Context, args shared.EncodeStreamArgs, deinterlaceFilter string) []shared.FFMpegArg {
	scaleFilter := scaleFilter(ctx, args)
	return []shared.FFMpegArg{shared.NewFFMpegArg(shared.KindString, "-filter_complex"),
		shared.NewFFMpegArg(shared.KindString, strings.Join([]string{
			interlaceIfNeeded("0:v:0", "postdeint", deinterlaceFilter),
			scaleIfNeeded("postdeint", "out", scaleFilter)}, ";")),
		shared.NewFFMpegArg(shared.KindString, "-map"), shared.NewFFMpegArg(shared.KindString, "[out]"),
	}
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

func languageFromArgs(args shared.EncodeStreamArgs) []shared.FFMpegArg {
	if args.Language != "" {
		slog.Info("setting lang", "to", args.Language)
		return []shared.FFMpegArg{
			shared.NewFFMpegArg(shared.KindString, "-metadata:s:0"),
			shared.NewFFMpegArg(shared.KindString, "language="+args.Language),
		}
	}
	slog.Info("NO language")
	return []shared.FFMpegArg{}
}
func vttEncodingStrategy() func(args shared.EncodeStreamArgs) []shared.FFMpegArg {
	return func(args shared.EncodeStreamArgs) []shared.FFMpegArg {
		return nil
	}
}

func x264EncodingStrategy(gopFrames int, crf string, bitrate string) func(args shared.EncodeStreamArgs) []shared.FFMpegArg {
	gopFramesStr := fmt.Sprintf("%d", gopFrames)
	return func(args shared.EncodeStreamArgs) []shared.FFMpegArg {
		ffmpegArgs := []shared.FFMpegArg{
			shared.NewFFMpegArg(shared.KindString, "-c:v"), shared.NewFFMpegArg(shared.KindString, "libx264"),
			shared.NewFFMpegArg(shared.KindString, "-profile:v"), shared.NewFFMpegArg(shared.KindString, "high"),
			shared.NewFFMpegArg(shared.KindString, "-level:v"), shared.NewFFMpegArg(shared.KindString, "4.1"),
			shared.NewFFMpegArg(shared.KindString, "-pix_fmt"), shared.NewFFMpegArg(shared.KindString, "yuv420p"),
			shared.NewFFMpegArg(shared.KindString, "-crf:v"), shared.NewFFMpegArg(shared.KindString, crf),
			shared.NewFFMpegArg(shared.KindString, "-preset:v"), shared.NewFFMpegArg(shared.KindString, args.Preset)}
		ffmpegArgs = append(ffmpegArgs, tune("x264", args.Kind)...)
		ffmpegArgs = append(ffmpegArgs,
			shared.NewFFMpegArg(shared.KindString, "-x264-params:v"), shared.NewFFMpegArg(shared.KindString, "keyint="+gopFramesStr+":min-keyint="+gopFramesStr+":no-scenecut=1:scenecut-intra=1:open-gop=1:b-pyramid=1:vbv-maxrate="+bitrate+":vbv-bufsize="+bufSize(bitrate)+":crf-max="+crfMax(crf)+":no-deblock=0:cabac=1:8x8dct=1"))

		ffmpegArgs = append(ffmpegArgs, []shared.FFMpegArg{shared.NewFFMpegArg(shared.KindString, "-fps_mode"), shared.NewFFMpegArg(shared.KindString, "cfr")}...)
		return ffmpegArgs
	}
}
func x265EncodingStrategy(gopFrames int, crf string, bitrate string) func(args shared.EncodeStreamArgs) []shared.FFMpegArg {
	gopFramesStr := fmt.Sprintf("%d", gopFrames)
	return func(args shared.EncodeStreamArgs) []shared.FFMpegArg {
		ffmpegArgs := []shared.FFMpegArg{
			shared.NewFFMpegArg(shared.KindString, "-c:v"), shared.NewFFMpegArg(shared.KindString, "libx265"),
			shared.NewFFMpegArg(shared.KindString, "-profile:v"), shared.NewFFMpegArg(shared.KindString, "main10"),
			shared.NewFFMpegArg(shared.KindString, "-level:v"), shared.NewFFMpegArg(shared.KindString, "5.1"),
			shared.NewFFMpegArg(shared.KindString, "-pix_fmt"), shared.NewFFMpegArg(shared.KindString, "yuv420p10le"),
			shared.NewFFMpegArg(shared.KindString, "-crf:v"), shared.NewFFMpegArg(shared.KindString, crf),
			shared.NewFFMpegArg(shared.KindString, "-preset:v"), shared.NewFFMpegArg(shared.KindString, args.Preset),
		}
		ffmpegArgs = append(ffmpegArgs, tune("x265", args.Kind)...)
		ffmpegArgs = append(ffmpegArgs,
			shared.NewFFMpegArg(shared.KindString, "-tag:v"), shared.NewFFMpegArg(shared.KindString, "hvc1"),
			shared.NewFFMpegArg(shared.KindString, "-x265-params:v"), shared.NewFFMpegArg(shared.KindString, "keyint="+gopFramesStr+":min-keyint="+gopFramesStr+":no-scenecut=1:scenecut-intra=1:open-gop=1:b-intra=1:bframes=4:vbv-maxrate="+bitrate+":vbv-bufsize="+bufSize(bitrate)))
		ffmpegArgs = append(ffmpegArgs, []shared.FFMpegArg{shared.NewFFMpegArg(shared.KindString, "-fps_mode"), shared.NewFFMpegArg(shared.KindString, "cfr")}...)
		return ffmpegArgs
	}
}
func aac2cEncodingStrategy(args shared.EncodeStreamArgs) []shared.FFMpegArg {
	return []shared.FFMpegArg{
		shared.NewFFMpegArg(shared.KindString, "-vn"),
		shared.NewFFMpegArg(shared.KindString, "-c"), shared.NewFFMpegArg(shared.KindString, "aac"),
		shared.NewFFMpegArg(shared.KindString, "-aac_coder"), shared.NewFFMpegArg(shared.KindString, "twoloop"),
		//"-frame_size", "960",
		shared.NewFFMpegArg(shared.KindString, "-b:a"), shared.NewFFMpegArg(shared.KindString, "448k"),
		shared.NewFFMpegArg(shared.KindString, "-ar"), shared.NewFFMpegArg(shared.KindString, "48000"),
		//FIXME: Keep mono as mono. Dont upsample
		shared.NewFFMpegArg(shared.KindString, "-ac"), shared.NewFFMpegArg(shared.KindString, "2"),
		//"-af", "aresample=async=1",
		shared.NewFFMpegArg(shared.KindString, "-af"), shared.NewFFMpegArg(shared.KindString, "aresample=async=1:comp_duration=1:max_soft_comp=0.05"),
	}
}

func copyStreamStrategy(args shared.EncodeStreamArgs) []shared.FFMpegArg {
	return []shared.FFMpegArg{
		shared.NewFFMpegArg(shared.KindString, "-c"), shared.NewFFMpegArg(shared.KindString, "copy"),
	}
}

/*
	func HLSManifestStrategy(args shared.EncodeStreamArgs) []shared.FFMpegArg {
		return []shared.FFMpegArg{
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
func dashManifestStrategy(ctx workflow.Context, args shared.EncodeStreamArgs) []shared.FFMpegArg {
	return []shared.FFMpegArg{
		shared.NewFFMpegArg(shared.KindString, "-map_chapters"), shared.NewFFMpegArg(shared.KindString, "-1"),
		shared.NewFFMpegArg(shared.KindString, "-map_metadata"), shared.NewFFMpegArg(shared.KindString, "-1"),
		//These are supposedly needed if ffmpeg does the dash packaging (not using e.g. mp4box)
		//"-movflags", "frag_keyframe+empty_moov+default_base_moof",
		shared.NewFFMpegArg(shared.KindString, "-movflags"), shared.NewFFMpegArg(shared.KindString, "faststart"),
		shared.NewFFMpegArg(shared.KindString, "-y"),
		shared.NewFFMpegArg(shared.KindTranscodedRepesentationFilePath, shared.TranscodedRepesentationFilePath{ESA: args}),
	}
}

func sidecarStrategy(ctx workflow.Context, args shared.EncodeStreamArgs) []shared.FFMpegArg {
	return []shared.FFMpegArg{
		shared.NewFFMpegArg(shared.KindString, "-y"),
		shared.NewFFMpegArg(shared.KindSubtitlesRepresentationFilePath, shared.SubtitlesRepresentationFilePath{ESA: args}),
	}
}

type InputStrategy func(ctx workflow.Context, args shared.EncodeStreamArgs) []shared.FFMpegArg
type EncodingStrategy func(args shared.EncodeStreamArgs) []shared.FFMpegArg
type LanguageStrategy func(args shared.EncodeStreamArgs) []shared.FFMpegArg
type ManifestStrategy func(ctx workflow.Context, args shared.EncodeStreamArgs) []shared.FFMpegArg
type DurationDeriverUsec func(ctx workflow.Context, inputID string, inputNo int, stream string) (int64, error)
type QueueSelector func(args shared.EncodeStreamArgs) string

func QueueSelectorLocal(args shared.EncodeStreamArgs) string {
	var queue string
	if shared.IsVideoCodec(args.Codec) {
		queue = "encodingQueue"
	} else {
		queue = "dasherQueue"
	}
	return queue
}

func NewEncodeStreamArgs(ctx workflow.Context, base *shared.EncodeStreamArgs, opts ...TranscodeOption) *shared.EncodeStreamArgs {
	//Apply provided functions
	for _, opt := range opts {
		opt(base)
	}

	return base
}

type TranscodeOption func(*shared.EncodeStreamArgs)

func WithMaxResolution(maxx shared.Resolution) TranscodeOption {
	return func(j *shared.EncodeStreamArgs) {
		j.VideoFilters.MaxResolution = maxx
	}
}

func WithPreset(p shared.Preset) TranscodeOption {
	return func(j *shared.EncodeStreamArgs) {
		j.Preset = p
	}
}

func TranscodingPipelineFactory(ctx workflow.Context, args shared.EncodeStreamArgs) TranscodingPipeline {
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
	case "vtt":
		res.inputStrategy = inputDirFileWithMapStrategy
		res.encodingStrategy = vttEncodingStrategy()
		res.languageStrategy = languageFromArgs
		res.manifestStrategy = sidecarStrategy
	default:
		slog.Error("UNSUPPORTED CODEC", "codec", args.Codec)
		return TranscodingPipeline{}
	}
	res.durationDeriver = CallDurationDeriverFfmpeg
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

func (m TranscodingPipeline) FfmpegArgs(ctx workflow.Context, args shared.EncodeStreamArgs, probeRawData deinterlacer.ProbeRawData) (shared.FFMpegArgs, error) {
	var ffmpegArgs []shared.FFMpegArg
	ffmpegArgs = append(ffmpegArgs, m.inputStrategy(ctx, args)...)
	if shared.IsVideoCodec(args.Codec) {
		filterRec := deinterlacer.DeriveFilterRecommendation(probeRawData, args)
		ffmpegArgs = append(ffmpegArgs, videoFilterStrategy(ctx, args, filterRec.FilterRecommendation)...)
	}
	ffmpegArgs = append(ffmpegArgs, m.encodingStrategy(args)...)
	ffmpegArgs = append(ffmpegArgs, m.languageStrategy(args)...)
	ffmpegArgs = append(ffmpegArgs, m.manifestStrategy(ctx, args)...)

	return CallFFMpegArgsProcessorProcess(ctx, ffmpegArgs)
}

func (m TranscodingPipeline) MP4BoxArgs(ctx workflow.Context, args shared.EncodeStreamArgs) (mp4boxDashReady.MP4BoxDashReadyArgs, error) {
	args.DstProps.DashMs = shared.DashMs2(gopFrames(ctx, args.InputID), 25)
	return CallMP4BoxDashReadyPrepare(ctx, args)
}

func (m TranscodingPipeline) NeedsProcessing(t transcodingOptionsRecorder.TranscodingOptionsRecord, ffmpegArgsExpanded shared.FFMpegArgs, dashReadyArgs mp4boxDashReady.MP4BoxDashReadyArgs) string {
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

func (m TranscodingPipeline) Process(ctx workflow.Context, args shared.EncodeStreamArgs, ffmpegArgsExpanded shared.FFMpegArgs, mp4boxargs mp4boxDashReady.MP4BoxDashReadyArgs) error {

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
	//defer workflow.CompleteSession(sessionCtx)
	defer func() {
		if r := recover(); r != nil {
			// 1. Log or print the actual internal panic that caused line 40 to fail
			slog.Error("Workflow panicked before session completion", "panic", r)

			// 2. Clear or stop the panic state so Temporal is allowed to safely yield/block
			// (Alternatively, you can handle the cleanup or re-panic at the very end of the function)
		}

		// Now it is completely safe for CompleteSession to await channels over the network!
		workflow.CompleteSession(sessionCtx)
	}()

	ctx2 := workflow.WithActivityOptions(sessionCtx, workflow.ActivityOptions{
		StartToCloseTimeout: 24 * time.Hour,
		HeartbeatTimeout:    10 * time.Minute,
	})

	var encodePreludeResp shared.EncodePreludeResp
	var a *localEncode.LocalEncode
	//spew.Dump(ffmpegArgs)
	err = workflow.ExecuteActivity(ctx2, a.EncodePrelude, shared.EncodePreludeArgs{
		SessionID:  sessionID,
		FfmpegArgs: ffmpegArgsExpanded,
		ESA:        args,
	}).Get(ctx2, &encodePreludeResp)
	if err != nil {
		slog.Error(" FfmpegEncodePreludefailed", "err", err.Error())
		return err
	}

	var ffmpegEncodeResp shared.EncodeResp
	err = workflow.ExecuteActivity(ctx2, a.Encode, shared.EncodeArgs{
		SessionID:       sessionID,
		FfmpegArgs:      ffmpegArgsExpanded,
		ESA:             args,
		TotalDurationUs: duration,
	}).Get(ctx2, &ffmpegEncodeResp)
	if err != nil {
		slog.Error("activity failed", "err", err.Error())
		return err
	}

	err = workflow.ExecuteActivity(ctx2, a.EncodePostlude, shared.EncodePostludeArgs{
		SessionID:  sessionID,
		FfmpegArgs: ffmpegArgsExpanded,
		ESA:        args,
	}).Get(ctx2, nil)

	mp4boxresp, err := CallMP4BoxDashReadyExecute(ctx, mp4boxargs)
	if err != nil {
		return shared.Error("Packager failed", "err", err)
	}

	t := transcodingOptionsRecorder.TranscodingOptionsRecord{
		EncodeStream:        args,
		Ffmpegargs:          ffmpegArgsExpanded,
		Stderr:              ffmpegEncodeResp.Stderr,
		MP4BoxDashReadyArgs: mp4boxargs,
		MP4Box: transcodingOptionsRecorder.Invocation{
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
