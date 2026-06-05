package dasherworker

import (
	"bytes"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/andersthomson/mediaserver/scrape"
	"github.com/davecgh/go-spew/spew"
	"github.com/natefinch/atomic"
	"github.com/pkg/errors"
	"go.temporal.io/sdk/workflow"
)

func Input(streamno int, m scrape.Msp) (scrape.InputT, error) {
	splits := strings.Split(m.Dash.Streams[streamno].Source, ":")
	inputNumber, err := strconv.Atoi(splits[0])
	if err != nil {
		return scrape.InputT{}, errors.WithStack(err)
	}
	return m.Inputs[inputNumber], nil
}
func InputFName(streamno int, m scrape.Msp) (string, error) {
	var inputNumber int
	var err error
	if m.Dash.Streams[streamno].Source != "" {
		splits := strings.Split(m.Dash.Streams[streamno].Source, ":")
		inputNumber, err = strconv.Atoi(splits[0])
		if err != nil {
			return "", errors.WithStack(err)
		}
		if inputNumber+1 > len(m.Inputs) {
			return "", errors.WithStack(fmt.Errorf("inputnumber out of bounds %v", m))
		}
		return m.Inputs[inputNumber].Filename, nil
	}
	inputNumber = m.Dash.Streams[streamno].ReferenceFile
	if inputNumber+1 > len(m.Inputs) {
		return "", errors.WithStack(fmt.Errorf("inputnumber out of bounds %v", m))
	}
	return m.Inputs[inputNumber].Filename, nil
}

type AllEncodingWorkflowArgs struct {
	Dir     string
	MspFile string
	Fast    bool
}

type AllEncodingWorkflowResp struct {
}

func AllEncodingWorkflow(ctx workflow.Context, args AllEncodingWorkflowArgs) (AllEncodingWorkflowResp, error) {
	slog.Info("Start", "W", "AllEncoding", "msp", args.MspFile)
	defer slog.Info("Stop ", "W", "AllEncoding", "msp", args.MspFile)

	ctx1 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute,
		TaskQueue:           "dasherQueue",
		//HeartbeatTimeout:    1000 * time.Second,
	})
	var M scrape.Msp
	err := workflow.ExecuteActivity(ctx1, ReadMspFile, args.Dir, args.MspFile).Get(ctx1, &M)

	dirTimestamp := workflow.Now(ctx).UTC().Format("2006-01-02T15-04-05Z")
	ProdDir := "/var/cache/mediacache/" + M.ShortName + "-" + M.Id + "/dash"
	DashDir := ProdDir + "." + dirTimestamp

	ctx1 = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute,
		TaskQueue:           "dasherQueue",
		//HeartbeatTimeout:    1000 * time.Second,
	})
	var preludeResp PreludeResp
	err = workflow.ExecuteActivity(ctx1, Prelude, PreludeArgs{
		DashDir: DashDir,
		Dir:     args.Dir,
	}).Get(ctx1, &preludeResp)
	if err != nil {
		return AllEncodingWorkflowResp{}, errors.WithStack(err)
	}

	//Find the encoding needs
	for streamno, stream := range M.Dash.Streams {
		switch stream.Codec {
		case "x264", "x265", "copy", "aac":
			inFname, err := InputFName(streamno, M)
			if err != nil {
				return AllEncodingWorkflowResp{}, errors.WithStack(err)
			}
			//Activity
			ctx1 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
				StartToCloseTimeout: 10 * time.Minute,
				TaskQueue:           "dasherQueue",
				//HeartbeatTimeout:    1000 * time.Second,
			})
			var MediaInterlaceAnalysis MediaInterlaceAnalysis
			err = workflow.ExecuteActivity(ctx1, AnalyzeMediaInterlace, AnalyzeMediaInterlaceArgs{
				Dir:   args.Dir,
				Fname: inFname,
			}).Get(ctx1, &MediaInterlaceAnalysis)
			if err != nil {
				return AllEncodingWorkflowResp{}, errors.WithStack(err)
			}

			drFname := DasherReadyFilename2(inFname, strconv.Itoa(streamno))
			inp, err := Input(streamno, M)
			if err != nil {
				return AllEncodingWorkflowResp{}, errors.WithStack(err)
			}
			args := EncodeStreamArgs{
				InputDirFile:  NewDirFile(args.Dir, inFname),
				Source:        M.Dash.Streams[streamno].Source,
				OutputDirFile: NewDirFile(DashDir, drFname+"-fragmented.mp4"),
				WorkDir:       DashDir,
				Kind:          inp.Kind,
				Preset:        preset(args.Fast),
				Profile:       M.Dash.Streams[streamno].Profile,
				Codec:         M.Dash.Streams[streamno].Codec,
				StreamNo:      streamno,
				Dir:           args.Dir,
				DstProps:      preludeResp.Tprops,
				SrcProps:      MediaInterlaceAnalysis,
			}
			if err := PipelineFactory(args).Process(ctx, args); err != nil {
				slog.Error("Pipeline processing failed", "err", err)
				return AllEncodingWorkflowResp{}, err
			}

		case "reference":

			inputNumber := M.Dash.Streams[streamno].ReferenceFile
			oldFile := args.Dir + "/" + M.Inputs[inputNumber].Filename

			inputFName, err := InputFName(streamno, M)
			if err != nil {
				return AllEncodingWorkflowResp{}, errors.WithStack(err)
			}
			newFilename := DasherReadyFilename2(inputFName, strconv.Itoa(streamno))

			newFile := DashDir + "/" + newFilename
			if _, err := CallLinkSrcMedia(ctx, oldFile, newFile); err != nil {
				return AllEncodingWorkflowResp{}, err
			}
		default:
			return AllEncodingWorkflowResp{}, fmt.Errorf("Msp malformed: Unsupported Codec %s in stream %d\n", stream.Codec, streamno)
		}

	}
	if err := atomic.WriteFile(filepath.Join(DashDir, "gopMs"), bytes.NewReader([]byte(strconv.FormatFloat(preludeResp.Tprops.DashMs, 'f', 0, 64)))); err != nil {
		return AllEncodingWorkflowResp{}, err
	}

	//Finalize
	ctx1 = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 100 * time.Minute,
		TaskQueue:           "dasherQueue",
		//HeartbeatTimeout:    1000 * time.Second,
	})
	err = workflow.ExecuteActivity(ctx1, Finalize, FinalizeArgs{
		TargetDir: DashDir,
		ProdDir:   ProdDir,
		Fast:      args.Fast,
	}).Get(ctx1, nil)
	if err != nil {
		return AllEncodingWorkflowResp{}, errors.WithStack(err)
	}

	return AllEncodingWorkflowResp{}, nil

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

func scaleFilter(profile string) string {
	switch profile {
	case "high":
		return "scale='if(gt(iw,ih),min(1920,iw),-2)':'if(gt(iw,ih),-2,min(1080,ih))'"
	case "low":
		return "scale='if(gt(iw,ih),min(1280,iw),-2)':'if(gt(iw,ih),-2,min(720,ih))'"
	}
	slog.Error("scaleFileter/unsupported profile", "profile", profile)
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
		"-itsoffset", fmt.Sprintf("%.3f", args.SrcProps.FirstPTS),
		"-i", args.InputDirFile,
	}
}

func inputDirFileWithMapStrategy(args EncodeStreamArgs) []any {
	return []any{
		"-i", args.InputDirFile,
		"-map", args.Source,
	}
}

func filterStrategy(args EncodeStreamArgs) []any {
	scaleFilter := scaleFilter(args.Profile)
	return []any{"-filter_complex",
		strings.Join([]string{
			interlaceIfNeeded("0:v:0", "postdeint", args.SrcProps.FilterRecommendation),
			scaleIfNeeded("postdeint", "out", scaleFilter)}, ";"),
		"-map", "[out]"}
}

func nullStrategy(_ EncodeStreamArgs) []any {
	return []any{}
}
func x264EncodingStrategy(crf string, bitrate string) func(args EncodeStreamArgs) []any {
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
			"-x264-params:v", "keyint="+strconv.FormatFloat(args.DstProps.GopFrames, 'f', 0, 64)+":min-keyint="+strconv.FormatFloat(args.DstProps.GopFrames, 'f', 0, 64)+":scenecut=0:open-gop=0:vbv-maxrate="+bitrate+":vbv-bufsize="+bufSize(bitrate)+":crf-max="+crfMax(crf)+":no-deblock=0:cabac=1:8x8dct=1")

		return ffmpegArgs
	}
}
func x265EncodingStrategy(crf string, bitrate string) func(args EncodeStreamArgs) []any {
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
			"-x265-params:v", "keyint="+strconv.FormatFloat(args.DstProps.GopFrames, 'f', 0, 64)+":min-keyint="+strconv.FormatFloat(args.DstProps.GopFrames, 'f', 0, 64)+":scenecut=0:open-gop=0:vbv-maxrate="+bitrate+":vbv-bufsize="+bufSize(bitrate))
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
		args.OutputDirFile,
	}
}

func dashManifestStrategy(args EncodeStreamArgs) []any {
	return []any{
		"-map_chapters", "-1",
		"-map_metadata", "-1",
		//These are supposedly needed if ffmpeg does the dash packaging (not using e.g. mp4box)
		"-movflags", "frag_keyframe+empty_moov+default_base_moof",
		//"-movflags", "+faststart+disable_chpl",
		args.OutputDirFile,
	}
}

func rawOutputStrategy(args EncodeStreamArgs) []any {
	return []any{
		args.OutputDirFile,
	}
}

type InputStrategy func(args EncodeStreamArgs) []any
type FilterStrategy func(args EncodeStreamArgs) []any
type EncodingStrategy func(args EncodeStreamArgs) []any
type ManifestStrategy func(args EncodeStreamArgs) []any
type DurationDeriverUsec func(ctx workflow.Context, args EncodeStreamArgs) (int64, error)
type QueueSelector func(args EncodeStreamArgs) string
type PackagingStrategy func(ctx workflow.Context, args EncodeStreamArgs) error

func BuildFfmpegArgs(args EncodeStreamArgs,
	applyInput InputStrategy,
	applyFilter FilterStrategy,
	applyEncoding EncodingStrategy,
	applyManifest ManifestStrategy) []any {
	ffmpegArgs := []any{}
	ffmpegArgs = append(ffmpegArgs, applyInput(args)...)
	ffmpegArgs = append(ffmpegArgs, applyFilter(args)...)
	ffmpegArgs = append(ffmpegArgs, applyEncoding(args)...)
	ffmpegArgs = append(ffmpegArgs, applyManifest(args)...)
	return ffmpegArgs
}

func durationDeriverFfmpeg(ctx workflow.Context, args EncodeStreamArgs) (int64, error) {
	ctx1 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
	})
	var duration int64
	err := workflow.ExecuteActivity(ctx1, GetVideoDurationUsec, args.InputDirFile.String()).Get(ctx1, &duration)
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

func MP4BoxPackager(ctx workflow.Context, args EncodeStreamArgs) error {
	ctx3 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Minute * 50,
		TaskQueue:           "dasherQueue",
		HeartbeatTimeout:    3600 * time.Second,
	})
	drFname := DasherReadyFilename2(args.InputDirFile.Fname, strconv.Itoa(args.StreamNo))

	var MP4BoxDashReadyResp MP4BoxDashReadyResp
	err := workflow.ExecuteActivity(ctx3, MP4BoxDashReady, MP4BoxDashReadyArgs{
		WorkDir:    args.WorkDir,
		DashMs:     strconv.FormatFloat(args.DstProps.DashMs, 'f', 0, 64),
		InputFname: args.InputDirFile.Fname,
		DrFname:    drFname,
	}).Get(ctx3, &MP4BoxDashReadyResp)
	if err != nil {
		slog.Error("MP4BoxDashReady activity failed", "err", err.Error())
		return err
	}
	return nil
}

type EncodeStreamArgs struct {
	InputDirFile  DirFile
	Source        string //ffmpeg -map x:y:z string
	OutputDirFile DirFile
	Dir           string
	WorkDir       string
	Kind          string

	Preset  string
	Profile string
	Codec   string

	StreamNo int
	DstProps CommonProperties
	SrcProps MediaInterlaceAnalysis
}

func PipelineFactory(args EncodeStreamArgs) ManagedPipeline {
	res := ManagedPipeline{}
	switch args.Codec {
	case "x264":
		res.inputStrategy = inputDirFileStrategy
		res.filterStrategy = filterStrategy
		res.encodingStrategy = x264EncodingStrategy(crf(args.Codec, args.Profile), bitrate(args.Codec, args.Profile))
		res.manifestStrategy = dashManifestStrategy
	case "x265":
		res.inputStrategy = inputDirFileStrategy
		res.filterStrategy = filterStrategy
		res.encodingStrategy = x265EncodingStrategy(crf(args.Codec, args.Profile), bitrate(args.Codec, args.Profile))
		res.manifestStrategy = dashManifestStrategy
	case "aac":
		res.inputStrategy = inputDirFileWithMapStrategy
		res.filterStrategy = nullStrategy
		res.encodingStrategy = aac2cEncodingStrategy
		res.manifestStrategy = dashManifestStrategy
	case "copy":
		res.inputStrategy = inputDirFileWithMapStrategy
		res.filterStrategy = nullStrategy
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
	filterStrategy   FilterStrategy
	encodingStrategy EncodingStrategy
	manifestStrategy ManifestStrategy
	durationDeriver  DurationDeriverUsec
	encoderQueue     QueueSelector
	packager         PackagingStrategy
}

func (m ManagedPipeline) Process(ctx workflow.Context, args EncodeStreamArgs) error {
	ffmpegArgs := BuildFfmpegArgs(args, m.inputStrategy, m.filterStrategy, m.encodingStrategy, m.manifestStrategy)
	duration, err := m.durationDeriver(ctx, args)
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
	spew.Dump(ffmpegArgs)
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

	if err := MP4BoxPackager(ctx, args); err != nil {
		slog.Error("MP4BoxPackager failed", "err", err)
		return err
	}
	return nil
}
