package dasherworker

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/andersthomson/mediaserver/scrape"
	"github.com/pkg/errors"
	"go.temporal.io/sdk/workflow"
)

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

type TargetProperties struct {
	GopFrames float64
	DashMs    float64
}

type EncodeParams struct {
	Preset      string
	StreamNo    int
	Msp         scrape.Msp
	Dir         string
	Props       TargetProperties
	SrcAnalysis MediaInterlaceAnalysis
}

func Input(streamno int, m scrape.Msp) (scrape.InputT, error) {
	splits := strings.Split(m.Dash.Streams[streamno].Source, ":")
	inputNumber, err := strconv.Atoi(splits[0])
	if err != nil {
		return scrape.InputT{}, errors.WithStack(err)
	}
	return m.Inputs[inputNumber], nil
}
func crf(stream scrape.StreamT) string {
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
	return crfT[stream.Codec][stream.Profile]
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

func scaleFilter(stream scrape.StreamT) string {
	switch stream.Codec {
	case "x264", "x265":
		switch stream.Profile {
		case "high":
			return "scale='if(gt(iw,ih),min(1920,iw),-2)':'if(gt(iw,ih),-2,min(1080,ih))'"
		case "low":
			return "scale='if(gt(iw,ih),min(1280,iw),-2)':'if(gt(iw,ih),-2,min(720,ih))'"
		}
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

func bitrate(stream scrape.StreamT) string {
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
	return T[stream.Codec][stream.Profile]
}

func preset(fast bool) string {
	if fast {
		return "ultrafast"
	} else {
		return "slow"
	}
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

			inputFName, err := InputFName(streamno, M)
			if err != nil {
				return AllEncodingWorkflowResp{}, errors.WithStack(err)
			}

			drFname := DasherReadyFilename2(inputFName, strconv.Itoa(streamno))
			inp, err := Input(streamno, M)
			if err != nil {
				return AllEncodingWorkflowResp{}, errors.WithStack(err)
			}

			var encodeStreamResp EncodeStreamResp

			encodeStreamResp, err = EncodeStream(ctx, EncodeStreamArgs{
				InputDirFile:  NewDirFile(args.Dir, inputFName),
				OutputDirFile: NewDirFile(DashDir, drFname+"-fragmented.mp4"),
				WorkDir:       DashDir,
				P:             EncodeParams{preset(args.Fast), streamno, M, args.Dir, preludeResp.Tprops, MediaInterlaceAnalysis},
				Kind:          inp.Kind,
			})
			if err != nil {
				slog.Info("Couldn't EncodeStream", "err", err)
				return AllEncodingWorkflowResp{}, fmt.Errorf("Couldn't EncodeStream: %+v", err)
			}
			fmt.Printf("Result %v\n", encodeStreamResp)
		case "reference":

			inputNumber := M.Dash.Streams[streamno].ReferenceFile
			oldFile := args.Dir + "/" + M.Inputs[inputNumber].Filename

			inputFName, err := InputFName(streamno, M)
			if err != nil {
				return AllEncodingWorkflowResp{}, errors.WithStack(err)
			}
			newFilename := DasherReadyFilename2(inputFName, strconv.Itoa(streamno))

			newFile := DashDir + "/" + newFilename
			if _, err := LinkSrcMediaActivity(ctx, oldFile, newFile); err != nil {
				return AllEncodingWorkflowResp{}, err
			}
		default:
			return AllEncodingWorkflowResp{}, fmt.Errorf("Msp malformed: Unsupported Codec %s in stream %d\n", stream.Codec, streamno)
		}

	}
	if err := os.WriteFile(filepath.Join(DashDir, "gopMs"), []byte(strconv.FormatFloat(preludeResp.Tprops.DashMs, 'f', 0, 64)), 0600); err != nil {
		return AllEncodingWorkflowResp{}, err
	}
	ctx1 = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute,
		TaskQueue:           "dasherQueue",
		//HeartbeatTimeout:    1000 * time.Second,
	})
	err = workflow.ExecuteActivity(ctx1, Finalize, FinalizeArgs{
		M: M,
		//DashMs:    preludeResp.Tprops.DashMs,
		TargetDir: DashDir,
		ProdDir:   ProdDir,
		Fast:      args.Fast,
	}).Get(ctx1, nil)
	if err != nil {
		return AllEncodingWorkflowResp{}, errors.WithStack(err)
	}

	return AllEncodingWorkflowResp{}, nil

}

type EncodeStreamArgs struct {
	InputDirFile  DirFile
	OutputDirFile DirFile
	WorkDir       string
	Kind          string
	P             EncodeParams
}

type EncodeStreamResp struct {
}

func EncodeStream(ctx workflow.Context, args EncodeStreamArgs) (EncodeStreamResp, error) {

	var ffmpegArgs []any
	var isVideoEncode bool
	scaleFilter := scaleFilter(args.P.Msp.Dash.Streams[args.P.StreamNo])
	switch args.P.Msp.Dash.Streams[args.P.StreamNo].Codec {
	case "x264":
		isVideoEncode = true
		ffmpegArgs = []any{
			"-itsoffset", fmt.Sprintf("%.3f", args.P.SrcAnalysis.FirstPTS),
			//"-c:v", "h264_v4l2m2m",
			"-i", args.InputDirFile,
			"-filter_complex", strings.Join([]string{interlaceIfNeeded("0:v:0", "postdeint", args.P.SrcAnalysis.FilterRecommendation),
				scaleIfNeeded("postdeint", "out", scaleFilter)}, ";"),
			"-map", "[out]",
			"-c:v", "libx264",
			"-profile:v", "high",
			"-level:v", "4.1",
			"-pix_fmt", "yuv420p",
			"-crf:v", crf(args.P.Msp.Dash.Streams[args.P.StreamNo]),
			"-preset:v", args.P.Preset}
		ffmpegArgs = append(ffmpegArgs, tune(args.P.Msp.Dash.Streams[args.P.StreamNo].Codec, args.Kind)...)
		ffmpegArgs = append(ffmpegArgs, []any{
			"-x264-params:v", "keyint=" + strconv.FormatFloat(args.P.Props.GopFrames, 'f', 0, 64) + ":min-keyint=" + strconv.FormatFloat(args.P.Props.GopFrames, 'f', 0, 64) + ":scenecut=0:open-gop=0:vbv-maxrate=" + bitrate(args.P.Msp.Dash.Streams[args.P.StreamNo]) + ":vbv-bufsize=" + bufSize(bitrate(args.P.Msp.Dash.Streams[args.P.StreamNo])) + ":crf-max=" + crfMax(crf(args.P.Msp.Dash.Streams[args.P.StreamNo])),
			"-movflags", "frag_keyframe+empty_moov+default_base_moof",
			args.OutputDirFile,
		}...)
	case "x265":
		isVideoEncode = true
		ffmpegArgs = []any{
			"-itsoffset", fmt.Sprintf("%.3f", args.P.SrcAnalysis.FirstPTS),
			"-i", args.InputDirFile,
			"-filter_complex", strings.Join([]string{interlaceIfNeeded("0:v:0", "postdeint", args.P.SrcAnalysis.FilterRecommendation),
				scaleIfNeeded("postdeint", "out", scaleFilter)}, ";"),
			"-map", "[out]",
			"-c:v", "libx265",
			"-profile:v", "main10",
			"-level:v", "5.1",
			"-pix_fmt", "yuv420p",
			"-crf:v", crf(args.P.Msp.Dash.Streams[args.P.StreamNo]),
			"-preset:v", args.P.Preset,
		}
		ffmpegArgs = append(ffmpegArgs, tune(args.P.Msp.Dash.Streams[args.P.StreamNo].Codec, args.Kind)...)
		ffmpegArgs = append(ffmpegArgs,
			"-tag:v", "hvc1",
			"-x265-params:v", "keyint="+strconv.FormatFloat(args.P.Props.GopFrames, 'f', 0, 64)+":min-keyint="+strconv.FormatFloat(args.P.Props.GopFrames, 'f', 0, 64)+":scenecut=0:open-gop=0:vbv-maxrate="+bitrate(args.P.Msp.Dash.Streams[args.P.StreamNo])+":vbv-bufsize="+bufSize(bitrate(args.P.Msp.Dash.Streams[args.P.StreamNo])),
			"-movflags", "frag_keyframe+empty_moov+default_base_moof",
			args.OutputDirFile,
		)
	case "aac":
		ffmpegArgs = []any{
			"-i", args.InputDirFile,
			"-map", args.P.Msp.Dash.Streams[args.P.StreamNo].Source,
			"-c", "aac",
			args.OutputDirFile,
		}
	case "copy":
		ffmpegArgs = []any{
			"-i", args.InputDirFile,
			"-map", args.P.Msp.Dash.Streams[args.P.StreamNo].Source,
			"-c", "copy",
			args.OutputDirFile,
		}
	default:
		return EncodeStreamResp{}, fmt.Errorf("Unsupported args.P.Msp.Dash.Streams[args.P.StreamNo].Codec : %s", args.P.Msp.Dash.Streams[args.P.StreamNo].Codec)
	}
	// Step 1: Probe
	ctx1 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
	})
	var duration int64
	err := workflow.ExecuteActivity(ctx1, GetVideoDurationUsec, args.InputDirFile.String()).Get(ctx1, &duration)
	if err != nil {
		return EncodeStreamResp{}, err
	}

	var a *LocalEncode
	//Step 2: Encode
	var queue string
	if isVideoEncode {
		queue = "encodingQueue"
	} else {
		queue = "dasherQueue"
	}

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
		return EncodeStreamResp{}, err
	}
	slog.Info("Created session")
	defer workflow.CompleteSession(sessionCtx)

	ctx2 := workflow.WithActivityOptions(sessionCtx, workflow.ActivityOptions{
		StartToCloseTimeout: 24 * time.Hour,
		HeartbeatTimeout:    20 * time.Second,
	})
	var encodePreludeResp EncodePreludeResp
	err = workflow.ExecuteActivity(ctx2, a.EncodePrelude, EncodePreludeArgs{
		FfmpegArgs: NewFFMpegArgs(ffmpegArgs),
	}).Get(ctx2, &encodePreludeResp)
	if err != nil {
		slog.Error(" FfmpegEncodePreludefailed", "err", err.Error())
		return EncodeStreamResp{}, err
	}

	var ffmpegEncodeResp EncodeResp
	err = workflow.ExecuteActivity(ctx2, a.Encode, EncodeArgs{
		FfmpegArgs:      encodePreludeResp.FfmpegArgs,
		TotalDurationUs: duration,
	}).Get(ctx2, &ffmpegEncodeResp)
	if err != nil {
		slog.Error("activity failed", "err", err.Error())
		return EncodeStreamResp{}, err
	}

	err = workflow.ExecuteActivity(ctx2, a.EncodePostlude, EncodePostludeArgs{
		FfmpegArgs: ffmpegEncodeResp.FfmpegArgs,
	}).Get(ctx2, nil)

	//Step 3: make Dash Ready
	ctx3 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Minute * 5,
		TaskQueue:           "dasherQueue",
		HeartbeatTimeout:    1000 * time.Second,
	})

	var MP4BoxDashReadyResp MP4BoxDashReadyResp
	err = workflow.ExecuteActivity(ctx3, MP4BoxDashReady, MP4BoxDashReadyArgs{
		WorkDir: args.WorkDir,
		P:       args.P,
	}).Get(ctx3, &MP4BoxDashReadyResp)
	if err != nil {
		slog.Error("MP4BoxDashReady activity failed", "err", err.Error())
		return EncodeStreamResp{}, err
	}

	return EncodeStreamResp{}, nil
}
