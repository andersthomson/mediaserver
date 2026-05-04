package dasherworker

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/andersthomson/mediaserver/scrape"
	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	"go.temporal.io/sdk/activity"
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
func tune(codec string, kind string) []string {
	switch codec {
	case "x264":
		switch kind {
		case "animation":
			return []string{"-tune:v", "animation"}
		default:
			return []string{"-tune:v", "film"}
		}
	case "x265":
		switch kind {
		case "animation":
			return []string{"-tune:v", "animation"}
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

func DasherReadyFilename(streamno int, m scrape.Msp) (string, error) {
	fname, err := InputFName(streamno, m)
	if err != nil {
		return "", err
	}
	return fname + "-encoded-" + fmt.Sprintf("%d", streamno) + ".mp4", nil
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
	ctx1 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute,
		TaskQueue:           "dasherQueue",
		//HeartbeatTimeout:    1000 * time.Second,
	})
	var preludeResp PreludeResp
	slog.Info("XXXXXXXX starting Prelude activity")
	err := workflow.ExecuteActivity(ctx1, Prelude, PreludeArgs{
		MspFile: args.MspFile,
		Dir:     args.Dir,
	}).Get(ctx1, &preludeResp)
	if err != nil {
		return AllEncodingWorkflowResp{}, errors.WithStack(err)
	}
	dirTimestamp := workflow.Now(ctx).UTC().Format("2006-01-02T15-04-05Z")
	ProdDir := "/var/cache/mediacache/" + preludeResp.M.ShortName + "-" + preludeResp.M.Id + "/dash"
	DashDir := ProdDir + "." + dirTimestamp

	//Find the encoding needs
	slog.Info("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
	for streamno, stream := range preludeResp.M.Dash.Streams {
		switch stream.Codec {
		case "x264", "x265", "copy", "aac":
			inFname, err := InputFName(streamno, preludeResp.M)
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
			slog.Info("XXXXXXXX starting AnalyzeMediaInterlace activity")
			err = workflow.ExecuteActivity(ctx1, AnalyzeMediaInterlace, AnalyzeMediaInterlaceArgs{
				Dir:   args.Dir,
				Fname: inFname,
			}).Get(ctx1, &MediaInterlaceAnalysis)
			if err != nil {
				return AllEncodingWorkflowResp{}, errors.WithStack(err)
			}
			spew.Dump(MediaInterlaceAnalysis)

			//WF ffmpeg encode
			var EncodingWorkflowResp EncodingWorkflowResp
			err = workflow.ExecuteChildWorkflow(ctx, EncodingWorkflow, EncodingWorkflowArgs{
				InputFilePath: args.Dir + "/" + inFname,
				WorkDir:       DashDir,
				P:             EncodeParams{preset(args.Fast), streamno, preludeResp.M, args.Dir, preludeResp.Tprops, MediaInterlaceAnalysis},
			}).Get(ctx, &EncodingWorkflowResp)
			if err != nil {
				slog.Info("Couldn't start child workflow", "err", err)
				return AllEncodingWorkflowResp{}, fmt.Errorf("Couldn't start child workflow. %+v", err)
			}
			fmt.Printf("Result %v\n", EncodingWorkflowResp)
		case "reference":
			ctx1 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
				StartToCloseTimeout: 10 * time.Minute,
				TaskQueue:           "dasherQueue",
				//HeartbeatTimeout:    1000 * time.Second,
			})
			slog.Info("XXXXXXXX starting LinkSrcMedia activity")
			err := workflow.ExecuteActivity(ctx1, LinkSrcMedia, LinkSrcMediaArgs{
				Streamno:  streamno,
				M:         preludeResp.M,
				Dir:       args.Dir,
				TargetDir: DashDir,
			}).Get(ctx1, nil)
			if err != nil {
				return AllEncodingWorkflowResp{}, errors.WithStack(err)
			}
		default:
			return AllEncodingWorkflowResp{}, fmt.Errorf("Msp malformed: Unsupported Codec %s in stream %d\n", stream.Codec, streamno)
		}

	}
	ctx1 = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute,
		TaskQueue:           "dasherQueue",
		//HeartbeatTimeout:    1000 * time.Second,
	})
	slog.Info("XXXXXXXX starting Finalize activity")
	err = workflow.ExecuteActivity(ctx1, Finalize, FinalizeArgs{
		M:         preludeResp.M,
		DashMs:    preludeResp.Tprops.DashMs,
		TargetDir: DashDir,
		ProdDir:   ProdDir,
		Fast:      args.Fast,
	}).Get(ctx1, nil)
	if err != nil {
		return AllEncodingWorkflowResp{}, errors.WithStack(err)
	}

	return AllEncodingWorkflowResp{}, nil

}

type EncodingWorkflowArgs struct {
	InputFilePath string
	WorkDir       string
	P             EncodeParams
}

type EncodingWorkflowResp struct {
}

func EncodingWorkflow(ctx workflow.Context, args EncodingWorkflowArgs) (EncodingWorkflowResp, error) {
	/*
		DEINTERLACE := "[$VIDEOSOURCE]bwdif=mode=0:parity=auto:deint=all,"
		SCALE_1080 := "scale='if(gt(iw,ih),min(1920,iw),-2)':'if(gt(iw,ih),-2,min(1080,ih))'"
		SCALE_720 := "scale='if(gt(iw,ih),min(1280,iw),-2)':'if(gt(iw,ih),-2,min(720,ih))'"
	*/

	inputFName, err := InputFName(args.P.StreamNo, args.P.Msp)
	if err != nil {
		return EncodingWorkflowResp{}, errors.WithStack(err)
	}
	drFname, err := DasherReadyFilename(args.P.StreamNo, args.P.Msp)
	if err != nil {
		return EncodingWorkflowResp{}, errors.WithStack(err)
	}
	outputFName := drFname + "-fragmented.mp4"
	inp, err := Input(args.P.StreamNo, args.P.Msp)
	if err != nil {
		return EncodingWorkflowResp{}, errors.WithStack(err)
	}

	var ffmpegArgs []string
	scaleFilter := scaleFilter(args.P.Msp.Dash.Streams[args.P.StreamNo])
	switch args.P.Msp.Dash.Streams[args.P.StreamNo].Codec {
	case "x264":
		ffmpegArgs = []string{
			"-itsoffset", fmt.Sprintf("%.3f", args.P.SrcAnalysis.FirstPTS),
			//"-c:v", "h264_v4l2m2m",
			"-i", args.P.Dir + "/" + inputFName,
			"-filter_complex", strings.Join([]string{interlaceIfNeeded("0:v:0", "postdeint", args.P.SrcAnalysis.FilterRecommendation),
				scaleIfNeeded("postdeint", "out", scaleFilter)}, ";"),
			"-map", "[out]",
			"-c:v", "libx264",
			"-profile:v", "high",
			"-level:v", "4.1",
			"-pix_fmt", "yuv420p",
			"-crf:v", crf(args.P.Msp.Dash.Streams[args.P.StreamNo]),
			"-preset:v", args.P.Preset}
		ffmpegArgs = append(ffmpegArgs, tune(args.P.Msp.Dash.Streams[args.P.StreamNo].Codec, inp.Kind)...)
		ffmpegArgs = append(ffmpegArgs, []string{
			"-x264-params:v", "keyint=" + strconv.FormatFloat(args.P.Props.GopFrames, 'f', 0, 64) + ":min-keyint=" + strconv.FormatFloat(args.P.Props.GopFrames, 'f', 0, 64) + ":scenecut=0:open-gop=0:vbv-maxrate=" + bitrate(args.P.Msp.Dash.Streams[args.P.StreamNo]) + ":vbv-bufsize=" + bufSize(bitrate(args.P.Msp.Dash.Streams[args.P.StreamNo])) + ":crf-max=" + crfMax(crf(args.P.Msp.Dash.Streams[args.P.StreamNo])),
			"-movflags", "frag_keyframe+empty_moov+default_base_moof",
			outputFName,
		}...)
	case "x265":
		ffmpegArgs = []string{
			"-itsoffset", fmt.Sprintf("%.3f", args.P.SrcAnalysis.FirstPTS),
			"-i", args.P.Dir + "/" + inputFName,
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
		ffmpegArgs = append(ffmpegArgs, tune(args.P.Msp.Dash.Streams[args.P.StreamNo].Codec, inp.Kind)...)
		ffmpegArgs = append(ffmpegArgs,
			"-tag:v", "hvc1",
			"-x265-params:v", "keyint="+strconv.FormatFloat(args.P.Props.GopFrames, 'f', 0, 64)+":min-keyint="+strconv.FormatFloat(args.P.Props.GopFrames, 'f', 0, 64)+":scenecut=0:open-gop=0:vbv-maxrate="+bitrate(args.P.Msp.Dash.Streams[args.P.StreamNo])+":vbv-bufsize="+bufSize(bitrate(args.P.Msp.Dash.Streams[args.P.StreamNo])),
			"-movflags", "frag_keyframe+empty_moov+default_base_moof",
			outputFName,
		)
	case "aac":
		ffmpegArgs = []string{
			"-i", args.P.Dir + "/" + inputFName,
			"-map", args.P.Msp.Dash.Streams[args.P.StreamNo].Source,
			"-c", "aac",
			outputFName,
		}
	case "copy":
		ffmpegArgs = []string{
			"-i", args.P.Dir + "/" + inputFName,
			"-map", args.P.Msp.Dash.Streams[args.P.StreamNo].Source,
			"-c", "copy",
			outputFName,
		}
	}
	//fmt.Printf("Starting %v\n", ffmpegArgs)
	//cmd := exec.Command("/usr/bin/ffmpeg", ffmpegArgs...)
	//cmd.Dir = DashDir(args.P.Msp)
	//cmd.Stdout = os.Stdout
	//cmd.Stderr = os.Stderr
	//cmd.Stdin = nil

	//fmt.Printf("FFMpeg encoding stream %d. %s becomes %s \n", args.P.StreamNo, inputFName, outputFName)
	//err = cmd.Run()
	//if err != nil {
	//	return "", errors.WithStack(err)
	//}

	// Step 1: Probe
	ctx1 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
	})
	var duration int64
	err = workflow.ExecuteActivity(ctx1, GetVideoDurationUsec, args.P.Dir+"/"+inputFName).Get(ctx1, &duration)
	if err != nil {
		return EncodingWorkflowResp{}, err
	}

	//Step 2: Encode
	ctx2 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Hour * 5,
		TaskQueue:           "encodingQueue",
		HeartbeatTimeout:    10 * time.Second,
	})
	var result FfmpegEncodeResp
	err = workflow.ExecuteActivity(ctx2, FfmpegEncode, FfmpegEncodeArgs{
		Args:            ffmpegArgs,
		Workdir:         args.WorkDir,
		TotalDurationUs: duration,
	}).Get(ctx2, &result)
	if err != nil {
		slog.Error("activity failed", "err", err.Error())
		return EncodingWorkflowResp{}, err
	}

	//Step 3: make Dash Ready
	ctx3 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Minute * 5,
		TaskQueue:           "encodingQueue",
		HeartbeatTimeout:    1000 * time.Second,
	})

	var MP4BoxDashReadyResp MP4BoxDashReadyResp
	err = workflow.ExecuteActivity(ctx3, MP4BoxDashReady, MP4BoxDashReadyArgs{
		WorkDir: args.WorkDir,
		P:       args.P,
	}).Get(ctx3, &MP4BoxDashReadyResp)
	if err != nil {
		slog.Error("MP4BoxDashReady activity failed", "err", err.Error())
		return EncodingWorkflowResp{}, err
	}

	return EncodingWorkflowResp{}, nil
}

type FfmpegEncodeArgs struct {
	Args            []string
	Workdir         string
	TotalDurationUs int64
}

type FfmpegEncodeResp struct {
	Exitcode int
	Stdout   string
	Stderr   string
}

func FfmpegEncode(ctx context.Context, args FfmpegEncodeArgs) (FfmpegEncodeResp, error) {
	var resp FfmpegEncodeResp

	// Create an extra pipe for progress only
	pr, pw, _ := os.Pipe()
	defer pr.Close()

	var newArgs []string
	if args.TotalDurationUs != 0 {
		newArgs = append(args.Args, []string{"-progress", "pipe:3"}...)
	} else {
		newArgs = args.Args
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/ffmpeg", newArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.ExtraFiles = []*os.File{pw}
	cmd.Dir = args.Workdir

	// 3. Start progress parser in background
	if args.TotalDurationUs != 0 {
		go func() {
			defer pw.Close() // Ensure the write-end closes so scanner finishes
			scanner := bufio.NewScanner(pr)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "out_time_ms=") {
					parts := strings.Split(line, "=")
					if len(parts) == 2 {
						currentUs, _ := strconv.ParseInt(parts[1], 10, 64)
						percent := (float64(currentUs) / float64(args.TotalDurationUs)) * 100
						activity.RecordHeartbeat(ctx, fmt.Sprintf("%4.1f percent complete", percent))
					}
				}
			}
		}()
	}

	// Run() starts the command and waits for it to finish
	err := cmd.Run()

	// 5. Handle Early Closure / Cancellation
	if ctx.Err() != nil {
		// Temporal canceled the context. cmd.Run() usually returns an error here.
		return resp, ctx.Err()
	}

	// Capture outputs
	resp.Stdout = stdout.String()
	resp.Stderr = stderr.String()

	// Get Exit Code
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			// This happens if the command couldn't start at all (e.g., binary not found)
			exitCode = -1
		}
	} else {
		exitCode = cmd.ProcessState.ExitCode()
	}
	resp.Exitcode = exitCode
	return resp, nil
}

type RsyncArgs struct {
}

func Rsync(ctx context.Context, args RsyncArgs) (string, error) {
	return "", nil
}
