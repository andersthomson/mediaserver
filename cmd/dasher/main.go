package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/andersthomson/mediaserver/scrape"
	"github.com/davecgh/go-spew/spew"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

func main() {
	dir := filepath.Dir(os.Args[1])
	base := filepath.Base(os.Args[1])
	if base == "" || dir == "" {
		panic("Need as arg 1 path to msp file\n")
	}
	//if err := makeDashWorkFlow("/var/lib/media/temp/testfil", "flaskhals.msp"); err != nil {
	if err := makeDashWorkFlow(dir, base); err != nil {
		fmt.Printf("ERROR: %+v\n", err)
	} else {
		fmt.Printf("Done.\n")
	}
}
func LookupEnvCaseInsensitive(key string) (string, bool) {
	targetKey := strings.ToLower(key)

	// os.Environ() returns a slice of strings in the form "KEY=VALUE"
	for _, env := range os.Environ() {
		pair := strings.SplitN(env, "=", 2)
		if len(pair) < 2 {
			continue
		}

		if strings.ToLower(pair[0]) == targetKey {
			return pair[1], true
		}
	}

	return "", false
}

func fast() bool {
	_, ok := LookupEnvCaseInsensitive("dasher_fast")
	return ok
}

func ActionReadMSP(dir string, mspFile string) (scrape.Msp, error) {
	return scrape.ReadMspFromFile(filepath.Join(dir, mspFile))
}

var DirTimestamp string

func DashDir(m scrape.Msp) string {
	return "/var/cache/mediacache/" + m.ShortName + "-" + m.Id + "/dash." + DirTimestamp
}

func DashDirProd(m scrape.Msp) string {
	return "/var/cache/mediacache/" + m.ShortName + "-" + m.Id + "/dash"
}

func DasherReadyFilename(streamno int, m scrape.Msp) (string, error) {
	fname, err := InputFName(streamno, m)
	if err != nil {
		return "", err
	}
	return fname + "-encoded-" + fmt.Sprintf("%d", streamno) + ".mp4", nil
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
			return "", errors.New("inputnumber out of bounds")
		}
		return m.Inputs[inputNumber].Filename, nil
	}
	inputNumber = m.Dash.Streams[streamno].ReferenceFile
	if inputNumber+1 > len(m.Inputs) {
		return "", errors.New("inputnumber out of bounds")
	}
	return m.Inputs[inputNumber].Filename, nil
}

func Input(streamno int, m scrape.Msp) (scrape.InputT, error) {
	splits := strings.Split(m.Dash.Streams[streamno].Source, ":")
	inputNumber, err := strconv.Atoi(splits[0])
	if err != nil {
		return scrape.InputT{}, errors.WithStack(err)
	}
	return m.Inputs[inputNumber], nil
}

type properties struct {
	streamType  string // video, audio, subtitles
	fps         float64
	gopMilliSec float64
	gopFrames   float64
}
type ProbeParams struct {
	Filename string
	Dir      string
}

// GetSourcePropertiesActivity combines GOP and FPS detection into a single remote call.
func GetSourcePropertiesActivity(ctx context.Context, params ProbeParams) (properties, error) {
	path := filepath.Join(params.Dir, params.Filename)

	// We call ffprobe once, asking for both stream info (FPS) and frame info (GOP)
	// Using CommandContext allows Temporal to kill the process if the activity times out.
	cmd := exec.CommandContext(ctx, "/usr/bin/ffprobe",
		"-v", "error",
		"-select_streams", "v:0",
		"-show_entries", "stream=r_frame_rate:frame=pts_time",
		"-skip_frame", "nokey",
		"-of", "json",
		"-read_intervals", "%+20", // Limit probe to first 20 seconds
		path,
	)

	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return properties{}, fmt.Errorf("ffprobe failed: %w", errors.WithStack(err))
	}

	// Internal anonymous struct to match the combined ffprobe JSON output
	var data struct {
		Streams []struct {
			RFrameRate string `json:"r_frame_rate"`
		} `json:"streams"`
		Frames []struct {
			PtsTime string `json:"pts_time"`
		} `json:"frames"`
	}

	if err := json.Unmarshal(buf.Bytes(), &data); err != nil {
		return properties{}, fmt.Errorf("failed to unmarshal ffprobe output: %w", errors.WithStack(err))
	}

	if len(data.Streams) == 0 {
		return properties{}, errors.New("no video streams found")
	}

	// 1. Calculate FPS
	splits := strings.Split(data.Streams[0].RFrameRate, "/")
	if len(splits) != 2 {
		return properties{}, fmt.Errorf("invalid frame rate format: %s", data.Streams[0].RFrameRate)
	}
	dividend, _ := strconv.ParseFloat(splits[0], 64)
	divisor, _ := strconv.ParseFloat(splits[1], 64)
	if divisor == 0 {
		return properties{}, errors.New("divisor is zero in frame rate")
	}
	calculatedFPS := dividend / divisor

	// 2. Calculate GOP
	if len(data.Frames) < 2 {
		return properties{}, errors.New("could not find at least two keyframes for GOP calculation")
	}
	t1, err := strconv.ParseFloat(data.Frames[0].PtsTime, 64)
	if err != nil {
		return properties{}, fmt.Errorf("Failed to parse as float: %v", data.Frames[0].PtsTime)
	}
	t2, err := strconv.ParseFloat(data.Frames[1].PtsTime, 64)
	if err != nil {
		return properties{}, fmt.Errorf("Failed to parse as float: %v", data.Frames[0].PtsTime)
	}

	diff := t2 - t1

	return properties{
		streamType:  "video",
		fps:         calculatedFPS,
		gopMilliSec: diff * 1000,
		gopFrames:   diff * calculatedFPS,
	}, nil
}

func dashMs(p properties) float64 {
	diff := p.gopMilliSec / 1000
	return math.Max(1.0, math.Round(4.0/diff)) * diff * 1000
}

type targetProperties struct {
	gopFrames float64
	dashMs    float64
}

func tune264(input scrape.InputT) string {
	switch input.Kind {
	case "animation":
		return "animation"
	default:
		return "film"
	}
}

func tune265(input scrape.InputT) string {
	switch input.Kind {
	case "animation":
		return "animation"
	case "":
		return ""
	default:
		return ""
	}
}

func preset() string {
	if fast() {
		return "ultrafast"
	} else {
		return "slow"
	}
}

func CanUseRPiHW() bool {
	// Attempt a 1-frame dummy transcode using the HW block
	cmd := exec.Command("ffmpeg", "-v", "error", "-f", "lavfi", "-i", "color=s=64x64", "-c:v", "h264_v4l2m2m", "-frames:v", "1", "-f", "null", "-")
	err := cmd.Run()
	return err == nil
}

func interlaceIfNeeded(in, out string, filter string) string {
	return fmt.Sprintf("[%s]%s[%s]", in, filter, out)
}
func scaleIfNeeded(in, out string, filter string) string {
	return fmt.Sprintf("[%s]%s[%s]", in, filter, out)
}
func adjustFPSIfNeeded(in, out string, high bool) string {
	s := "null"
	if high {
		s = "mpdecimate, fps=25"
	}
	return fmt.Sprintf("[%s]%s[%s]", in, s, out)
}

type EncodeParams struct {
	StreamNo    int
	Msp         scrape.Msp
	Dir         string
	Props       targetProperties
	SrcAnalysis InterlaceAnalysis
}

func EncodeStreamActivity(ctx context.Context, p EncodeParams) (string, error) {
	/*
		DEINTERLACE := "[$VIDEOSOURCE]bwdif=mode=0:parity=auto:deint=all,"
		SCALE_1080 := "scale='if(gt(iw,ih),min(1920,iw),-2)':'if(gt(iw,ih),-2,min(1080,ih))'"
		SCALE_720 := "scale='if(gt(iw,ih),min(1280,iw),-2)':'if(gt(iw,ih),-2,min(720,ih))'"
	*/

	inputFName, err := InputFName(p.StreamNo, p.Msp)
	if err != nil {
		return "", errors.WithStack(err)
	}
	drFname, err := DasherReadyFilename(p.StreamNo, p.Msp)
	if err != nil {
		return "", errors.WithStack(err)
	}
	outputFName := drFname + "-fragmented.mp4"

	var args []string
	var scaleFilter string
	switch p.Msp.Dash.Streams[p.StreamNo].Codec {
	case "x264", "x265":
		switch p.Msp.Dash.Streams[p.StreamNo].Profile {
		case "high":
			scaleFilter = "scale='if(gt(iw,ih),min(1920,iw),-2)':'if(gt(iw,ih),-2,min(1080,ih))'"
		case "low":
			scaleFilter = "scale='if(gt(iw,ih),min(1280,iw),-2)':'if(gt(iw,ih),-2,min(720,ih))'"
		default:
			return "", fmt.Errorf("Unsupported profile: " + p.Msp.Dash.Streams[p.StreamNo].Profile)
		}
	}
	switch p.Msp.Dash.Streams[p.StreamNo].Codec {
	case "x264":
		var crf int
		var bitrate int
		switch p.Msp.Dash.Streams[p.StreamNo].Profile {
		case "high":
			crf = 18
			bitrate = 6000
		case "low":
			crf = 21
			bitrate = 800
		default:
			return "", fmt.Errorf("Unsupported profile: " + p.Msp.Dash.Streams[p.StreamNo].Profile)
		}

		crfMax := 5 + crf
		bufsize := 2 * bitrate
		inp, err := Input(p.StreamNo, p.Msp)
		if err != nil {
			return "", errors.WithStack(err)
		}
		args = []string{
			"-itsoffset", fmt.Sprintf("%.3f", p.SrcAnalysis.FirstPTS),
			//"-c:v", "h264_v4l2m2m",
			"-i", p.Dir + "/" + inputFName,
			"-filter_complex", strings.Join([]string{interlaceIfNeeded("0:v:0", "postdeint", p.SrcAnalysis.FilterRecommendation),
				scaleIfNeeded("postdeint", "out", scaleFilter)}, ";"),
			"-map", "[out]",
			"-c:v", "libx264",
			"-profile:v", "high",
			"-level:v", "4.1",
			"-pix_fmt", "yuv420p",
			"-crf:v", strconv.Itoa(crf),
			"-preset:v", preset(),
			"-tune:v", tune264(inp),
			"-x264-params:v", "keyint=" + strconv.FormatFloat(p.Props.gopFrames, 'f', 0, 64) + ":min-keyint=" + strconv.FormatFloat(p.Props.gopFrames, 'f', 0, 64) + ":scenecut=0:open-gop=0:vbv-maxrate=" + strconv.Itoa(bitrate) + ":vbv-bufsize=" + strconv.Itoa(bufsize) + ":crf-max=" + strconv.Itoa(crfMax),
			"-movflags", "frag_keyframe+empty_moov+default_base_moof",
			outputFName,
		}
	case "x265":
		var crf int
		var bitrate int
		switch p.Msp.Dash.Streams[p.StreamNo].Profile {
		case "high":
			crf = 21
			bitrate = 2000
		case "low":
			crf = 21
			bitrate = 800
		default:
			return "", fmt.Errorf("Unsupported profile: " + p.Msp.Dash.Streams[p.StreamNo].Profile)
		}

		bufsize := 2 * bitrate
		args = []string{
			"-itsoffset", fmt.Sprintf("%.3f", p.SrcAnalysis.FirstPTS),
			"-i", p.Dir + "/" + inputFName,
			"-filter_complex", strings.Join([]string{interlaceIfNeeded("0:v:0", "postdeint", p.SrcAnalysis.FilterRecommendation),
				scaleIfNeeded("postdeint", "out", scaleFilter)}, ";"),
			"-map", "[out]",
			"-c:v", "libx265",
			"-profile:v", "main10",
			"-level:v", "5.1",
			"-pix_fmt", "yuv420p",
			"-crf:v", strconv.Itoa(crf),
			"-preset:v", preset(),
		}
		inp, err := Input(p.StreamNo, p.Msp)
		if err != nil {
			return "", errors.WithStack(err)
		}
		if tune := tune265(inp); tune != "" {
			args = append(args, "-tune:v", tune)
		}
		args = append(args,
			"-tag:v", "hvc1",
			"-x265-params:v", "keyint="+strconv.FormatFloat(p.Props.gopFrames, 'f', 0, 64)+":min-keyint="+strconv.FormatFloat(p.Props.gopFrames, 'f', 0, 64)+":scenecut=0:open-gop=0:vbv-maxrate="+strconv.Itoa(bitrate)+":vbv-bufsize="+strconv.Itoa(bufsize),
			"-movflags", "frag_keyframe+empty_moov+default_base_moof",
			outputFName,
		)
	case "aac":
		args = []string{
			"-i", p.Dir + "/" + inputFName,
			"-map", p.Msp.Dash.Streams[p.StreamNo].Source,
			"-c", "aac",
			outputFName,
		}
	case "copy":
		args = []string{
			"-i", p.Dir + "/" + inputFName,
			"-map", p.Msp.Dash.Streams[p.StreamNo].Source,
			"-c", "copy",
			outputFName,
		}
	}
	fmt.Printf("Starting %v\n", args)
	cmd := exec.Command("/usr/bin/ffmpeg", args...)
	cmd.Dir = DashDir(p.Msp)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	fmt.Printf("FFMpeg encoding stream %d. %s becomes %s \n", p.StreamNo, inputFName, outputFName)
	err = cmd.Run()
	if err != nil {
		return "", errors.WithStack(err)
	}

	args = []string{
		"-dash", strconv.FormatFloat(p.Props.dashMs, 'f', 0, 64),
		"-rap",
		"-profile",
		"onDemand",
		"-segment-name", outputFName + "-postDash.mp4",
		"-out", "manifest.mpd",
		outputFName}
	cmd = exec.Command("/usr/bin/MP4Box", args...)
	cmd.Dir = DashDir(p.Msp)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	drFname, err = DasherReadyFilename(p.StreamNo, p.Msp)
	if err != nil {
		return "", errors.WithStack(err)
	}
	fmt.Printf("MP4Box dashing stream %d.  %s becomes %s \n", p.StreamNo, outputFName, drFname)
	fmt.Printf("Starting /usr/bin/MP4Box %v\n", args)
	err = cmd.Run()
	if err != nil {
		return "", errors.WithStack(err)
	}
	if err := os.Remove(DashDir(p.Msp) + "/" + outputFName); err != nil {
		return "", errors.WithStack(err)
	}
	if err := os.Remove(DashDir(p.Msp) + "/manifest.mpd"); err != nil {
		return "", errors.WithStack(err)
	}
	if err := os.Rename(DashDir(p.Msp)+"/"+outputFName+"-postDash.mp4init.mp4", DashDir(p.Msp)+"/"+drFname); err != nil {
		return "", errors.WithStack(err)
	}
	return "", nil
}

func linkAction(streamno int, m scrape.Msp, dir string) error {
	//Get the source file
	inputNumber := m.Dash.Streams[streamno].ReferenceFile
	srcFile := m.Inputs[inputNumber].Filename
	dstFile, err := DasherReadyFilename(streamno, m)
	if err != nil {
		return errors.WithStack(err)
	}
	fmt.Printf("Creating symlink %s -> %s\n", DashDir(m)+"/"+dstFile, dir+"/"+srcFile)
	if err := os.Symlink(dir+"/"+srcFile, DashDir(m)+"/"+dstFile); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func dasherAction(m scrape.Msp, gopMs float64) error {
	fmt.Printf("dasherAction\n")
	var inputs []string
	for streamno, _ := range m.Dash.Streams {
		drFname, err := DasherReadyFilename(streamno, m)
		if err != nil {
			return errors.WithStack(err)
		}
		inputs = append(inputs, drFname+":id="+strconv.Itoa(streamno))
	}
	args := []string{"-dash", strconv.FormatFloat(gopMs, 'f', 0, 64), "-rap", "-profile", "onDemand", "-out", "manifest.mpd"}
	args = append(args, inputs...)
	spew.Dump(args)
	cmd := exec.Command("/usr/bin/MP4Box", args...)
	cmd.Dir = DashDir(m)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func replaceWithSymlink(src, target string) error {
	if err := os.Remove(src); err != nil {
		return errors.WithStack(err)
	}
	if err := os.Symlink(target, src); err != nil {
		return err
	}
	return nil
}

func makeDashWorkFlow(dir string, mspFile string) error {
	DirTimestamp = time.Now().UTC().Format("2006-01-02T15-04-05Z")
	m, err := ActionReadMSP(dir, mspFile)
	if err != nil {
		return fmt.Errorf("MSP read of %s/%s failed: %w", dir, mspFile, errors.WithStack(err))
	}
	//Sanity check:
	var referenceFiles = map[int]bool{}
	var tprops targetProperties
	for streamno, stream := range m.Dash.Streams {
		if stream.Codec == "reference" {
			referenceFiles[stream.ReferenceFile] = true
			//At least one output stream want to reference an input stream.
			//Check that the input's gop is sane
			switch {
			case isDashReadyVideo(dir + "/" + m.Inputs[stream.ReferenceFile].Filename):
				props, err := GetSourcePropertiesActivity(context.Background(), ProbeParams{m.Inputs[stream.ReferenceFile].Filename, dir})
				if err != nil {
					return errors.WithStack(err)
				}
				if props.gopMilliSec < 1500 || props.gopMilliSec > 5000 {
					return fmt.Errorf("Source %d, which you want to have referenced, has an unsupported gop %f\n", streamno, props.gopMilliSec)
				}
				tprops.gopFrames = props.gopFrames
				tprops.dashMs = dashMs(props)
			case isDashReadyAudio(dir + "/" + m.Inputs[stream.ReferenceFile].Filename):
			default:
				return fmt.Errorf("Source %d, which you want to have referenced, is not dash ready\n", stream.ReferenceFile)
			}
		}
	}
	if tprops.gopFrames == 0 {
		tprops.gopFrames = 100
		tprops.dashMs = 4000
	}
	if err := os.MkdirAll(DashDir(m), os.ModePerm); err != nil {
		return errors.WithStack(err)
	}
	//Find the encoding needs
	for streamno, stream := range m.Dash.Streams {
		switch stream.Codec {
		case "x264", "x265", "copy", "aac":
			inFname, err := InputFName(streamno, m)
			if err != nil {
				return errors.WithStack(err)
			}
			srcAnalysis, err := AnalyzeMediaActivity(context.Background(), dir, inFname)
			if err != nil {
				return errors.WithStack(err)
			}
			spew.Dump(srcAnalysis)
			if _, err := EncodeStreamActivity(context.Background(), EncodeParams{streamno, m, dir, tprops, srcAnalysis}); err != nil {
				return err
			}
		case "reference":
			linkAction(streamno, m, dir)
		default:
			return fmt.Errorf("Msp malformed: Unsupported Codec %s in stream %d\n", stream.Codec, streamno)
		}

	}
	//Build Dash
	dasherAction(m, tprops.dashMs)

	for streamno, _ := range m.Dash.Streams {
		dashFName, err := DasherReadyFilename(streamno, m)
		if err != nil {
			return errors.WithStack(err)
		}
		replaceWithSymlink(strings.TrimSuffix(dashFName, ".mp4")+"_dashinit.mp4", dashFName)
	}
	fixAudioPresentationTimeOffset(DashDir(m) + "/" + "manifest.mpd")
	tmpSuffix := uuid.NewString()
	if err := os.Symlink(filepath.Base(DashDir(m)), DashDirProd(m)+tmpSuffix); err != nil {
		return fmt.Errorf("Symlinking for production failed: %v", errors.WithStack(err))
	}
	if err := os.Rename(DashDirProd(m)+tmpSuffix, DashDirProd(m)); err != nil {
		return fmt.Errorf("Renaming to production failed: %v", errors.WithStack(err))
	}
	return nil
}
