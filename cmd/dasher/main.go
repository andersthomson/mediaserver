package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/andersthomson/mediaserver/scrape"
)

func main() {
	dir := filepath.Dir(os.Args[1])
	base := filepath.Base(os.Args[1])
	if base == "" || dir == "" {
		panic("Need as arg 1 path to msp file\n")
	}
	//if err := makeDashWorkFlow("/var/lib/media/temp/testfil", "flaskhals.msp"); err != nil {
	if err := makeDashWorkFlow(dir, base); err != nil {
		fmt.Printf("ERROR: %W\n", err)
	} else {
		fmt.Printf("Done.\n")
	}
}

func ActionReadMSP(dir string, mspFile string) (scrape.Msp, error) {
	return scrape.ReadMspFromFile(filepath.Join(dir, mspFile))
}

func DashDir(m scrape.Msp) string {
	return "/var/cache/mediacache/" + m.ShortName + "-" + m.Id + "/dash"
}

func DasherReadyFilename(streamno int, m scrape.Msp) (string, error) {
	fname, err := InputFName(streamno, m)
	if err != nil {
		return "", err
	}
	return DashDir(m) + "/" + fname + "-encoded-" + fmt.Sprintf("%d", streamno) + ".mp4", nil
}

func InputFName(streamno int, m scrape.Msp) (string, error) {
	var inputNumber int
	var err error
	if m.Dash.Streams[streamno].Source != "" {
		splits := strings.Split(m.Dash.Streams[streamno].Source, ":")
		inputNumber, err = strconv.Atoi(splits[0])
		if err != nil {
			return "", err
		}
		if inputNumber+1 > len(m.Inputs) {
			return "", errors.New("inputnumber out of bounds")
		}
		return m.Inputs[inputNumber].Filename, nil
	}
	if m.Dash.Streams[streamno].ReferenceFile != 0 {
		inputNumber = m.Dash.Streams[streamno].ReferenceFile
		return m.Inputs[inputNumber].Filename, nil
	}
	return "", fmt.Errorf("No inputFName derived for stream %d. m=%v\n", streamno, m)
}

func Input(streamno int, m scrape.Msp) (scrape.InputT, error) {
	splits := strings.Split(m.Dash.Streams[streamno].Source, ":")
	inputNumber, err := strconv.Atoi(splits[0])
	if err != nil {
		return scrape.InputT{}, err
	}
	return m.Inputs[inputNumber], nil
}

// source is e.g. "0:v:0"
func gop(fname string, dir string) (float64, float64, error) { //milliseconds,frames
	//ffprobe -v error -select_streams v:0 -skip_frame nokey -show_entries frame=pts_time -print_format json -read_intervals %+2 "input.mp4"
	fmt.Printf("XXXXXXX %s\n", fname)
	cmd := exec.Command("/usr/bin/ffprobe", "-v", "error", "-select_streams", "v:0", "-skip_frame", "nokey", "-show_entries", "frame=pts_time", "-of", "json", "-read_intervals", "%+20", dir+"/"+fname)
	buf := new(bytes.Buffer)
	cmd.Stdout = buf
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return 0.0, 0.0, err
	}
	type ProbeOutput struct {
		Frames []struct {
			PtsTime string `json:"pts_time"`
		} `json:"frames"`
	}
	var data ProbeOutput
	if err := json.Unmarshal(buf.Bytes(), &data); err != nil || len(data.Frames) < 2 {
		fmt.Printf("%v\n", string(buf.Bytes()))
		return 0.0, 0.0, fmt.Errorf("Error: Could not find two keyframes.")
	}
	t1, _ := strconv.ParseFloat(data.Frames[0].PtsTime, 64)
	t2, _ := strconv.ParseFloat(data.Frames[1].PtsTime, 64)
	diff := t2 - t1
	_fps, err := fps(fname, dir)
	if err != nil {
		return 0.0, 0.0, err
	}
	gopFrames := diff * _fps
	ms := diff * 1000

	fmt.Printf("Offset:     %f\n", t1)
	fmt.Printf("GOP (sec):  %f\n", diff)
	fmt.Printf("GOP (ms):   %.0f (Use for MP4Box -dash)\n", ms)
	fmt.Printf("GOP (f):    %.0f (Use for FFmpeg keyint)\n", gopFrames)
	return ms, gopFrames, nil
}

func fps(fname string, dir string) (float64, error) {
	cmd := exec.Command("/usr/bin/ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries", "stream=r_frame_rate", "-of", "json", dir+"/"+fname)
	buf := new(bytes.Buffer)
	cmd.Stdout = buf
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return 0.0, err
	}
	type resT struct {
		Streams []struct {
			RFrameRate string `json:"r_frame_rate"`
		} `json:"streams"`
	}
	//spew.Dump(buf.Bytes())
	var res resT
	if err := json.Unmarshal(buf.Bytes(), &res); err != nil {
		return 0.0, fmt.Errorf("5s", err.Error()+string(buf.Bytes()))
	}
	splits := strings.Split(res.Streams[0].RFrameRate, "/")
	dividend, err := strconv.Atoi(splits[0])
	if err != nil {
		return 0.0, err
	}
	divisor, err := strconv.Atoi(splits[1])
	if err != nil {
		return 0.0, err
	}
	return float64(dividend) / float64(divisor), nil
}

type properties struct {
	streamType  string // video, audio, subtitles
	fps         float64
	gopMilliSec float64
	gopFrames   float64
}

func sourceProperties(fname string, dir string) (properties, error) {
	gopMs, gopFrames, err := gop(fname, dir)
	if err != nil {
		return properties{}, err
	}

	var res properties
	res.fps, err = fps(fname, dir)
	if err != nil {
		return properties{}, err
	}
	res.gopMilliSec = gopMs
	res.gopFrames = gopFrames
	return res, nil
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

func deinterlaceIfNeeded(in, out string, profile scrape.InputT) string {
	var filter string
	switch profile.Interlaced {
	case true:
		filter = "bwdif=mode=0:parity=auto:deint=all"
	case false:
		filter = "null"
	}
	return fmt.Sprintf("[%s]%s[%s]", in, filter, out)
}

func scaleIfNeeded(in, out string, filter string) string {
	return fmt.Sprintf("[%s]%s[%s]", in, filter, out)
}

type EncodeParams struct {
	StreamNo int
	Msp      scrape.Msp
	Dir      string
	Props    targetProperties
}

func EncodeStreamActivity(ctx context.Context, p EncodeParams) (string, error) {
	/*
		DEINTERLACE := "[$VIDEOSOURCE]bwdif=mode=0:parity=auto:deint=all,"
		SCALE_1080 := "scale='if(gt(iw,ih),min(1920,iw),-2)':'if(gt(iw,ih),-2,min(1080,ih))'"
		SCALE_720 := "scale='if(gt(iw,ih),min(1280,iw),-2)':'if(gt(iw,ih),-2,min(720,ih))'"
	*/

	inputFName, err := InputFName(p.StreamNo, p.Msp)
	if err != nil {
		return "", err
	}
	drFname, err := DasherReadyFilename(p.StreamNo, p.Msp)
	if err != nil {
		return "", err
	}
	outputFName := drFname + "-fragmented.mp4"

	var args []string
	var scaleFilter string
	switch p.Msp.Dash.Streams[p.StreamNo].Profile {
	case "high":
		scaleFilter = "scale='if(gt(iw,ih),min(1920,iw),-2)':'if(gt(iw,ih),-2,min(1080,ih))'"
	case "low":
		scaleFilter = "scale='if(gt(iw,ih),min(1280,iw),-2)':'if(gt(iw,ih),-2,min(720,ih))'"
	default:
		return "", fmt.Errorf("Unsupported profile: " + p.Msp.Dash.Streams[p.StreamNo].Profile)
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
			return "", err
		}
		args = []string{
			"-itsoffset", "0.080",
			"-c:v", "h264_v4l2m2m",
			"-i", p.Dir + "/" + inputFName,
			"-filter_complex", strings.Join([]string{deinterlaceIfNeeded(p.Msp.Dash.Streams[p.StreamNo].Source, "postdeint", inp),
				scaleIfNeeded("postdeint", "out", scaleFilter)}, ";"),
			"-map", "[out]",
			"-c:v", "libx264",
			"-profile:v", "high",
			"-level:v", "4.1",
			"-pix_fmt", "yuv420p",
			"-crf:v", strconv.Itoa(crf),
			"-preset:v", "slow",
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
			"-i", p.Dir + "/" + inputFName,
			"-map", p.Msp.Dash.Streams[p.StreamNo].Source,
			"-c:v", "libx265",
			"-profile:v", "main10",
			"-level:v", "5.1",
			"-pix_fmt", "yuv420p",
			"-crf:v", strconv.Itoa(crf),
			"-preset:v", "slow",
		}
		inp, err := Input(p.StreamNo, p.Msp)
		if err != nil {
			return "", err
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
	if err := os.MkdirAll(DashDir(p.Msp), os.ModePerm); err != nil {
		return "", err
	}
	cmd := exec.Command("/usr/bin/ffmpeg", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	fmt.Printf("FFMpeg encoding stream %d. %s becomes %s \n", p.StreamNo, inputFName, outputFName)
	err = cmd.Run()
	if err != nil {
		return "", err
	}

	args = []string{
		"-dash", strconv.FormatFloat(p.Props.dashMs, 'f', 0, 64), "-rap", "-profile", "onDemand", "-segment-name", outputFName + "-postDash.mp4", "-out", "manifest.mpd", outputFName}
	cmd = exec.Command("/usr/bin/MP4Box", args...)
	cmd.Dir = DashDir(p.Msp)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	drFname, err = DasherReadyFilename(p.StreamNo, p.Msp)
	if err != nil {
		return "", err
	}
	fmt.Printf("MP4Box dashing stream %d.  %s becomes %s \n", p.StreamNo, outputFName, drFname)
	fmt.Printf("Starting /usr/bin/MP4Box %v\n", args)
	err = cmd.Run()
	if err != nil {
		return "", err
	}
	if err := os.Remove(outputFName); err != nil {
		return "", err
	}
	if err := os.Remove(DashDir(p.Msp) + "/manifest.mpd"); err != nil {
		return "", err
	}
	if err := os.Rename(outputFName+"-postDash.mp4init.mp4", drFname); err != nil {
		return "", err
	}
	return "", nil
}

func linkAction(streamno int, m scrape.Msp, dir string) error {
	//Get the source file
	inputNumber := m.Dash.Streams[streamno].ReferenceFile
	srcFile := m.Inputs[inputNumber].Filename
	dstFile, err := DasherReadyFilename(streamno, m)
	if err != nil {
		return err
	}
	fmt.Printf("Creating symlink %s -> %s\n", dstFile, srcFile)
	if err := os.Symlink(dir+"/"+srcFile, dstFile); err != nil {
		return err
	}
	return nil
}

func dasherAction(m scrape.Msp, gopMs float64) error {
	fmt.Printf("dasherAction\n")
	var inputs []string
	for streamno, _ := range m.Dash.Streams {
		drFname, err := DasherReadyFilename(streamno, m)
		if err != nil {
			return err
		}
		inputs = append(inputs, drFname+":id="+strconv.Itoa(streamno))
	}
	args := []string{"-dash", strconv.FormatFloat(gopMs, 'f', 0, 64), "-rap", "-profile", "onDemand", "-out", DashDir(m) + "/manifest.mpd"}
	args = append(args, inputs...)
	//spew.Dump(args)
	cmd := exec.Command("/usr/bin/MP4Box", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func replaceWithSymlink(src, target string) error {
	if err := os.Remove(src); err != nil {
		return err
	}
	if err := os.Symlink(target, src); err != nil {
		return err
	}
	return nil
}

func makeDashWorkFlow(dir string, mspFile string) error {
	m, err := ActionReadMSP(dir, mspFile)
	if err != nil {
		return fmt.Errorf("MSP read of %s/%s failed: %w", dir, mspFile, err)
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
				props, err := sourceProperties(m.Inputs[stream.ReferenceFile].Filename, dir)
				if err != nil {
					return err
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
	//Find the encoding needs
	for streamno, stream := range m.Dash.Streams {
		switch stream.Codec {
		case "x264", "x265", "copy", "aac":
			if _, err := EncodeStreamActivity(context.Background(), EncodeParams{streamno, m, dir, tprops}); err != nil {
				return err
			}
		case "reference":
			linkAction(streamno, m, dir)
		default:
			return fmt.Errorf("Unsupported Codec %s in stream %d\n", stream.Codec, streamno)
		}

	}
	//Build Dash
	dasherAction(m, tprops.dashMs)

	for streamno, _ := range m.Dash.Streams {
		dashFName, err := DasherReadyFilename(streamno, m)
		if err != nil {
			return err
		}
		replaceWithSymlink(strings.TrimSuffix(dashFName, ".mp4")+"_dashinit.mp4", dashFName)
	}
	fixAudioPresentationTimeOffset(DashDir(m) + "/" + "manifest.mpd")
	return nil
}
