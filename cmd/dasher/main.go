package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/andersthomson/mediaserver/scrape"
	"github.com/davecgh/go-spew/spew"
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

func DasherReadyFilename(streamno int, m scrape.Msp) string {
	return DashDir(m) + "/" + InputFName(streamno, m) + "-encoded-" + fmt.Sprintf("%d", streamno) + ".mp4"
}

func InputFName(streamno int, m scrape.Msp) string {
	splits := strings.Split(m.Dash.Streams[streamno].Source, ":")
	inputNumber, err := strconv.Atoi(splits[0])
	if err != nil {
		panic(err)
	}
	return m.Inputs[inputNumber]
}

// source is e.g. "0:v:0"
func gop(fname string, source string, dir string) (float64, float64) { //milliseconds,frames
	//ffprobe -v error -select_streams v:0 -skip_frame nokey -show_entries frame=pts_time -print_format json -read_intervals %+2 "input.mp4"
	videostream := strings.SplitN(source, ":", 2)
	cmd := exec.Command("/usr/bin/ffprobe", "-v", "error", "-select_streams", videostream[1], "-skip_frame", "nokey", "-show_entries", "frame=pts_time", "-of", "json", "-read_intervals", "%+20", dir+"/"+fname)
	buf := new(bytes.Buffer)
	cmd.Stdout = buf
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		panic(err)
	}
	type ProbeOutput struct {
		Frames []struct {
			PtsTime string `json:"pts_time"`
		} `json:"frames"`
	}
	var data ProbeOutput
	if err := json.Unmarshal(buf.Bytes(), &data); err != nil || len(data.Frames) < 2 {
		fmt.Printf("%v\n", string(buf.Bytes()))
		panic("Error: Could not find two keyframes.")
	}
	t1, _ := strconv.ParseFloat(data.Frames[0].PtsTime, 64)
	t2, _ := strconv.ParseFloat(data.Frames[1].PtsTime, 64)
	diff := t2 - t1
	gopFrames := diff * fps(fname, source, dir)
	ms := diff * 1000

	fmt.Printf("Offset:     %f\n", t1)
	fmt.Printf("GOP (sec):  %f\n", diff)
	fmt.Printf("GOP (ms):   %.0f (Use for MP4Box -dash)\n", ms)
	fmt.Printf("GOP (f):    %.0f (Use for FFmpeg keyint)\n", gopFrames)
	return ms, gopFrames
}

func fps(fname string, source string, dir string) float64 {
	videostream := strings.SplitN(source, ":", 2)
	cmd := exec.Command("/usr/bin/ffprobe", "-v", "error", "-select_streams", videostream[1], "-show_entries", "stream=r_frame_rate", "-of", "json", dir+"/"+fname)
	buf := new(bytes.Buffer)
	cmd.Stdout = buf
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		panic(err)
	}
	type resT struct {
		Streams []struct {
			RFrameRate string `json:"r_frame_rate"`
		} `json:"streams"`
	}
	spew.Dump(buf.Bytes())
	var res resT
	if err := json.Unmarshal(buf.Bytes(), &res); err != nil {
		panic(err.Error() + string(buf.Bytes()))
	}
	splits := strings.Split(res.Streams[0].RFrameRate, "/")
	dividend, err := strconv.Atoi(splits[0])
	if err != nil {
		panic(err)
	}
	divisor, err := strconv.Atoi(splits[1])
	if err != nil {
		panic(err)
	}
	return float64(dividend) / float64(divisor)
}

type properties struct {
	fps         float64
	gopMilliSec float64
	gopFrames   float64
}

func sourceProperties(fname string, source string, dir string) properties {
	gopMs, gopFrames := gop(fname, source, dir)

	var res properties
	res.fps = fps(fname, source, dir)
	res.gopMilliSec = gopMs
	res.gopFrames = gopFrames
	return res
}
func dashMs(p properties) float64 {
	diff := p.gopMilliSec / 1000
	return math.Max(1.0, math.Round(4.0/diff)) * diff * 1000
}

type targetProperties struct {
	gopFrames float64
	dashMs    float64
}

func encodeAction(streamno int, m scrape.Msp, dir string, props targetProperties) {
	inputFName := InputFName(streamno, m)
	outputFName := DasherReadyFilename(streamno, m) + "-fragmented.mp4"

	var args []string

	switch m.Dash.Streams[streamno].Codec {
	case "x264":
		var crf int
		var bitrate int
		switch m.Dash.Streams[streamno].Profile {
		case "high":
			crf = 18
			bitrate = 6000
		case "low":
			crf = 21
			bitrate = 800
		default:
			panic("Unsupported profile: " + m.Dash.Streams[streamno].Profile)
		}
		tune := "film"
		switch m.Dash.Streams[streamno].Tune {
		case "animation":
			tune = "animation"
		case "":
		default:
			panic("Unsupported x264 tune: " + m.Dash.Streams[streamno].Tune)
		}

		crfMax := 5 + crf
		bufsize := 2 * bitrate
		args = []string{
			"-itsoffset", "0.080",
			"-i", dir + "/" + inputFName,
			"-map", m.Dash.Streams[streamno].Source,
			"-c:v", "libx264",
			"-profile:v", "high",
			"-level:v", "4.1",
			"-pix_fmt", "yuv420p",
			"-crf:v", strconv.Itoa(crf),
			"-preset:v", "veryfast",
			"-tune:v", tune,
			"-x264-params:v", "keyint=" + strconv.FormatFloat(props.gopFrames, 'f', 0, 64) + ":min-keyint=" + strconv.FormatFloat(props.gopFrames, 'f', 0, 64) + ":scenecut=0:open-gop=0:vbv-maxrate=" + strconv.Itoa(bitrate) + ":vbv-bufsize=" + strconv.Itoa(bufsize) + ":crf-max=" + strconv.Itoa(crfMax),
			"-movflags", "frag_keyframe+empty_moov+default_base_moof",
			outputFName,
		}
	case "x265":
		var crf int
		var bitrate int
		switch m.Dash.Streams[streamno].Profile {
		case "high":
			crf = 21
			bitrate = 2000
		case "low":
			crf = 21
			bitrate = 800
		default:
			panic("Unsupported profile: " + m.Dash.Streams[streamno].Profile)
		}

		tune := ""
		switch m.Dash.Streams[streamno].Tune {
		case "animation":
			tune = "animation"
		case "":
		default:
			panic("Unsupported x265 tune: " + m.Dash.Streams[streamno].Tune)
		}

		bufsize := 2 * bitrate
		args = []string{
			"-i", dir + "/" + inputFName,
			"-map", m.Dash.Streams[streamno].Source,
			"-c:v", "libx265",
			"-profile:v", "main10",
			"-level:v", "5.1",
			"-pix_fmt", "yuv420p",
			"-crf:v", strconv.Itoa(crf),
			"-preset:v", "veryfast",
		}
		if tune != "" {
			args = append(args, "-tune:v", tune)
		}
		args = append(args,
			"-tag:v", "hvc1",
			"-x265-params:v", "keyint="+strconv.FormatFloat(props.gopFrames, 'f', 0, 64)+":min-keyint="+strconv.FormatFloat(props.gopFrames, 'f', 0, 64)+":scenecut=0:open-gop=0:vbv-maxrate="+strconv.Itoa(bitrate)+":vbv-bufsize="+strconv.Itoa(bufsize),
			"-movflags", "frag_keyframe+empty_moov+default_base_moof",
			outputFName,
		)
	case "aac":
		args = []string{
			"-i", dir + "/" + inputFName,
			"-map", m.Dash.Streams[streamno].Source,
			"-c", "aac",
			outputFName,
		}
	case "copy":
		args = []string{
			"-i", dir + "/" + inputFName,
			"-map", m.Dash.Streams[streamno].Source,
			"-c", "copy",
			outputFName,
		}
	}
	fmt.Printf("Starting %v\n", args)
	if err := os.MkdirAll(DashDir(m), os.ModePerm); err != nil {
		panic(err)
	}
	cmd := exec.Command("/usr/bin/ffmpeg", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	fmt.Printf("FFMpeg encoding stream %d. %s becomes %s \n", streamno, inputFName, outputFName)
	err := cmd.Run()
	if err != nil {
		panic(err)
	}

	args = []string{
		"-dash", strconv.FormatFloat(props.dashMs, 'f', 0, 64), "-rap", "-profile", "onDemand", "-segment-name", outputFName + "-postDash.mp4", "-out", "manifest.mpd", outputFName}
	cmd = exec.Command("/usr/bin/MP4Box", args...)
	cmd.Dir = DashDir(m)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	fmt.Printf("MP4Box dashing stream %d.  %s becomes %s \n", streamno, outputFName, DasherReadyFilename(streamno, m))
	fmt.Printf("Starting /usr/bin/MP4Box %v\n", args)
	err = cmd.Run()
	if err != nil {
		panic(err)
	}
	if err := os.Remove(outputFName); err != nil {
		panic(err)
	}
	if err := os.Remove(DashDir(m) + "/manifest.mpd"); err != nil {
		panic(err)
	}
	if err := os.Rename(outputFName+"-postDash.mp4init.mp4", DasherReadyFilename(streamno, m)); err != nil {
		panic(err)
	}
	return
}

func linkAction(streamno int, m scrape.Msp, dir string) {
	//Get the source file
	inputNumber, err := strconv.Atoi(m.Dash.Streams[streamno].Source)
	if err != nil {
		panic(err)
	}
	srcFile := m.Inputs[inputNumber]
	dstFile := DasherReadyFilename(streamno, m)
	fmt.Printf("Creating symlink %s -> %s\n", dstFile, srcFile)
	if err := os.Symlink(dir+"/"+srcFile, dstFile); err != nil {
		panic(err)
	}
}

func dasherAction(m scrape.Msp, gopMs float64) {
	fmt.Printf("dasherAction\n")
	var inputs []string
	for streamno, _ := range m.Dash.Streams {
		inputs = append(inputs, DasherReadyFilename(streamno, m)+":id="+strconv.Itoa(streamno))
	}
	args := []string{"-dash", strconv.FormatFloat(gopMs, 'f', 0, 64), "-rap", "-profile", "onDemand", "-out", DashDir(m) + "/manifest.mpd"}
	args = append(args, inputs...)
	spew.Dump(args)
	cmd := exec.Command("/usr/bin/MP4Box", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		panic(err)
	}
	fmt.Printf("FIXME replace the new dasher files with symlinks to the 'dasherReady' files\n")

}

func replaceWithSymlink(src, target string) {
	if err := os.Remove(src); err != nil {
		panic(err)
	}
	if err := os.Symlink(target, src); err != nil {
		panic(err)
	}
}

func makeDashWorkFlow(dir string, mspFile string) error {
	m, err := ActionReadMSP(dir, mspFile)
	if err != nil {
		return fmt.Errorf("MSP read of %s/%s failed: %w", dir, mspFile, err)
	}
	//Sanity check:
	var referencedSources = map[string]bool{}
	var tprops targetProperties
	for streamno, stream := range m.Dash.Streams {
		if stream.Codec == "reference" {
			referencedSources[stream.Source] = true
			//At least one output stream want to reference an input stream.
			//Check that the input's gop is sane
			props := sourceProperties(InputFName(streamno, m), stream.Source, dir)
			if props.gopMilliSec < 1500 || props.gopMilliSec > 5000 {
				panic(fmt.Sprintf("Source %d, which you want to have referenced, has an unsupported gop %d\n", streamno, props.gopMilliSec))
			}
			tprops.gopFrames = props.gopFrames
			tprops.dashMs = dashMs(props)
		}
	}
	if len(referencedSources) > 1 {
		panic("At most one referenced source allowed\n")
	}
	if tprops.gopFrames == 0 {
		tprops.gopFrames = 100
		tprops.dashMs = 4000
	}
	//Find the encoding needs
	for streamno, stream := range m.Dash.Streams {
		switch stream.Codec {
		case "x264":
			encodeAction(streamno, m, dir, tprops)
		case "x265":
			encodeAction(streamno, m, dir, tprops)
		case "copy":
			encodeAction(streamno, m, dir, tprops)
		case "aac":
			encodeAction(streamno, m, dir, tprops)
		case "reference":
			linkAction(streamno, m, dir)
		default:
			panic(fmt.Sprintf("Unsupported Codec %s in stream %d\n", stream.Codec, streamno))
		}

	}
	//Build Dash
	dasherAction(m, tprops.dashMs)

	for streamno, _ := range m.Dash.Streams {
		dashFName := DasherReadyFilename(streamno, m)
		replaceWithSymlink(strings.TrimSuffix(dashFName, ".mp4")+"_dashinit.mp4", dashFName)
	}
	fixAudioPresentationTimeOffset(DashDir(m) + "/" + "manifest.mpd")
	return nil
}
