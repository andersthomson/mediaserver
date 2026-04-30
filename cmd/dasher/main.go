package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker"
	"github.com/andersthomson/mediaserver/scrape"
	"github.com/davecgh/go-spew/spew"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"go.temporal.io/sdk/client"
)

func main() {
	// Create the client once
	c, err := client.Dial(client.Options{
		HostPort: "localhost:7233",
	})
	if err != nil {
		panic(err)
	}
	defer c.Close()

	dir := filepath.Dir(os.Args[1])
	base := filepath.Base(os.Args[1])
	if base == "" || dir == "" {
		panic("Need as arg 1 path to msp file\n")
	}
	//if err := makeDashWorkFlow("/var/lib/media/temp/testfil", "flaskhals.msp"); err != nil {
	if err := makeDashWorkFlow(c, dir, base); err != nil {
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

type SrcProperties struct {
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
func GetSourcePropertiesActivity(ctx context.Context, params ProbeParams) (SrcProperties, error) {
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
		return SrcProperties{}, fmt.Errorf("ffprobe failed: %w", errors.WithStack(err))
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
		return SrcProperties{}, fmt.Errorf("failed to unmarshal ffprobe output: %w", errors.WithStack(err))
	}

	if len(data.Streams) == 0 {
		return SrcProperties{}, errors.New("no video streams found")
	}

	// 1. Calculate FPS
	splits := strings.Split(data.Streams[0].RFrameRate, "/")
	if len(splits) != 2 {
		return SrcProperties{}, fmt.Errorf("invalid frame rate format: %s", data.Streams[0].RFrameRate)
	}
	dividend, _ := strconv.ParseFloat(splits[0], 64)
	divisor, _ := strconv.ParseFloat(splits[1], 64)
	if divisor == 0 {
		return SrcProperties{}, errors.New("divisor is zero in frame rate")
	}
	calculatedFPS := dividend / divisor

	// 2. Calculate GOP
	if len(data.Frames) < 2 {
		return SrcProperties{}, errors.New("could not find at least two keyframes for GOP calculation")
	}
	t1, err := strconv.ParseFloat(data.Frames[0].PtsTime, 64)
	if err != nil {
		return SrcProperties{}, fmt.Errorf("Failed to parse as float: %v", data.Frames[0].PtsTime)
	}
	t2, err := strconv.ParseFloat(data.Frames[1].PtsTime, 64)
	if err != nil {
		return SrcProperties{}, fmt.Errorf("Failed to parse as float: %v", data.Frames[0].PtsTime)
	}

	diff := t2 - t1

	return SrcProperties{
		streamType:  "video",
		fps:         calculatedFPS,
		gopMilliSec: diff * 1000,
		gopFrames:   diff * calculatedFPS,
	}, nil
}

func dashMs(p SrcProperties) float64 {
	diff := p.gopMilliSec / 1000
	return math.Max(1.0, math.Round(4.0/diff)) * diff * 1000
}

func preset() string {
	if fast() {
		return "ultrafast"
	} else {
		return "slow"
	}
}

func EncodeStreamActivity(ctx context.Context, tc client.Client, p dasherworker.EncodeParams) (string, error) {
	// ExecuteWorkflow(ctx, options, workflowFunc, args...)
	run, err := tc.ExecuteWorkflow(context.Background(),
		client.StartWorkflowOptions{
			ID:        "MyWorkflowID", // Unique ID for business logic
			TaskQueue: "dasherQueue",  // Which worker group should handle this
		},
		"EncodingWorkflow",
		dasherworker.EncodingWorkflowArgs{
			WorkDir: DashDir(p.Msp),
			P:       p,
		})
	if err != nil {
		slog.Info("Couldn't start workflow", "err", err)
		return "", fmt.Errorf("Couldn't start workflow. %+v", err)
	}
	fmt.Printf("Started Workflow ID: %s\n", run.GetID())
	var res dasherworker.EncodingWorkflowResp
	if err = run.Get(context.Background(), &res); err != nil {
		slog.Info("Couldn't start workflow", "err", err)
		return "", fmt.Errorf("Couldn't start workflow. %s", err.Error())
	}
	fmt.Printf("Result %v\n", res)

	return "", nil
}

func linkAction(streamno int, m scrape.Msp, dir string) error {
	//Get the source file
	inputNumber := m.Dash.Streams[streamno].ReferenceFile
	srcFile := m.Inputs[inputNumber].Filename
	dstFile, err := dasherworker.DasherReadyFilename(streamno, m)
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
		drFname, err := dasherworker.DasherReadyFilename(streamno, m)
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
		return errors.WithStack(err)
	}
	return nil
}

func makeDashWorkFlow(tc client.Client, dir string, mspFile string) error {
	DirTimestamp = time.Now().UTC().Format("2006-01-02T15-04-05Z")
	m, err := ActionReadMSP(dir, mspFile)
	if err != nil {
		return fmt.Errorf("MSP read of %s/%s failed: %w", dir, mspFile, errors.WithStack(err))
	}
	//Sanity check:
	var referenceFiles = map[int]bool{}
	var tprops dasherworker.TargetProperties
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
				tprops.GopFrames = props.gopFrames
				tprops.DashMs = dashMs(props)
			case isDashReadyAudio(dir + "/" + m.Inputs[stream.ReferenceFile].Filename):
			default:
				return fmt.Errorf("Source %d, which you want to have referenced, is not dash ready\n", stream.ReferenceFile)
			}
		}
	}
	if tprops.GopFrames == 0 {
		tprops.GopFrames = 100
		tprops.DashMs = 4000
	}
	if err := os.MkdirAll(DashDir(m), os.ModePerm); err != nil {
		return errors.WithStack(err)
	}
	//Find the encoding needs
	for streamno, stream := range m.Dash.Streams {
		switch stream.Codec {
		case "x264", "x265", "copy", "aac":
			inFname, err := dasherworker.InputFName(streamno, m)
			if err != nil {
				return errors.WithStack(err)
			}
			srcAnalysis, err := dasherworker.AnalyzeMediaActivity(context.Background(), dir, inFname)
			if err != nil {
				return errors.WithStack(err)
			}
			spew.Dump(srcAnalysis)
			if _, err := EncodeStreamActivity(context.Background(), tc, dasherworker.EncodeParams{preset(), streamno, m, dir, tprops, srcAnalysis}); err != nil {
				return err
			}
		case "reference":
			linkAction(streamno, m, dir)
		default:
			return fmt.Errorf("Msp malformed: Unsupported Codec %s in stream %d\n", stream.Codec, streamno)
		}

	}
	//Build Dash
	dasherAction(m, tprops.DashMs)

	for streamno, _ := range m.Dash.Streams {
		dashFName, err := dasherworker.DasherReadyFilename(streamno, m)
		if err != nil {
			return err
		}
		if err := replaceWithSymlink(DashDir(m)+"/"+strings.TrimSuffix(dashFName, ".mp4")+"_dashinit.mp4", dashFName); err != nil {
			return err
		}
	}
	fixAudioPresentationTimeOffset(DashDir(m) + "/" + "manifest.mpd")
	if fast() {
		if err := os.WriteFile(DashDir(m)+"/"+"dasher_fast=1", nil, 0644); err != nil {
			return errors.WithStack(err)
		}
	}

	tmpSuffix := uuid.NewString()
	if err := os.Symlink(filepath.Base(DashDir(m)), DashDirProd(m)+tmpSuffix); err != nil {
		return fmt.Errorf("Symlinking for production failed: %v", errors.WithStack(err))
	}
	if err := os.Rename(DashDirProd(m)+tmpSuffix, DashDirProd(m)); err != nil {
		return fmt.Errorf("Renaming to production failed: %v", errors.WithStack(err))
	}
	return nil
}
