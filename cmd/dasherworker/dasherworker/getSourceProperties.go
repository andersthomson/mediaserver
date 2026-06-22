package dasherworker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
)

type SrcProperties struct {
	Fps         float64
	GopMilliSec GopMs
	GopFrames   float64
}
type ProbeParams struct {
	Filename string
	Dir      string
}

// GetSourcePropertiesActivity combines GOP and FPS detection into a single remote call.
func GetSourceProperties(ctx context.Context, params ProbeParams) (SrcProperties, error) {
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

	spew.Dump(calculatedFPS)
	return SrcProperties{
		Fps:         calculatedFPS,
		GopMilliSec: GopMs(diff * 1000),
		GopFrames:   diff * calculatedFPS,
	}, nil
}
