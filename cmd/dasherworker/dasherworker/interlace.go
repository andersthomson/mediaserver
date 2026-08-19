package dasherworker

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	"go.temporal.io/sdk/workflow"
)

type FilterRecommendation struct {
	FilterRecommendation string `json:"filter_recommendation"`
}

// ProbeRawData isolates the uncalculated raw system metrics captured directly from hardware files.
type ProbeRawData struct {
	FieldOrder   string
	TffCount     int
	BffCount     int
	ProgCount    int
	DecimateDrop int
	DecimateKeep int
}

func CallExecuteProbes(ctx workflow.Context, inputID string, inputNo int, stream string) (ProbeRawData, error) {
	return CallActivityIO[any, ProbeRawData](ctx, ExecuteProbes, inputID, inputNo, stream)
}

func ExecuteProbes(ctx context.Context, inputID string, inputNo int, stream string) (ProbeRawData, error) {
	fullPath := storage.ResolveInputNumber(inputID, inputNo)
	return ExecuteProbesFile(ctx, fullPath, stream)
}

func ExecuteProbesFile(ctx context.Context, fullPath string, stream string) (ProbeRawData, error) {
	var raw ProbeRawData

	// 2. Fetch Duration and calculate seek point
	duration, err := getVideoDuration(ctx, fullPath)
	if err != nil {
		return raw, errors.WithStack(err)
	}
	seekPoint := 0.0
	if duration > 2.0 {
		seekPoint = duration / 2
	}

	// 3. Fetch Container Metadata Field Order
	fieldOrderCmd := exec.CommandContext(ctx, "ffprobe", "-v", "error", "-select_streams", stream, "-show_entries", "stream=field_order", "-of", "default=noprint_wrappers=1:nokey=1", fullPath)
	fieldOrderOut, _ := fieldOrderCmd.Output()
	raw.FieldOrder = strings.ToLower(strings.TrimSpace(string(fieldOrderOut)))

	// 4. Run IDET Pixel Scan
	idetCmd := exec.CommandContext(ctx, "ffmpeg", "-ss", fmt.Sprintf("%f", seekPoint), "-i", fullPath, "-vf", "idet", "-frames:v", "1000", "-an", "-c:v", "rawvideo", "-f", "null", "-")
	var idetStderr bytes.Buffer
	idetCmd.Stderr = &idetStderr
	if err := idetCmd.Run(); err != nil {
		return raw, errors.Wrap(err, "ffmpeg idet analysis failed")
	}

	reIdet := regexp.MustCompile(`TFF:\s+(\d+)\s+BFF:\s+(\d+)\s+Progressive:\s+(\d+)`)
	idetMatches := reIdet.FindAllStringSubmatch(idetStderr.String(), -1)
	if len(idetMatches) > 0 {
		lastMatch := idetMatches[len(idetMatches)-1]
		raw.TffCount, _ = strconv.Atoi(lastMatch[1])
		raw.BffCount, _ = strconv.Atoi(lastMatch[2])
		raw.ProgCount, _ = strconv.Atoi(lastMatch[3])
	}

	// 5. Run Duplicate Frame Detection Pass
	dupCmd := exec.CommandContext(ctx, "ffmpeg", "-ss", "00:10:00", "-t", "10", "-i", fullPath, "-vf", "mpdecimate", "-loglevel", "debug", "-f", "null", "-")
	var dupBuf bytes.Buffer
	dupCmd.Stderr = &dupBuf
	_ = dupCmd.Run()
	dupOutput := dupBuf.String()

	raw.DecimateDrop = strings.Count(dupOutput, "drop")
	raw.DecimateKeep = strings.Count(dupOutput, "keep")

	return raw, nil
}

func getVideoDuration(ctx context.Context, fullPath string) (float64, error) {
	cmd := exec.CommandContext(ctx, "ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=noprint_wrappers=1:nokey=1", fullPath)
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	return strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
}

func DeriveFilterRecommendation(raw ProbeRawData) FilterRecommendation {
	analysis := FilterRecommendation{
		FilterRecommendation: "null",
	}

	// Parse structural metadata header hints
	isMetadataInterlaced := strings.Contains(raw.FieldOrder, "top") ||
		strings.Contains(raw.FieldOrder, "bottom") ||
		strings.Contains(raw.FieldOrder, "tt") ||
		strings.Contains(raw.FieldOrder, "bb") ||
		strings.Contains(raw.FieldOrder, "tb") ||
		strings.Contains(raw.FieldOrder, "bt")

	totalPixelFrames := raw.TffCount + raw.BffCount + raw.ProgCount

	// Process IDET Matrix Ratios
	if totalPixelFrames > 0 {
		progressiveRatio := float64(raw.ProgCount) / float64(totalPixelFrames)
		interlacedRatio := float64(raw.TffCount+raw.BffCount) / float64(totalPixelFrames)

		if interlacedRatio > 0.15 || isMetadataInterlaced {
			// Resolve target parity
			parity := "auto"
			if strings.Contains(raw.FieldOrder, "top") || strings.Contains(raw.FieldOrder, "tt") || strings.Contains(raw.FieldOrder, "tb") {
				parity = "tff"
			} else if strings.Contains(raw.FieldOrder, "bottom") || strings.Contains(raw.FieldOrder, "bb") || strings.Contains(raw.FieldOrder, "bt") {
				parity = "bff"
			} else if raw.TffCount > raw.BffCount {
				parity = "tff"
			} else if raw.BffCount > raw.TffCount {
				parity = "bff"
			}

			// Branch filter optimization based on pixel reality thresholds
			if progressiveRatio > 0.90 {
				analysis.FilterRecommendation = "fieldmatch=order=" + parity + ":combmatch=full,yadif=mode=send_frame:deint=interlaced,format=yuv420p10le"
			} else {
				analysis.FilterRecommendation = "bwdif=mode=0:parity=" + parity + ":deint=all,format=yuv420p10le"
			}
		}
	}

	// Process Cadence Verification Metrics
	totalDecimateFrames := raw.DecimateDrop + raw.DecimateKeep
	spew.Dump(raw.DecimateDrop)
	spew.Dump(raw.DecimateKeep)

	if totalDecimateFrames > 0 && (float64(raw.DecimateDrop)/float64(totalDecimateFrames)) > 0.40 {
		//"Fake High FPS"
		if analysis.FilterRecommendation != "null" {
			analysis.FilterRecommendation = strings.ReplaceAll(analysis.FilterRecommendation, "mode=send_frame", "mode=0")
		}
	} else {
		if strings.Contains(analysis.FilterRecommendation, "mode=send_frame") {
			analysis.FilterRecommendation = strings.ReplaceAll(analysis.FilterRecommendation, "mode=send_frame", "mode=0")
		}
	}

	// Chain final structural scaling and sync targets
	analysis.FilterRecommendation += ",fps=fps=25:round=near"
	const forceStartAtZero = "setpts=N/25/TB"
	if analysis.FilterRecommendation == "null" {
		analysis.FilterRecommendation = forceStartAtZero
	} else {
		analysis.FilterRecommendation += "," + forceStartAtZero
	}

	return analysis
}
