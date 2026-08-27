package deinterlacer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
)

type Deinterlacer struct {
	Storage *storage.Storage
}

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

	CodecName   string
	Width       int
	Height      int
	PAR         string
	StartTime   float64
	IsCFR       bool
	HasFixedGOP bool
	GOPSize     int
}

func (d *Deinterlacer) ExecuteProbes(ctx context.Context, inputID string, inputNo int, stream string) (ProbeRawData, error) {
	fullPath := d.Storage.ResolveInputNumber(inputID, inputNo)
	return ExecuteProbesFile(ctx, fullPath, stream)
}

func ExecuteProbesFile(ctx context.Context, fullPath string, stream string) (ProbeRawData, error) {
	type FFprobeJSON struct {
		Streams []struct {
			CodecName    string `json:"codec_name"`
			Width        int    `json:"width"`
			Height       int    `json:"height"`
			SampleAspect string `json:"sample_aspect_ratio"`
			StartTime    string `json:"start_time"`
			RFrameRate   string `json:"r_frame_rate"`
			AvgFrameRate string `json:"avg_frame_rate"`
		} `json:"streams"`
		Frames []struct {
			PictType string `json:"pict_type"`
		} `json:"frames"`
	}

	var raw ProbeRawData

	// 2. Fetch Duration and calculate seek point
	duration, err := getVideoDuration(ctx, fullPath)
	if err != nil {
		return raw, fmt.Errorf("Failed to get video duration", err)
	}
	seekPoint := 0.0
	if duration > 2.0 {
		seekPoint = duration / 2
	}
	slog.Info("HERE 2.5")
	// 2.5 Fetch Container Structural Metadata & GOP Cadence (Fixed to avoid deprecated fields)
	structCmd := exec.CommandContext(ctx, "ffprobe", "-v", "error", "-select_streams", stream, "-show_streams", "-show_frames", "-show_entries", "stream=codec_name,width,height,sample_aspect_ratio,start_time,r_frame_rate,avg_frame_rate:frame=pict_type", "-read_intervals", "%+#300", "-of", "json", fullPath)
	if structOut, err := structCmd.Output(); err == nil {
		var probeData FFprobeJSON
		if json.Unmarshal(structOut, &probeData) == nil && len(probeData.Streams) > 0 {
			s := probeData.Streams[0]
			raw.CodecName = s.CodecName
			raw.Width = s.Width
			raw.Height = s.Height
			raw.PAR = s.SampleAspect
			if raw.PAR == "" || raw.PAR == "0:1" {
				raw.PAR = "1:1"
			}
			raw.StartTime, _ = strconv.ParseFloat(s.StartTime, 64)
			raw.IsCFR = (s.RFrameRate == s.AvgFrameRate && s.RFrameRate != "0/0")

			var keyframeIndices []int
			for frameIdx, frame := range probeData.Frames {
				if frame.PictType == "I" {
					keyframeIndices = append(keyframeIndices, frameIdx)
				}
			}
			if len(keyframeIndices) >= 3 {
				firstInterval := keyframeIndices[1] - keyframeIndices[0]
				isUniform := true
				for i := 2; i < len(keyframeIndices); i++ {
					if (keyframeIndices[i] - keyframeIndices[i-1]) != firstInterval {
						isUniform = false
						break
					}
				}
				if keyframeIndices[0] != 0 {
					isUniform = false
				}
				raw.HasFixedGOP = isUniform
				raw.GOPSize = firstInterval
			}
		}
	}

	slog.Info("HERE 2.5")
	// 3. Fetch Container Metadata Field Order
	fieldOrderCmd := exec.CommandContext(ctx, "ffprobe", "-v", "error", "-select_streams", stream, "-show_entries", "stream=field_order", "-of", "default=noprint_wrappers=1:nokey=1", fullPath)
	fieldOrderOut, _ := fieldOrderCmd.Output()
	raw.FieldOrder = strings.ToLower(strings.TrimSpace(string(fieldOrderOut)))

	slog.Info("HERE 2.5")
	// 4. Run IDET Pixel Scan
	idetCmd := exec.CommandContext(ctx, "ffmpeg", "-ss", fmt.Sprintf("%f", seekPoint), "-i", fullPath, "-vf", "idet", "-frames:v", "1000", "-an", "-c:v", "rawvideo", "-f", "null", "-")
	var idetStderr bytes.Buffer
	idetCmd.Stderr = &idetStderr
	if err := idetCmd.Run(); err != nil {
		return raw, shared.Fatal("ffmpeg idet analysis failed", "err", err, "stderr", idetStderr.String())
	}

	slog.Info("HERE 2.5")
	reIdet := regexp.MustCompile(`TFF:\s+(\d+)\s+BFF:\s+(\d+)\s+Progressive:\s+(\d+)`)
	idetMatches := reIdet.FindAllStringSubmatch(idetStderr.String(), -1)
	if len(idetMatches) > 0 {
		lastMatch := idetMatches[len(idetMatches)-1]
		raw.TffCount, _ = strconv.Atoi(lastMatch[1])
		raw.BffCount, _ = strconv.Atoi(lastMatch[2])
		raw.ProgCount, _ = strconv.Atoi(lastMatch[3])
	}

	slog.Info("HERE 2.5")
	// 5. Run Duplicate Frame Detection Pass
	dupCmd := exec.CommandContext(ctx, "ffmpeg", "-ss", "00:10:00", "-t", "10", "-i", fullPath, "-vf", "mpdecimate", "-loglevel", "debug", "-f", "null", "-")
	var dupBuf bytes.Buffer
	dupCmd.Stderr = &dupBuf
	_ = dupCmd.Run()
	dupOutput := dupBuf.String()

	raw.DecimateDrop = strings.Count(dupOutput, "drop")
	raw.DecimateKeep = strings.Count(dupOutput, "keep")

	slog.Info("HERE 2.5")
	return raw, nil
}

func getVideoDuration(ctx context.Context, fullPath string) (float64, error) {
	cmd := exec.CommandContext(ctx, "ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=noprint_wrappers=1:nokey=1", fullPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("Error: %v: %s", err, stderr.String())
	}
	return strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
}

func DeriveFilterRecommendation(raw ProbeRawData, esa shared.EncodeStreamArgs) FilterRecommendation {
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
				analysis.FilterRecommendation = "fieldmatch=order=" + parity + ":combmatch=full,yadif=mode=send_frame:deint=interlaced,format=" + codec2Format(esa.Codec)
			} else {
				analysis.FilterRecommendation = "bwdif=mode=0:parity=" + parity + ":deint=all,format=" + codec2Format(esa.Codec)
			}
		}
	}

	// Process Cadence Verification Metrics
	totalDecimateFrames := raw.DecimateDrop + raw.DecimateKeep
	//spew.Dump(raw.DecimateDrop)
	//spew.Dump(raw.DecimateKeep)

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

func codec2Format(codec string) string {
	switch codec {
	case "x264":
		return "yuv420p"
	case "x265":
		return "yuv420p10le"
	default:
		slog.Error("UNKNOWN CODEC in codec2Format()", "codec", codec)
		return "yuv420p"
	}
}
