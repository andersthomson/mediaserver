package dasherworker

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
)

func getVideoDuration(ctx context.Context, fullPath string) (float64, error) {
	cmd := exec.CommandContext(ctx, "ffprobe",
		"-v", "error",
		"-show_entries", "format=duration",
		"-of", "default=noprint_wrappers=1:nokey=1",
		fullPath,
	)

	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	return strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
}

type AnalyzeMediaInterlaceArgs struct {
	InputID string
	InputNo int
	Stream  string
	//Dir     string
	//Fname   string
}

type MediaInterlaceAnalysis struct {
	FilterRecommendation string  `json:"filter_recommendation"`
	FirstPTS             float64 `json:"first_pts"`
	ProgressiveRatio     float64 `json:"progressive_ratio"`
	InterlacedRatio      float64 `json:"interlaced_ratio"`
	DetectedParity       string  `json:"detected_parity"`
	IsFakeHighFPS        bool
}

func AnalyzeMediaInterlace(ctx context.Context, args AnalyzeMediaInterlaceArgs) (MediaInterlaceAnalysis, error) {
	slog.Info("Start", "A", "AnalyzeMediaInterlace", "args", args)
	defer slog.Info("Stop ", "A", "AnalyzeMediaInterlace", "args", args)
	//fullPath := filepath.Join(args.Dir, args.Fname)
	fullPath := storage.ResolveInputNumber(args.InputID, args.InputNo)
	return AnalyzeMediaInterlaceFile(ctx, fullPath, args.Stream)
}

func AnalyzeMediaInterlaceFile(ctx context.Context, fullPath string, stream string) (MediaInterlaceAnalysis, error) {
	analysis := MediaInterlaceAnalysis{FilterRecommendation: "null"}

	// 1. SYNC PROBE: Capture the First PTS (The 0.08s sync mystery)
	// We do this separately because the main probe uses -ss which resets PTS.
	syncCmd := exec.CommandContext(ctx, "ffmpeg", "-t", "0.1", "-i", fullPath, "-f", "null", "-")
	var syncBuf bytes.Buffer
	syncCmd.Stderr = &syncBuf
	_ = syncCmd.Run()
	rePTS := regexp.MustCompile(`start:\s+([0-9.]+)`)
	if match := rePTS.FindStringSubmatch(syncBuf.String()); len(match) > 1 {
		analysis.FirstPTS, _ = strconv.ParseFloat(match[1], 64)
	}

	seekPoint := 0.0
	duration, err := getVideoDuration(ctx, fullPath)
	if err != nil {
		return MediaInterlaceAnalysis{}, errors.WithStack(err)
	}
	if duration > 2.0 {
		seekPoint = duration / 2
	}
	// 2. INTERLACE PROBE: Visual Analysis
	cmd := exec.CommandContext(ctx, "ffmpeg",
		"-ss", fmt.Sprintf("%f", seekPoint), // Seek to a safe, dynamic point
		"-i", fullPath,
		"-vf", "idet",
		"-frames:v", "1000", // Analyze exactly 1000 frames
		"-an",
		"-c:v", "rawvideo",
		"-f", "null", "-",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return analysis, Error("ffmpeg analysis failed", "err", err)
	}

	output := stderr.String()
	reIdet := regexp.MustCompile(`TFF:\s+(\d+)\s+BFF:\s+(\d+)\s+Progressive:\s+(\d+)`)
	matches := reIdet.FindAllStringSubmatch(output, -1)

	if len(matches) > 0 {
		// Use the final summary match
		lastMatch := matches[len(matches)-1]
		tff, _ := strconv.Atoi(lastMatch[1])
		bff, _ := strconv.Atoi(lastMatch[2])
		prog, _ := strconv.Atoi(lastMatch[3])

		total := tff + bff + prog
		if total > 0 {
			analysis.ProgressiveRatio = float64(prog) / float64(total)
			analysis.InterlacedRatio = float64(tff+bff) / float64(total)

			if analysis.InterlacedRatio > 0.15 {
				// TRUE INTERLACED
				// Determine parity based on idet counts
				if tff > bff {
					analysis.DetectedParity = "tff"
				} else if bff > tff {
					analysis.DetectedParity = "bff"
				} else {
					analysis.DetectedParity = "auto"
				}
				analysis.FilterRecommendation = fmt.Sprintf("bwdif=mode=0:parity=%s:deint=all", analysis.DetectedParity)
			} else if analysis.ProgressiveRatio > 0.85 {
				// PIXELS ARE PROGRESSIVE - Check if Metadata is lying (PsF)
				// We call ffprobe specifically for the 'field_order' metadata
				fieldOrderCmd := exec.CommandContext(ctx, "ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries", "stream=field_order", "-of", "default=noprint_wrappers=1:nokey=1", fullPath)
				fieldOrderOut, _ := fieldOrderCmd.Output()
				fieldOrder := strings.TrimSpace(string(fieldOrderOut))

				// If metadata says 'tt' (top field) or 'bb', but pixels are progressive -> PsF!
				if fieldOrder != "progressive" && fieldOrder != "unknown" && fieldOrder != "" {
					var parity string
					if strings.Contains(fieldOrder, "tb") || strings.Contains(fieldOrder, "top") {
						parity = "tff"
					} else if strings.Contains(fieldOrder, "bt") || strings.Contains(fieldOrder, "bottom") {
						parity = "bff"
					} else {
						parity = "auto"
					}
					analysis.FilterRecommendation = "fieldmatch=order=" + parity + ":combmatch=full,yadif=mode=send_frame:deint=interlaced,format=yuv420p"
					analysis.DetectedParity = "PsF (" + fieldOrder + ")"
				} else {
					analysis.FilterRecommendation = "null"
				}
			}
		}
	}

	// 3. DUPLICATE PROBE: Detect "Fake" High FPS
	dupCmd := exec.CommandContext(ctx, "ffmpeg",
		"-ss", "00:10:00",
		"-t", "10",
		"-i", fullPath,
		"-vf", "mpdecimate",
		"-loglevel", "debug",
		"-f", "null", "-",
	)

	var dupBuf bytes.Buffer
	dupCmd.Stderr = &dupBuf
	_ = dupCmd.Run()
	dupOutput := dupBuf.String()
	//fmt.Println(dupOutput)
	dropCount := strings.Count(dupOutput, "drop")
	keepCount := strings.Count(dupOutput, "keep")
	totalCount := dropCount + keepCount
	spew.Dump(dropCount)
	spew.Dump(keepCount)
	// If drops are > 40% of total frames, it's a doubled cadence (Fake High FPS)
	if totalCount > 0 && (float64(dropCount)/float64(totalCount)) > 0.40 {
		analysis.IsFakeHighFPS = true
		//analysis.FilterRecommendation += ",mpdecimate,fps=25"
		//analysis.FilterRecommendation += ",fps=25,mpdecimate" + fmt.Sprintf(",setpts=PTS-STARTPTS")
	}

	slog.Info("Analysis Complete", "fullPath", fullPath, "PTS", analysis.FirstPTS, "filterRecommendation", analysis.FilterRecommendation)
	return analysis, nil
}

func isSourceFlaggedInterlaced(ffmpegOutput string) bool {
	// Look for common interlaced indicators in FFmpeg stream mapping
	// e.g., "progressive", "interlaced", "tff", "bff"
	re := regexp.MustCompile(`(tff|bff|interlaced)`)
	return re.MatchString(ffmpegOutput)
}
