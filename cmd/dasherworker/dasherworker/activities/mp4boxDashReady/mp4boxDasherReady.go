package mp4boxDashReady

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
)

type MP4BoxDashReady struct {
	Storage *storage.Storage
}

type MP4BoxDashReadyArgs struct {
	TranscodedFilePath  string
	ManifestFilePath    string
	DasherReadyFilePath string
	WorkDir             string
	DashMs              string
	MP4BoxArgs          []string
}

func (m *MP4BoxDashReady) MP4BoxDashReadyPrepare(ctx context.Context, args shared.EncodeStreamArgs) (MP4BoxDashReadyArgs, error) {
	dasherReadyFilePath := m.Storage.DasherReadyRepresentationFilePath(args)
	manifestFilePath := m.Storage.DasherReadyRepresentationManifestFilePath(args)
	transcodedFilePath := m.Storage.TranscodedRepresentationFilePath(args)

	boxArgs := []string{
		"-dash", args.DstProps.DashMs,
		"-rap",
		"-profile",
		"onDemand",
		"-segment-name", filepath.Base(dasherReadyFilePath),
		"-out", filepath.Base(manifestFilePath),
		filepath.Base(transcodedFilePath),
	}

	return MP4BoxDashReadyArgs{
		DasherReadyFilePath: dasherReadyFilePath,
		ManifestFilePath:    manifestFilePath,
		TranscodedFilePath:  transcodedFilePath,
		WorkDir:             m.Storage.ProdDir(args.InputID),
		DashMs:              args.DstProps.DashMs,
		MP4BoxArgs:          boxArgs,
	}, nil
}

type MP4BoxDashReadyResp struct {
	Dir    string
	Stdout string
	Stderr string
}

func (_ *MP4BoxDashReady) MP4BoxDashReadyExecute(ctx context.Context, args MP4BoxDashReadyArgs) (MP4BoxDashReadyResp, error) {

	slog.Info("MP4Box dashing stream", "filePath", args.TranscodedFilePath)
	stdoutBuf, stderrBuf, err := common.MP4Box(ctx, args.WorkDir, args.MP4BoxArgs)
	if err != nil {
		return MP4BoxDashReadyResp{}, err
	}
	dashMsI, _ := strconv.Atoi(args.DashMs)
	if err := VerifySegmentAlignment(stderrBuf.String(), dashMsI); err != nil {
		return MP4BoxDashReadyResp{}, shared.FatalError(err)
	}
	resp := MP4BoxDashReadyResp{
		Dir:    args.WorkDir,
		Stdout: stdoutBuf.String(),
		Stderr: stderrBuf.String(),
	}
	//remove unneded files
	if err := os.Remove(args.TranscodedFilePath); err != nil {
		return resp, shared.Fatal("Failed to remove %s: %v", args.TranscodedFilePath, err)
	}
	if err := os.Remove(args.ManifestFilePath); err != nil {
		return resp, shared.Fatal("Failed to remove %s: %v", args.ManifestFilePath, err)
	}

	basename, ok := strings.CutSuffix(filepath.Base(args.DasherReadyFilePath), ".mp4")
	if !ok {
		return resp, shared.Fatal("DasherReadyFilePath MUST end in .mp4")
	}
	if err := os.Rename(filepath.Join(filepath.Dir(args.DasherReadyFilePath), basename+".mp4init.mp4"), args.DasherReadyFilePath); err != nil {
		return resp, shared.Fatal("Failed to rename %s %s:%v", filepath.Join(filepath.Dir(args.DasherReadyFilePath), basename+".mp4init.mp4"), args.DasherReadyFilePath, err)
	}
	return resp, nil
}

func VerifySegmentAlignment(stderr string, dashMs int) error {
	if dashMs <= 0 {
		return fmt.Errorf("invalid target dashMs: %d", dashMs)
	}
	expectedSeconds := float64(dashMs) / 1000.0

	// 1. Strip ANSI color codes out of memory instantly
	ansiRe := regexp.MustCompile(`\x1B\[[0-9;]*[a-zA-Z]`)
	cleanStderr := ansiRe.ReplaceAllString(stderr, "")

	// 2. FIX: Flexible pattern matcher to support spaces anywhere inside the parenthesis layout
	progressRe := regexp.MustCompile(`seg\s+#\s*(\d+)\s+([\d.]+)s\s*\(\s*([\d.]+)\s*%\s*\)`)

	scanner := bufio.NewScanner(strings.NewReader(cleanStderr))
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		for i := 0; i < len(data); i++ {
			if data[i] == '\n' || data[i] == '\r' {
				return i + 1, data[0:i], nil
			}
		}
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	})

	lineCount := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		matches := progressRe.FindStringSubmatch(line)
		if len(matches) != 4 {
			continue
		}
		lineCount++

		segmentNum := matches[1]
		durationStr := matches[2]
		percentageStr := matches[3]

		duration, err := strconv.ParseFloat(durationStr, 64)
		if err != nil {
			return fmt.Errorf("malformed duration parse on seg #%s: %w", segmentNum, err)
		}

		percentage, err := strconv.ParseFloat(percentageStr, 64)
		if err != nil {
			return fmt.Errorf("malformed percentage parse on seg #%s: %w", segmentNum, err)
		}

		if percentage == 0 {
			continue
		}

		calculatedSegmentSeconds := duration / (percentage / 100.0)
		diff := math.Abs(calculatedSegmentSeconds - expectedSeconds)

		if diff > 0.05 { // Increased tolerance to 50ms to handle 2-decimal log rounding safely
			return fmt.Errorf("alignment deviation detected on seg #%s: calculated to %.4fs, expected %.4fs (diff: %.4fs)",
				segmentNum, calculatedSegmentSeconds, expectedSeconds, diff)
		}
	}

	if lineCount == 0 {
		return fmt.Errorf("verification failed: no matching segment progress signatures were found in stderr stream")
	}

	return nil
}
