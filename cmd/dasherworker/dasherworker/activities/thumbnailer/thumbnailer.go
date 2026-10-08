package thumbnailer

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
	"slices"
	"strconv"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/encoder"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
)

type ThumbnailConfig struct {
	TileWidth       int
	TileHeight      int
	GridCols        int
	GridRows        int
	IntervalSeconds int
	ImagePrefix     string
}

type Thumbnailer struct {
	Storage *storage.Storage
}

func (t *Thumbnailer) Thumbnail(ctx context.Context, args shared.EncodeStreamArgs, config ThumbnailConfig) error {
	type Invocation struct {
		Dir      string
		Args     []string
		Stdout   string
		Stderr   string
		ExitCode int
	}
	type ThumbnailRecord struct {
		Config ThumbnailConfig
		Ffmpeg Invocation
	}

	inputVideo := t.Storage.DasherReadyRepresentationFilePath(args)
	vttOutput := t.Storage.ThumbnailsVTTFilePath(args.InputID)
	vttOutputLog := t.Storage.ThumbnailsVTTTranscodingLogFilePath(args.InputID)

	// 1. Automatically fetch the exact duration via ffprobe
	slog.Info("Analyzing video duration...")
	duration, err := getVideoDuration(inputVideo)
	if err != nil {
		slog.Error("Error probing video", "inputVideo", inputVideo, "err", err)
		return shared.FatalError(err)
	}
	slog.Info("Detected Video Duration", "vttOutput", vttOutput, "duarion", duration)

	outputDir := filepath.Dir(inputVideo)
	ffmpegExtractArgs := ffmpegExtractArguments(inputVideo, outputDir, config)

	var tr ThumbnailRecord
	err = shared.LoadOptions(ctx, vttOutputLog, &tr)
	if err == nil {
		if tr.Config == config && slices.Equal(tr.Ffmpeg.Args, ffmpegExtractArgs) {
			slog.Info("Thumbs already extracted.Skipping", "vttOutput", vttOutput)
			return nil
		}
	}

	// 2. Automatically extract sheets using FFmpeg
	slog.Info("Extracting image grid sheets via FFmpeg...")
	stdout, stderr, exitCode, err := executeFFmpegExtract(ctx, int64(duration)*1000*1000, inputVideo, ffmpegExtractArgs)
	if err != nil {
		slog.Info("Error extracting images", "vttOutput", vttOutput, "err", err)
		return shared.FatalError(err)
	}

	// 3. Automatically generate the clean WebVTT layout map
	slog.Info("Generating fully indexed metadata file", "vttOutput", vttOutput)
	if err := generateVTT(vttOutput, duration, config); err != nil {
		slog.Error("Error generating VTT file", "err", err)
		return shared.FatalError(err)
	}
	shared.RecordOptions(ctx, vttOutputLog, ThumbnailRecord{
		Config: config,
		Ffmpeg: Invocation{
			Dir:      "",
			Args:     ffmpegExtractArgs,
			Stdout:   stdout,
			Stderr:   stderr,
			ExitCode: exitCode,
		},
	})
	return nil
}

// FFProbeResult maps the required json metadata outputs from the video container
type FFProbeResult struct {
	Format struct {
		Duration string `json:"duration"`
	} `json:"format"`
}

// getVideoDuration uses ffprobe to dynamically pull the video duration in seconds
func getVideoDuration(videoPath string) (int, error) {
	cmd := exec.Command("ffprobe",
		"-v", "error",
		"-show_entries", "format=duration",
		"-of", "json",
		videoPath,
	)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("ffprobe failed: %w", err)
	}

	var result FFProbeResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		return 0, err
	}

	durationFloat, err := strconv.ParseFloat(result.Format.Duration, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration format: %w", err)
	}

	return int(math.Ceil(durationFloat)), nil
}

func ffmpegExtractArguments(videoPath, outputDir string, config ThumbnailConfig) []string {
	fpsParam := fmt.Sprintf("fps=1/%d,scale=%d:%d,tile=%dx%d",
		config.IntervalSeconds,
		config.TileWidth,
		config.TileHeight,
		config.GridCols,
		config.GridRows,
	)

	outputPattern := filepath.Join(outputDir, config.ImagePrefix+"%04d.jpg")

	return []string{
		"-y", // Automatically overwrite existing files
		"-i", videoPath,
		"-vf", fpsParam,
		"-vsync", "vfr",
		"-q:v", "3",
		outputPattern,
		"-nostats",
		"-progress", "pipe:3",
	}
}

// executeFFmpegExtract calls the time-based sprite tile system natively
func executeFFmpegExtract(ctx context.Context, durationUs int64, videoPath string, ffmpegargs []string) (string, string, int, error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		return "", "", 0, err
	}
	defer pr.Close()

	cmd := exec.CommandContext(ctx, "ffmpeg",
		ffmpegargs...,
	)
	cmd.ExtraFiles = []*os.File{pw}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	meta := encoder.ExecutionMetadata{
		LogIdentifier:   "Thumbnailer",
		TargetID:        videoPath,
		TotalDurationUs: durationUs,
	}

	if err := cmd.Start(); err != nil {
		pw.Close()
		return "", "", 0, err
	}
	pw.Close()

	// Works out of the box!
	res, err := encoder.RunPreStartedFFmpegCmd(ctx, cmd, pr, meta, &stdoutBuf, &stderrBuf)

	if err != nil {
		return "", "", 0, fmt.Errorf("ffmpeg thumbnail extraction failed: %w", err)
	}
	return res.Stdout, res.Stderr, res.ExitCode, nil
}

// formatVTTTime formats time blocks to strict Shaka tokenizer requirements
func formatVTTTime(seconds int) string {
	hours := seconds / 3600
	minutes := (seconds % 3600) / 60
	secs := seconds % 60
	return fmt.Sprintf("%02d:%02d:%02d.000", hours, minutes, secs)
}

// generateVTT maps coordinate coordinates based on video duration
func generateVTT(outputPath string, totalDurationSeconds int, config ThumbnailConfig) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString("WEBVTT\n\n"); err != nil {
		return err
	}

	tilesPerSheet := config.GridCols * config.GridRows
	totalThumbnails := int(math.Ceil(float64(totalDurationSeconds) / float64(config.IntervalSeconds)))

	for i := 0; i < totalThumbnails; i++ {
		startTime := i * config.IntervalSeconds
		endTime := startTime + config.IntervalSeconds
		if endTime > totalDurationSeconds {
			endTime = totalDurationSeconds
		}

		sheetNumber := (i / tilesPerSheet) + 1
		tileIndex := i % tilesPerSheet
		col := tileIndex % config.GridCols
		row := tileIndex / config.GridCols

		x := col * config.TileWidth
		y := row * config.TileHeight

		cueTiming := fmt.Sprintf("%s --> %s\n", formatVTTTime(startTime), formatVTTTime(endTime))
		cuePayload := fmt.Sprintf("%s%04d.jpg#xywh=%d,%d,%d,%d\n\n",
			config.ImagePrefix, sheetNumber, x, y, config.TileWidth, config.TileHeight)

		if _, err := file.WriteString(cueTiming + cuePayload); err != nil {
			return err
		}
	}
	return nil
}

/*
type Invocation struct {
	Dir      string
	Args     []string
	Stdout   string
	Stderr   string
	ExitCode int
}
type ThumbnailRecord struct {
	Config ThumbnailConfig
	Ffmpeg Invocation
}

type ThubnailRecorder struct {
	Storage *storage.Storage
}

func (t *ThumbnailRecorder) RecordTranscodingOptions(ctx context.Context, tr TranscodingOptionsRecord) (string, error) {
	base := t.Storage.DasherReadyRepresentationTranscodingLogFilePath(tr.EncodeStream)
	return shared.RecordOptions(ctx, base, tr)
}

func (t *ThumbnailRecorder) LoadTranscodingOptions(ctx context.Context, e shared.EncodeStreamArgs) (*TranscodingOptionsRecord, error) {
	var tr TranscodingOptionsRecord
	err := shared.LoadOptions(ctx, t.Storage.DasherReadyRepresentationTranscodingLogFilePath(e), &tr)
	return &tr, err
}*/
