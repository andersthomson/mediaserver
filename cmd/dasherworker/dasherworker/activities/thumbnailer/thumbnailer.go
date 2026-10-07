package thumbnailer

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

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/encoder"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
)

type Thumbnailer struct {
	Storage *storage.Storage
}

func (t *Thumbnailer) Thumbnail(ctx context.Context, args shared.EncodeStreamArgs) error {
	config := ThumbnailConfig{
		TileWidth:       160,
		TileHeight:      90,
		GridCols:        5,
		GridRows:        5,
		IntervalSeconds: 2, // 1 thumbnail every 2 seconds
		ImagePrefix:     "thumb_",
	}

	inputVideo := t.Storage.DasherReadyRepresentationFilePath(args)

	// 1. Automatically fetch the exact duration via ffprobe
	fmt.Println("Analyzing video duration...")
	duration, err := getVideoDuration(inputVideo)
	if err != nil {
		fmt.Printf("Error probing video: %v\n", err)
		return err
	}
	fmt.Printf("Detected Video Duration: %d seconds\n", duration)

	// 2. Automatically extract sheets using FFmpeg
	fmt.Println("Extracting image grid sheets via FFmpeg...")
	outputDir := filepath.Dir(inputVideo)
	if err := executeFFmpegExtract(ctx, inputVideo, outputDir, config, int64(duration)*1000*1000); err != nil {
		fmt.Printf("Error extracting images: %v\n", err)
		return err
	}

	// 3. Automatically generate the clean WebVTT layout map
	vttOutput := t.Storage.ThumbnailsVTTFilePath(args.InputID)
	fmt.Printf("Generating fully indexed metadata file: %s...\n", vttOutput)
	if err := generateVTT(vttOutput, duration, config); err != nil {
		fmt.Printf("Error generating VTT file: %v\n", err)
		return err
	}

	fmt.Println("Automation complete! All assets are fully synchronized.")
	return nil
}

type ThumbnailConfig struct {
	TileWidth       int
	TileHeight      int
	GridCols        int
	GridRows        int
	IntervalSeconds int
	ImagePrefix     string
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

// executeFFmpegExtract calls the time-based sprite tile system natively
func executeFFmpegExtract(ctx context.Context, videoPath, outputDir string, config ThumbnailConfig, durationUs int64) error {
	fpsParam := fmt.Sprintf("fps=1/%d,scale=%d:%d,tile=%dx%d",
		config.IntervalSeconds,
		config.TileWidth,
		config.TileHeight,
		config.GridCols,
		config.GridRows,
	)

	outputPattern := filepath.Join(outputDir, config.ImagePrefix+"%04d.jpg")

	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	defer pr.Close()

	cmd := exec.CommandContext(ctx, "ffmpeg",

		"-y", // Automatically overwrite existing files
		"-i", videoPath,
		"-vf", fpsParam,
		"-vsync", "vfr",
		"-q:v", "3",
		outputPattern,
		"-nostats",
		"-progress", "pipe:3",
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
		return err
	}
	pw.Close()

	// Works out of the box!
	_, err = encoder.RunPreStartedFFmpegCmd(ctx, cmd, pr, meta, &stdoutBuf, &stderrBuf)

	if err != nil {
		return fmt.Errorf("ffmpeg thumbnail extraction failed: %w", err)
	}
	return nil
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

func do(inputVideo string) {
}
