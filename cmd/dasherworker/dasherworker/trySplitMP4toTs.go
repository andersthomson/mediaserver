package dasherworker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// VideoFormatDetails encapsulates the core playback parameters extracted from the track headers
type VideoFormatDetails struct {
	Codec     string // Precise browser-compliant tag (e.g., "hvc1" or "avc1")
	Bitrate   int    // Overall average bitrate in bits-per-second (bps)
	Width     int    // Physical pixel width
	Height    int    // Physical pixel height
	DisplayAR string // Visual aspect ratio string (e.g., "16:9" or "4:3")
}

// FFprobeFullQuery maps the comprehensive streams and format metadata blocks returned by the binary
type FFprobeFullQuery struct {
	Streams []StreamEntry `json:"streams"`
	Format  FormatEntry   `json:"format"`
}

type StreamEntry struct {
	CodecType          string `json:"codec_type"`
	CodecTagString     string `json:"codec_tag_string"` // Precise string signature (e.g., "hvc1")
	Width              int    `json:"width"`
	Height             int    `json:"height"`
	DisplayAspectRatio string `json:"display_aspect_ratio"` // Captures anamorphic aspect maps cleanly
}

type FormatEntry struct {
	BitRate string `json:"bit_rate"` // Global file container average bitrate
}

// GetVideoFormatDetails executes a high-speed header scan over an MP4 container file
func GetVideoFormatDetails(ctx context.Context, mp4Path string) (VideoFormatDetails, error) {
	// Execute a broad structured trace over streams and format entries simultaneously
	cmd := exec.CommandContext(ctx, "ffprobe",
		"-v", "error",
		"-show_entries", "stream=codec_type,codec_tag_string,width,height,display_aspect_ratio:format=bit_rate",
		"-of", "json",
		mp4Path,
	)

	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf

	if err := cmd.Run(); err != nil {
		return VideoFormatDetails{}, fmt.Errorf("ffprobe video metadata scan failed: %w", err)
	}

	var data FFprobeFullQuery
	if err := json.Unmarshal(outBuf.Bytes(), &data); err != nil {
		return VideoFormatDetails{}, fmt.Errorf("failed decoding metadata JSON envelope: %w", err)
	}

	// Locate the primary video stream record entry
	var videoStream *StreamEntry
	for i := range data.Streams {
		if data.Streams[i].CodecType == "video" {
			videoStream = &data.Streams[i]
			break
		}
	}

	if videoStream == nil {
		return VideoFormatDetails{}, fmt.Errorf("media file contains no traceable video streams: %s", mp4Path)
	}

	// Parse the container's global average bitrate string safely into an integer
	globalBitrate := 0
	if data.Format.BitRate != "" {
		parsed, err := strconv.Atoi(data.Format.BitRate)
		if err == nil {
			globalBitrate = parsed
		}
	}

	// Compile the collected parameters into our unified response structure
	return VideoFormatDetails{
		Codec:     videoStream.CodecTagString,
		Bitrate:   globalBitrate,
		Width:     videoStream.Width,
		Height:    videoStream.Height,
		DisplayAR: videoStream.DisplayAspectRatio,
	}, nil
}

func TrySplitMp4ToTs(ctx context.Context, shortName string, mp4Path string) (bool, error) {
	//ffmpeg -i Amelie\ från\ Montmartre.mp4 -map 0:a:0 -c:a copy -f hls -hls_list_size 0 -hls_flags single_file audio.m3u8
	details, err := GetVideoFormatDetails(ctx, mp4Path)
	if err != nil {
		return false, err
	}
	args := []string{
		"-i", mp4Path,
		"-map", "0:a:0",
		"-c:a", "copy",
		"-f", "hls",
		"-hls_list_size", "0",
		"-hls_flags", "single_file",
		filepath.Join(filepath.Dir(mp4Path), shortName+"_audio.m3u8"),
		"-map", "0:v:0",
		"-c:v", "copy",
		"-f", "hls",
		"-hls_list_size", "0",
		"-hls_flags", "single_file",
		filepath.Join(filepath.Dir(mp4Path), fmt.Sprintf("%s_video_%s_%dx%d_%d.m3u8", shortName, details.Codec, details.Width, details.Height, details.Bitrate/1024)),
	}

	cmd := exec.CommandContext(ctx, "ffmpeg", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("Ffmpeg failed: %v", err)
	}
	return true, nil
}
