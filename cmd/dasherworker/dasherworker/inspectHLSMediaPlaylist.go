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
	"strings"

	iso639_3 "github.com/barbashov/iso639-3"
	"github.com/davecgh/go-spew/spew"
)

// ============================================================================
// Shared Domain Target Structs
// ============================================================================

type AudioTrack struct {
	GroupID   string `json:"group_id"`
	Name      string `json:"name"`
	Language  string `json:"language"`
	URI       string `json:"uri"`
	Codecs    string `json:"codecs"`
	IsDefault bool   `json:"is_default"`
}

type SubtitleTrack struct {
	GroupID   string `json:"group_id"`
	Name      string `json:"name"`
	Language  string `json:"language"`
	URI       string `json:"uri"`
	IsDefault bool   `json:"is_default"`
}

type VideoVariant struct {
	Bandwidth  int    `json:"bandwidth"`
	AvgBitrate int    `json:"avg_bitrate"`
	Resolution string `json:"resolution"`
	FrameRate  string `json:"frame_rate"`
	Codecs     string `json:"codecs"`
	AudioGroup string `json:"audio_group"`
	SubsGroup  string `json:"subs_group"`
	Playlist   string `json:"playlist"`
}

type HLSMasterConfig struct {
	AudioTracks    []AudioTrack
	SubtitleTracks []SubtitleTrack
	VideoVariants  []VideoVariant
}

type FFprobeFormatAndStreams struct {
	Streams []StreamDetail `json:"streams"`
}

type StreamDetail struct {
	CodecType  string            `json:"codec_type"`
	CodecName  string            `json:"codec_name"`
	Profile    string            `json:"profile"`
	Width      int               `json:"width,omitempty"`
	Height     int               `json:"height,omitempty"`
	RFrameRate string            `json:"r_frame_rate"`
	Tags       map[string]string `json:"tags,omitempty"`
}

// ============================================================================
// Core Automated Ingestion Engine
// ============================================================================

// AutomaticInspectPlaylist extracts everything natively by reading the .m3u8 file text.
// No media file paths are required as inputs anymore.
func AutomaticInspectPlaylist(ctx context.Context, m3u8Path string, groupID string, fallbackLang string, isDefault bool) (interface{}, error) {
	// 1. Derive playlist file properties
	playlistURIName := filepath.Base(m3u8Path)
	playlistDir := filepath.Dir(m3u8Path)

	ext := strings.ToLower(filepath.Ext(m3u8Path))
	if ext == ".vtt" || strings.Contains(strings.ToLower(m3u8Path), "subs") || strings.Contains(strings.ToLower(groupID), "sub") {
		return SubtitleTrack{
			GroupID:   groupID,
			Name:      fmt.Sprintf("%s Subtitles", strings.ToUpper(fallbackLang)),
			Language:  fallbackLang,
			URI:       playlistURIName,
			IsDefault: isDefault,
		}, nil
	}

	fileData, err := os.ReadFile(m3u8Path)
	if err != nil {
		return nil, fmt.Errorf("failed reading m3u8 file text: %w", err)
	}

	lines := strings.Split(string(fileData), "\n")
	var totalBytes int64
	var totalDuration float64
	var maxSegmentBitrate float64
	var currentDuration float64

	// This will dynamically capture the "video.ts" or "audio.ts" filename string from the text
	var discoveredMediaURI string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines or top-level file formatting headers
		if line == "" || strings.HasPrefix(line, "#EXTM3U") {
			continue
		}

		// 1. Capture the float duration safely (Remove 'continue' here!)
		if strings.HasPrefix(line, "#EXTINF:") {
			cleaned := strings.TrimSuffix(strings.TrimPrefix(line, "#EXTINF:"), ",")
			if dur, err := strconv.ParseFloat(cleaned, 64); err == nil {
				currentDuration = dur
			}
			// NO CONTINUE HERE: Let it fall through or check the next line type cleanly
		}

		// 2. Process byte ranges immediately when currentDuration is active
		if strings.HasPrefix(line, "#EXT-X-BYTERANGE:") {
			cleaned := strings.TrimPrefix(line, "#EXT-X-BYTERANGE:")
			parts := strings.Split(cleaned, "@")

			// We check currentDuration > 0 here safely because line 1 just updated it!
			if len(parts) > 0 && currentDuration > 0 {
				if segmentBytes, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
					totalBytes += segmentBytes
					totalDuration += currentDuration

					segmentBitrate := (float64(segmentBytes) * 8) / currentDuration
					if segmentBitrate > maxSegmentBitrate {
						maxSegmentBitrate = segmentBitrate
					}
				}
			}
			// DO NOT set currentDuration = 0 here, or you will blind the very next segment pass!
			continue
		}

		// 3. Capture the relative binary filename path safely
		// Skip lines that start with '#' so we only capture the raw filename string (e.g. "video.ts")
		if !strings.HasPrefix(line, "#") {
			if discoveredMediaURI == "" {
				discoveredMediaURI = line
			}
			// Reset our segment clock tracker ONLY after the full block sequence (INF -> BYTERANGE -> TS) is fully spent
			currentDuration = 0
		}
	}

	if totalDuration == 0 {
		return nil, fmt.Errorf("zero traceable timeline segments found inside manifest: %s", m3u8Path)
	}
	spew.Dump(m3u8Path)

	avgBitrate := int((float64(totalBytes) * 8) / totalDuration)
	peakBitrate := int(maxSegmentBitrate)
	if peakBitrate <= avgBitrate {
		peakBitrate = int(float64(avgBitrate) * 1.10)
	}

	if discoveredMediaURI == "" {
		return nil, fmt.Errorf("failed to extract media asset URI reference string out of manifest text: %s", m3u8Path)
	}

	// Build the true absolute file path location for ffprobe to hit on disk
	fullMediaFilePath := filepath.Join(playlistDir, discoveredMediaURI)

	// 2. Query structural characteristics using a fast ffprobe header pass
	cmd := exec.CommandContext(ctx, "ffprobe",
		"-v", "error",
		"-show_entries", "stream=codec_type,codec_name,profile,width,height,r_frame_rate,tags",
		"-of", "json",
		fullMediaFilePath,
	)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffprobe capability lookup failed for %s: %w", fullMediaFilePath, err)
	}

	var caps FFprobeFormatAndStreams
	if err := json.Unmarshal(outBuf.Bytes(), &caps); err != nil {
		return nil, fmt.Errorf("failed decoding ffprobe capability data: %w", err)
	}
	if len(caps.Streams) == 0 {
		return nil, fmt.Errorf("container file features zero traceable media streams: %s", fullMediaFilePath)
	}

	stream := caps.Streams[0]

	// 3. Map records cleanly based on class group properties
	switch strings.ToLower(stream.CodecType) {
	case "video":
		codecString := "avc1.640028"
		if stream.CodecName == "hevc" {
			codecString = "hvc1.1.6.L120.90"
		}

		fpsStr := "25.000"
		if parts := strings.Split(stream.RFrameRate, "/"); len(parts) == 2 {
			if num, err := strconv.ParseFloat(parts[0], 64); err == nil {
				if den, err := strconv.ParseFloat(parts[1], 64); err == nil && den > 0 {
					fpsStr = fmt.Sprintf("%.3f", num/den)
				}
			}
		}

		return VideoVariant{
			Bandwidth:  peakBitrate,
			AvgBitrate: avgBitrate,
			Resolution: fmt.Sprintf("%dx%d", stream.Width, stream.Height),
			FrameRate:  fpsStr,
			Codecs:     codecString,
			Playlist:   playlistURIName,
		}, nil

	case "audio":
		trackLang := fallbackLang
		if stream.Tags != nil {
			if val, exists := stream.Tags["language"]; exists && val != "" && val != "und" {
				trackLang = val
			}
		}
		if before, ok := strings.CutSuffix(m3u8Path, ".m3u8"); ok {
			if data, err := os.ReadFile(before + ".language"); err == nil {
				trackLang = strings.TrimSpace(string(data))
			}
		}
		langName := fmt.Sprintf("%s (%s)", strings.ToUpper(trackLang), strings.ToUpper(stream.CodecName))
		if langNamePtr := iso639_3.FromAnyCode(trackLang); langNamePtr != nil {
			langName = langNamePtr.Name
		}
		codecString := "mp4a.40.2"
		if stream.CodecName == "ac3" {
			codecString = "ac-3"
		} else if stream.CodecName == "eac3" {
			codecString = "ec-3"
		}

		return AudioTrack{
			GroupID:   groupID,
			Name:      langName,
			Language:  trackLang,
			Codecs:    codecString,
			URI:       playlistURIName,
			IsDefault: isDefault,
		}, nil

	default:
		return nil, fmt.Errorf("unrecognized pipeline content classification group: %+v", stream)
	}
}

// ============================================================================
// Workflow Orchestration Master Integration Pattern
// ============================================================================

func RunMasterCompositionWorkflowBlock(ctx context.Context) error {
	// 1. Simply pass the path of your .m3u8 files. The logic handles the rest automatically.
	vRaw, _ := AutomaticInspectPlaylist(ctx, "/var/cache/mediacache/movie/video.m3u8", "", "en", false)
	videoRec := vRaw.(VideoVariant)

	aRaw, _ := AutomaticInspectPlaylist(ctx, "/var/cache/mediacache/movie/audio.m3u8", "audio-hevc", "en", true)
	audioRec := aRaw.(AudioTrack)

	// 2. Cross-link the codecs and audio dependencies together cleanly in memory
	videoRec.Codecs = fmt.Sprintf("%s,%s", videoRec.Codecs, audioRec.Codecs)
	videoRec.AudioGroup = audioRec.GroupID

	// 3. Complete text compilation file serialization block...
	// config := HLSMasterConfig{ AudioTracks: []AudioTrack{audioRec}, VideoVariants: []VideoVariant{videoRec} }
	// return CompositeAdvancedHLSMasterActivity(ctx, config, "/var/cache/mediacache/movie/master.m3u8")
	return nil
}
