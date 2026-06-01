package dasherworker

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// ============================================================================
// Core Compilation Logic
// ============================================================================

// ComposeAdvancedHLSMasterActivity generates a highly secure, multi-track master playlist.
// It is fully isolated and processes strings in memory, meaning no media files are modified.
func ComposeAdvancedHLSMasterActivity(ctx context.Context, config HLSMasterConfig, outputPath string) error {
	var sb strings.Builder

	// 1. Write required global protocol headers
	sb.WriteString("#EXTM3U\n")
	sb.WriteString("#EXT-X-VERSION:4\n\n")

	// 2. Append Audio Track Group Definitions
	if len(config.AudioTracks) > 0 {
		sb.WriteString("# ============================================================================\n")
		sb.WriteString("# AUDIO TRACK GROUPS\n")
		sb.WriteString("# ============================================================================\n")
		for _, audio := range config.AudioTracks {
			isDefaultStr := "NO"
			if audio.IsDefault {
				isDefaultStr = "YES"
			}
			line := fmt.Sprintf(
				"#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"%s\",NAME=\"%s\",DEFAULT=%s,AUTOSELECT=YES,LANGUAGE=\"%s\",URI=\"%s\"\n",
				audio.GroupID, audio.Name, isDefaultStr, audio.Language, audio.URI,
			)
			sb.WriteString(line)
		}
		sb.WriteString("\n")
	}

	// 3. Append Subtitle Track Group Definitions
	if len(config.SubtitleTracks) > 0 {
		sb.WriteString("# ============================================================================\n")
		sb.WriteString("# SUBTITLE TRACK GROUPS\n")
		sb.WriteString("# ============================================================================\n")
		for _, sub := range config.SubtitleTracks {
			isDefaultStr := "NO"
			if sub.IsDefault {
				isDefaultStr = "YES"
			}
			line := fmt.Sprintf(
				"#EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID=\"%s\",NAME=\"%s\",DEFAULT=%s,AUTOSELECT=YES,LANGUAGE=\"%s\",URI=\"%s\"\n",
				sub.GroupID, sub.Name, isDefaultStr, sub.Language, sub.URI,
			)
			sb.WriteString(line)
		}
		sb.WriteString("\n")
	}

	// 4. Append Video Stream Rungs (Variant Stream Hierarchies)
	if len(config.VideoVariants) > 0 {
		sb.WriteString("# ============================================================================\n")
		sb.WriteString("# VIDEO REPRESENTATION LAYERS (Variant Streams)\n")
		sb.WriteString("# ============================================================================\n")
		for _, video := range config.VideoVariants {
			// Construct the attribute parameters tag sequentially
			line := fmt.Sprintf(
				"#EXT-X-STREAM-INF:BANDWIDTH=%d,AVERAGE-BANDWIDTH=%d,RESOLUTION=%s,FRAME-RATE=%s,CODECS=\"%s\"",
				video.Bandwidth, video.AvgBitrate, video.Resolution, video.FrameRate, video.Codecs,
			)

			// Cross-bind optional audio and subtitle groups safely if configured
			if video.AudioGroup != "" {
				line += fmt.Sprintf(",AUDIO=\"%s\"", video.AudioGroup)
			}
			if video.SubsGroup != "" {
				line += fmt.Sprintf(",SUBTITLES=\"%s\"", video.SubsGroup)
			}
			line += "\n"

			// Append the path block pointing to the target media playlist
			sb.WriteString(line)
			sb.WriteString(video.Playlist + "\n\n")
		}
	}

	// 5. Commit the compiled payload directly to the storage volume
	err := os.WriteFile(outputPath, []byte(sb.String()), 0644)
	if err != nil {
		return fmt.Errorf("failed writing advanced master playlist text to storage: %w", err)
	}

	return nil
}
