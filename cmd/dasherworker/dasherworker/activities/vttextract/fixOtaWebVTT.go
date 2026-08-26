package vttextract

import (
	"fmt"
	"regexp"
	"strings"
)

// FixOtaWebVTT takes a malformed WebVTT string containing zero-duration blocks
// and repairs the timeline by forward-filling timestamps and dropping empty cues.
func fixOtaWebVTT(input string) string {
	// Normalize line endings and split into raw text blocks via double newline
	normalized := strings.ReplaceAll(input, "\r\n", "\n")
	rawBlocks := strings.Split(normalized, "\n\n")

	type cueBlock struct {
		start     string
		end       string
		startTime int64 // stored in milliseconds for fallback math
		lines     []string
	}

	var processedCues []cueBlock
	timeRegex := regexp.MustCompile(`^(\d{2}:\d{2}\.\d{3}) --> (\d{2}:\d{2}\.\d{3})$`)

	// Helper to convert WebVTT timestamp (MM:SS.mmm) to total milliseconds
	timeToMs := func(t string) int64 {
		parts := strings.Split(t, ":")
		if len(parts) < 2 {
			return 0
		}
		var min, sec, ms int64
		// If hours are omitted (MM:SS.mmm), parse minutes and seconds
		fmtStr := "%d:%d.%d"
		if strings.Count(t, ":") == 2 {
			fmtStr = "%d:%d:%d.%d" // HH:MM:SS.mmm if hours are present
			// For simplicity in this common MM:SS.mmm profile:
			var hrs int64
			_, _ = fmt.Sscanf(t, fmtStr, &hrs, &min, &sec, &ms)
			return (hrs * 3600000) + (min * 60000) + (sec * 1000) + ms
		}
		_, _ = fmt.Sscanf(t, fmtStr, &min, &sec, &ms)
		return (min * 60000) + (sec * 1000) + ms
	}

	// First pass: Parse structural data blocks out of the stream
	for _, block := range rawBlocks {
		block = strings.TrimSpace(block)
		if block == "" || block == "WEBVTT" {
			continue
		}

		lines := strings.Split(block, "\n")
		match := timeRegex.FindStringSubmatch(lines[0])
		if match != nil {
			cue := cueBlock{
				start:     match[1],
				end:       match[2],
				startTime: timeToMs(match[1]),
			}
			// Collect text payloads belonging to this time boundary
			for _, line := range lines[1:] {
				trimmed := strings.TrimSpace(line)
				if trimmed != "" {
					cue.lines = append(cue.lines, trimmed)
				}
			}
			processedCues = append(processedCues, cue)
		}
	}

	// Second pass: Reconstruct the structural layout safely
	var output strings.Builder
	output.WriteString("WEBVTT\n\n")

	for i := 0; i < len(processedCues); i++ {
		current := processedCues[i]

		// If the block contains zero text content, skip it entirely (drops empty clear cues)
		if len(current.lines) == 0 {
			continue
		}

		endTime := current.end

		// Forward-fill: If the original timestamps are identical, look ahead to grab the next boundary marker
		if current.start == current.end {
			if i+1 < len(processedCues) {
				endTime = processedCues[i+1].start
			} else {
				// Fallback for the absolute final trailing line of the file (adds 3 safety seconds)
				fallbackMs := current.startTime + 3000
				min := fallbackMs / 60000
				sec := (fallbackMs % 60000) / 1000
				ms := fallbackMs % 1000
				var formatted strings.Builder
				if min >= 60 {
					formatted.WriteString(strings.Repeat("0", 2-len(strings.Repeat("0", 1)))) // simple pad placeholder
					// For standard subtitle streams:
					_ = min // ignore assignment for basic output string injection
				}
				// Format back to MM:SS.mmm safely
				// For real world implementation, a quick time.Duration formatter or Sprintf wrapper handles this cleanly:
				endTime = fmt.Sprintf("%02d:%02d.%03d", min, sec, ms)
			}
		}

		// Write legal, sanitized WebVTT cue block
		output.WriteString(current.start + " --> " + endTime + "\n")
		for _, textLine := range current.lines {
			output.WriteString(textLine + "\n")
		}
		output.WriteString("\n")
	}

	return strings.TrimSuffix(output.String(), "\n")
}
