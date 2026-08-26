package vttextract

import (
	"regexp"
	"strings"
)

// NeedsOtaFix scans a WebVTT string to determine if it contains zero-duration cues
// or empty clearance blocks characteristic of malformed OTA broadcast rips.
func needsOtaFix(input string) bool {
	// Normalize line endings and split into structural block chunks
	normalized := strings.ReplaceAll(input, "\r\n", "\n")
	blocks := strings.Split(normalized, "\n\n")

	timeRegex := regexp.MustCompile(`^(\d{2}:\d{2}\.\d{3}) --> (\d{2}:\d{2}\.\d{3})$`)

	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if block == "" || block == "WEBVTT" {
			continue
		}

		lines := strings.Split(block, "\n")
		match := timeRegex.FindStringSubmatch(lines[0])

		if match != nil {
			start := match[1]
			end := match[2]

			// Issue 1: Detected a zero-duration event (Start Time == End Time)
			if start == end {
				return true
			}

			// Issue 2: Detected an orphaned timestamp block containing no text payload
			if len(lines) == 1 {
				return true
			}

			// Additional safety check: If there are lines but they are entirely whitespace
			hasText := false
			for _, line := range lines[1:] {
				if strings.TrimSpace(line) != "" {
					hasText = true
					break
				}
			}
			if !hasText {
				return true
			}
		}
	}

	// The file layout is clean, legal, and ready for standard streaming
	return false
}
