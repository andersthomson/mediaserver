package dasherworker

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// GetForcedKeyframeTimestamps parses an existing video.m3u8 text layout
// and compiles a comma-separated string of absolute keyframe timestamps.
func GetForcedKeyframeTimestamps(m3u8Path string) (string, error) {
	file, err := os.Open(m3u8Path)
	if err != nil {
		return "", fmt.Errorf("failed to open master m3u8 playlist: %w", err)
	}
	defer file.Close()

	var timestamps []string
	var currentTime float64

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Isolate the duration lines (e.g., #EXTINF:3.840000,)
		if strings.HasPrefix(line, "#EXTINF:") {
			cleaned := strings.TrimPrefix(line, "#EXTINF:")
			cleaned = strings.TrimSuffix(cleaned, ",")

			duration, err := strconv.ParseFloat(cleaned, 64)
			if err == nil {
				// Format the absolute timestamp with 3 decimal places
				timestamps = append(timestamps, fmt.Sprintf("%.3f", currentTime))
				currentTime += duration
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading manifest text stream: %w", err)
	}

	if len(timestamps) == 0 {
		return "", fmt.Errorf("no segment durations found inside manifest: %s", m3u8Path)
	}

	// Join the array slice into a single string: "0.000,3.840,7.680,11.520..."
	return strings.Join(timestamps, ","), nil
}
