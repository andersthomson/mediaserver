package dasherworker

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
)

type BitrateResults struct {
	AverageBandwidth int // To map directly to AVERAGE-BANDWIDTH
	PeakBandwidth    int // To map directly to BANDWIDTH
}

// CalculateHLSBitrates parses an existing single-file .m3u8 manifest text layout
// and extracts the exact average and peak byte-range bitrates in memory.
func CalculateHLSBitrates(m3u8Path string) (BitrateResults, error) {
	file, err := os.Open(m3u8Path)
	if err != nil {
		return BitrateResults{}, err
	}
	defer file.Close()
	if info, err := file.Stat(); err == nil {
		fmt.Printf("File opened: %s | Size: %d bytes\n", m3u8Path, info.Size())
	}

	var totalBytes int64
	var totalDuration float64
	var maxSegmentBitrate float64

	scanner := bufio.NewScanner(file)
	var currentDuration float64

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		spew.Dump(line)

		// 1. Capture the segment duration line (e.g., #EXTINF:3.840000,)
		if strings.HasPrefix(line, "#EXTINF:") {
			cleaned := strings.TrimPrefix(line, "#EXTINF:")
			cleaned = strings.TrimSuffix(cleaned, ",")
			dur, err := strconv.ParseFloat(cleaned, 64)
			if err == nil {
				currentDuration = dur
			}
		}

		// 2. Capture the matching byte range allocation line (e.g., #EXT-X-BYTERANGE:1416580@2914159988)
		if strings.HasPrefix(line, "#EXT-X-BYTERANGE:") {
			cleaned := strings.TrimPrefix(line, "#EXT-X-BYTERANGE:")

			// Isolate the length component before the '@' symbol
			parts := strings.Split(cleaned, "@")
			if len(parts) > 0 && currentDuration > 0 {
				segmentBytes, err := strconv.ParseInt(parts[0], 10, 64)
				if err == nil {
					totalBytes += segmentBytes
					totalDuration += currentDuration

					// Compute the instant bitrate of this individual segment in bits-per-second
					segmentBitrate := (float64(segmentBytes) * 8) / currentDuration
					if segmentBitrate > maxSegmentBitrate {
						maxSegmentBitrate = segmentBitrate
					}
				}
			}
			// Reset tracker for the next sequence iteration
			currentDuration = 0
		}
		spew.Dump(currentDuration)
	}
	if err := scanner.Err(); err != nil {
		slog.Error("Scanner failed reading M3U8", "err", err)
		return BitrateResults{}, err
	}

	if totalDuration == 0 {
		return BitrateResults{}, fmt.Errorf("failed to parse valid segments out of manifest %s", m3u8Path)
	}

	// Calculate overall global average bitrate
	avgBitrate := int((float64(totalBytes) * 8) / totalDuration)
	peakBitrate := int(maxSegmentBitrate)

	// Under standard HLS guidelines, if the peak calculation fails or spikes irregularly,
	// ensure the maximum ceiling bandwidth is at least 10% higher than the average.
	if peakBitrate <= avgBitrate {
		peakBitrate = int(float64(avgBitrate) * 1.10)
	}

	return BitrateResults{
		AverageBandwidth: avgBitrate,
		PeakBandwidth:    peakBitrate,
	}, nil
}
