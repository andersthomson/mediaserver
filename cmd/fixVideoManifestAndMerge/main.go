package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

// ============================================================================
// DASH MPD XML Data Structures
// ============================================================================

type MPD struct {
	XMLName                   xml.Name `xml:"MPD"`
	Xmlns                     string   `xml:"xmlns,attr"`
	Xsi                       string   `xml:"xmlns:xsi,attr"`
	SchemaLocation            string   `xml:"xsi:schemaLocation,attr"`
	MinBufferTime             string   `xml:"minBufferTime,attr"`
	Type                      string   `xml:"type,attr"`
	MediaPresentationDuration string   `xml:"mediaPresentationDuration,attr"`
	Profiles                  string   `xml:"profiles,attr"`
	Period                    Period   `xml:"Period"`
}

type Period struct {
	ID             string          `xml:"id,attr"`
	Start          string          `xml:"start,attr"`
	AdaptationSets []AdaptationSet `xml:"AdaptationSet"`
}

type AdaptationSet struct {
	ID               string           `xml:"id,attr"`
	ContentType      string           `xml:"contentType,attr"`
	SegmentAlignment string           `xml:"segmentAlignment,attr"`
	Representations  []Representation `xml:"Representation"`
}

type Representation struct {
	ID              string          `xml:"id,attr"`
	MimeType        string          `xml:"mimeType,attr"`
	Codecs          string          `xml:"codecs,attr"`
	Bandwidth       string          `xml:"bandwidth,attr"`
	Width           string          `xml:"width,attr,omitempty"`
	Height          string          `xml:"height,attr,omitempty"`
	BaseURL         string          `xml:"BaseURL"`
	SegmentTemplate SegmentTemplate `xml:"SegmentTemplate"`
}

type SegmentTemplate struct {
	Timescale       string           `xml:"timescale,attr"`
	Initialization  string           `xml:"initialization,attr"`
	Index           string           `xml:"index,attr"`
	SegmentTimeline *SegmentTimeline `xml:"SegmentTimeline"`
}

type SegmentTimeline struct {
	S []TimelineS `xml:"S"`
}

type TimelineS struct {
	T string `xml:"t,attr,omitempty"`
	D string `xml:"d,attr"`
	R string `xml:"r,attr,omitempty"`
}

// ============================================================================
// FFprobe JSON Mapping Structures
// ============================================================================

type FFprobeOutput struct {
	Packets []Packet `json:"packets"`
}

type Packet struct {
	KeyFrame     int    `json:"key_frame"`     // 1 = Keyframe, 0 = Non-keyframe
	DurationTime string `json:"duration_time"` // Read floating seconds natively (e.g. 0.040000)
}

// ============================================================================
// Core Processing Logic
// ============================================================================

// ExtractGOPTimelines scans a single-file fragmented MP4 using ffprobe.
// It detects true binary keyframes and generates a millisecond-based (timescale 1000) timeline.
func ExtractGOPTimelines(ctx context.Context, mp4Path string, streamSelect string) ([]TimelineS, error) {
	// Querying key_frame and duration_time avoids string token errors
	cmd := exec.CommandContext(ctx, "ffprobe",
		"-v", "error",
		"-show_entries", "packet=key_frame,duration_time",
		"-select_streams", streamSelect,
		"-of", "json",
		mp4Path,
	)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffprobe structural scan failed for %s: %w", mp4Path, err)
	}

	var probeData FFprobeOutput
	if err := json.Unmarshal(outBuf.Bytes(), &probeData); err != nil {
		return nil, fmt.Errorf("failed to decode ffprobe payload: %w", err)
	}

	var timelineSegments []TimelineS
	var currentSegmentDuration int64

	// Convert seconds float natively into clean millisecond chunks (timescale 1000)
	timescaleMultiplier := float64(1000)

	for i, packet := range probeData.Packets {
		dur, _ := strconv.ParseFloat(packet.DurationTime, 10)
		durMs := int64(dur * timescaleMultiplier)

		// CRITICAL BOUNDARY CORRECTION: Slice segments purely when key_frame == 1
		if i > 0 && packet.KeyFrame == 1 {
			timelineSegments = append(timelineSegments, TimelineS{D: strconv.FormatInt(currentSegmentDuration, 10)})
			currentSegmentDuration = 0
		}
		currentSegmentDuration += durMs
	}
	// Append final trailing segment sequence
	if currentSegmentDuration > 0 {
		timelineSegments = append(timelineSegments, TimelineS{D: strconv.FormatInt(currentSegmentDuration, 10)})
	}

	return timelineSegments, nil
}

// CompositeMasterManifestActivity reads your cold-storage continuous video and audio files,
// parses their exact indexing realities via ffprobe, and writes a Shaka-compliant master MPD.
func CompositeMasterManifestActivity(ctx context.Context, videoMp4, audioMp4, outputPath string) error {
	// 1. Calculate granular, drifting video segment durations
	videoTimeline, err := ExtractGOPTimelines(ctx, videoMp4, "v:0")
	if err != nil {
		return fmt.Errorf("video processing error: %w", err)
	}

	// 2. Calculate matching, synchronized audio segment durations
	audioTimeline, err := ExtractGOPTimelines(ctx, audioMp4, "a:0")
	if err != nil {
		return fmt.Errorf("audio processing error: %w", err)
	}

	// 3. Construct the clean, unified, multi-track "isoff-main" structure
	masterMpd := MPD{
		Xmlns:                     "urn:mpeg:dash:schema:mpd:2011",
		Xsi:                       "http://w3.org",
		SchemaLocation:            "urn:mpeg:DASH:schema:MPD:2011 http://iso.org",
		MinBufferTime:             "PT1.5S",
		Type:                      "static",
		MediaPresentationDuration: "PT1H56M29.4S",
		Profiles:                  "urn:mpeg:dash:profile:isoff-main:2011", // Strict main profile validation
		Period: Period{
			ID:    "0",
			Start: "PT0.0S",
			AdaptationSets: []AdaptationSet{
				{
					ID:               "0",
					ContentType:      "video",
					SegmentAlignment: "true",
					Representations: []Representation{
						{
							ID:        "1",
							MimeType:  "video/mp4",
							Codecs:    "hvc1.1.6.L120.90", // Fully explicit tier skips error 4032
							Bandwidth: "3099187",
							Width:     "1920",
							Height:    "1080",
							BaseURL:   "video_1080p_copy-stream0.mp4",
							SegmentTemplate: SegmentTemplate{
								Timescale:      "1000", // Locks with millisecond calculation loop
								Initialization: "video_1080p_copy-stream0.mp4",
								Index:          "video_1080p_copy-stream0.mp4", // Points Shaka to the single container file
								SegmentTimeline: &SegmentTimeline{
									S: videoTimeline,
								},
							},
						},
					},
				},
				{
					ID:               "1",
					ContentType:      "audio",
					SegmentAlignment: "true",
					Representations: []Representation{
						{
							ID:        "2",
							MimeType:  "audio/mp4",
							Codecs:    "mp4a.40.2",
							Bandwidth: "192000",
							BaseURL:   "audio_copy-stream0.mp4",
							SegmentTemplate: SegmentTemplate{
								Timescale:      "1000",
								Initialization: "audio_copy-stream0.mp4",
								Index:          "audio_copy-stream0.mp4",
								SegmentTimeline: &SegmentTimeline{
									S: audioTimeline,
								},
							},
						},
					},
				},
			},
		},
	}

	// 4. Marshal layout mapping structures to valid XML format
	outputData, err := xml.MarshalIndent(masterMpd, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal master xml payload: %w", err)
	}

	// Prepend standardized XML header requirement string bounds
	finalPayload := append([]byte(xml.Header), outputData...)
	return os.WriteFile(outputPath, finalPayload, 0644)
}

// ============================================================================
// Main Execution Entrypoint (Testing Example)
// ============================================================================
func main() {
	ctx := context.Background()

	videoFile := os.Args[1]
	audioFile := os.Args[2]
	outputManifest := os.Args[3]

	fmt.Println("Starting manifest composition via native file header inspection...")
	err := CompositeMasterManifestActivity(ctx, videoFile, audioFile, outputManifest)
	if err != nil {
		fmt.Printf("Execution failed: %v\n", err)
		return
	}
	fmt.Printf("Success! Stall-free master manifest saved to: %s\n", outputManifest)
}
