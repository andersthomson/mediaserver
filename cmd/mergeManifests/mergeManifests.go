package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
)

// Minimal structural mappings for parsing DASH manifests
type MPD struct {
	XMLName            xml.Name `xml:"MPD"`
	MinBufferTime      string   `xml:"minBufferTime,attr"`
	Type               string   `xml:"type,attr"`
	MediaPresDuration  string   `xml:"mediaPresentationDuration,attr"`
	MaxSubsegDuration  string   `xml:"maxSubsegmentDuration,attr"`
	Profiles           string   `xml:"profiles,attr"`
	ProgramInformation string   `xml:"ProgramInformation,omitempty"`
	Period             Period   `xml:"Period"`
}

type Period struct {
	Duration       string          `xml:"duration,attr,omitempty"`
	AdaptationSets []AdaptationSet `xml:"AdaptationSet"`
}

type AdaptationSet struct {
	Content []byte `xml:",innerxml"`
}

func main() {
	if err := MergeManifestsActivity(context.Background(), os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

// MergeManifestsActivity merges separate audio and video MPDs into one master MPD.
func MergeManifestsActivity(ctx context.Context, videoMpdPath, audioMpdPath, outputPath string) error {
	// 1. Read and parse the Video MPD (which serves as our master template base)
	videoData, err := os.ReadFile(videoMpdPath)
	if err != nil {
		return fmt.Errorf("failed to read video mpd: %w", err)
	}
	var masterMpd MPD
	if err := xml.Unmarshal(videoData, &masterMpd); err != nil {
		return fmt.Errorf("failed to unmarshal video mpd: %w", err)
	}

	// 2. Read and parse the Audio MPD
	audioData, err := os.ReadFile(audioMpdPath)
	if err != nil {
		return fmt.Errorf("failed to read audio mpd: %w", err)
	}
	var audioMpd MPD
	if err := xml.Unmarshal(audioData, &audioMpd); err != nil {
		return fmt.Errorf("failed to unmarshal audio mpd: %w", err)
	}

	// 3. Inject the audio AdaptationSets directly into the master Period track block
	if len(audioMpd.Period.AdaptationSets) == 0 {
		return fmt.Errorf("audio mpd contains no AdaptationSets")
	}
	masterMpd.Period.AdaptationSets = append(masterMpd.Period.AdaptationSets, audioMpd.Period.AdaptationSets...)

	// 4. Marshal back to XML and save to disk
	outputData, err := xml.MarshalIndent(masterMpd, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal merged master mpd: %w", err)
	}

	// Prepend the required XML header prefix signature
	finalPayload := append([]byte(xml.Header), outputData...)
	if err := os.WriteFile(outputPath, finalPayload, 0644); err != nil {
		return fmt.Errorf("failed to save merged master mpd: %w", err)
	}

	return nil
}
