package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/clbanning/mxj/v2"
)

// Structural mapping for MPD that preserves unknown attributes
type MPD struct {
	XMLName xml.Name   `xml:"MPD"`
	Other   []xml.Attr `xml:",any,attr"`
	Periods []Period   `xml:"Period"`
}

type Period struct {
	Other          []xml.Attr      `xml:",any,attr"`
	AdaptationSets []AdaptationSet `xml:"AdaptationSet"`
}

type AdaptationSet struct {
	MimeType        string           `xml:"mimeType,attr"`
	Other           []xml.Attr       `xml:",any,attr"`
	Representations []Representation `xml:"Representation"`
}

type Representation struct {
	ID          string       `xml:"id,attr"`
	MimeType    string       `xml:"mimeType,attr"`
	BaseURL     string       `xml:"BaseURL"`
	Other       []xml.Attr   `xml:",any,attr"`
	SegmentBase *SegmentBase `xml:"SegmentBase"`
	Content     []byte       `xml:",innerxml"`
}
type SegmentBase struct {
	// omitempty prevents presentationTimeOffset="" on video tracks
	PTO             string `xml:"presentationTimeOffset,attr,omitempty"`
	IndexRange      string `xml:"indexRange,attr,omitempty"`
	IndexRangeExact string `xml:"indexRangeExact,attr,omitempty"`
	Timescale       string `xml:"timescale,attr,omitempty"`

	// This MUST be defined to preserve the <Initialization /> tag
	Initialization *Initialization `xml:"Initialization,omitempty"`

	// Catch-all for any other attributes we didn't name
	OtherAttrs []xml.Attr `xml:",any,attr"`
}

type Initialization struct {
	Range string     `xml:"range,attr"`
	Other []xml.Attr `xml:",any,attr"`
}

// FFprobe JSON mapping for data extraction
type ProbeResult struct {
	Streams []struct {
		TimeBase string `json:"time_base"`
	} `json:"streams"`
	Packets []struct {
		PtsTime string `json:"pts_time"`
	} `json:"packets"`
}

func getProbeData(file string, streamType string) (float64, float64, error) {
	// Execute ffprobe to get the first packet's timestamp and the stream's time_base
	cmd := exec.Command("/usr/bin/ffprobe", "-v", "error", "-select_streams", streamType,
		"-show_entries", "stream=time_base:packet=pts_time",
		"-read_intervals", "%+1", "-of", "json", file)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return 0, 0, err
	}

	var res ProbeResult
	if err := json.Unmarshal(out, &res); err != nil || len(res.Packets) == 0 {
		return 0, 0, fmt.Errorf("failed to parse probe data for %s", file)
	}
	// Parse first packet time (e.g., 0.080000 or -0.023220)
	startTime, err := strconv.ParseFloat(res.Packets[0].PtsTime, 64)
	if err != nil {
		return 0, 0, err
	}
	// Parse timescale from "1/44100" or "1/12800"
	var timescale float64
	fmt.Sscanf(res.Streams[0].TimeBase, "1/%f", &timescale)

	return startTime, timescale, nil
}

func fixAudioPresentationTimeOffset(mpdPath string) {

	// 1. Read and Unmarshal the existing Manifest
	data, err := os.ReadFile(mpdPath)
	if err != nil {
		fmt.Printf("Error reading manifest: %v\n", err)
		return
	}

	var mpd MPD
	if err := xml.Unmarshal(data, &mpd); err != nil {
		fmt.Printf("Error unmarshaling XML: %v\n", err)
		return
	}

	var videoFile, audioFile string

	// 2. Identify the referenced files from the manifest
	for _, p := range mpd.Periods {
		for _, as := range p.AdaptationSets {
			for _, rep := range as.Representations {
				if rep.MimeType == "video/mp4" {
					videoFile = rep.BaseURL
				} else if rep.MimeType == "audio/mp4" {
					audioFile = rep.BaseURL
				}
			}
		}
	}

	if videoFile == "" || audioFile == "" {
		fmt.Println("Error: Could not identify both video and audio files in the manifest.")
		return
	}

	// 3. Extract exact timing data via ffprobe
	vStart, vTimescale, err := getProbeData(filepath.Dir(mpdPath)+"/"+videoFile, "0")
	if err != nil {
		panic(err)
	}
	aStart, _, err := getProbeData(filepath.Dir(mpdPath)+"/"+audioFile, "0")
	if err != nil {
		panic(err)
	}

	// If video is later than audio (e.g., 0.08 > 0.00)
	if vStart > aStart {
		vPTO := int(math.Round((vStart - aStart) * vTimescale))
		fixManifestPresentationTimeOffsets(mpdPath, vPTO)
		fmt.Printf("Success: Patched manifest\n")
	}

}

func fixManifestPresentationTimeOffsets(mpdPath string, vPTO int) {
	patchedPath := mpdPath // Overwriting the original manifest

	data, err := os.ReadFile(mpdPath)
	if err != nil {
		fmt.Printf("Error reading manifest: %v\n", err)
		return
	}

	// Using mxj to prevent tag loss and duplication
	m, err := mxj.NewMapXml(data)
	if err != nil {
		fmt.Printf("Error parsing XML: %v\n", err)
		return
	}

	reps, err := m.ValuesForPath("MPD.Period.AdaptationSet.Representation")
	if err != nil {
		fmt.Printf("No representations found: %v\n", err)
		return
	}

	for _, r := range reps {
		rep, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if this is a Video representation
		if rep["-mimeType"] == "video/mp4" {
			sb, ok := rep["SegmentBase"].(map[string]interface{})
			if !ok {
				continue
			}

			// Apply the Video PTO (e.g., 1024)
			// This "swallows" the 0.08s delay so the video starts at 0.0
			sb["-presentationTimeOffset"] = vPTO
			fmt.Printf("Patched Video ID %v with PTO %d\n", rep["-id"], vPTO)
		}

		// Ensure Audio PTO is explicitly 0 or removed to prevent spinning
		if rep["-mimeType"] == "audio/mp4" {
			if sb, ok := rep["SegmentBase"].(map[string]interface{}); ok {
				delete(sb, "-presentationTimeOffset")
				fmt.Printf("Reset Audio ID %v PTO to 0\n", rep["-id"])
			}
		}
	}

	output, _ := m.XmlIndent("", "  ")
	header := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	os.WriteFile(patchedPath, append(header, output...), 0644)
}
