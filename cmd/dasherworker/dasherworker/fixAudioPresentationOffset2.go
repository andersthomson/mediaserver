package dasherworker

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/clbanning/mxj/v2"
)

// getAbsolutePTO calculates the absolute presentationTimeOffset for a track
func getAbsolutePTO(file string, streamType string) (int, error) {
	// FFprobe JSON mapping for robust data extraction
	type ProbeResult struct {
		Streams []struct {
			TimeBase string `json:"time_base"`
		} `json:"streams"`
		Packets []struct {
			PtsTime string `json:"pts_time"`
		} `json:"packets"`
	}

	// 1. First choice: Use ffprobe to see if we can find sidx or initial packet properties
	// We select via "v" or "a" directly to prevent multi-stream mixing bugs
	cmd := exec.Command("ffprobe", "-v", "error", "-select_streams", streamType,
		"-show_entries", "stream=time_base:packet=pts_time",
		"-read_intervals", "%+1", "-of", "json", file)

	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("ffprobe failed for file %s: %w", file, err)
	}

	var res ProbeResult
	if err := json.Unmarshal(out, &res); err != nil {
		return 0, fmt.Errorf("failed to parse json for %s: %w", file, err)
	}

	if len(res.Streams) == 0 {
		return 0, fmt.Errorf("no streams found for type %s in file %s", streamType, file)
	}

	// Parse out the timeline timescale (e.g. "1/12800" -> 12800)
	var timescale float64
	timeBase := res.Streams[0].TimeBase
	if !strings.HasPrefix(timeBase, "1/") {
		return 0, fmt.Errorf("unexpected time_base format: %s", timeBase)
	}
	fmt.Sscanf(timeBase, "1/%f", &timescale)
	if timescale == 0 {
		timescale = 1.0 // Safety fallback
	}

	// Fallback to 0 if packets array is empty
	if len(res.Packets) == 0 {
		return 0, nil
	}

	// Parse the absolute start time of the first packet sample
	startTime, err := strconv.ParseFloat(res.Packets[0].PtsTime, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse packet pts_time: %w", err)
	}

	// Absolute PTO calculation: timestamp * timescale
	// We use math.Max to cleanly drop negative priming offsets if needed by the player
	absolutePTO := int(math.Round(math.Max(0, startTime) * timescale))
	return absolutePTO, nil
}

func fixPresentationTimeOffsets2(mpdPath string) {
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
		PTO             string          `xml:"presentationTimeOffset,attr,omitempty"`
		IndexRange      string          `xml:"indexRange,attr,omitempty"`
		IndexRangeExact string          `xml:"indexRangeExact,attr,omitempty"`
		Timescale       string          `xml:"timescale,attr,omitempty"`
		Initialization  *Initialization `xml:"Initialization,omitempty"`
		OtherAttrs      []xml.Attr      `xml:",any,attr"`
	}

	type Initialization struct {
		Range string     `xml:"range,attr"`
		Other []xml.Attr `xml:",any,attr"`
	}

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
	baseDir := filepath.Dir(mpdPath)

	// 2. Identify the referenced media filenames
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

	if videoFile == "" {
		fmt.Println("Error: Could not identify video file in the manifest.")
		return
	}

	// 3. Compute absolute values per file independently
	vAbsolutePTO, err := getAbsolutePTO(filepath.Join(baseDir, videoFile), "v")
	if err != nil {
		fmt.Printf("Error probing video: %v\n", err)
		return
	}

	var aAbsolutePTO int
	hasAudio := audioFile != ""
	if hasAudio {
		aAbsolutePTO, err = getAbsolutePTO(filepath.Join(baseDir, audioFile), "a")
		if err != nil {
			fmt.Printf("Error probing audio: %v\n", err)
			return
		}
	}

	// 4. Transform manifest using mxj map manipulation to retain unrecognized blocks
	m, err := mxj.NewMapXml(data)
	if err != nil {
		fmt.Printf("Error parsing XML into map: %v\n", err)
		return
	}

	reps, err := m.ValuesForPath("MPD.Period.AdaptationSet.Representation")
	if err != nil {
		fmt.Printf("No representations found: %v\n", err)
		return
	}

	// Normalize if single stream representation returned instead of standard array
	for _, r := range reps {
		rep, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		// Patch Video Absolute Timeline Location
		if rep["-mimeType"] == "video/mp4" {
			if sb, ok := rep["SegmentBase"].(map[string]interface{}); ok {
				if vAbsolutePTO > 0 {
					sb["-presentationTimeOffset"] = vAbsolutePTO
					fmt.Printf("Patched Video ID %v with Absolute PTO %d\n", rep["-id"], vAbsolutePTO)
				} else {
					delete(sb, "-presentationTimeOffset")
					fmt.Printf("Removed PTO from Video ID %v (starts cleanly at 0)\n", rep["-id"])
				}
			}
		}

		// Patch Audio Absolute Timeline Location
		if rep["-mimeType"] == "audio/mp4" && hasAudio {
			if sb, ok := rep["SegmentBase"].(map[string]interface{}); ok {
				if aAbsolutePTO > 0 {
					sb["-presentationTimeOffset"] = aAbsolutePTO
					fmt.Printf("Patched Audio ID %v with Absolute PTO %d\n", rep["-id"], aAbsolutePTO)
				} else {
					delete(sb, "-presentationTimeOffset")
					fmt.Printf("Removed PTO from Audio ID %v (starts cleanly at 0)\n", rep["-id"])
				}
			}
		}
	}

	// 5. Build, serialize, and write the valid output manifest back out
	output, err := m.XmlIndent("", "  ")
	if err != nil {
		fmt.Printf("Error producing XML tree: %v\n", err)
		return
	}

	header := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	if err := os.WriteFile(mpdPath, append(header, output...), 0644); err != nil {
		fmt.Printf("Error writing updated manifest: %v\n", err)
		return
	}
	fmt.Println("Success: Updated manifest with matching container timeline properties.")
}
