package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

type FFProbeOutput struct {
	Frames []Frame `json:"frames"`
}

type Frame struct {
	PtsTime    string `json:"pts_time"`
	PktPtsTime string `json:"pkt_pts_time"`
	PictType   string `json:"pict_type"`
}

func getGOPConstraints(masterFile string) (string, error) {
	cmd := exec.Command("ffprobe",
		"-loglevel", "quiet", "-select_streams", "v:0", "-show_frames",
		"-show_entries", "frame=pts_time,pkt_pts_time,pict_type", "-of", "json",
		masterFile,
	)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", err
	}

	var probeData FFProbeOutput
	if err := json.Unmarshal(stdout.Bytes(), &probeData); err != nil {
		return "", err
	}

	var forceKeyFramesStr string
	for _, frame := range probeData.Frames {
		if frame.PictType != "I" {
			continue
		}
		rawTime := frame.PtsTime
		if rawTime == "" {
			rawTime = frame.PktPtsTime
		}
		if rawTime == "" {
			continue
		}
		pts, _ := strconv.ParseFloat(rawTime, 64)
		if pts > 0 {
			if forceKeyFramesStr != "" {
				forceKeyFramesStr += ","
			}
			forceKeyFramesStr += rawTime
		}
	}
	return forceKeyFramesStr, nil
}

func main() {
	masterFile := os.Args[1]

	// 1. Isolate variable GOP string from master file
	gopString, err := getGOPConstraints(masterFile)
	if err != nil {
		fmt.Printf("Error probing master: %v\n", err)
		return
	}

	// 2. Pass 1: Transcode directly to fragmented MP4 (fMP4) single files
	fmt.Println("Executing Pass 1: Creating aligned fMP4 single-file variants...")
	pass1 := exec.Command("ffmpeg", "-y", "-i", masterFile,
		"-force_key_frames", gopString,
		"-forced-idr", "1",
		"-movflags", "frag_custom+dash+delay_moov",
		"-s:v:0", "1920x1080", "-b:v:0", "5000k", "-c:v:0", "libx264", "-c:a:0", "aac", "v_1080p.mp4",
		"-s:v:1", "1280x720", "-b:v:1", "2500k", "-c:v:1", "libx264", "-c:a:1", "aac", "v_720p.mp4",
	)
	if err := pass1.Run(); err != nil {
		fmt.Printf("Pass 1 failed: %v\n", err)
		return
	}

	// 3. Pass 2A: Write the DASH Manifest from pre-fragmented files
	fmt.Println("Executing Pass 2A: Writing DASH MPD file...")
	dashPass := exec.Command("ffmpeg", "-y",
		"-i", "v_1080p.mp4", "-i", "v_720p.mp4",
		"-c", "copy",
		"-map", "0:v:0", "-map", "0:a:0",
		"-map", "1:v:0", "-map", "1:a:0",
		"-f", "dash", "-single_file", "1", "-dash_segment_type", "mp4",
		"-adaptation_sets", "id=0,streams=v id=1,streams=a",
		"manifest.mpd",
	)
	if err := dashPass.Run(); err != nil {
		fmt.Printf("DASH manifest generation failed: %v\n", err)
		return
	}

	// 4. Pass 2B: Write HLS manifests
	fmt.Println("Executing Pass 2B: Writing HLS child playlists...")
	hls1080 := exec.Command("ffmpeg", "-y", "-i", "v_1080p.mp4", "-c", "copy", "-f", "hls", "-hls_segment_type", "fmp4", "-hls_flags", "single_file", "-hls_time", "0", "1080p.m3u8")
	hls720 := exec.Command("ffmpeg", "-y", "-i", "v_720p.mp4", "-c", "copy", "-f", "hls", "-hls_segment_type", "fmp4", "-hls_flags", "single_file", "-hls_time", "0", "720p.m3u8")

	if err := hls1080.Run(); err != nil || hls720.Run() != nil {
		fmt.Println("HLS child generation failed")
		return
	}

	// 5. Build and output the top-level HLS Master playlist file
	masterPlaylistContent := `#EXTM3U
#EXT-X-VERSION:6
#EXT-X-STREAM-INF:BANDWIDTH=5500000,RESOLUTION=1920x1080,CODECS="avc1.64002a,mp4a.40.2"
1080p.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=2800000,RESOLUTION=1280x720,CODECS="avc1.4d401f,mp4a.40.2"
720p.m3u8
`
	if err := os.WriteFile("master.m3u8", []byte(masterPlaylistContent), 0644); err != nil {
		fmt.Printf("Failed to write master HLS file: %v\n", err)
		return
	}

	fmt.Println("\nAll jobs successfully finalized!")
	fmt.Println("Outputs generated: v_1080p.mp4, v_720p.mp4, manifest.mpd, master.m3u8")
}
