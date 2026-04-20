package main

import (
	"fmt"
	"os/exec"
)

func main() {
	// 1. Generate Sync Pattern (Flash + Beep)
	// Creates a 10s video at 25fps with a 1kHz tone.
	// The drawtext filter overlays a frame-accurate timer.
	fmt.Println("Step 1: Generating Test Pattern with FFmpeg...")
	cmd := exec.Command("ffmpeg", "-y",
		"-f", "lavfi", "-i", "testsrc=duration=10:size=1280x720:rate=25",
		"-f", "lavfi", "-i", "sine=frequency=1000:duration=10",
		"-filter_complex", "[0:v]drawtext=text='%{pts\\:hms}':x=(w-tw)/2:y=h-(2*th):fontsize=60:fontcolor=white:box=1:boxcolor=black@0.5[v]",
		"-map", "[v]", "-map", "1:a",
		"-c:v", "libx264", "-g", "25", "-keyint_min", "25", "-sc_threshold", "0",
		"-c:a", "aac", "-b:a", "128k",
		"sync_test.mp4")

	if err := cmd.Run(); err != nil {
		fmt.Printf("Error generating MP4: %v\n", err)
		return
	}

	// 2. Dash using MP4Box (onDemand profile)
	fmt.Println("Step 2: Creating DASH manifest with MP4Box...")
	dashCmd := exec.Command("MP4Box", "-dash", "4000", "-rap", "-profile", "onDemand",
		"-out", "sync_test.mpd", "sync_test.mp4")

	if err := dashCmd.Run(); err != nil {
		fmt.Printf("Error Dashing: %v\n", err)
		return
	}

	fmt.Println("Success! Use sync_test.mpd in Shaka Player or Dash.js.")
}
