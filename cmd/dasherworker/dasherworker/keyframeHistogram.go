package dasherworker

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"os/exec"

	"go.temporal.io/sdk/workflow"
)

func CallKeyFrameHistogram(ctx workflow.Context, inputID string, inputNo int, stream string) (map[int]int, error) {
	res, err := CallActivityIO[KeyframeHistogramArgs, KeyframeHistogramResp](ctx, KeyframeHistogram, KeyframeHistogramArgs{
		InputID: inputID,
		InputNo: inputNo,
		Stream:  stream,
	})
	return res, err
}

type KeyframeHistogramArgs struct {
	InputID string
	InputNo int
	Stream  string
}

type KeyframeHistogramResp map[int]int

// FFprobeOutput maps the exact JSON structure returned by the ffprobe command
func KeyframeHistogram(ctx context.Context, args KeyframeHistogramArgs) (KeyframeHistogramResp, error) {

	videoPath := storage.ResolveInputNumber(args.InputID, args.InputNo)

	return KeyframeHistogramFile(videoPath, args.Stream)
}

func KeyframeHistogramFile(videoPath string, stream string) (KeyframeHistogramResp, error) {
	type Frame struct {
		PictType string `json:"pict_type"`
		KeyFrame int    `json:"key_frame"`
		// Use string because ffprobe can sometimes output "N/A" for packet positions
		CodedPictureNumber string `json:"coded_picture_number"`
	}
	type FFprobeOutput struct {
		Frames []Frame `json:"frames"`
	}
	// 1. Configure ffprobe to select only video frames and output JSON metadata
	// We extract both 'key_frame' (true IDR/Entry points) and 'pict_type'
	cmd := exec.Command("ffprobe",
		"-v", "error",
		"-select_streams", stream,
		"-show_entries", "frame=key_frame,pict_type,coded_picture_number",
		"-of", "json",
		videoPath,
	)
	// 1. Set up the stderr buffer to catch execution errors
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// 2. Establish a direct read pipe to the command's stdout
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, Fatal("Failed to create stdout pipe", "err", err)
	}

	// 3. Start the process asynchronously
	if err := cmd.Start(); err != nil {
		return nil, Fatal("Failed to start ffprobe", "err", err)
	}

	// 4. Stream and parse the JSON directly from the pipe
	var metadata FFprobeOutput
	decoder := json.NewDecoder(stdoutPipe)
	if err := decoder.Decode(&metadata); err != nil {
		return nil, Fatal("Failed to decode JSON stream", "err", err)
	}

	// 5. Wait for the command to clean up and exit
	if err := cmd.Wait(); err != nil {
		log.Fatalf("ffprobe failed: %v\nStderr: %s", err, stderr.String())
	}

	// 4. Calculate intervals and build the histogram
	histogram := make(map[int]int)
	lastKeyFrameIndex := -1
	currentFrameIndex := 0

	for _, frame := range metadata.Frames {
		// key_frame == 1 indicates a true seekable IDR keyframe boundary
		if frame.KeyFrame == 1 {
			if lastKeyFrameIndex != -1 {
				// Calculate the distance (GOP size) from the last keyframe
				interval := currentFrameIndex - lastKeyFrameIndex
				histogram[interval]++
			} else {
				// Handle the very first keyframe in the file (usually frame 0)
				// We track it, but it doesn't have a preceding interval yet
			}
			lastKeyFrameIndex = currentFrameIndex
		}
		currentFrameIndex++
	}

	return histogram, nil
}
