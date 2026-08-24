package dasherworker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
	"go.temporal.io/sdk/workflow"
)

func CallIsMpeg2VideoWithBrokenDTS(ctx workflow.Context, inputID string, inputNo int, stream string) (bool, error) {
	return CallActivityIO[any, bool](ctx, IsMpeg2VideoWithBrokenDTS, inputID, inputNo, stream)
}

func IsMpeg2VideoWithBrokenDTS(ctx context.Context, inputID string, inputNo int, stream string) (bool, error) {
	dir, msp := storage.ResolveInput(inputID)
	inputFile := filepath.Join(dir, msp.Inputs[inputNo].Filename)

	// FFprobeStream models the stream metadata structure from ffprobe JSON
	type FFprobeStream struct {
		CodecName string `json:"codec_name"`
	}

	// FFprobePacket models individual frame packet timings from ffprobe JSON
	type FFprobePacket struct {
		Dts int64 `json:"dts"` // Handles when dts is string-formatted or "N/A"
	}

	// FFprobeResult wraps the structural arrays returned by ffprobe queries
	type FFprobeResult struct {
		Streams []FFprobeStream `json:"streams"`
		Packets []FFprobePacket `json:"packets"`
	}

	// Run a single optimized ffprobe query for BOTH codec info and the first 3 seconds of packets
	args := []string{
		"-v", "error",
		"-read_intervals", "%3",
		"-select_streams", stream,
		"-show_entries", "stream=codec_name:packet=dts",
		"-of", "json",
		inputFile,
	}

	fmt.Printf("%v\n", args)
	cmd := exec.CommandContext(ctx, "ffprobe", args...)

	var out bytes.Buffer
	cmd.Stdout = &out

	// Execute command safely
	if err := cmd.Run(); err != nil {
		return false, shared.Error("Metadata analysis failed", "filename", inputFile, "err", err)
	}

	// Unmarshal the raw JSON bytes straight into our native Go structs
	var meta FFprobeResult
	if err := json.Unmarshal(out.Bytes(), &meta); err != nil {
		return false, shared.Error("JSON parsing failed", "filename", inputFile, "err", err)
	}

	// Evaluate the structural conditions cleanly
	isMPEG2 := false
	if len(meta.Streams) > 0 && meta.Streams[0].CodecName == "mpeg2video" {
		isMPEG2 = true
	}

	isCorruptedTimeline := false
	var prevDTS int64 = -1
	for _, packet := range meta.Packets {
		// A DTS value of 0 is valid, but if it backtracks or loops we catch it
		if packet.Dts <= prevDTS && prevDTS != -1 {
			isCorruptedTimeline = true
			break
		}
		prevDTS = packet.Dts
	}

	// Assemble final arguments based on findings
	return isMPEG2 && isCorruptedTimeline, nil
}
