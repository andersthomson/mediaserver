package vttextract

import (
	"context"
	"log/slog"
	"os"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
)

type VttExtractor struct {
	Storage *storage.Storage
}

// Returns language tag
func (v *VttExtractor) ExtractVtt(ctx context.Context, inputID string, number int, stream string) (string, error) {
	videoPath := v.Storage.ResolveInputNumber(inputID, number)

	// Step 1: Extract the text stream via FFmpeg
	vtt, err := extractSubtitlesFromContainer(ctx, videoPath, stream)
	if err != nil {
		return "AAAAAAA", err
	}
	slog.Info("Subs eextracted")
	// Step 2: Check if the file exhibits broken OTA broadcast timelines
	if needsOtaFix(vtt) {
		// Step 3: Run the forward-filling repair transformation logic in memory
		vtt = fixOtaWebVTT(vtt)
		slog.Info("subs fixed")
	}

	lang, err := getSubtitleLanguage(ctx, videoPath, stream)
	slog.Info("lang fetched")
	if err != nil {
		return "BBBBB", err
	}
	slog.Info("Returning successfully")
	return lang, os.WriteFile(v.Storage.SubtitlesRepresentationFilePath(inputID, lang), []byte(vtt), 0644)
}
