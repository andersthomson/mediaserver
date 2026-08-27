package vttextract

import (
	"context"
	"log/slog"
	"os"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/durationDeriver"
)

type VttExtractor struct {
	Storage *storage.Storage
}

// Returns language tag
func (v *VttExtractor) ExtractVtt(ctx context.Context, inputID string, number int, stream string) (string, error) {
	videoPath := v.Storage.ResolveInputNumber(inputID, number)
	_, m := v.Storage.ResolveInput(inputID)
	configuredLanguage := m.Inputs[number].Language

	deriver := durationDeriver.DurationDeriver{Storage: v.Storage}
	var durationUs int64
	if d, err := deriver.GetMediaDurationUsec(ctx, inputID, number, stream); err != nil {
		durationUs = d
	}
	// Step 1: Extract the text stream via FFmpeg
	vtt, err := extractSubtitlesFromContainer(ctx, videoPath, stream, durationUs)
	if err != nil {
		return "", err
	}
	slog.Info("Subs eextracted")
	// Step 2: Check if the file exhibits broken OTA broadcast timelines
	if needsOtaFix(vtt) {
		// Step 3: Run the forward-filling repair transformation logic in memory
		vtt = fixOtaWebVTT(vtt)
		slog.Info("subs fixed")
	}
	var lang string
	if configuredLanguage != "" {
		lang = configuredLanguage
	} else {
		lang, err = getSubtitleLanguage(ctx, videoPath, stream)
		slog.Info("lang fetched")
		if err != nil {
			return "", err
		}
	}
	slog.Info("Derived language", "shortname", m.ShortName, "id", m.Id, "inputNumber", number, "language", lang)
	return lang, os.WriteFile(v.Storage.SubtitlesRepresentationFilePath(inputID, lang), []byte(vtt), 0644)
}
