package vttstitch

import (
	"context"
	"fmt"
	"os"

	mpd "github.com/Eyevinn/dash-mpd/mpd"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
)

type VttStitcher struct {
	Storage *storage.Storage
}

// StitchSubtitle injects an external WebVTT subtitle track into an existing DASH manifest
func (v *VttStitcher) Stitch(ctx context.Context, inputID string, languages []string) error {
	inputPath := v.Storage.AudioVideoManifestFilePath(inputID)
	outputPath := v.Storage.ManifestFilePath(inputID)

	// 1. Read the existing MP4Box VOD manifest file
	xmlData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input manifest: %w", err)
	}

	// 2. Parse into the strict ISO/IEC schema structure to preserve source tags
	manifest, err := mpd.ReadFromString(string(xmlData))
	if err != nil {
		return fmt.Errorf("failed to unmarshal manifest XML: %w", err)
	}

	// 3. Ensure the manifest contains at least one period block to attach to
	if len(manifest.Periods) == 0 {
		return fmt.Errorf("invalid manifest: zero periods found")
	}

	for idx, lang := range languages {
		// Create a clean adaptation set for subtitles mapping the XML Schema safely
		subtitleSet := mpd.AdaptationSetType{
			Id:                  ptrUint32(uint32(idx) + 1000), // ✅ Fixed: Expects *uint32 pointer token
			Lang:                lang,                          // ✅ Fixed: Expects pure string literal
			SubsegmentAlignment: true,                          // ✅ Fixed: Expects pure bool literal

			// ✅ Fixed: MimeType is nested inside the base type struct container
			RepresentationBaseType: mpd.RepresentationBaseType{
				MimeType: "text/vtt",
			},

			// ✅ Fixed: Plural slice allocation naming convention
			Representations: []*mpd.RepresentationType{
				{
					Id:        "sub_" + lang,
					Bandwidth: 256, // Subtitles require a minimal base bandwidth constraint

					// ✅ Fixed: Type descriptor is BaseURLType
					BaseURLs: []*mpd.BaseURLType{
						{
							Value: mpd.AnyURI("subtitles_" + lang + ".vtt"),
						},
					},
				},
			},
		}

		// 6. Append the new text track to the first Period block
		manifest.Periods[0].AdaptationSets = append(manifest.Periods[0].AdaptationSets, &subtitleSet)
	}
	// 7. Marshal structural updates back into file
	w, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer w.Close()

	if _, err := manifest.Write(w, "    ", true); err != nil {
		return err
	}
	w.Close()
	return nil
}

// Helper to provide a uint32 pointer for the ID field
func ptrUint32(v uint32) *uint32 { return &v }
