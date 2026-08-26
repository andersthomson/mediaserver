package vttstitch

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strconv"

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
	// 7. Marshal structural updates back into a formatted XML data array
	output, err := xml.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal updated manifest: %w", err)
	}

	// 8. Write the complete payload back to disk with valid XML headers
	finalPayload := append([]byte(xml.Header), output...)
	if err := os.WriteFile(outputPath, finalPayload, 0644); err != nil {
		return fmt.Errorf("failed to write updated manifest to disk: %w", err)
	}

	return nil
}

// Helper to provide a uint32 pointer for the ID field
func ptrUint32(v uint32) *uint32 { return &v }

// cleanISODurations replaces ISO 8601 strings with flat string decimal seconds (e.g., "3.840")
func cleanISODurations(xmlData []byte) []byte {
	// isoDurationRegex extracts Hours, Minutes, and Seconds from patterns like PT0H0M3.840S or PT2M15S
	var isoDurationRegex = regexp.MustCompile(`PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?`)

	// Find patterns like duration="PT0H0M3.840S" or mediaPresentationDuration="PT1H2M3S"
	attrRegex := regexp.MustCompile(`(Duration|Duration)="(PT[^"]+)"`)

	return attrRegex.ReplaceAllFunc(xmlData, func(match []byte) []byte {
		submatches := attrRegex.FindSubmatch(match)
		if len(submatches) < 3 {
			return match
		}
		attrName := submatches[1]
		isoStr := string(submatches[2])

		matches := isoDurationRegex.FindStringSubmatch(isoStr)
		if len(matches) == 0 {
			return match
		}

		var hours, minutes, seconds float64
		if matches[1] != "" {
			hours, _ = strconv.ParseFloat(matches[1], 64)
		}
		if matches[2] != "" {
			minutes, _ = strconv.ParseFloat(matches[2], 64)
		}
		if matches[3] != "" {
			seconds, _ = strconv.ParseFloat(matches[3], 64)
		}

		totalSeconds := (hours * 3600) + (minutes * 60) + seconds

		// Reconstruct as standard flat decimal string: duration="3.840"
		return []byte(fmt.Sprintf(`%s="%.3f"`, attrName, totalSeconds))
	})
}
