package vttextract

import (
	"strings"
	"testing"
)

func TestVttExtractor(t *testing.T) {
	// 1. Define the broken, illegal WebVTT data exactly as extracted from your OTA video file
	malformedInput := `WEBVTT

00:02.208 --> 00:02.208


00:02.368 --> 00:02.368
-sattes igång i dag. Det
experimentella kraftverket alstrar...

00:06.432 --> 00:06.432


00:06.752 --> 00:06.752
Nog om det. Bortsett från hennes
usla grammatik och teknik-

00:10.528 --> 00:10.528


00:10.816 --> 00:10.816
-så har den djärva Lois Lane rätt.`

	// 2. Execute validation test (Assert that the analyzer flags the file)
	t.Run("Check Malformed Detection", func(t *testing.T) {
		needsFix := needsOtaFix(malformedInput)
		if !needsFix {
			t.Errorf("Expected NeedsOtaFix to return true for corrupted OTA data, got false")
		}
	})

	// 3. Execute fixer execution test
	t.Run("Execute Transformation and Re-verify", func(t *testing.T) {
		fixedOutput := fixOtaWebVTT(malformedInput)

		// Assert that the newly generated file layout is clean and no longer flagged as broken
		stillNeedsFix := needsOtaFix(fixedOutput)
		if stillNeedsFix {
			t.Errorf("The output from FixOtaWebVTT is still being flagged as malformed by the analyzer")
		}

		// Assert that illegal zero-duration lines are fully stripped out of the string buffer
		if strings.Contains(fixedOutput, "00:02.208 --> 00:02.208") {
			t.Errorf("The zero-duration blank block 00:02.208 was not dropped from the stream")
		}

		// Assert that the valid Swedish text has its duration successfully forward-filled
		// (The end time must now match the start time of the upcoming text block)
		expectedTimeline := "00:02.368 --> 00:06.432"
		if !strings.Contains(fixedOutput, expectedTimeline) {
			t.Errorf("Expected timeline to be healed to %q, but it was missing from output:\n%s", expectedTimeline, fixedOutput)
		}

		// Print the final legal layout to the test results console for manual visual confirmation
		//	t.Logf("Pristine Compliant WebVTT Output Generation:\n%s", fixedOutput)
	})
}
