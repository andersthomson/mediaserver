package dasherworker

import (
	"fmt"
)

func scalingFilter(fromRel Resolution, fromSar float64, toRel Resolution) string {
	// 1. INPUT METADATA (Obtained from your earlier ffprobe scans)
	// For your PAL DVD source, these values are: 720, 576, and (64.0/45.0)
	srcWidth := float64(fromRel.Width)   // Replace with your dynamic parsed width variable
	srcHeight := float64(fromRel.Height) // Replace with your dynamic parsed height variable
	sar := fromSar                       // Replace with your dynamic parsed SAR ratio variable

	// Normalize to square pixels for display sizing
	displayWidth := srcWidth * sar
	displayHeight := srcHeight

	// 2. CALCULATE SCALE SCALEFACTOR
	scaleFactor := 1.0
	factorW := float64(toRel.Width) / displayWidth
	factorH := float64(toRel.Height) / displayHeight

	// If the video overshoots either boundary, pick the most aggressive shrink factor
	if factorW < 1.0 || factorH < 1.0 {
		if factorW < factorH {
			scaleFactor = factorW
		} else {
			scaleFactor = factorH
		}
	}

	// 3. GENERATE TARGET DIMENSIONS (Divisible by 2)
	targetWidth := int(displayWidth * scaleFactor)
	targetHeight := int(displayHeight * scaleFactor)

	// The clean bitwise rule to force values down to the nearest even number
	targetWidth = targetWidth &^ 1
	targetHeight = targetHeight &^ 1

	return fmt.Sprintf("scale=%d:%d,setsar=1", targetWidth, targetHeight)
}
