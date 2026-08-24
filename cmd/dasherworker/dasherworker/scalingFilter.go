package dasherworker

import (
	"fmt"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
)

func scalingFilter(fromRel shared.Resolution, fromSar float64, toRel shared.Resolution) string {
	srcWidth := float64(fromRel.Width)
	srcHeight := float64(fromRel.Height)
	sar := fromSar

	// 1. NORMALIZE TO SQUARE PIXELS FOR DISPLAY SIZING
	displayWidth := srcWidth * sar
	displayHeight := srcHeight

	// 2. CALCULATE SCALE FACTORS FOR BOTH DIMENSIONS
	factorW := float64(toRel.Width) / displayWidth
	factorH := float64(toRel.Height) / displayHeight

	// Always pick the smaller factor to ensure the video fits entirely inside the box
	scaleFactor := factorW
	if factorH < factorW {
		scaleFactor = factorH
	}

	// CONDITIONAL: ONLY downscale. If the video is smaller than the box, do not upscale it.
	if scaleFactor > 1.0 {
		scaleFactor = 1.0
	}

	// 3. GENERATE TARGET DIMENSIONS (Divisible by 2)
	targetWidth := int(displayWidth * scaleFactor)
	targetHeight := int(displayHeight * scaleFactor)

	// Force values down to the nearest even number for FFmpeg compatibility
	targetWidth = targetWidth &^ 1
	targetHeight = targetHeight &^ 1

	return fmt.Sprintf("scale=%d:%d,setsar=1", targetWidth, targetHeight)
}
