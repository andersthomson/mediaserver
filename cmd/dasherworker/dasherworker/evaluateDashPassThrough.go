package dasherworker

import (
	"strings"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/deinterlacer"
)

// TranscodeReason maps explicit engineering flags to explain why pass-through failed.
type TranscodeReason string

const (
	ReasonUnsupportedCodec  TranscodeReason = "UNSUPPORTED_CODEC"
	ReasonInterlacedVideo   TranscodeReason = "INTERLACED_OR_TELECYNED_SOURCE"
	ReasonVariableFrameRate TranscodeReason = "VARIABLE_FRAME_RATE_VFR"
	ReasonVariableGOP       TranscodeReason = "NON_UNIFORM_KEYFRAME_INTERVAL"
	ReasonBadAlignment      TranscodeReason = "NON_ZERO_START_TIME"
	ReasonUnstableGeometry  TranscodeReason = "INVALID_GEOMETRY_OR_ASPECT_RATIO"
)

// EvaluateDashPassThrough evaluates the raw probe data to decide if an asset is instantly DASH-ready.
func EvaluateDashPassThrough(data deinterlacer.ProbeRawData) (bool, []TranscodeReason) {
	var reasons []TranscodeReason

	// 1. Validate Codec (Must be standard browser/MSE-friendly web formats)
	codec := strings.ToLower(strings.TrimSpace(data.CodecName))
	if codec != "h264" && codec != "hevc" && codec != "av1" && codec != "vp9" {
		reasons = append(reasons, ReasonUnsupportedCodec)
	}

	// 2. Validate Video Scan and Temporal Cadence (Must be purely progressive)
	// Checks both the container level header and the actual physical pixel layout counters.
	isInterlacedHeader := data.FieldOrder != "" && data.FieldOrder != "progressive" && data.FieldOrder != "unknown"
	hasInterlacedFrames := data.TffCount > 5 || data.BffCount > 5 // Tolerate up to 5 misidentified frames noise
	if isInterlacedHeader || hasInterlacedFrames {
		reasons = append(reasons, ReasonInterlacedVideo)
	}

	// 3. Validate Frame Rate Mode (Must be Constant Frame Rate)
	if !data.IsCFR {
		reasons = append(reasons, ReasonVariableFrameRate)
	}

	// 4. Validate GOP Architecture (Must have predictable, uniform keyframe cadence)
	if !data.HasFixedGOP || data.GOPSize <= 0 {
		reasons = append(reasons, ReasonVariableGOP)
	}

	// 5. Validate Track Alignment (Audio/Video must start closely aligned to 0.0)
	// Streams with significant initialization offsets drop packets or stall on chunk boundaries.
	if data.StartTime > 0.1 || data.StartTime < -0.1 {
		reasons = append(reasons, ReasonBadAlignment)
	}

	// 6. Validate Spatial Consistency
	if data.Width <= 0 || data.Height <= 0 || data.PAR == "" {
		reasons = append(reasons, ReasonUnstableGeometry)
	}

	// If any validation fails, it is not ready for pass-through and needs transcoding
	if len(reasons) > 0 {
		return false, reasons
	}

	return true, nil
}
