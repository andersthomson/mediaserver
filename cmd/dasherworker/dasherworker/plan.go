package dasherworker

type Target struct {
	AdaptationSets []any
	Postprocessing any
}

type VideoAdaptationSet struct {
	Representations []VideoRepresentation
}

type VideoRepresentation struct {
	referenceFile *string
	ffmpegSource  string
	Language      string
	Kind          string
}

type AudioAdaptationSet struct {
	Representations []AudioRepresentation
}

type AudioRepresentation struct {
	referenceFile *string
	ffmpegSource  string
	Language      string
}

type SubtitlesRepresentation struct {
}
