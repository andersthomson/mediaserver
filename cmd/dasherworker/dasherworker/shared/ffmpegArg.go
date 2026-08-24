package shared

import "encoding/json"

type TranscodedRepesentationFilePath struct {
	ESA EncodeStreamArgs
}

type InputFilePath struct {
	Id     string
	Number int
}

type FFMpegArgKind string

const (
	KindString                          FFMpegArgKind = "STRING"
	KindTranscodedRepesentationFilePath FFMpegArgKind = "TranscodedRepesentationFilePath"
	KindInputFilePath                   FFMpegArgKind = "INPUTFILEPATH"
)

type FFMpegArg struct {
	Kind    FFMpegArgKind
	Payload json.RawMessage
}

func NewFFMpegArg(kind FFMpegArgKind, v any) FFMpegArg {
	bytes, _ := json.Marshal(v) // Pre-serialize so it traverses Temporal safely
	return FFMpegArg{Kind: kind, Payload: bytes}
}
