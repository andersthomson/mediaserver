package ffmpegArgs

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
)

type FFMpegArgsPocessor struct {
	Storage *storage.Storage
}

func (f *FFMpegArgsPocessor) Process(ctx context.Context, s []shared.FFMpegArg) (shared.FFMpegArgs, error) {
	res := shared.FFMpegArgs{}
	res.Args = make([]string, len(s))
	for idx, x := range s {
		switch x.Kind {
		case shared.KindString:
			var str string
			if err := json.Unmarshal(x.Payload, &str); err != nil {
				return res, shared.Fatal("json unmarshal failed", "err", err)
			}
			res.Args[idx] = str
		case shared.KindTranscodedRepesentationFilePath:
			var v shared.TranscodedRepesentationFilePath
			if err := json.Unmarshal(x.Payload, &v); err != nil {
				return res, shared.Fatal("json unmarshal failed", "err", err)
			}
			p := f.Storage.TranscodedRepresentationFilePath(v.ESA)
			res.Args[idx] = filepath.Base(p)
		case shared.KindInputFilePath:
			var v shared.InputFilePath
			if err := json.Unmarshal(x.Payload, &v); err != nil {
				return res, shared.Fatal("json unmarshal failed", "err", err)
			}
			p := f.Storage.ResolveInputNumber(v.Id, v.Number)
			res.Args[idx] = filepath.Base(p)
		case shared.KindSubtitlesRepresentationFilePath:
			var v shared.SubtitlesRepresentationFilePath
			if err := json.Unmarshal(x.Payload, &v); err != nil {
				return res, shared.Fatal("json unmarshal failed", "err", err)
			}
			p := f.Storage.SubtitlesRepresentationFilePath(v.ESA.InputID, v.ESA.Language)
			res.Args[idx] = filepath.Base(p)
		default:
			slog.Error("unsupported FFMpegArgKind", "value", x.Kind)
		}
	}
	return res, nil
}
