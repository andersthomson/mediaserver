package dasherworker

import (
	"path/filepath"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/deinterlacer"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/durationDeriver"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/ffmpegArgs"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/finalize"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/getStreamDimensions"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/isBroken"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/keyframeHistogram"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/mp4boxDashReady"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/mspreader"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/transcodingOptionsRecorder"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
	"github.com/andersthomson/mediaserver/scrape"
	"go.temporal.io/sdk/workflow"
)

func CallReadMspFile(ctx workflow.Context, mspPath string) (scrape.Msp, error) {
	return CallActivityIO[string, scrape.Msp](ctx, mspreader.Read, filepath.Dir(mspPath), filepath.Base(mspPath))
}

func CallFinalize(ctx workflow.Context, inputID string, ensure bool) (finalize.FinalizeResp, error) {
	var a *finalize.Finalize
	resp, err := CallActivityIO[finalize.FinalizeArgs, finalize.FinalizeResp](ctx, a.Finalize, finalize.FinalizeArgs{InputID: inputID, Ensure: ensure})
	if err != nil {
		return resp, shared.Error("CallFinalize failed", "err", err)
	}
	return resp, nil
}
func CallMP4BoxDashReadyPrepare(ctx workflow.Context, args shared.EncodeStreamArgs) (mp4boxDashReady.MP4BoxDashReadyArgs, error) {
	var a *mp4boxDashReady.MP4BoxDashReady
	return CallActivityIO[shared.EncodeStreamArgs, mp4boxDashReady.MP4BoxDashReadyArgs](ctx, a.MP4BoxDashReadyPrepare, args)
}

func CallMP4BoxDashReadyExecute(ctx workflow.Context, args mp4boxDashReady.MP4BoxDashReadyArgs) (mp4boxDashReady.MP4BoxDashReadyResp, error) {
	var a *mp4boxDashReady.MP4BoxDashReady
	return CallActivityIO[mp4boxDashReady.MP4BoxDashReadyArgs, mp4boxDashReady.MP4BoxDashReadyResp](ctx, a.MP4BoxDashReadyExecute, args)
}

func CallRecordTranscodingOptions(ctx workflow.Context, t transcodingOptionsRecorder.TranscodingOptionsRecord) error {
	var a *transcodingOptionsRecorder.TranscodingOptionsRecorder
	_, err := CallActivityFast[any, string](ctx, a.RecordTranscodingOptions, t)
	return err
}

func CallLoadTranscodingOptions(ctx workflow.Context, e shared.EncodeStreamArgs) (*transcodingOptionsRecorder.TranscodingOptionsRecord, error) {
	var a *transcodingOptionsRecorder.TranscodingOptionsRecorder
	return CallActivityFast[shared.EncodeStreamArgs, *transcodingOptionsRecorder.TranscodingOptionsRecord](ctx, a.LoadTranscodingOptions, e)
}

func CallFFMpegArgsProcessorProcess(ctx workflow.Context, s []shared.FFMpegArg) (shared.FFMpegArgs, error) {
	var a *ffmpegArgs.FFMpegArgsPocessor
	return CallActivityFast[[]shared.FFMpegArg, shared.FFMpegArgs](ctx, a.Process, s)
}
func CallDurationDeriverFfmpeg(ctx workflow.Context, inputID string, inputNo int, stream string) (int64, error) {
	var a *durationDeriver.DurationDeriver
	return CallActivityIO[any, int64](ctx, a.GetMediaDurationUsec, inputID, inputNo, stream)
}

func CallIsMpeg2VideoWithBrokenDTS(ctx workflow.Context, inputID string, inputNo int, stream string) (bool, error) {
	var a *isBroken.IsBroken
	return CallActivityIO[any, bool](ctx, a.IsMpeg2VideoWithBrokenDTS, inputID, inputNo, stream)
}

func CallKeyFrameHistogram(ctx workflow.Context, inputID string, inputNo int, stream string) (map[int]int, error) {
	var a *keyframeHistogram.KeyframeHistogram
	res, err := CallActivityIO[keyframeHistogram.KeyframeHistogramArgs, keyframeHistogram.KeyframeHistogramResp](ctx, a.KeyframeHistogram, keyframeHistogram.KeyframeHistogramArgs{
		InputID: inputID,
		InputNo: inputNo,
		Stream:  stream,
	})
	return res, err
}

func CallGetStreamDimensions(ctx workflow.Context, inputID string, inputNo int, stream string) (int, int, float64, error) {
	var a *getStreamDimensions.GSD
	sDim, err := CallActivityIO[getStreamDimensions.GetStreamDimensionsArgs, getStreamDimensions.StreamDimensions](ctx, a.GetStreamDimensions, getStreamDimensions.GetStreamDimensionsArgs{InputID: inputID, InputNo: inputNo, Stream: stream})
	return sDim.Width, sDim.Height, sDim.SAR, err
}

func CallExecuteProbes(ctx workflow.Context, inputID string, inputNo int, stream string) (deinterlacer.ProbeRawData, error) {
	var a *deinterlacer.Deinterlacer
	return CallActivityIO[any, deinterlacer.ProbeRawData](ctx, a.ExecuteProbes, inputID, inputNo, stream)
}
