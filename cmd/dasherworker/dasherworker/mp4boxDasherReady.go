package dasherworker

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type MP4BoxDashReadyArgs struct {
	EncodeArgs         EncodeStreamArgs
	TranscodedFilePath string
	ManifestFilePath   string
	DrFname            string
	DrFilePath         string
	DrDir              string
	WorkDir            string
	DashMs             string
	MP4BoxArgs         []string
}

type MP4BoxDashReadyResp struct {
	Stdout string
	Stderr string
}

func MP4BoxDashReady(ctx context.Context, args MP4BoxDashReadyArgs) (MP4BoxDashReadyResp, error) {

	slog.Info("MP4Box dashing stream", "filePath", args.TranscodedFilePath)
	stdoutBuf, stderrBuf, err := MP4Box(ctx, args.WorkDir, args.MP4BoxArgs)
	if err != nil {
		return MP4BoxDashReadyResp{}, err
	}

	//remove unneded files
	if err := os.Remove(args.TranscodedFilePath); err != nil {
		return MP4BoxDashReadyResp{}, Fatal("Failed to remove %s: %v", args.TranscodedFilePath, err)
	}
	if err := os.Remove(args.ManifestFilePath); err != nil {
		return MP4BoxDashReadyResp{}, Fatal("Failed to remove %s: %v", args.ManifestFilePath, err)
	}

	basename, ok := strings.CutSuffix(args.DrFname, ".mp4")
	if !ok {
		return MP4BoxDashReadyResp{}, Fatal("drFname MUST end in .mp4")
	}
	if err := os.Rename(filepath.Join(args.DrDir, basename+".mp4init.mp4"), args.DrFilePath); err != nil {
		return MP4BoxDashReadyResp{}, Fatal("Failed to rename %s %s:%v", filepath.Join(args.DrDir, basename+".mp4init.mp4"), args.DrFilePath, err)
	}
	return MP4BoxDashReadyResp{
		Stdout: stdoutBuf.String(),
		Stderr: stderrBuf.String(),
	}, nil
}
