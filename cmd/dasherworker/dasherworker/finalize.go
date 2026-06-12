package dasherworker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/pkg/errors"
)

func dasherAction2(ctx context.Context, targetDir string) error {
	slog.Info("Start", "F", "dasherAction2", "targetDir", targetDir)
	defer slog.Info("Stop ", "F", "dasherAction2", "targetDir", targetDir)

	pattern := "*.mp4"
	matches, err := filepath.Glob(targetDir + "/" + pattern)
	if err != nil {
		return err
	}

	var inputs []string
	var codecs []string
	var gopMs float64

	for _, match := range matches {
		props, err := GetSourceProperties(ctx, ProbeParams{
			Dir:      filepath.Dir(match),
			Filename: filepath.Base(match),
		})
		if err != nil {
			slog.Error("Failed to get properties", "file", match, "err", err)
			return err
		}
		if gopMs != 0 && gopMs != props.GopMilliSec {
			slog.Error("Got different gopMs", "previous", gopMs, "new", props.GopMilliSec)
			return errors.New("Different gops")
		}
		gopMs = props.GopMilliSec

		codec, err := GetStreamZeroCodec(match)
		if err != nil {
			return fmt.Errorf("Failed to find codec for %s: %v", match, err)
		}
		if idx := slices.Index(codecs, codec); idx == -1 {
			codecs = append(codecs, codec)
		}
		codecIdx := slices.Index(codecs, codec)
		inputs = append(inputs, filepath.Base(match)+":asID="+strconv.Itoa(codecIdx+1))
	}

	//args := []string{"-dash", strconv.FormatFloat(gopMs, 'f', 0, 64), "-rap", "-profile", "onDemand", "-out", "manifest.mpd"}
	args := []string{"-dash", strconv.FormatFloat(gopMs, 'f', 0, 64), "-rap", "-profile", "onDemand", "-out", "manifest.mpd"}
	args = append(args, inputs...)
	return MP4Box(ctx, targetDir, args)
}

func replaceWithSymlink(src, target string) error {
	if err := os.Remove(src); err != nil {
		return errors.WithStack(err)
	}
	if err := os.Symlink(target, src); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type FinalizeArgs struct {
	InputID string
	Fast    bool
}

type FinalizeResp struct {
}

func Finalize(ctx context.Context, args FinalizeArgs) (FinalizeResp, error) {
	slog.Info("Start", "A", "Finalize", "InputID", args.InputID)
	defer slog.Info("Stop ", "A", "Finalize", "InputID)", args.InputID)

	dir := storage.ProdDir(args.InputID)
	dasherAction2(ctx, dir)

	/*
		pattern := "*.mp4"
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return FinalizeResp{}, err
		}
			for _, dashFName := range matches {
				if err := replaceWithSymlink(strings.TrimSuffix(dashFName, ".mp4")+"_dashinit.mp4", filepath.Base(dashFName)); err != nil {
					return FinalizeResp{}, errors.WithStack(err)
				}
			}*/
	//fixAudioPresentationTimeOffset(args.TargetDir + "/" + "manifest.mpd")
	/*
		fixPresentationTimeOffsets2(args.TargetDir + "/" + "manifest.mpd")
		if args.Fast {
			if err := os.WriteFile(args.TargetDir+"/"+"dasher_fast=1", nil, 0644); err != nil {
				return FinalizeResp{}, errors.WithStack(err)
			}
		}
	*/
	/*
		tmpSuffix := uuid.NewString()
		if err := os.Symlink(filepath.Base(args.TargetDir), args.ProdDir+tmpSuffix); err != nil {
			return FinalizeResp{}, fmt.Errorf("Symlinking for production failed: %v", errors.WithStack(err))
		}
		if err := os.Rename(args.ProdDir+tmpSuffix, args.ProdDir); err != nil {
			return FinalizeResp{}, fmt.Errorf("Renaming to production failed: %v", errors.WithStack(err))
		}
	*/
	return FinalizeResp{}, nil
}
