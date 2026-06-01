package dasherworker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

func dasherAction2(ctx context.Context, targetDir string) error {
	slog.Info("Start", "F", "dasherAction2", "targetDir", targetDir)
	defer slog.Info("Stop ", "F", "dasherAction2", "targetDir", targetDir)

	pattern := "*-encoded-?.mp4"
	matches, err := filepath.Glob(targetDir + "/" + pattern)
	if err != nil {
		return err
	}

	var inputs []string
	var codecs []string
	for _, match := range matches {
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

	gopMsFilename := filepath.Join(targetDir, "gopMs")
	gopMs, err := os.ReadFile(gopMsFilename)
	if err != nil {
		slog.Error("FAIL to read file", "F", "dasherAction2", "fname", gopMsFilename, "err", err)
		return fmt.Errorf("Failed to read gopMs file for targetDir %s: %+v", targetDir, err)
	}
	//args := []string{"-dash", strconv.FormatFloat(gopMs, 'f', 0, 64), "-rap", "-profile", "onDemand", "-out", "manifest.mpd"}
	args := []string{"-dash", string(gopMs), "-rap", "-profile", "onDemand", "-out", "manifest.mpd"}
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
	TargetDir string
	ProdDir   string
	Fast      bool
}

type FinalizeResp struct {
}

func Finalize(ctx context.Context, args FinalizeArgs) (FinalizeResp, error) {
	slog.Info("Start", "A", "Finalize", "ProdDir", args.ProdDir)
	defer slog.Info("Stop ", "A", "Finalize", "ProdDir", args.ProdDir)

	dasherAction2(ctx, args.TargetDir)

	pattern := "*-encoded-?.mp4"
	matches, err := filepath.Glob(args.TargetDir + "/" + pattern)
	if err != nil {
		return FinalizeResp{}, err
	}
	for _, dashFName := range matches {
		if err := replaceWithSymlink(strings.TrimSuffix(dashFName, ".mp4")+"_dashinit.mp4", filepath.Base(dashFName)); err != nil {
			return FinalizeResp{}, errors.WithStack(err)
		}
	}
	//fixAudioPresentationTimeOffset(args.TargetDir + "/" + "manifest.mpd")
	fixPresentationTimeOffsets2(args.TargetDir + "/" + "manifest.mpd")
	if args.Fast {
		if err := os.WriteFile(args.TargetDir+"/"+"dasher_fast=1", nil, 0644); err != nil {
			return FinalizeResp{}, errors.WithStack(err)
		}
	}

	tmpSuffix := uuid.NewString()
	if err := os.Symlink(filepath.Base(args.TargetDir), args.ProdDir+tmpSuffix); err != nil {
		return FinalizeResp{}, fmt.Errorf("Symlinking for production failed: %v", errors.WithStack(err))
	}
	if err := os.Rename(args.ProdDir+tmpSuffix, args.ProdDir); err != nil {
		return FinalizeResp{}, fmt.Errorf("Renaming to production failed: %v", errors.WithStack(err))
	}
	return FinalizeResp{}, nil
}
