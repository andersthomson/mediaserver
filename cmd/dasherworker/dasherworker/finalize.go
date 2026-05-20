package dasherworker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/andersthomson/mediaserver/scrape"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

func MP4Box(dir string, args []string) error {
	cmd := exec.Command("/usr/bin/MP4Box", args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func dasherAction2(targetDir string) error {
	slog.Info("Start", "F", "dasherAction2", "targetDir", targetDir)
	defer slog.Info("Stop ", "F", "dasherAction2", "targetDir", targetDir)

	pattern := "*-encoded-?.mp4"
	matches, err := filepath.Glob(targetDir + "/" + pattern)
	if err != nil {
		return err
	}

	var inputs []string
	for idx, match := range matches {
		inputs = append(inputs, filepath.Base(match)+":id="+strconv.Itoa(idx))
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
	return MP4Box(targetDir, args)
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
	M         scrape.Msp
	TargetDir string
	ProdDir   string
	Fast      bool
}

type FinalizeResp struct {
}

func Finalize(ctx context.Context, args FinalizeArgs) (FinalizeResp, error) {
	slog.Info("Start", "A", "Finalize", "ProdDir", args.ProdDir)
	defer slog.Info("Stop ", "A", "Finalize", "ProdDir", args.ProdDir)

	//dasherAction(args.M, args.DashMs, args.TargetDir)
	dasherAction2(args.TargetDir)

	pattern := "*-encoded-?.mp4"
	matches, err := filepath.Glob(args.TargetDir + "/" + pattern)
	if err != nil {
		return FinalizeResp{}, err
	}

	for _, dashFName := range matches {
		if err := replaceWithSymlink(args.TargetDir+"/"+strings.TrimSuffix(dashFName, ".mp4")+"_dashinit.mp4", dashFName); err != nil {
			return FinalizeResp{}, errors.WithStack(err)
		}
	}
	fixAudioPresentationTimeOffset(args.TargetDir + "/" + "manifest.mpd")
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
