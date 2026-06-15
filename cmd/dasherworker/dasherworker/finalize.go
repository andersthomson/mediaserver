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

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
)

// Check *.mp4 video files and return first file's properties (or an error)
type GetOneTargetsPropertiesResp struct {
	Found bool
	Props SrcProperties
}

func GetOneTargetsProperties(ctx context.Context, targetDir string) (GetOneTargetsPropertiesResp, error) {
	pattern := "*.mp4"
	matches, err := filepath.Glob(targetDir + "/" + pattern)
	if err != nil {
		return GetOneTargetsPropertiesResp{}, Error("Failed to glob", "pattern", targetDir+"/"+pattern, "err", err)
	}
	slog.Info("MATCHES", "found", matches)
	for _, match := range matches {
		codec, err := GetStreamZeroCodec(match)
		if err != nil {
			return GetOneTargetsPropertiesResp{}, Error("Failed to find codec", "filePath", match, "err", err)
		}
		if isVideoCodec(codec) {
			props, err := GetSourceProperties(ctx, ProbeParams{
				Dir:      filepath.Dir(match),
				Filename: filepath.Base(match),
			})
			if err != nil {
				return GetOneTargetsPropertiesResp{}, Error("Failed to get properties", "filePath", match, "err", err)
			}
			return GetOneTargetsPropertiesResp{
				Found: true,
				Props: props,
			}, nil
		} else {
			slog.Info("NOt viDEO", "file", match)
		}
	}
	return GetOneTargetsPropertiesResp{
		Found: false,
		Props: SrcProperties{},
	}, nil
}
func fileSizesAreEqualAndNonZero(filePath1, filePath2 string) (bool, error) {
	f1, err := os.Stat(filePath1)
	if err != nil {
		return false, Error("Stat failed", "err", err)
	}
	f2, err := os.Stat(filePath2)
	if err != nil {
		return false, Error("Stat failed", "err", err)
	}
	if f1.Size() == 0 || f2.Size() == 0 {
		return false, Error("At lease one file is zero size", "file1", filePath1, "file2", filePath2)
	}
	return f1.Size() == f2.Size(), nil
}

func dashName(fname string) (string, error) {
	base, ok := strings.CutSuffix(fname, ".mp4")
	if !ok {
		return "", Error("InputFilename does not end in .mp4", "fname", fname)
	}
	return base + "_dashinit.mp4", nil
}

func dasherAction2(ctx context.Context, targetDir string) error {
	slog.Info("Start", "F", "dasherAction2", "targetDir", targetDir)
	defer slog.Info("Stop ", "F", "dasherAction2", "targetDir", targetDir)

	pattern := "*.mp4"
	matches, err := filepath.Glob(targetDir + "/" + pattern)
	if err != nil {
		return err
	}

	var mp4BoxInputs []string
	var inputFiles []string
	var codecs []string
	var gopMs float64

	for _, match := range matches {
		codec, err := GetStreamZeroCodec(match)
		if err != nil {
			return fmt.Errorf("Failed to find codec for %s: %v", match, err)
		}
		switch {
		case isVideoCodec(codec):
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
		}
		if idx := slices.Index(codecs, codec); idx == -1 {
			codecs = append(codecs, codec)
		}
		codecIdx := slices.Index(codecs, codec)
		mp4BoxInputs = append(mp4BoxInputs, filepath.Base(match)+":asID="+strconv.Itoa(codecIdx+1))
		inputFiles = append(inputFiles, filepath.Base(match))
	}

	//args := []string{"-dash", strconv.FormatFloat(gopMs, 'f', 0, 64), "-rap", "-profile", "onDemand", "-out", "manifest.mpd"}
	args := []string{"-dash", strconv.FormatFloat(gopMs, 'f', 0, 64), "-rap", "-profile", "onDemand", "-out", "manifest.mpd"}
	args = append(args, mp4BoxInputs...)
	if err := MP4Box(ctx, targetDir, args); err != nil {
		return err
	}
	fixManifestBaseURLs(filepath.Join(targetDir, "manifest.mpd"))
	for _, in := range inputFiles {
		dName, err := dashName(in)
		if err != nil {
			return err
		}
		equal, err := fileSizesAreEqualAndNonZero(filepath.Join(targetDir, in), filepath.Join(targetDir, dName))
		if err != nil {
			return err
		}
		if !equal {
			return Error("Generated dash file not equal", "orig", in, "dash", dName)
		}
		if err := os.Remove(filepath.Join(targetDir, dName)); err != nil {
			return Error("os.Remove failed", "filename", filepath.Join(targetDir, dName), "err", err)
		}
	}
	return nil
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
}

type FinalizeResp struct {
}

func Finalize(ctx context.Context, args FinalizeArgs) (FinalizeResp, error) {
	slog.Info("Start", "A", "Finalize", "InputID", args.InputID)
	defer slog.Info("Stop ", "A", "Finalize", "InputID)", args.InputID)

	dir := storage.ProdDir(args.InputID)
	spew.Dump(args)
	return FinalizeResp{}, dasherAction2(ctx, dir)
}
