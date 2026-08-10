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
	"go.temporal.io/sdk/workflow"
)

func FinalizeWF(ctx workflow.Context, args FinalizeArgs) (FinalizeResp, error) {
	return CallActivityIO[FinalizeArgs, FinalizeResp](ctx, Finalize, args)
}

func CallFinalize(ctx workflow.Context, inputID string) error {
	_, err := CallActivityIO[FinalizeArgs, FinalizeResp](ctx, Finalize, FinalizeArgs{InputID: inputID})
	if err != nil {
		return Error("CallFinalizefailed", "err", err)
	}
	return nil
}

type FinalizeArgs struct {
	InputID string
}

type FinalizeResp struct {
	MP4BoxStdout string
	MP4BoxStderr string
}

func Finalize(ctx context.Context, args FinalizeArgs) (FinalizeResp, error) {
	slog.Info("Start", "A", "Finalize", "InputID", args.InputID)
	defer slog.Info("Stop ", "A", "Finalize", "InputID)", args.InputID)
	spew.Dump(args)

	targetDir := storage.ProdDir(args.InputID)
	//dir, msp := storage.ResolveInput(args.InputID)
	vStart, aStart := getVideoAndAudioStartTimes(ctx, args.InputID)

	pattern := "*.mp4"
	matches, err := filepath.Glob(targetDir + "/" + pattern)
	if err != nil {
		return FinalizeResp{}, Error("Failed to glob", "err", err)
	}

	var mp4BoxInputs []string
	var inputFiles []string
	var codecs []string
	var gopFrames int
	var fps float64

	for _, match := range matches {
		lang, err := GetStreamZeroLanguage(match)
		if err != nil {
			return FinalizeResp{}, Fatal("Failed to find language", "match", match, "err", err)
		}
		codec, err := GetStreamZeroCodec(match)
		if err != nil {
			return FinalizeResp{}, Fatal("Failed to find codec", "match", match, "err", err)
		}
		spew.Dump(codec)
		switch {
		case isVideoCodec(codec):
			props, err := GetSourceProperties(ctx, ProbeParams{
				Dir:      filepath.Dir(match),
				Filename: filepath.Base(match),
			})
			if err != nil {
				return FinalizeResp{}, Fatal("Failed to get properties", "file", match, "err", err)
			}
			if gopFrames != 0 && gopFrames != props.GopFrames {
				return FinalizeResp{}, Fatal("Got different gopFrames", "previous", gopFrames, "new", props.GopFrames)
			}
			gopFrames = props.GopFrames
			fps = props.Fps
			slog.Info("Setting gopFrames", "match", match, "gopFrames", gopFrames)
		}
		if idx := slices.Index(codecs, codec); idx == -1 {
			codecs = append(codecs, codec)
		}
		codecIdx := slices.Index(codecs, codec)
		if isVideoCodec(codec) {
			mp4BoxInputs = append(mp4BoxInputs, filepath.Base(match)+"#video"+":lang="+lang+":asID="+strconv.Itoa(codecIdx+1)+":delay="+fmt.Sprintf("%d", int(vStart*1000)))
		} else {
			mp4BoxInputs = append(mp4BoxInputs, filepath.Base(match)+"#audio"+":lang="+lang+":asID="+strconv.Itoa(codecIdx+1)+":delay="+fmt.Sprintf("%d", int(aStart*1000)))
		}

		inputFiles = append(inputFiles, filepath.Base(match))
	}
	if gopFrames == 0 {
		return FinalizeResp{}, Error("Failed to find a file with video", "matches", matches)
	}
	fpsI, err := FloatToInt(fps)
	if err != nil {
		return FinalizeResp{}, Error("File to put into mpd manifest has fractional fps", "fps", fps, "matches", matches)
	}
	spew.Dump(gopFrames)

	//args := []string{"-dash", strconv.FormatFloat(gopMs, 'f', 0, 64), "-rap", "-profile", "onDemand", "-out", "manifest.mpd"}
	boxArgs := []string{"-dash", dashMs2(gopFrames, fpsI), "-rap", "-flat", "-profile", "onDemand", "-out", "manifest.mpd"}
	boxArgs = append(boxArgs, mp4BoxInputs...)
	stdoutBuf, stderrBuf, err := MP4Box(ctx, targetDir, boxArgs)
	if err != nil {
		return FinalizeResp{
			MP4BoxStdout: stdoutBuf.String(),
			MP4BoxStderr: stderrBuf.String(),
		}, err
	}
	fixManifestBaseURLs(filepath.Join(targetDir, "manifest.mpd"))
	for _, in := range inputFiles {
		dName, err := dashName(in)
		if err != nil {
			return FinalizeResp{}, err
		}
		equal, err := fileSizesAreEqualAndNonZero(filepath.Join(targetDir, in), filepath.Join(targetDir, dName))
		if err != nil {
			return FinalizeResp{}, err
		}
		if !equal {
			return FinalizeResp{}, Error("Generated dash file not equal", "orig", in, "dash", dName)
		}
		if err := os.Remove(filepath.Join(targetDir, dName)); err != nil {
			return FinalizeResp{}, Error("os.Remove failed", "filename", filepath.Join(targetDir, dName), "err", err)
		}
	}
	return FinalizeResp{
		MP4BoxStdout: stdoutBuf.String(),
		MP4BoxStderr: stderrBuf.String(),
	}, nil
}

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

func getVideoAndAudioStartTimes(ctx context.Context, inputID string) (float64, float64) {
	dir, msp := storage.ResolveInput(inputID)
	videoSourceIdx := getFirstInputStreamWithPrefix(msp.Inputs, "v")
	vInput := msp.Inputs[videoSourceIdx]
	vStart, _ := GetStremStartTime(filepath.Join(dir, vInput.Filename), vInput.Stream)

	audioSourceIdx := getFirstInputStreamWithPrefix(msp.Inputs, "a")
	aInput := msp.Inputs[audioSourceIdx]
	aStart, _ := GetStremStartTime(filepath.Join(dir, aInput.Filename), aInput.Stream)

	return vStart, aStart
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
