package finalize

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared"
	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
)

type FinalizeArgs struct {
	Ensure  bool
	InputID string
}

type FinalizeResp struct {
	DidExecute   bool
	MP4BoxStdout string
	MP4BoxStderr string
}

type Finalize struct {
	Storage *storage.Storage
}

func (f *Finalize) Finalize(ctx context.Context, args FinalizeArgs) (FinalizeResp, error) {
	slog.Info("Start", "A", "Finalize", "InputID", args.InputID)
	defer slog.Info("Stop ", "A", "Finalize", "InputID)", args.InputID)
	spew.Dump(args)

	targetDir := f.Storage.ProdDir(args.InputID)
	vStart, aStart := getVideoAndAudioStartTimes(ctx, f.Storage, args.InputID)

	pattern := "*.mp4"
	matches, err := filepath.Glob(targetDir + "/" + pattern)
	if err != nil {
		return FinalizeResp{}, shared.Error("Failed to glob", "err", err)
	}

	var mp4BoxInputs []string
	var inputFiles []string
	var codecs []string
	var gopFrames int
	var fps float64

	for _, match := range matches {
		lang, err := GetStreamZeroLanguage(match)
		if err != nil {
			return FinalizeResp{}, shared.Fatal("Failed to find language", "match", match, "err", err)
		}
		codec, err := GetStreamZeroCodec(match)
		if err != nil {
			return FinalizeResp{}, shared.Fatal("Failed to find codec", "match", match, "err", err)
		}
		spew.Dump(codec)
		switch {
		case shared.IsVideoCodec(codec):
			props, err := GetSourceProperties(ctx, ProbeParams{
				Dir:      filepath.Dir(match),
				Filename: filepath.Base(match),
			})
			if err != nil {
				return FinalizeResp{}, shared.Fatal("Failed to get properties", "file", match, "err", err)
			}
			if gopFrames != 0 && gopFrames != props.GopFrames {
				return FinalizeResp{}, shared.Fatal("Got different gopFrames", "previous", gopFrames, "new", props.GopFrames)
			}
			gopFrames = props.GopFrames
			fps = props.Fps
			slog.Info("Setting gopFrames", "match", match, "gopFrames", gopFrames)
		}
		if idx := slices.Index(codecs, codec); idx == -1 {
			codecs = append(codecs, codec)
		}
		codecIdx := slices.Index(codecs, codec)
		if shared.IsVideoCodec(codec) {
			mp4BoxInputs = append(mp4BoxInputs, filepath.Base(match)+"#video"+":lang="+lang+":asID="+strconv.Itoa(codecIdx+1)+":delay="+fmt.Sprintf("%d", int(vStart*1000)))
		} else {
			mp4BoxInputs = append(mp4BoxInputs, filepath.Base(match)+"#audio"+":lang="+lang+":asID="+strconv.Itoa(codecIdx+1)+":delay="+fmt.Sprintf("%d", int(aStart*1000)))
		}

		inputFiles = append(inputFiles, filepath.Base(match))
	}
	if gopFrames == 0 {
		return FinalizeResp{}, shared.Error("Failed to find a file with video", "matches", matches)
	}
	fpsI, err := floatToInt(fps)
	if err != nil {
		return FinalizeResp{}, shared.Error("File to put into mpd manifest has fractional fps", "fps", fps, "matches", matches)
	}
	spew.Dump(gopFrames)

	if args.Ensure {
		//If manifest newer than all referenced files, skip creating it
		mfinfo, err := os.Stat(filepath.Join(targetDir, "manifest.mpd"))
		if errors.Is(err, os.ErrNotExist) {
			goto proceed
		}
		if err != nil {
			return FinalizeResp{}, err
		}
		mTime := mfinfo.ModTime()
		for _, in := range inputFiles {
			f, err := os.Stat(filepath.Join(targetDir, in))
			if err != nil {
				return FinalizeResp{}, err
			}
			if mTime.Before(f.ModTime()) {
				slog.Info("Need manifest rebuild", "newer file", in)
				goto proceed
			}

		}
		//No need to process
		return FinalizeResp{}, nil
	}
proceed:
	//args := []string{"-dash", strconv.FormatFloat(gopMs, 'f', 0, 64), "-rap", "-profile", "onDemand", "-out", "manifest.mpd"}
	boxArgs := []string{"-dash", shared.DashMs2(gopFrames, fpsI), "-rap", "-flat", "-profile", "onDemand", "-out", "manifest.mpd"}
	boxArgs = append(boxArgs, mp4BoxInputs...)
	stdoutBuf, stderrBuf, err := common.MP4Box(ctx, targetDir, boxArgs)
	if err != nil {
		return FinalizeResp{
			DidExecute:   true,
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
			return FinalizeResp{}, shared.Error("Generated dash file not equal", "orig", in, "dash", dName)
		}
		if err := os.Remove(filepath.Join(targetDir, dName)); err != nil {
			return FinalizeResp{}, shared.Error("os.Remove failed", "filename", filepath.Join(targetDir, dName), "err", err)
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
		return GetOneTargetsPropertiesResp{}, shared.Error("Failed to glob", "pattern", targetDir+"/"+pattern, "err", err)
	}
	slog.Info("MATCHES", "found", matches)
	for _, match := range matches {
		codec, err := GetStreamZeroCodec(match)
		if err != nil {
			return GetOneTargetsPropertiesResp{}, shared.Error("Failed to find codec", "filePath", match, "err", err)
		}
		if shared.IsVideoCodec(codec) {
			props, err := GetSourceProperties(ctx, ProbeParams{
				Dir:      filepath.Dir(match),
				Filename: filepath.Base(match),
			})
			if err != nil {
				return GetOneTargetsPropertiesResp{}, shared.Error("Failed to get properties", "filePath", match, "err", err)
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
		return false, shared.Error("Stat failed", "err", err)
	}
	f2, err := os.Stat(filePath2)
	if err != nil {
		return false, shared.Error("Stat failed", "err", err)
	}
	if f1.Size() == 0 || f2.Size() == 0 {
		return false, shared.Error("At lease one file is zero size", "file1", filePath1, "file2", filePath2)
	}
	return f1.Size() == f2.Size(), nil
}

func dashName(fname string) (string, error) {
	base, ok := strings.CutSuffix(fname, ".mp4")
	if !ok {
		return "", shared.Error("InputFilename does not end in .mp4", "fname", fname)
	}
	return base + "_dashinit.mp4", nil
}

func getVideoAndAudioStartTimes(ctx context.Context, storage *storage.Storage, inputID string) (float64, float64) {
	dir, msp := storage.ResolveInput(inputID)
	videoSourceIdx := shared.GetFirstInputStreamWithPrefix(msp.Inputs, "v")
	vInput := msp.Inputs[videoSourceIdx]
	vStart, _ := GetStremStartTime(filepath.Join(dir, vInput.Filename), vInput.Stream)

	audioSourceIdx := shared.GetFirstInputStreamWithPrefix(msp.Inputs, "a")
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

// FloatToInt converts a whole number float64 to int.
func floatToInt(f float64) (int, error) {
	// 1. Check for NaN or Infinities (unusable float states)
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, errors.New("cannot convert NaN or Infinity to int")
	}

	// 2. Prevent Int Overflow / Underflow
	// On 64-bit systems, math.MaxInt is MaxInt64. On 32-bit, it is MaxInt32.
	if f > float64(math.MaxInt) || f < float64(math.MinInt) {
		return 0, fmt.Errorf("float value %f overflows integer boundaries", f)
	}

	// 3. Counteract Floating-Point Precision Drift
	// math.Round ensures 5.00000000001 or 4.99999999999 both snap cleanly to 5
	rounded := math.Round(f)

	// 4. Verify it was actually a whole number (Tolerance Check)
	// We check if the difference between the original and rounded value is negligible
	const epsilon = 1e-9
	if math.Abs(f-rounded) > epsilon {
		return 0, fmt.Errorf("float value %f contains fractional data and is not a whole number", f)
	}

	return int(rounded), nil
}
