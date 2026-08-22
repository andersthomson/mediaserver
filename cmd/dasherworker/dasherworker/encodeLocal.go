package dasherworker

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"go.temporal.io/sdk/activity"
	"golang.org/x/time/rate"
)

var _ Encoder = &LocalEncode{}

type LocalEncode struct {
}

// Gives the workdir for a local ffmpeg encode.
func (_ LocalEncode) workDir(sessionID string, ESA EncodeStreamArgs) string {
	p := storage.ProdDir(ESA.InputID)
	return filepath.Join(p, ".sessionID-"+sessionID)
}

func (l LocalEncode) makeWorkDir(sessionID string, ESA EncodeStreamArgs) string {
	wd := l.workDir(sessionID, ESA)
	if err := os.Mkdir(wd, 0755); err != nil {
		slog.Error("Failed to create ffmpeg working dir", "err", err)
	} else {
		slog.Info("Created ffmpeg workdir", "dir", wd)
	}
	return wd
}

func (l LocalEncode) inputSymlink(sessionID string, ESA EncodeStreamArgs, ffmpegargs FFMpegArgs) string {
	return filepath.Join(l.workDir(sessionID, ESA), filepath.Base(storage.ResolveInputNumber(ESA.InputID, ESA.InputNo)))
}

func (l *LocalEncode) EncodePrelude(ctx context.Context, args EncodePreludeArgs) (EncodePreludeResp, error) {
	slog.Info("Start", "A", "LocalEncode/Prelude", "inputFname", args.FfmpegArgs.InputFname)
	defer slog.Info("Stop ", "A", "LocalEncode/Prelude", "inputFname", args.FfmpegArgs.InputFname)
	//slog.Info("local/prelude", "args", args)
	slog.Info("local/prelude: symlinking input file")
	_ = l.makeWorkDir(args.SessionID, args.ESA)
	newName := l.inputSymlink(args.SessionID, args.ESA, args.FfmpegArgs)
	oldName := storage.ResolveInputNumber(args.ESA.InputID, args.ESA.InputNo)
	//oldName := filepath.Join(args.FfmpegArgs.InputDir, args.FfmpegArgs.InputFname)

	if err := os.Symlink(oldName, newName); err != nil {
		slog.Error("Failed to symlink input file", "oldname", oldName, "newname", newName, "err", err)
		return EncodePreludeResp{}, fmt.Errorf("Failed to symlink input file (%s): %s", args.FfmpegArgs.InputFname, err)
	}
	return EncodePreludeResp{
		FfmpegArgs: args.FfmpegArgs,
	}, nil
}
func (l *LocalEncode) Encode(ctx context.Context, args EncodeArgs) (EncodeResp, error) {
	slog.Info("Start", "A", "LocalEncode/Encode", "inputFname", args.FfmpegArgs.InputFname)
	defer slog.Info("Stop ", "A", "LocalEncode/Encode", "inputFname", args.FfmpegArgs.InputFname)
	slog.Info("local/Encode", "args", args)
	var resp EncodeResp

	// Create an extra pipe for progress only
	pr, pw, _ := os.Pipe()
	defer pr.Close()

	var newArgs []string
	if args.TotalDurationUs != 0 {
		newArgs = append(args.FfmpegArgs.Args, []string{"-progress", "pipe:3"}...)
	} else {
		newArgs = args.FfmpegArgs.Args
	}
	spew.Dump(newArgs)
	cmd := exec.CommandContext(ctx, "/usr/bin/ffmpeg", newArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.ExtraFiles = []*os.File{pw}
	cmd.Dir = l.workDir(args.SessionID, args.ESA)

	// 3. Start progress parser in background
	if args.TotalDurationUs != 0 {
		go func() {
			defer pw.Close() // Ensure the write-end closes so scanner finishes
			tlogger := NewThrottledLogger(rate.Every(5*time.Second), 3)
			scanner := bufio.NewScanner(pr)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "out_time_ms=") {
					parts := strings.Split(line, "=")
					if len(parts) == 2 {
						currentUs, _ := strconv.ParseInt(parts[1], 10, 64)
						percent := (float64(currentUs) / float64(args.TotalDurationUs)) * 100
						activity.RecordHeartbeat(ctx, fmt.Sprintf("%4.1f percent complete", percent))
						tlogger.Info("Progress", "F", "FfmpegLocalEncode", "workdir", l.workDir(args.SessionID, args.ESA), "percent", percent)
					}
				}
			}
		}()
	}

	// Run() starts the command and waits for it to finish
	err := cmd.Run()

	// 5. Handle Early Closure / Cancellation
	if ctx.Err() != nil {
		// Temporal canceled the context. cmd.Run() usually returns an error here.
		return resp, ctx.Err()
	}

	// Capture outputs
	resp.Stderr = stderr.String()
	if resp.Stderr != "" {
		slog.Error("LocalFFmpeg error", "stderr", resp.Stderr)
	}

	// Get Exit Code
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			// This happens if the command couldn't start at all (e.g., binary not found)
			exitCode = -1
		}
	} else {
		exitCode = cmd.ProcessState.ExitCode()
	}
	resp.Exitcode = exitCode
	return EncodeResp{}, err
}
func (l *LocalEncode) EncodePostlude(ctx context.Context, args EncodePostludeArgs) (EncodePostludeResp, error) {
	slog.Info("Start", "A", "LocalEncode/Postlude", "inputFname", args.FfmpegArgs.InputFname)
	defer slog.Info("Stop ", "A", "LocalEncode/Postlude", "inputFname", args.FfmpegArgs.InputFname)

	//slog.Info("local/postlude", "args", args)
	//slog.Info("local/postlude: removing input symlink")
	inputSymlink := l.inputSymlink(args.SessionID, args.ESA, args.FfmpegArgs)
	workDir := l.workDir(args.SessionID, args.ESA)
	targetOutputPath := storage.TranscodedRepresentationFilePath(args.ESA)
	outputPath := filepath.Join(workDir, filepath.Base(targetOutputPath))
	if err := os.Remove(inputSymlink); err != nil {
		return EncodePostludeResp{}, Error("Failed to remove symlink to input file", "file", inputSymlink, "err", err)
	}
	if err := os.Rename(outputPath, targetOutputPath); err != nil {
		return EncodePostludeResp{}, Error("Failed to rename ffmpeg result file into place", "outputPath", outputPath, "targetOutputPath", targetOutputPath, "err", err)
	}
	if err := os.Remove(workDir); err != nil {
		return EncodePostludeResp{}, Error("Failed to remove ffmpeg workdir", "workdir", workDir, "err", err)
	}
	return EncodePostludeResp{
		FfmpegArgs: args.FfmpegArgs,
	}, nil
}

type FfmpegEncodeArgs struct {
	Ffmpeg          string
	Args            []string
	Workdir         string
	TotalDurationUs int64
}

type FfmpegEncodeResp struct {
	Exitcode int
	Stdout   string
	Stderr   string
}
