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
	"regexp"
	"time"

	"github.com/creack/pty"
	"go.temporal.io/sdk/activity"
	"golang.org/x/time/rate"
)

type mp4BoxProgressWriter struct {
	ctx    context.Context
	re     *regexp.Regexp
	fname  string
	logger *ThrottledLogger
}

func (w *mp4BoxProgressWriter) Write(p []byte) (n int, err error) {
	str := string(p)
	//slog.Info("RAW", "string", str)
	// Captures the raw digits before a percentage sign (e.g., "50%")
	//match := w.re.FindString(str)
	// FindStringSubmatch returns an array: [0] is the full match, [1] is the captured digits
	matches := w.re.FindStringSubmatch(str)
	if len(matches) > 1 {
		// matches[1] isolates just the actual global percentage (e.g., "93")
		match := matches[1]

		statusStr := fmt.Sprintf("MP4Box processing %s: %s%% completed", w.fname, match)

		w.logger.Info("MP4Box Heartbeat", "file", w.fname, "value", statusStr)
		activity.RecordHeartbeat(w.ctx, statusStr)
	}
	/*
		if match != "" {
			statusStr := fmt.Sprintf("MP4Box processing %s: %s completed", w.fname, match)

			// Send throttled log and Temporal heartbeat
			w.logger.Info("MP4Box Heartbeat", "file", w.fname, "value", statusStr)
			activity.RecordHeartbeat(w.ctx, statusStr)
		}*/
	return len(p), nil
}

func MP4Box(ctx context.Context, dir string, args []string) error {
	slog.Info("MP4Box", "dir", dir, "args", args)
	cmd := exec.CommandContext(ctx, "/usr/bin/MP4Box", args...)
	cmd.Dir = dir
	//cmd.Stdout = os.Stdout
	//cmd.Stderr = os.Stderr

	f, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("failed to start MP4Box for %v: %+v", args, err)
	}

	pw := &mp4BoxProgressWriter{
		ctx: ctx,
		// Matches digits followed by optional spaces and a percent sign (e.g., "45%")
		//re:    regexp.MustCompile(`\d+\s*%`),
		re:    regexp.MustCompile(`MPD\s+[\d\.]+\s*s\s+(\d+)\s*%`),
		fname: filepath.Base("SOME-FILENAME"),
		// Adjust rate limiting to match your application's ThrottledLogger definition
		logger: NewThrottledLogger(rate.Every(3*time.Second), 1),
	}

	// Create a synchronization channel
	done := make(chan struct{})

	go func() {
		defer close(done)

		scanner := bufio.NewScanner(f)
		// Custom split function to handle carriage returns (\r) and newlines (\n) cleanly
		scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
			if atEOF && len(data) == 0 {
				return 0, nil, nil
			}
			if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
				return i + 1, data[0:i], nil
			}
			if atEOF {
				return len(data), data, nil
			}
			return 0, nil, nil
		})

		// Scanner safely extracts complete progress lines, eliminating partial regex matches
		for scanner.Scan() {
			// Pass the string to your progress writer logic safely
			_, _ = pw.Write(scanner.Bytes())
		}
	}()

	err = cmd.Wait()

	// Force close the PTY file descriptor now.
	f.Close()

	<-done // Wait for the background reader to process the last remaining bytes
	if err != nil {
		return fmt.Errorf("MP4Box failed: %v", err)
	}
	return nil
}

type MP4BoxDashReadyArgs struct {
	WorkDir    string
	InputFname string
	DrFname    string
	DashMs     string
}

type MP4BoxDashReadyResp struct {
	Stdout string
	Stderr string
}

func MP4BoxDashReady(ctx context.Context, args MP4BoxDashReadyArgs) (MP4BoxDashReadyResp, error) {
	drFname := args.DrFname

	outputFName := drFname + "-fragmented.mp4"

	boxArgs := []string{
		"-dash", args.DashMs,
		"-rap",
		"-profile",
		"onDemand",
		"-segment-name", outputFName + "-postDash.mp4",
		"-out", "manifest.mpd",
		outputFName}

	fmt.Printf("MP4Box dashing a stream.  %s becomes %s \n", outputFName, drFname)
	if err := MP4Box(ctx, args.WorkDir, boxArgs); err != nil {
		return MP4BoxDashReadyResp{}, err
	}

	//remove unneded files
	if err := os.Remove(args.WorkDir + "/" + outputFName); err != nil {
		return MP4BoxDashReadyResp{}, fmt.Errorf("Failed to remove %s: %v", args.WorkDir+"/"+outputFName, err)
	}
	if err := os.Remove(args.WorkDir + "/manifest.mpd"); err != nil {
		return MP4BoxDashReadyResp{}, fmt.Errorf("Failed to remove %s: %v", args.WorkDir+"/manifest.mpd", err)
	}
	if err := os.Rename(args.WorkDir+"/"+outputFName+"-postDash.mp4init.mp4", args.WorkDir+"/"+drFname); err != nil {
		return MP4BoxDashReadyResp{}, fmt.Errorf("Failed to rename %s %s:%v", args.WorkDir+"/"+outputFName+"-postDash.mp4init.mp4", args.WorkDir+"/"+drFname, err)
	}
	return MP4BoxDashReadyResp{}, nil
}
