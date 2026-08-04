package dasherworker

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/creack/pty"
	"go.temporal.io/sdk/activity"
	"golang.org/x/time/rate"
)

type progressWriter struct {
	ctx      context.Context
	re       *regexp.Regexp
	toRemote bool
	hostname string
	port     int
	fname    string
	logger   *ThrottledLogger
}

func (w *progressWriter) Write(p []byte) (n int, err error) {
	str := string(p)
	//slog.Info("GOT", "string", str)

	// FindString looks for the first occurrence of digits followed by %
	// This is more resilient to the leading spaces rsync uses
	match := w.re.FindString(str)
	if match != "" {
		// match will be "7%"
		var dStr string
		if w.toRemote {
			dStr = "Local->Remote"
		} else {
			dStr = "Remote->Local"
		}
		str = fmt.Sprintf("%s %s %s completed", dStr, w.fname, match)
		w.logger.Info("Rsync Heartbeat", "host", w.hostname, "port", w.port, "value", str)
		activity.RecordHeartbeat(w.ctx, str)
	}
	return len(p), nil
}

func RsyncActivity(ctx context.Context, localPath, remotePath, remoteUser, remoteHost string, port int, toRemote bool) error {
	var src, dst string
	var remoteAddr string
	if remoteUser != "" {
		remoteAddr = fmt.Sprintf("%s@%s:%s", remoteUser, remoteHost, remotePath)
	} else {
		remoteAddr = fmt.Sprintf("%s:%s", remoteHost, remotePath)
	}

	if toRemote {
		src = localPath
		dst = remoteAddr
	} else {
		src = remoteAddr
		dst = localPath
	}

	// --info=progress2 is critical for the parser to see a single percentage line
	args := []string{
		"-avP", "--no-inc-recursive", "--mkpath", "--info=progress2", "--append-verify", "-e", "ssh -p " + strconv.Itoa(port) + " -T", src, dst}

	cmd := exec.CommandContext(ctx, "rsync", args...)
	f, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("rsync with %s failed: %+v", remoteAddr, err)
	}
	defer f.Close()

	slog.Info("rsync here", "args", args)
	pw := &progressWriter{
		ctx:      ctx,
		re:       regexp.MustCompile(`\d+%`),
		toRemote: toRemote,
		fname:    filepath.Base(localPath),
		hostname: remoteHost,
		port:     port,
		logger:   NewThrottledLogger(rate.Every(5*time.Second), 3),
	}

	// Connect stdout directly to our spy writer
	go func() {
		_, _ = io.Copy(pw, f)
	}()

	return cmd.Wait()

}
