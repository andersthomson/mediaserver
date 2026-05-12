package dasherworker

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"regexp"
	"strings"

	"github.com/creack/pty"
	"go.temporal.io/sdk/activity"
)

type progressWriter struct {
	ctx context.Context
	re  *regexp.Regexp
}

func (w *progressWriter) Write(p []byte) (n int, err error) {
	str := string(p)
	slog.Info("GOT", "string", str)

	// FindString looks for the first occurrence of digits followed by %
	// This is more resilient to the leading spaces rsync uses
	match := w.re.FindString(str)
	if match != "" {
		// match will be "7%" - strip the % to get just the number
		val := strings.TrimSuffix(match, "%")
		slog.Info("Rsync Heartbeat", "val", val)
		activity.RecordHeartbeat(w.ctx, val)
	}
	return len(p), nil
}

func RsyncActivity(ctx context.Context, localPath, remotePath, remoteUser, remoteHost string, toRemote bool) error {
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
		"-avzP", "--no-inc-recursive", "--mkpath", "--info=progress2", "--append-verify", "-e", "ssh -T", src, dst}

	cmd := exec.CommandContext(ctx, "rsync", args...)
	f, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("rsync with %s failed: %+v", remoteAddr, err)
	}
	defer f.Close()

	slog.Info("rsync here", "args", args)
	// In your activity:
	pw := &progressWriter{
		ctx: ctx,
		re:  regexp.MustCompile(`\d+%`),
	}

	// Connect stdout directly to our spy writer
	go func() {
		_, _ = io.Copy(pw, f)
	}()

	return cmd.Wait()

}
