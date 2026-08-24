package dasherworker

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/shared/throttledLogger"
	"github.com/creack/pty"
	"go.temporal.io/sdk/activity"
	"golang.org/x/time/rate"
)

type progressParser struct {
	ctx      context.Context
	re       *regexp.Regexp
	toRemote bool
	hostname string
	port     int
	fname    string
	logger   *throttledLogger.ThrottledLogger
}

func (p *progressParser) parseLine(line string, forceLogger bool) {
	// FindString will now safely inspect clean, isolated lines
	match := p.re.FindString(line)
	if match != "" {
		var dStr string
		if p.toRemote {
			dStr = "Local->Remote"
		} else {
			dStr = "Remote->Local"
		}
		str := fmt.Sprintf("%s %s %s completed", dStr, p.fname, match)
		if forceLogger {
			slog.Info("Rsync Heartbeat", "host", p.hostname, "port", p.port, "value", str)
		} else {
			p.logger.Info("Rsync Heartbeat", "host", p.hostname, "port", p.port, "value", str)
		}
		activity.RecordHeartbeat(p.ctx, str)
	}
}

// dropCRLF is a custom split function that splits on BOTH \n and \r
func dropCRLF(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	// Find either a newline or a carriage return
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		// We found a line termination character.
		// Return the data up to the character, and advance past it.
		return i + 1, data[:i], nil
	}

	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}

	// Request more data.
	return 0, nil, nil
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

	args := []string{
		"-avP", "--no-inc-recursive", "--mkpath", "--info=progress2", "--append-verify", "-e", "ssh -p " + strconv.Itoa(port) + " -T", src, dst}

	cmd := exec.CommandContext(ctx, "rsync", args...)
	f, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("rsync with %s failed: %+v", remoteAddr, err)
	}
	defer f.Close()

	slog.Info("rsync here", "args", args)

	pp := &progressParser{
		ctx:      ctx,
		re:       regexp.MustCompile(`\d+%`),
		toRemote: toRemote,
		fname:    filepath.Base(localPath),
		hostname: remoteHost,
		port:     port,
		logger:   throttledLogger.New(rate.Every(5*time.Second), 3),
	}

	// Initialize the scanner using the pseudo-terminal file descriptor
	scanner := bufio.NewScanner(f)
	scanner.Split(dropCRLF)

	// Read line-by-line concurrently
	go func() {
		for scanner.Scan() {
			pp.parseLine(scanner.Text(), false)
		}
	}()

	err = cmd.Wait()
	if err != nil {
		return Error("rsync execution failed", "err", err)
	}
	pp.parseLine("100%", true)
	return nil
}
