package dasherworker

import (
	"fmt"

	"github.com/andersthomson/mediaserver/scrape"
)

func XDasherReadyFilename(streamno int, m scrape.Msp) (string, error) {
	fname, err := InputFName(streamno, m)
	if err != nil {
		return "", err
	}
	return DasherReadyFilename2(fname, fmt.Sprintf("%d", streamno)), nil
}

func DasherReadyFilename2(basename, streamIdx string) string {
	return basename + "-encoded-" + streamIdx + ".mp4"
}
