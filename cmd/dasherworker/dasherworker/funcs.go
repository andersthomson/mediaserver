package dasherworker

import (
	"fmt"

	"github.com/andersthomson/mediaserver/scrape"
)

func DasherReadyFilename(streamno int, m scrape.Msp) (string, error) {
	fname, err := InputFName(streamno, m)
	if err != nil {
		return "", err
	}
	return fname + "-encoded-" + fmt.Sprintf("%d", streamno) + ".mp4", nil
}
