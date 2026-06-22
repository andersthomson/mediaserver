package dasherworker

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/andersthomson/mediaserver/scrape"
	"github.com/pkg/errors"
)

type PreludeArgs struct {
	DashDir string
	Dir     string
	M       scrape.Msp
}

type PreludeResp struct {
	Tprops CommonProperties
}

func XPrelude(ctx context.Context, args PreludeArgs) (PreludeResp, error) {
	slog.Info("Start", "A", "Prelude")
	defer slog.Info("Stop ", "A", "Prelude")
	//Sanity check:
	var referenceFiles = map[int]bool{}
	var tprops CommonProperties
	for streamno, stream := range args.M.Dash.Streams {
		if stream.Codec == "reference" {
			referenceFiles[stream.ReferenceFile] = true
			//At least one output stream want to reference an input stream.
			//Check that the input's gop is sane
			switch {
			case isDashReadyVideo(args.Dir + "/" + args.M.Inputs[stream.ReferenceFile].Filename):
				props, err := GetSourceProperties(context.Background(), ProbeParams{args.M.Inputs[stream.ReferenceFile].Filename, args.Dir})
				if err != nil {
					return PreludeResp{}, errors.WithStack(err)
				}
				if props.GopMilliSec < 1500 || props.GopMilliSec > 5000 {
					return PreludeResp{}, fmt.Errorf("Source %d, which you want to have referenced, has an unsupported gop %f\n", streamno, props.GopMilliSec)
				}
				tprops.GopFrames = props.GopFrames
				tprops.DashMs = dashMs(props.GopMilliSec)
			case isDashReadyAudio(args.Dir + "/" + args.M.Inputs[stream.ReferenceFile].Filename):
			default:
				return PreludeResp{}, fmt.Errorf("Source %d, which you want to have referenced, is not dash ready\n", stream.ReferenceFile)
			}
		}
	}
	if tprops.GopFrames == 0 {
		tprops.GopFrames = 100
		tprops.DashMs = 4000
	}
	return PreludeResp{
		Tprops: tprops,
	}, nil
}
