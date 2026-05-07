package dasherworker

import (
	"context"
	"fmt"
	"math"
	"os"

	"github.com/andersthomson/mediaserver/scrape"
	"github.com/pkg/errors"
)

// FIXME remove!!!
var DirTimestamp string

func DashDir(m scrape.Msp) string {
	return "/var/cache/mediacache/" + m.ShortName + "-" + m.Id + "/dash." + DirTimestamp
}

type PreludeArgs struct {
	DashDir string
	Dir     string
	M       scrape.Msp
}

type PreludeResp struct {
	Tprops TargetProperties
}

func dashMs(p SrcProperties) float64 {
	diff := p.gopMilliSec / 1000
	return math.Max(1.0, math.Round(4.0/diff)) * diff * 1000
}

func Prelude(ctx context.Context, args PreludeArgs) (PreludeResp, error) {
	//Sanity check:
	var referenceFiles = map[int]bool{}
	var tprops TargetProperties
	for streamno, stream := range args.M.Dash.Streams {
		if stream.Codec == "reference" {
			referenceFiles[stream.ReferenceFile] = true
			//At least one output stream want to reference an input stream.
			//Check that the input's gop is sane
			switch {
			case isDashReadyVideo(args.Dir + "/" + args.M.Inputs[stream.ReferenceFile].Filename):
				props, err := GetSourcePropertiesActivity(context.Background(), ProbeParams{args.M.Inputs[stream.ReferenceFile].Filename, args.Dir})
				if err != nil {
					return PreludeResp{}, errors.WithStack(err)
				}
				if props.gopMilliSec < 1500 || props.gopMilliSec > 5000 {
					return PreludeResp{}, fmt.Errorf("Source %d, which you want to have referenced, has an unsupported gop %f\n", streamno, props.gopMilliSec)
				}
				tprops.GopFrames = props.gopFrames
				tprops.DashMs = dashMs(props)
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
	if err := os.MkdirAll(args.DashDir, os.ModePerm); err != nil {
		return PreludeResp{}, errors.WithStack(fmt.Errorf("XYZ %+v: %s", err, args.DashDir))
	}
	return PreludeResp{
		Tprops: tprops,
	}, nil
}
