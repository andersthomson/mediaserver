package dasherworker

import (
	"context"
	"fmt"
	"os"

	"github.com/andersthomson/mediaserver/scrape"
	"github.com/pkg/errors"
)

type LinkSrcMediaArgs struct {
	Streamno  int
	M         scrape.Msp
	Dir       string
	TargetDir string
}

func LinkSrcMedia(ctx context.Context, args LinkSrcMediaArgs) (string, error) {
	//Get the source file
	inputNumber := args.M.Dash.Streams[args.Streamno].ReferenceFile
	srcFile := args.M.Inputs[inputNumber].Filename
	dstFile, err := DasherReadyFilename(args.Streamno, args.M)
	if err != nil {
		return "", errors.WithStack(err)
	}
	fmt.Printf("Creating symlink %s -> %s\n", args.TargetDir+"/"+dstFile, args.Dir+"/"+srcFile)
	if err := os.Symlink(args.Dir+"/"+srcFile, args.TargetDir+"/"+dstFile); err != nil {
		return "", errors.WithStack(err)
	}
	return "", nil
}
