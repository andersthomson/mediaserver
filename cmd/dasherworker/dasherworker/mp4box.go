package dasherworker

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/pkg/errors"
)

type MP4BoxDashReadyArgs struct {
	WorkDir string
	P       EncodeParams
	DashMs  string
}

type MP4BoxDashReadyResp struct {
	Exitcode int
	Stdout   string
	Stderr   string
}

func MP4BoxDashReady(ctx context.Context, args MP4BoxDashReadyArgs) (MP4BoxDashReadyResp, error) {
	fname, err := InputFName(args.P.StreamNo, args.P.Msp)
	if err != nil {
		return MP4BoxDashReadyResp{}, err
	}

	drFname := DasherReadyFilename2(fname, strconv.Itoa(args.P.StreamNo))
	outputFName := drFname + "-fragmented.mp4"

	boxArgs := []string{
		"-dash", args.DashMs,
		"-rap",
		"-profile",
		"onDemand",
		"-segment-name", outputFName + "-postDash.mp4",
		"-out", "manifest.mpd",
		outputFName}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.Command("/usr/bin/MP4Box", boxArgs...)
	cmd.Dir = args.WorkDir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	fmt.Printf("MP4Box dashing a stream.  %s becomes %s \n", outputFName, drFname)
	fmt.Printf("Starting /usr/bin/MP4Box %v\n", boxArgs)
	err = cmd.Run()
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

	//remove unneded files
	if err := os.Remove(args.WorkDir + "/" + outputFName); err != nil {
		return MP4BoxDashReadyResp{}, errors.WithStack(err)
	}
	if err := os.Remove(args.WorkDir + "/manifest.mpd"); err != nil {
		return MP4BoxDashReadyResp{}, errors.WithStack(err)
	}
	if err := os.Rename(args.WorkDir+"/"+outputFName+"-postDash.mp4init.mp4", args.WorkDir+"/"+drFname); err != nil {
		return MP4BoxDashReadyResp{}, errors.WithStack(err)
	}
	return MP4BoxDashReadyResp{
		Stdout:   stdout.String(),
		Stderr:   stdout.String(),
		Exitcode: exitCode,
	}, nil
}
