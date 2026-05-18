package dasherworker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/andersthomson/mediaserver/scrape"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

func dasherAction(m scrape.Msp, gopMs float64, targetDir string) error {
	fmt.Printf("dasherAction\n")
	var inputs []string
	for streamno, _ := range m.Dash.Streams {
		drFname, err := DasherReadyFilename(streamno, m)
		if err != nil {
			return errors.WithStack(err)
		}
		inputs = append(inputs, drFname+":id="+strconv.Itoa(streamno))
	}
	args := []string{"-dash", strconv.FormatFloat(gopMs, 'f', 0, 64), "-rap", "-profile", "onDemand", "-out", "manifest.mpd"}
	args = append(args, inputs...)
	slog.Info("dasherAction", "exec", "MP4Box", "args", args)
	cmd := exec.Command("/usr/bin/MP4Box", args...)
	cmd.Dir = targetDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
func replaceWithSymlink(src, target string) error {
	if err := os.Remove(src); err != nil {
		return errors.WithStack(err)
	}
	if err := os.Symlink(target, src); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type FinalizeArgs struct {
	M         scrape.Msp
	DashMs    float64
	TargetDir string
	ProdDir   string
	Fast      bool
}

type FinalizeResp struct {
}

func Finalize(ctx context.Context, args FinalizeArgs) (FinalizeResp, error) {

	dasherAction(args.M, args.DashMs, args.TargetDir)

	for streamno, _ := range args.M.Dash.Streams {
		dashFName, err := DasherReadyFilename(streamno, args.M)
		if err != nil {
			return FinalizeResp{}, errors.WithStack(err)
		}
		if err := replaceWithSymlink(args.TargetDir+"/"+strings.TrimSuffix(dashFName, ".mp4")+"_dashinit.mp4", dashFName); err != nil {
			return FinalizeResp{}, errors.WithStack(err)
		}
	}
	fixAudioPresentationTimeOffset(args.TargetDir + "/" + "manifest.mpd")
	if args.Fast {
		if err := os.WriteFile(args.TargetDir+"/"+"dasher_fast=1", nil, 0644); err != nil {
			return FinalizeResp{}, errors.WithStack(err)
		}
	}

	tmpSuffix := uuid.NewString()
	if err := os.Symlink(filepath.Base(args.TargetDir), args.ProdDir+tmpSuffix); err != nil {
		return FinalizeResp{}, fmt.Errorf("Symlinking for production failed: %v", errors.WithStack(err))
	}
	if err := os.Rename(args.ProdDir+tmpSuffix, args.ProdDir); err != nil {
		return FinalizeResp{}, fmt.Errorf("Renaming to production failed: %v", errors.WithStack(err))
	}
	return FinalizeResp{}, nil
}
