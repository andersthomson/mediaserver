package dasherworker

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/andersthomson/mediaserver/scrape"
	"github.com/pkg/errors"
	"go.temporal.io/sdk/workflow"
)

type LinkSrcMediaArgs struct {
	Streamno  int
	M         scrape.Msp
	Dir       string
	TargetDir string
}

func LinkSrcMediaMsp(ctx workflow.Context, args LinkSrcMediaArgs) (string, error) {
	slog.Info("1")
	inputNumber := args.M.Dash.Streams[args.Streamno].ReferenceFile
	oldFile := args.Dir + "/" + args.M.Inputs[inputNumber].Filename
	newFilename, err := DasherReadyFilename(args.Streamno, args.M)
	if err != nil {
		return "", errors.WithStack(err)
	}
	newFile := args.TargetDir + "/" + newFilename

	ctx1 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute,
		TaskQueue:           "dasherQueue",
		//HeartbeatTimeout:    1000 * time.Second,
	})
	err = workflow.ExecuteActivity(ctx1, LinkSrcMedia, oldFile, newFile).Get(ctx1, nil)
	return "", err
}

func LinkSrcMedia2(ctx workflow.Context, src, dst string) (string, error) {
	ctx1 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute,
		TaskQueue:           "dasherQueue",
	})
	err := workflow.ExecuteActivity(ctx1, LinkSrcMedia, src, dst).Get(ctx1, nil)
	return "", err
}
func LinkSrcMedia(ctx context.Context, oldname string, newname string) (string, error) {
	slog.Info("LinkSrcMedia/Creating symlink", "oldname", oldname, "newname", newname)
	if err := os.Symlink(oldname, newname); err != nil {
		return "", errors.WithStack(err)
	}
	return "", nil
}
