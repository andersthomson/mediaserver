package dasherworker

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/pkg/errors"
	"go.temporal.io/sdk/workflow"
)

func LinkSrcMediaActivity(ctx workflow.Context, oldname, newname string) (string, error) {
	ctx1 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute,
		TaskQueue:           "dasherQueue",
	})
	return "", workflow.ExecuteActivity(ctx1, LinkSrcMedia, oldname, newname).Get(ctx1, nil)
}

func LinkSrcMedia(ctx context.Context, oldname string, newname string) (string, error) {
	slog.Info("LinkSrcMedia/Creating symlink", "oldname", oldname, "newname", newname)
	if err := os.Symlink(oldname, newname); err != nil {
		return "", errors.WithStack(err)
	}
	return "", nil
}
