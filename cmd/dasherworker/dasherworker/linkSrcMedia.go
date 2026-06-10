package dasherworker

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"go.temporal.io/sdk/workflow"
)

func CallLinkSrcMedia(ctx workflow.Context, oldname, newname string) (string, error) {
	ctx1 := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Minute,
		TaskQueue:           "dasherQueue",
	})
	return "", workflow.ExecuteActivity(ctx1, LinkSrcMedia, oldname, newname).Get(ctx1, nil)
}

func LinkSrcMedia(ctx context.Context, oldname string, newname string) (string, error) {
	slog.Info("LinkSrcMedia/Creating symlink", "oldname", oldname, "newname", newname)
	if err := os.Symlink(oldname, newname); err != nil {
		return "", fmt.Errorf("Failed to symlink oldname:%s newname:%s err:%v", oldname, newname, err)
	}
	return "", nil
}
