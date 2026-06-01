package dasherworker

import (
	"context"
	"log/slog"
	"time"

	"github.com/davecgh/go-spew/spew"
	"go.temporal.io/sdk/workflow"
)

func GetSourcePropertiesWF(ctx workflow.Context, params ProbeParams) (SrcProperties, error) {
	var srcProperties SrcProperties
	ctxA := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Minute * 50,
		TaskQueue:           "dasherQueue",
		HeartbeatTimeout:    3600 * time.Second,
	})

	err := workflow.ExecuteActivity(
		ctxA,
		GetSourcePropertiesActivity,
		params,
	).Get(ctx, &srcProperties)

	if err != nil {
		slog.Error("GetSourcePropertiesActivity failed", "err", err.Error())
		return SrcProperties{}, err
	}
	spew.Dump(srcProperties)
	return srcProperties, nil
}

func GetSourcePropertiesActivity(ctx context.Context, params ProbeParams) (SrcProperties, error) {
	x, y := GetSourceProperties(ctx, params)
	spew.Dump(x)
	spew.Dump(y)
	return x, y
}
