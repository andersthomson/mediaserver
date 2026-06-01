package dasherworker

import (
	"log/slog"
	"time"

	"go.temporal.io/sdk/workflow"
)

func CallActivityFast[IN, OUT any](ctx workflow.Context, activity any, args ...IN) (OUT, error) {
	return CallActivity[IN, OUT](ctx, activity, 1*time.Minute, args...)
}
func CallActivityIO[IN, OUT any](ctx workflow.Context, activity any, args ...IN) (OUT, error) {
	return CallActivity[IN, OUT](ctx, activity, 20*time.Minute, args...)
}

func CallActivity[IN, OUT any](ctx workflow.Context, activity any, startToCloseTimeout time.Duration, args ...IN) (OUT, error) {
	ctxA := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: startToCloseTimeout,
		TaskQueue:           "dasherQueue",
	})

	// Convert []IN to []any
	activityArgs := make([]any, len(args))
	for i, v := range args {
		activityArgs[i] = v
	}
	var out OUT
	err := workflow.ExecuteActivity(
		ctxA,
		activity,
		activityArgs...,
	).Get(ctx, &out)

	if err != nil {
		slog.Error("CallActivity failed", "activity", activity, "err", err.Error())
		var zero OUT
		return zero, err
	}
	//spew.Dump(out)
	return out, nil
}
