package dasherworker

import (
	"context"
	"os"
)

func FileExists(ctx context.Context, fname string) (bool, error) {
	_, err := os.Stat(fname)
	return err == nil, nil
}
