package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker"
	"go.temporal.io/sdk/client"
)

func main() {
	// Create the client once
	c, err := client.Dial(client.Options{
		HostPort: "localhost:7233",
	})
	if err != nil {
		panic(err)
	}
	defer c.Close()

	dir := filepath.Dir(os.Args[1])
	base := filepath.Base(os.Args[1])
	if base == "" || dir == "" {
		panic("Need as arg 1 path to msp file\n")
	}
	//if err := makeDashWorkFlow("/var/lib/media/temp/testfil", "flaskhals.msp"); err != nil {
	if err := makeDashWorkFlow(c, dir, base); err != nil {
		fmt.Printf("ERROR: %+v\n", err)
	} else {
		fmt.Printf("Done.\n")
	}
}

func LookupEnvCaseInsensitive(key string) (string, bool) {
	targetKey := strings.ToLower(key)

	// os.Environ() returns a slice of strings in the form "KEY=VALUE"
	for _, env := range os.Environ() {
		pair := strings.SplitN(env, "=", 2)
		if len(pair) < 2 {
			continue
		}

		if strings.ToLower(pair[0]) == targetKey {
			return pair[1], true
		}
	}

	return "", false
}

func fast() bool {
	_, ok := LookupEnvCaseInsensitive("dasher_fast")
	return ok
}

func EncodeStreamActivity(ctx context.Context, tc client.Client, p dasherworker.EncodeParams) (string, error) {
	// ExecuteWorkflow(ctx, options, workflowFunc, args...)

	return "", nil
}

func makeDashWorkFlow(tc client.Client, dir string, mspFile string) error {
	////////////////////////////////////////////// call here
	slog.Info("Starting wf")
	run, err := tc.ExecuteWorkflow(context.Background(),
		client.StartWorkflowOptions{
			ID: "EncodeMsp-" + filepath.Base(mspFile) + "-" + time.Now().String(), // Unique ID for business logic
			//ID:        "EncodeMsp-" + filepath.Base(mspFile), // Unique ID for business logic
			TaskQueue: "dasherQueue", // Which worker group should handle this
		},
		"AllEncodingWorkflow",
		dasherworker.AllEncodingWorkflowArgs{
			Dir:     dir,
			MspFile: mspFile,
			Fast:    fast(),
		})
	if err != nil {
		slog.Info("Couldn't start workflow", "err", err)
		return fmt.Errorf("Couldn't start workflow. %+v", err)
	}
	if err := run.Get(context.Background(), nil); err != nil {
		return err
	}
	//Build Dash
	return nil
}
