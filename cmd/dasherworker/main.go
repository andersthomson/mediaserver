package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker"
	"go.temporal.io/sdk/client"
	tworker "go.temporal.io/sdk/worker"
)

type silentLogger struct{}

func (l *silentLogger) Debug(msg string, kv ...interface{}) {}
func (l *silentLogger) Info(msg string, kv ...interface{})  {}
func (l *silentLogger) Warn(msg string, kv ...interface{})  {}
func (l *silentLogger) Error(msg string, kv ...interface{}) {}

func createRemoteWorker(c client.Client, rw remoteworker) tworker.Worker {
	execSize := 1
	if rw.Concurrency > 0 {
		execSize = rw.Concurrency
	}
	remoteEncodeWorker := tworker.New(c, "encodingQueue", tworker.Options{
		EnableSessionWorker:                true,
		Identity:                           "remote-" + rw.Name,
		MaxConcurrentSessionExecutionSize:  execSize,
		MaxConcurrentActivityExecutionSize: execSize + 1,
	})

	re := &dasherworker.RemoteEncode{}
	if rw.Hostname == "" {
		panic(fmt.Sprintf("Hostname must be set: %+v", rw))
	} else {
		re.Hostname = rw.Hostname
	}
	if rw.Port != 0 {
		re.Port = rw.Port
	} else {
		re.Port = 22
	}
	if rw.Username != "" {
		re.Username = rw.Username
	}
	if rw.Dir != "" {
		re.Dir = rw.Dir
	} else {
		re.Dir = "dasherworker.d"
	}
	if rw.Ffmpeg != "" {
		re.Ffmpeg = rw.Ffmpeg
	} else {
		re.Ffmpeg = "ffmpeg"
	}
	remoteEncodeWorker.RegisterActivity(re)
	return remoteEncodeWorker
}

func main() {

	conf, err := ReadConfigFromFile("dasherworker.conf")
	if err != nil {
		panic(err)
	}
	// Connect to local server
	c, err := client.Dial(client.Options{
		HostPort: "127.0.0.1:7233",
		Logger:   &silentLogger{}, // This silences the SDK internal logs
	})
	if err != nil {
		slog.Error("Unable to create client", "err", err)
	}
	defer c.Close()

	if len(os.Args) > 1 {
		for _, rw := range conf.Remotes {
			if rw.Name == os.Args[1] {
				remoteEncodeWorker := createRemoteWorker(c, rw)
				fmt.Printf("Starting remote worker for %s\n", rw.Name)
				if err := remoteEncodeWorker.Run(tworker.InterruptCh()); err != nil {
					panic(fmt.Sprintf("remoteEncoding worker failed: %+v\n", err))
				}
				return
			}
		}
	}

	for _, rw := range conf.Remotes {
		if rw.Start {
			remoteEncodeWorker := createRemoteWorker(c, rw)
			fmt.Printf("Starting remote worker for %s\n", rw.Name)
			go func() {
				if err := remoteEncodeWorker.Run(tworker.InterruptCh()); err != nil {
					panic(fmt.Sprintf("remoteEncoding worker failed: %+v\n", err))
				}
			}()
		}
	}
	if conf.Local.Start {
		we := tworker.New(c, "encodingQueue", tworker.Options{
			EnableSessionWorker:                true,
			Identity:                           "local-encoding",
			MaxConcurrentSessionExecutionSize:  1,
			MaxConcurrentActivityExecutionSize: 1 + 1,
		})
		we.RegisterActivity(&dasherworker.LocalEncode{})
		fmt.Printf("Starting local worker\n")
		go func() {
			if err := we.Run(tworker.InterruptCh()); err != nil {
				panic(fmt.Sprintf("localEncoding worker failed: %+v\n", err))
			}
		}()
	}

	// Create a worker on a specific Task Queue
	w := tworker.New(c, "dasherQueue", tworker.Options{
		EnableSessionWorker:                    true,
		Identity:                               "dasherQueueWorker",
		MaxConcurrentWorkflowTaskExecutionSize: 6,
		MaxConcurrentActivityExecutionSize:     1,
	})

	w.RegisterWorkflow(dasherworker.EnsureDashWF)
	w.RegisterWorkflow(dasherworker.GetSourcePropertiesWF)
	w.RegisterWorkflow(dasherworker.LinkHLSSourcesWF)
	w.RegisterWorkflow(dasherworker.StorageAddWF)
	w.RegisterWorkflow(dasherworker.FinalizeWF)
	w.RegisterWorkflow(dasherworker.HLSRenderMasterWF)

	w.RegisterWorkflow(dasherworker.CreateRepresentation)

	w.RegisterActivity(&dasherworker.LocalEncode{})
	w.RegisterActivity(dasherworker.ReadMspFile)
	w.RegisterActivity(dasherworker.ResolveInput)
	w.RegisterActivity(dasherworker.GetMediaDurationUsec)
	w.RegisterActivity(dasherworker.GetSourcePropertiesActivity)
	w.RegisterActivity(dasherworker.LoadTranscodingOptions)
	w.RegisterActivity(dasherworker.GetStreamDimensions)
	w.RegisterActivity(dasherworker.LinkSrcMedia)
	w.RegisterActivity(dasherworker.MP4BoxDashReadyPrepare)
	w.RegisterActivity(dasherworker.MP4BoxDashReadyExecute)
	w.RegisterActivity(dasherworker.FileExists)
	w.RegisterActivity(dasherworker.GetOneTargetsProperties)
	w.RegisterActivity(dasherworker.KeyframeHistogram)
	w.RegisterActivity(dasherworker.Finalize)
	w.RegisterActivity(dasherworker.RecordTranscodingOptions)
	w.RegisterActivity(dasherworker.ExecuteProbes)

	w.RegisterActivity(dasherworker.HLSRenderMaster)
	w.RegisterActivity(dasherworker.GenerateHLSLanguageFileActivity)
	w.RegisterActivity(dasherworker.IsMpeg2VideoWithBrokenDTS)
	// Run the worker (blocks until interrupted)
	err = w.Run(tworker.InterruptCh())
	if err != nil {
		slog.Error("Unable to start worker", "err", err)
	}
}
