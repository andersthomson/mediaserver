package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/common/storage"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/deinterlacer"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/durationDeriver"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/ffmpegArgs"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/finalize"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/getStreamDimensions"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/isBroken"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/keyframeHistogram"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/localEncode"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/mp4boxDashReady"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/mspreader"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/remoteEncode"
	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker/activities/transcodingOptionsRecorder"
	"go.temporal.io/sdk/client"
	tworker "go.temporal.io/sdk/worker"
)

type silentLogger struct{}

func (l *silentLogger) Debug(msg string, kv ...interface{}) {}
func (l *silentLogger) Info(msg string, kv ...interface{})  {}
func (l *silentLogger) Warn(msg string, kv ...interface{})  {}
func (l *silentLogger) Error(msg string, kv ...interface{}) {}

func createRemoteWorker(c client.Client, rw remoteworker, storage *storage.Storage) tworker.Worker {
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

	re := &remoteEncode.RemoteEncode{Storage: storage}
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

	storage := storage.New()
	if len(os.Args) > 1 {
		for _, rw := range conf.Remotes {
			if rw.Name == os.Args[1] {
				remoteEncodeWorker := createRemoteWorker(c, rw, storage)
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
			remoteEncodeWorker := createRemoteWorker(c, rw, storage)
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
		we.RegisterActivity(&localEncode.LocalEncode{Storage: storage})
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
	//w.RegisterWorkflow(dasherworker.GetSourcePropertiesWF)
	//w.RegisterWorkflow(dasherworker.LinkHLSSourcesWF)
	//w.RegisterWorkflow(dasherworker.StorageAddWF)
	//w.RegisterWorkflow(dasherworker.FinalizeWF)
	w.RegisterWorkflow(dasherworker.HLSRenderMasterWF)

	w.RegisterWorkflow(dasherworker.CreateRepresentation)

	w.RegisterActivity(mspreader.Read)
	w.RegisterActivity(&localEncode.LocalEncode{Storage: storage})
	w.RegisterActivity(&deinterlacer.Deinterlacer{Storage: storage})
	w.RegisterActivity(&ffmpegArgs.FFMpegArgsPocessor{Storage: storage})
	w.RegisterActivity(&durationDeriver.DurationDeriver{Storage: storage})
	w.RegisterActivity(&finalize.Finalize{Storage: storage})
	w.RegisterActivity(&getStreamDimensions.GSD{Storage: storage})
	w.RegisterActivity(&isBroken.IsBroken{Storage: storage})
	w.RegisterActivity(&keyframeHistogram.KeyframeHistogram{Storage: storage})
	w.RegisterActivity(&mp4boxDashReady.MP4BoxDashReady{Storage: storage})
	w.RegisterActivity(&transcodingOptionsRecorder.TranscodingOptionsRecorder{Storage: storage})
	// Run the worker (blocks until interrupted)
	err = w.Run(tworker.InterruptCh())
	if err != nil {
		slog.Error("Unable to start worker", "err", err)
	}
}
