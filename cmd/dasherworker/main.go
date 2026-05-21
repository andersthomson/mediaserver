package main

import (
	"fmt"
	"log/slog"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker"
	"go.temporal.io/sdk/client"
	tworker "go.temporal.io/sdk/worker"
)

type silentLogger struct{}

func (l *silentLogger) Debug(msg string, kv ...interface{}) {}
func (l *silentLogger) Info(msg string, kv ...interface{})  {}
func (l *silentLogger) Warn(msg string, kv ...interface{})  {}
func (l *silentLogger) Error(msg string, kv ...interface{}) {}

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

	for _, rw := range conf.Remotes {
		if rw.Start {
			remoteEncodeWorker := tworker.New(c, "encodingQueue", tworker.Options{
				EnableSessionWorker:                true,
				Identity:                           "remote-" + rw.Hostname,
				MaxConcurrentActivityExecutionSize: 1,
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

			fmt.Printf("Starting remote worker for %s\n", rw.Hostname)
			go func() {
				if err := remoteEncodeWorker.Run(tworker.InterruptCh()); err != nil {
					panic(fmt.Sprintf("remoteEncoding worker failed", err))
				}
			}()
		}
	}
	if conf.Local.Start {
		we := tworker.New(c, "encodingQueue", tworker.Options{
			EnableSessionWorker:                true,
			Identity:                           "local-encoding",
			MaxConcurrentActivityExecutionSize: 1,
		})
		we.RegisterActivity(&dasherworker.LocalEncode{})
		fmt.Printf("Starting local worker\n")
		go func() {
			if err := we.Run(tworker.InterruptCh()); err != nil {
				panic(fmt.Sprintf("localEncoding worker failed", err))
			}
		}()
	}
	// Create a worker on a specific Task Queue
	w := tworker.New(c, "dasherQueue", tworker.Options{
		EnableSessionWorker:                true,
		Identity:                           "dasherQueueWorker",
		MaxConcurrentActivityExecutionSize: 10,
	})

	//w.RegisterWorkflow(dasherworker.Encode)
	w.RegisterWorkflow(dasherworker.AllEncodingWorkflow)
	w.RegisterActivity(&dasherworker.LocalEncode{})
	w.RegisterActivity(dasherworker.ReadMspFile)
	w.RegisterActivity(dasherworker.Prelude)
	w.RegisterActivity(dasherworker.LinkSrcMedia)
	w.RegisterActivity(dasherworker.MP4BoxDashReady)
	w.RegisterActivity(dasherworker.Finalize)
	w.RegisterActivity(dasherworker.AnalyzeMediaInterlace)
	w.RegisterActivity(dasherworker.GetVideoDurationUsec)

	// Run the worker (blocks until interrupted)
	err = w.Run(tworker.InterruptCh())
	if err != nil {
		slog.Error("Unable to start worker", "err", err)
	}
}
