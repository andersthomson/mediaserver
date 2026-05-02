package main

import (
	"log"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
) // Adjust to your module name

func main() {
	// Connect to local server
	c, err := client.Dial(client.Options{
		HostPort: "127.0.0.1:7233",
	})
	if err != nil {
		log.Fatalln("Unable to create client", err)
	}
	defer c.Close()

	encodeWorker := worker.New(c, "encodingQueue", worker.Options{
		Identity:                           "encoding-worker-01",
		MaxConcurrentActivityExecutionSize: 10,
	})
	encodeWorker.RegisterActivity(dasherworker.FfmpegEncode)
	encodeWorker.RegisterActivity(dasherworker.MP4BoxDashReady)

	go func() {
		if err := encodeWorker.Run(worker.InterruptCh()); err != nil {
			log.Fatalln("Encoding worker failed", err)
		}
	}()

	// Create a worker on a specific Task Queue
	w := worker.New(c, "dasherQueue", worker.Options{})

	w.RegisterWorkflow(dasherworker.EncodingWorkflow)
	w.RegisterWorkflow(dasherworker.AllEncodingWorkflow)

	w.RegisterActivity(dasherworker.LinkSrcMedia)
	w.RegisterActivity(dasherworker.Finalize)
	w.RegisterActivity(dasherworker.AnalyzeMediaInterlace)
	w.RegisterActivity(dasherworker.GetVideoDurationUsec)

	// Run the worker (blocks until interrupted)
	err = w.Run(worker.InterruptCh())
	if err != nil {
		log.Fatalln("Unable to start worker", err)
	}
}
