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
		MaxConcurrentActivityExecutionSize: 1,
	})
	encodeWorker.RegisterActivity(dasherworker.FfmpegEncode)

	go func() {
		if err := encodeWorker.Run(worker.InterruptCh()); err != nil {
			log.Fatalln("Encoding worker failed", err)
		}
	}()

	// Create a worker on a specific Task Queue
	w := worker.New(c, "dasherQueue", worker.Options{})

	w.RegisterWorkflow(dasherworker.EncodingWorkflow)

	w.RegisterActivity(dasherworker.GetVideoDurationUsec)

	// Run the worker (blocks until interrupted)
	err = w.Run(worker.InterruptCh())
	if err != nil {
		log.Fatalln("Unable to start worker", err)
	}
}
