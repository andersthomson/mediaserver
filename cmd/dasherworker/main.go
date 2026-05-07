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

	remoteEncodeWorker := worker.New(c, "encodingQueue", worker.Options{
		EnableSessionWorker:                true,
		Identity:                           "remote-encoding-worker-01",
		MaxConcurrentActivityExecutionSize: 1,
	})
	remoteEncodeWorker.RegisterActivity(&dasherworker.RemoteEncode{})
	go func() {
		if err := remoteEncodeWorker.Run(worker.InterruptCh()); err != nil {
			log.Fatalln("remoteEncoding worker failed", err)
		}
	}()

	encodeWorker := worker.New(c, "encodingQueue", worker.Options{
		EnableSessionWorker:                true,
		Identity:                           "local-encoding-worker-01",
		MaxConcurrentActivityExecutionSize: 1,
	})
	encodeWorker.RegisterActivity(&dasherworker.LocalEncode{})

	go func() {
		if err := encodeWorker.Run(worker.InterruptCh()); err != nil {
			log.Fatalln("Encoding worker failed", err)
		}
	}()

	// Create a worker on a specific Task Queue
	w := worker.New(c, "dasherQueue", worker.Options{
		Identity:                           "dasherQueueWorker",
		MaxConcurrentActivityExecutionSize: 10,
	})

	w.RegisterWorkflow(dasherworker.EncodingWorkflow)
	w.RegisterWorkflow(dasherworker.AllEncodingWorkflow)

	w.RegisterActivity(dasherworker.ReadMspFile)
	w.RegisterActivity(dasherworker.Prelude)
	w.RegisterActivity(dasherworker.LinkSrcMedia)
	w.RegisterActivity(dasherworker.MP4BoxDashReady)
	w.RegisterActivity(dasherworker.Finalize)
	w.RegisterActivity(dasherworker.AnalyzeMediaInterlace)
	w.RegisterActivity(dasherworker.GetVideoDurationUsec)

	// Run the worker (blocks until interrupted)
	err = w.Run(worker.InterruptCh())
	if err != nil {
		log.Fatalln("Unable to start worker", err)
	}
}
