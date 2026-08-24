package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/andersthomson/mediaserver/cmd/dasherworker/dasherworker"
	"github.com/andersthomson/mediaserver/scrape"
	"github.com/davecgh/go-spew/spew"
	"github.com/google/uuid"
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

	if len(os.Args) > 0 {
		switch os.Args[1] {
		case "properties":
			/*
				p, err := dasherworker.GetSourceProperties(context.Background(), dasherworker.ProbeParams{
					Dir:      filepath.Dir(os.Args[2]),
					Filename: filepath.Base(os.Args[2]),
				})
				if err != nil {
					fmt.Println(err)
				}
				spew.Dump(p)
			*/
			/*

				var srcProperties dasherworker.SrcProperties
					run, err := c.ExecuteWorkflow(context.Background(),
						client.StartWorkflowOptions{
							ID:        uuid.New().String(), // Unique ID for business logic
							TaskQueue: "dasherQueue",       // Which worker group should handle this
						},
						"GetSourcePropertiesWF",
						dasherworker.ProbeParams{
							Dir:      filepath.Dir(os.Args[2]),
							Filename: filepath.Base(os.Args[2]),
						})
					if err != nil {
						slog.Info("Couldn't start workflow", "err", err)
						return
					}
					if err := run.Get(context.Background(), &srcProperties); err != nil {
						slog.Info("Could not fetch result", "err", err)
						return
					}
					spew.Dump(srcProperties)
			*/
			return
		case "stat":
			stat()
			return
		case "splitmp4":
			_, err := dasherworker.TrySplitMp4ToTs(context.Background(), os.Args[2], os.Args[3])
			if err != nil {
				fmt.Printf("Fail: %v\n", err)
				return
			}
			fmt.Printf("Success\n")
			return
			/*
				case "keyframeHistogram":
					h, err := dasherworker.KeyframeHistogramFile(os.Args[2], os.Args[3])
					if err != nil {
						log.Fatalf("Error: %v\n", err)
					}
					fmt.Print("Keyframes  Occurences\n")
					for _, key := range slices.Sorted(maps.Keys(h)) {
						fmt.Printf("%d %d\n", key, h[key])
					}
					return*/
		case "HLSlinkSources":
			msp, err := scrape.ReadMspFromFile(os.Args[2])
			if err != nil {
				fmt.Printf("Fail: %v\n", err)
				return
			}

			run, err := c.ExecuteWorkflow(context.Background(),
				client.StartWorkflowOptions{
					ID:        uuid.New().String(), // Unique ID for business logic
					TaskQueue: "dasherQueue",       // Which worker group should handle this
				},
				"LinkHLSSourcesWF",
				msp,
				filepath.Dir(os.Args[2]),
			)
			if err != nil {
				slog.Info("Couldn't start workflow", "err", err)
				return
			}
			run.Get(context.Background(), nil)
			return
		case "ensuredash":
			run, err := c.ExecuteWorkflow(context.Background(),
				client.StartWorkflowOptions{
					ID:        uuid.New().String(), // Unique ID for business logic
					TaskQueue: "dasherQueue",       // Which worker group should handle this
				},
				//"EnsureDashWF",
				dasherworker.EnsureDashWF,
				dasherworker.EnsureDashWFArgs{
					MspPath: os.Args[2],
					Fast:    fast(),
				})
			if err != nil {
				slog.Info("Couldn't start workflow", "err", err)
				return
			}
			run.Get(context.Background(), nil)
			return
		case "representation":
			run, err := c.ExecuteWorkflow(context.Background(),
				client.StartWorkflowOptions{
					ID:        uuid.New().String(), // Unique ID for business logic
					TaskQueue: "dasherQueue",       // Which worker group should handle this
				},
				"CreateRepresentation",
				dasherworker.CreateRepresentationArgs{
					Dir:     filepath.Dir(os.Args[2]),
					MspFile: filepath.Base(os.Args[2]),
					Fast:    fast(),
				})
			if err != nil {
				slog.Info("Couldn't start workflow", "err", err)
				return
			}
			run.Get(context.Background(), nil)
			return
		case "storageadd":
			run, err := c.ExecuteWorkflow(context.Background(),
				client.StartWorkflowOptions{
					ID:        uuid.New().String(), // Unique ID for business logic
					TaskQueue: "dasherQueue",       // Which worker group should handle this
				},
				"StorageAddWF",
				os.Args[2])
			if err != nil {
				slog.Info("Couldn't start workflow", "err", err)
				return
			}
			run.Get(context.Background(), nil)
			return
			/*
				case "finalize":
					msp, err := scrape.ReadMspFromFile(os.Args[2])
					if err != nil {
						fmt.Printf("Fail: %v\n", err)
						return
					}

					run, err := c.ExecuteWorkflow(context.Background(),
						client.StartWorkflowOptions{
							ID:        uuid.New().String(), // Unique ID for business logic
							TaskQueue: "dasherQueue",       // Which worker group should handle this
						},
						"FinalizeWF",
						dasherworker.FinalizeArgs{
							InputID: msp.Id,
						})
					if err != nil {
						slog.Info("Couldn't start workflow", "err", err)
						return
					}
					run.Get(context.Background(), nil)
					return*/
		case "keyframes":
			// Local dry-run demonstration
			m3u8Input := os.Args[2]
			fmt.Println("Extracting absolute drift timeline points from 1080p manifest...")

			keyframeString, err := dasherworker.GetForcedKeyframeTimestamps(m3u8Input)
			if err != nil {
				fmt.Printf("Extraction failed: %v\n", err)
				return
			}

			fmt.Println("\n--- PASS THIS STRING TO YOUR 720P WORKER ---")
			//fmt.Println(keyframeString[:100] + "...") // Print preview snippet
			fmt.Println(keyframeString) // Print preview snippet
			return
		case "HLSBitrates":
			res, err := dasherworker.CalculateHLSBitrates(os.Args[2])
			if err != nil {
				fmt.Errorf("Failed: %v\n", err)
			}
			spew.Dump(res)
			return
		case "HLSRenderMaster":
			msp, err := scrape.ReadMspFromFile(os.Args[2])
			if err != nil {
				fmt.Printf("Fail: %v\n", err)
				return
			}

			run, err := c.ExecuteWorkflow(context.Background(),
				client.StartWorkflowOptions{
					ID:        uuid.New().String(), // Unique ID for business logic
					TaskQueue: "dasherQueue",       // Which worker group should handle this
				},
				"HLSRenderMasterWF",
				msp,
			)
			if err != nil {
				slog.Info("Couldn't start workflow", "err", err)
				return
			}
			run.Get(context.Background(), nil)
			fmt.Printf("Rendered master\n")
			return

		case "HLSmaster0":
			ctx := context.Background()

			// Build out your structured definition block matching your current storage folder array
			manifestPipelineConfig := dasherworker.HLSMasterConfig{
				/*
					AudioTracks: []dasherworker.AudioTrack{
						{GroupID: "audio-hevc", Name: "English", Language: "en", URI: "audio_en_hevc.m3u8", IsDefault: true},
						{GroupID: "audio-hevc", Name: "Français", Language: "fr", URI: "audio_fr_hevc.m3u8", IsDefault: false},
						{GroupID: "audio-avc", Name: "English", Language: "en", URI: "audio_en_avc.m3u8", IsDefault: true},
						{GroupID: "audio-avc", Name: "Français", Language: "fr", URI: "audio_fr_avc.m3u8", IsDefault: false},
					},
					SubtitleTracks: []dasherworker.SubtitleTrack{
						{GroupID: "subs", Name: "English", Language: "en", URI: "subs_en.m3u8", IsDefault: true},
						{GroupID: "subs", Name: "Français", Language: "fr", URI: "subs_fr.m3u8", IsDefault: false},
					},
					VideoVariants: []dasherworker.VideoVariant{
						// HEVC Stream-Copy & Transcode Ladder
						{Bandwidth: 3198000, AvgBitrate: 3000000, Resolution: "1920x1080", FrameRate: "25.000", Codecs: "hvc1.1.6.L120.90,mp4a.40.2", AudioGroup: "audio-hevc", SubsGroup: "subs", Playlist: "video_1080p_hevc.m3u8"},
						{Bandwidth: 1800000, AvgBitrate: 1600000, Resolution: "1280x720", FrameRate: "25.000", Codecs: "hvc1.1.6.L120.90,mp4a.40.2", AudioGroup: "audio-hevc", SubsGroup: "subs", Playlist: "video_720p_hevc.m3u8"},

						// H.264 Universal Fallback Transcode Ladder
						{Bandwidth: 4500000, AvgBitrate: 4000000, Resolution: "1920x1080", FrameRate: "25.000", Codecs: "avc1.640028,mp4a.40.2", AudioGroup: "audio-avc", SubsGroup: "subs", Playlist: "video_1080p_avc.m3u8"},
						{Bandwidth: 2200000, AvgBitrate: 2000000, Resolution: "1280x720", FrameRate: "25.000", Codecs: "avc1.4d401f,mp4a.40.2", AudioGroup: "audio-avc", SubsGroup: "subs", Playlist: "video_720p_avc.m3u8"},
					},
				*/
			}
			for _, f := range os.Args[2:] {
				x, err := dasherworker.AutomaticInspectPlaylist(ctx, f, "GROUPID", "FALLBACKLANG", true)
				if err != nil {
					fmt.Printf("Failed: %v\n", err)
					return
				}
				switch xT := x.(type) {
				case dasherworker.AudioTrack:
					xT.GroupID = "audio-group"
					manifestPipelineConfig.AudioTracks = append(manifestPipelineConfig.AudioTracks, xT)
				case dasherworker.SubtitleTrack:
					xT.GroupID = "subs-group"
					manifestPipelineConfig.SubtitleTracks = append(manifestPipelineConfig.SubtitleTracks, xT)
				case dasherworker.VideoVariant:
					xT.AudioGroup = "audio-group"
					manifestPipelineConfig.VideoVariants = append(manifestPipelineConfig.VideoVariants, xT)
				}
			}

			targetPath := "master.m3u8"
			fmt.Println("Initializing multi-codec, multi-language master manifest assembly...")

			err = dasherworker.ComposeAdvancedHLSMasterActivity(ctx, manifestPipelineConfig, targetPath)
			if err != nil {
				fmt.Printf("Composition failed: %v\n", err)
				return
			}

			fmt.Printf("Success! Production-ready master playlist compiled to: %s\n", targetPath)
			return

		}
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
