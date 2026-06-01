package dasherworker

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/andersthomson/mediaserver/scrape"
	"go.temporal.io/sdk/workflow"
)

func HLSRenderMaster(ctx context.Context, m scrape.Msp) (string, error) {
	slog.Info("THERE")
	prodDir := HLSProdDir(m)
	m3u8Matches, err := filepath.Glob(filepath.Join(prodDir, "*.m3u8"))
	if err != nil {
		return "", err
	}
	master := HLSMasterConfig{}
	for _, f := range m3u8Matches {
		if filepath.Base(f) == "master.m3u8" {
			continue
		}
		x, err := AutomaticInspectPlaylist(ctx, f, "GROUPID", "FALLBACKLANG", true)
		if err != nil {
			fmt.Printf("Failed: %v\n", err)
			return "", err
		}
		switch xT := x.(type) {
		case AudioTrack:
			xT.GroupID = "audio-group"
			master.AudioTracks = append(master.AudioTracks, xT)
		case SubtitleTrack:
			xT.GroupID = "subs-group"
			master.SubtitleTracks = append(master.SubtitleTracks, xT)
		case VideoVariant:
			xT.AudioGroup = "audio-group"
			master.VideoVariants = append(master.VideoVariants, xT)
		}
	}

	targetPath := filepath.Join(prodDir, "master.m3u8")
	slog.Info("Initializing multi-codec, multi-language master manifest assembly...")

	err = ComposeAdvancedHLSMasterActivity(ctx, master, targetPath)
	if err != nil {
		slog.Error("Composition failed", "err", err)
		return "", err
	}
	return "", nil

}

func HLSRenderMasterWF(ctx workflow.Context, m scrape.Msp) (string, error) {
	slog.Info("HERE")
	return CallActivityFast[scrape.Msp, string](ctx, HLSRenderMaster, m)
}
