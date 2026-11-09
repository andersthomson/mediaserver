package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
)

// CustomEvent matches your exact user interface signature
type CustomEvent struct {
	Event string // Strictly "CREATE" (directories only), "CLOSE", or "REMOVE"
	Path  string // Full structural path
}

type WatcherThingy struct {
	epollFile  *os.File
	fd         int
	outChannel chan CustomEvent
	mu         sync.RWMutex
	wdToPath   map[int]string
	pathToWd   map[string]int
}

// NewWatcherThingy initializes the non-blocking native facility
func NewWatcherThingy(directories ...string) (*WatcherThingy, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("failed to init inotify: %w", err)
	}

	wt := &WatcherThingy{
		epollFile:  os.NewFile(uintptr(fd), "/dev/inotify"),
		fd:         fd,
		outChannel: make(chan CustomEvent, 200),
		wdToPath:   make(map[int]string),
		pathToWd:   make(map[string]int),
	}

	for _, rootDir := range directories {
		cleanRoot := filepath.Clean(rootDir)
		if err := wt.addWatchRecursive(cleanRoot); err != nil {
			wt.Close()
			return nil, err
		}
	}

	go wt.readEventsLoop()

	return wt, nil
}

func (wt *WatcherThingy) Events() <-chan CustomEvent {
	return wt.outChannel
}

func (wt *WatcherThingy) Close() {
	wt.mu.Lock()
	defer wt.mu.Unlock()

	if wt.epollFile != nil {
		_ = wt.epollFile.Close()
		wt.epollFile = nil
	}
}

func (wt *WatcherThingy) addWatchRecursive(rootPath string) error {
	wt.mu.Lock()
	defer wt.mu.Unlock()

	//slog.Info("Watching", "rootPath", rootPath)
	return filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			return nil
		}

		if _, active := wt.pathToWd[path]; active {
			return nil
		}

		// Watch for creations, writes finalizing, and deletions/moves
		mask := uint32(syscall.IN_CREATE | syscall.IN_CLOSE_WRITE | syscall.IN_DELETE | syscall.IN_MOVED_FROM | syscall.IN_MOVED_TO)
		//slog.Info("inotifyWatch", "path", path)
		wd, err := syscall.InotifyAddWatch(wt.fd, path, mask)
		if err != nil {
			return nil
		}

		wt.wdToPath[wd] = path
		wt.pathToWd[path] = wd
		return nil
	})
}

func (wt *WatcherThingy) readEventsLoop() {
	defer close(wt.outChannel)

	buf := make([]byte, (syscall.SizeofInotifyEvent+syscall.NAME_MAX+1)*20)

	for {
		wt.mu.RLock()
		f := wt.epollFile
		wt.mu.RUnlock()
		if f == nil {
			return
		}

		n, err := f.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			continue
		}

		var offset uint32
		for offset < uint32(n) {
			if offset+syscall.SizeofInotifyEvent > uint32(n) {
				break
			}

			eventBuf := buf[offset : offset+syscall.SizeofInotifyEvent]
			reader := bytes.NewReader(eventBuf)

			var rawEvent syscall.InotifyEvent
			if err := binary.Read(reader, binary.LittleEndian, &rawEvent); err != nil {
				break // Corrupt data window
			}
			//spew.Dump(rawEvent)
			nameLen := rawEvent.Len
			var name string
			if nameLen > 0 {
				nameBytes := buf[offset+syscall.SizeofInotifyEvent : offset+syscall.SizeofInotifyEvent+nameLen]
				if idx := bytes.IndexByte(nameBytes, 0); idx >= 0 {
					name = string(nameBytes[:idx])
				}
			}

			wt.evaluateInotifyEvent(rawEvent.Wd, rawEvent.Mask, name)
			offset += syscall.SizeofInotifyEvent + nameLen
		}
	}
}

func (wt *WatcherThingy) evaluateInotifyEvent(wd int32, mask uint32, name string) {
	wt.mu.RLock()
	parentPath, exists := wt.wdToPath[int(wd)]
	wt.mu.RUnlock()
	if !exists {
		return
	}

	fullPath := filepath.Join(parentPath, name)
	slog.Info("Evaluating", "fullpath", fullPath, "name", name, "mask", mask)

	// 1. Dynamic Directory Sub-branch Generation
	if mask&uint32(syscall.IN_CREATE) != 0 {
		info, err := os.Stat(fullPath)
		if err == nil && info.IsDir() {
			_ = wt.addWatchRecursive(fullPath)
			wt.outChannel <- CustomEvent{Event: "CREATE", Path: fullPath}
			return
		}
	}

	// 2. FILE STABLE & READY: Triggers when local writing stops OR when an outside move drops IN
	if mask&uint32(syscall.IN_CLOSE_WRITE) != 0 || mask&uint32(syscall.IN_MOVED_TO) != 0 {
		info, err := os.Stat(fullPath)
		if err == nil && !info.IsDir() {
			//slog.Info("Added tochannel", "type", "CLOSE", "path", fullPath)
			wt.outChannel <- CustomEvent{Event: "CLOSE", Path: fullPath}
		}
		return
	}

	// 3. FILE GONE: Triggers when local file is deleted OR moved outside of watched pools
	if mask&uint32(syscall.IN_DELETE) != 0 || mask&uint32(syscall.IN_MOVED_FROM) != 0 {
		wt.mu.Lock()
		if targetWd, active := wt.pathToWd[fullPath]; active {
			_, _ = syscall.InotifyRmWatch(wt.fd, uint32(targetWd))
			delete(wt.wdToPath, targetWd)
			delete(wt.pathToWd, fullPath)
		}
		wt.mu.Unlock()

		wt.outChannel <- CustomEvent{Event: "REMOVE", Path: fullPath}
	}
}

func Xmain() {
	_ = os.MkdirAll("./media1", 0755)

	log.Println("Running direct status-only inotify engine...")
	Watcher, err := NewWatcherThingy("./media1")
	if err != nil {
		log.Fatalf("Setup failure: %v", err)
	}

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		log.Println("\nExiting daemon cleanly...")
		Watcher.Close()
	}()

	// YOUR EXACT SIMPLIFIED SPECIFICATION LOOP:
	for ev := range Watcher.Events() {
		fmt.Printf("Event %v, on path %v\n", ev.Event, ev.Path)
	}
}
