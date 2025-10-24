package main

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/andersthomson/mediaserver/datasource"
	"github.com/andersthomson/mediaserver/scrape"
	"github.com/s3rj1k/go-fanotify/fanotify"
	"golang.org/x/sys/unix"
)

type faNotifyDirectoryRepo struct {
	dsLck     sync.Mutex
	ds        map[string]datasource.DataSource //filname->datasource.DataSource
	dir       string
	recursive bool
}

func NewFaNotifyDirectoryRepo(dir string, recursive bool) *faNotifyDirectoryRepo {
	r := faNotifyDirectoryRepo{
		dir:       dir,
		recursive: recursive,
	}
	r.ds = make(map[string]datasource.DataSource, 64)
	return &r
}
func (d *faNotifyDirectoryRepo) AllDataSources() []datasource.DataSource {
	var r []datasource.DataSource
	d.dsLck.Lock()
	r = slices.Collect(maps.Values(d.ds))
	d.dsLck.Unlock()
	if r == nil {
		return []datasource.DataSource{}
	}
	return r
}
func (f *faNotifyDirectoryRepo) Refresh() {
	notify, err := fanotify.Initialize(
		unix.FAN_CLOEXEC|
			unix.FAN_REPORT_DFID_NAME|
			unix.FAN_CLASS_NOTIF,
		os.O_RDONLY|
			unix.O_LARGEFILE|
			unix.O_CLOEXEC,
	)
	if err != nil {
		//time.Sleep(64 * time.Second)
		panic(fmt.Sprintf("XXX %s %v\n", f.dir, err))
	}
	//fmt.Printf("NEW FANOTIFY INSTANCE %s\n", f.dir)

	if err = notify.Mark(
		unix.FAN_MARK_ADD,
		unix.FAN_ACCESS|
			unix.FAN_MODIFY|
			unix.FAN_ATTRIB|
			unix.FAN_CLOSE_WRITE|
			unix.FAN_CLOSE_NOWRITE|
			unix.FAN_OPEN|
			unix.FAN_MOVED_FROM|
			unix.FAN_MOVED_TO|
			unix.FAN_CREATE|
			unix.FAN_DELETE|
			unix.FAN_DELETE_SELF|
			unix.FAN_MOVE_SELF|
			unix.FAN_OPEN_EXEC|
			//unix.FAN_Q_OVERFLOW|
			//unix.FAN_FS_ERROR|
			unix.FAN_EVENT_ON_CHILD|
			unix.FAN_ONDIR|
			unix.FAN_RENAME,
		unix.AT_FDCWD,
		f.dir,
	); err != nil {
		logger.Error("fanotify Mark failed", "dir", f.dir, "error", err)
	}

	logger.Info("prepped", "dir", f.dir)
	go func() {
		for {
			//fmt.Printf("fanotify: %s Waiting\n", f.dir)
			//res, err := GetFANotifyEvent(notify, os.Getpid())
			res, err := GetFANotifyEvent(notify)
			if err != nil {
				panic(err)
				fmt.Printf("error: %v\n", err)
				return
			}
			//fmt.Printf("GOT %s\n", spew.Sdump(res))
			var efStr []string
			for _, ef := range res.EventInfo {
				efStr = append(efStr, fmt.Sprintf("%T/%v", ef, ef))
			}
			//slog.Info("fanotify", "dir", f.dir, "event", maskDump(res.Event.Mask), "eventInfo", efStr)
			switch {
			case res.Event.MatchMask(unix.FAN_ONDIR) && res.Event.MatchMask(unix.FAN_CREATE): //Create subdir
				if len(res.EventInfo) != 1 {
					logger.Info("faNotifyDirectoryRepo: unexpected DfidName length (!=1)", "res.DfidName", res.EventInfo)
					continue
				}
				eventInfo, ok := res.EventInfo[0].(FanotifyEventInfoDfidName)
				if !ok {
					logger.Error("Unexpected fanotify EventInfo for event", "Event", res)
					continue
				}
				fmt.Printf("fname: %s\n", eventInfo.Filename)
				dr := NewFaNotifyDirectoryRepo(filepath.Join(f.dir, eventInfo.Filename), f.recursive)
				dr.Refresh()
				allRepos.Add(dr)
			case res.Event.MatchMask(unix.FAN_ONDIR) && res.Event.MatchMask(unix.FAN_DELETE_SELF): //Delete monitored dir
				allRepos.Delete(f)
				return
			case res.Event.MatchMask(unix.FAN_CLOSE_WRITE): //A file with new content

				eventInfo, ok := res.EventInfo[0].(FanotifyEventInfoDfidName)
				if !ok {
					logger.Error("Unexpected fanotify EventInfo for event", "Event", res)
					continue
				}
				if filepath.Ext(eventInfo.Filename) == ".mp4" {
					logger.Info("fanotify", "event", "CLOSE_WRITE", "dir", f.dir, "file", eventInfo.Filename)
					ds := scrape.ScrapeFile(logger, f.dir, eventInfo.Filename)
					f.dsLck.Lock()
					f.ds[eventInfo.Filename] = ds
					f.dsLck.Unlock()
				}
			case res.Event.MatchMask(unix.FAN_MOVED_TO): //A file with new content
				eventInfo, ok := res.EventInfo[0].(FanotifyEventInfoDfidName)
				if !ok {
					logger.Error("Unexpected fanotify EventInfo for event", "Event", res)
					continue
				}
				if filepath.Ext(eventInfo.Filename) == ".mp4" {
					logger.Info("fanotify", "event", "MOVED_TO", "dir", f.dir, "file", eventInfo.Filename)
					ds := scrape.ScrapeFile(logger, f.dir, eventInfo.Filename)
					f.dsLck.Lock()
					f.ds[eventInfo.Filename] = ds
					f.dsLck.Unlock()
				}
			case res.Event.MatchMask(unix.FAN_MOVED_FROM): //A file removed
				eventInfo, ok := res.EventInfo[0].(FanotifyEventInfoDfidName)
				if !ok {
					logger.Error("Unexpected fanotify EventInfo for event", "Event", res)
					continue
				}
				if filepath.Ext(eventInfo.Filename) == ".mp4" {
					logger.Info("fanotify", "event", "MOVED_FROM", "dir", f.dir, "file", eventInfo.Filename)
					f.dsLck.Lock()
					delete(f.ds, eventInfo.Filename)
					f.dsLck.Unlock()
				}
			case res.Event.MatchMask(unix.FAN_DELETE): //File removal
				eventInfo, ok := res.EventInfo[0].(FanotifyEventInfoDfidName)
				if !ok {
					logger.Error("Unexpected fanotify EventInfo for event", "Event", res)
					continue
				}
				if filepath.Ext(eventInfo.Filename) == ".mp4" {
					logger.Info("fanotify", "event", "DELETE", "dir", f.dir, "file", eventInfo.Filename)
					f.dsLck.Lock()
					delete(f.ds, eventInfo.Filename)
					f.dsLck.Unlock()

				}
			default:
				//slog.Info("fanotify: Unhandled event", "dir", f.dir, "event", maskDump(res.Event.Mask), "eventInfo", efStr)
			}

		}
	}()
	//With that off to the background, lets poke each file such that the above is triggered
	//spew.Dump(f)
	go func() {
		entries, err := os.ReadDir(f.dir)
		if err != nil {
			panic(err)
			return
		}
		for _, e := range entries {
			if e.IsDir() && e.Name() != "." {
				longname := filepath.Join(f.dir, e.Name())
				err := unix.Access(longname, unix.R_OK)
				if err != nil {
					continue
				}
				//fmt.Printf("Trying %s\n", longname)
				dr := NewFaNotifyDirectoryRepo(longname, f.recursive)
				dr.Refresh()
				allRepos.Add(dr)
				//time.Sleep(20 * time.Second)
			} else {
				fname := e.Name()
				if IsMP4File(fname) {
					go func(fname string) {
						//spew.Dump(fname)
						ds := scrape.ScrapeFile(logger, f.dir, fname)
						f.dsLck.Lock()
						f.ds[fname] = ds
						f.dsLck.Unlock()
					}(fname)

				}
			}
		}
		if err = notify.Mark(
			unix.FAN_MARK_REMOVE,
			unix.FAN_CLOSE_NOWRITE,
			unix.AT_FDCWD,
			f.dir,
		); err != nil {
			panic(fmt.Sprintf("QWE %v\n", err))
		}
	}()

}
