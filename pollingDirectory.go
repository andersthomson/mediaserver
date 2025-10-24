package main

import (
	"sync"
	"time"

	"github.com/andersthomson/mediaserver/datasource"
)

type directoryRepo struct {
	dsLck sync.Mutex
	ds    []datasource.DataSource
	dir   string
}

func (d *directoryRepo) Refresh() {
	go func() {
		for {
			i := ScanDir(d.dir)
			d.dsLck.Lock()
			d.ds = i
			d.dsLck.Unlock()
			time.Sleep(time.Minute)
		}
	}()
}

func (d *directoryRepo) AllDataSources() []datasource.DataSource {
	var r []datasource.DataSource
	d.dsLck.Lock()
	r = d.ds
	d.dsLck.Unlock()
	if r == nil {
		return []datasource.DataSource{}
	}
	return r
}
