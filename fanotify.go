package main

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/s3rj1k/go-fanotify/fanotify"
	"golang.org/x/sys/unix"
)

type FanotifyEventInfoHeader struct {
	InfoType uint8
	Pad      uint8
	Len      uint16
}

const FanotifyEventInfoHeaderSize = 1 + 1 + 2

type KernelFsidT struct {
	Val [2]int32
}

const KernelFsidTSize = 2 * 4

const FanEventInfoTypeFidId uint8 = 1
const FanEventInfoTypeDfidNameId uint8 = 2
const FanEventInfoTypeDfidId uint8 = 3
const FanEventInfoTypePidfdId uint8 = 4
const FanEventInfoTypeErrorId uint8 = 5

type FileHandle struct {
	HandleBytes uint32
	HandeType   int32
	FHandle     [1]byte
}

const FileHandleSize = 4 + 4 + 1

type FanotifyEventInfoFid struct {
	Hdr    FanotifyEventInfoHeader
	Fsid   KernelFsidT
	Handle FileHandle
}

type FanotifyEventInfoDfidName struct {
	Filename string
}

func (_ FanotifyEventInfoDfidName) FanotifyEventInfo() {
}

type FanotifyEventInfoOldDfidName struct {
	Filename string
}

func (_ FanotifyEventInfoOldDfidName) FanotifyEventInfo() {
}

type FanotifyEventInfoNewDfidName struct {
	Filename string
}

func (_ FanotifyEventInfoNewDfidName) FanotifyEventInfo() {
}

const FanotifyEventInfoFidSize = FanotifyEventInfoHeaderSize + FileHandleSize + FileHandleSize

type FanotifyEventInfoIfc interface {
	FanotifyEventInfo()
}

type FANotifyEvent struct {
	Event     *fanotify.EventMetadata
	EventInfo []FanotifyEventInfoIfc
}

func readFrame(frame []byte) (string, error) {
	fid := new(FanotifyEventInfoFid)
	if err := binary.Read(bytes.NewBuffer(frame), binary.LittleEndian, fid); err != nil {
		return "", fmt.Errorf("fanotify: event error, %w", err)
	}
	//spew.Dump(dfidName)
	fnamestart := FanotifyEventInfoFidSize - 2 + int(fid.Handle.HandleBytes)
	//slog.Info("fanotify fname", "offset", fnamestart)
	//slog.Info("fanotify fname", "value", frameSlice[fnamestart])
	part := frame[fnamestart:]
	s := string(part[:bytes.IndexByte(part, 0)])

	//slog.Info("fanotify", "fname", part)
	//slog.Info("fanotify", "fname", s)
	return s, nil
}

func GetFANotifyEvent(notify *fanotify.NotifyFD, pids ...int) (FANotifyEvent, error) {
	var res FANotifyEvent
	data, err := notify.GetEvent(pids...)
	if err != nil {
		return FANotifyEvent{}, fmt.Errorf("notify.GetEvent failed: %w", err)
	}

	if data == nil {
		panic("nil")
		return FANotifyEvent{}, nil
	}
	res.Event = data
	defer data.Close()

	infoTypesSlice := make([]byte, int(data.Event_len)-int(data.Metadata_len))
	n, err := notify.Rd.Read(infoTypesSlice)
	_ = n
	//slog.Info("fanotify infoType", "size", n, "err", err, "remainder", infoTypesSlice)
	offset := 0
	for {
		//fmt.Printf("OFFSET %d\n", offset)
		//slog.Info("fanotify processing ", "offset", offset)
		frame := new(FanotifyEventInfoHeader)
		if err := binary.Read(bytes.NewBuffer(infoTypesSlice[offset:]), binary.LittleEndian, frame); err != nil {
			return FANotifyEvent{}, fmt.Errorf("fanotify: event error, %w", err)
		}
		//spew.Dump(frame)
		frameSlice := infoTypesSlice[offset : offset+int(frame.Len)]

		switch frame.InfoType {
		case unix.FAN_EVENT_INFO_TYPE_DFID_NAME:
			fname, err := readFrame(frameSlice)
			if err != nil {
				return FANotifyEvent{}, err
			}

			var dfidName FanotifyEventInfoDfidName
			dfidName.Filename = fname
			res.EventInfo = append(res.EventInfo, dfidName)
		case unix.FAN_EVENT_INFO_TYPE_OLD_DFID_NAME:
			fname, err := readFrame(frameSlice)
			if err != nil {
				return FANotifyEvent{}, err
			}

			var dfidName FanotifyEventInfoOldDfidName
			dfidName.Filename = fname
			res.EventInfo = append(res.EventInfo, dfidName)
		case unix.FAN_EVENT_INFO_TYPE_NEW_DFID_NAME:
			fname, err := readFrame(frameSlice)
			if err != nil {
				return FANotifyEvent{}, err
			}

			var dfidName FanotifyEventInfoNewDfidName
			dfidName.Filename = fname
			res.EventInfo = append(res.EventInfo, dfidName)
		default:
			logger.Error("fanotify: unsupported info type", "type", frame.InfoType)
			return FANotifyEvent{}, fmt.Errorf("fanotify: unsupported info type: %d", frame.InfoType)
		}
		offset += int(frame.Len)
		if offset == len(infoTypesSlice) {
			return res, nil
		}
		if offset > len(infoTypesSlice) {
			panic("offset out of bounds")
		}
	}
	return FANotifyEvent{}, fmt.Errorf("Error: offect calc wrong")
}

func maskDump(mask uint64) []string {
	var r []string

	for {
		switch {
		case (mask & unix.FAN_ACCESS) == unix.FAN_ACCESS: //0x01
			r = append(r, "FAN_ACCESS")
			mask = mask &^ unix.FAN_CLOEXEC
		case (mask & unix.FAN_MODIFY) == unix.FAN_MODIFY: //0x02
			r = append(r, "FAN_MODIFY")
			mask = mask &^ unix.FAN_MODIFY
		case (mask & unix.FAN_ATTRIB) == unix.FAN_ATTRIB: //0x04
			r = append(r, "FAN_ATTRIB")
			mask = mask &^ unix.FAN_ATTRIB
		case (mask & unix.FAN_CLOSE_WRITE) == unix.FAN_CLOSE_WRITE: //0x08
			r = append(r, "FAN_CLOSE_WRITE")
			mask = mask &^ unix.FAN_CLOSE_WRITE
		case (mask & unix.FAN_CLOSE_NOWRITE) == unix.FAN_CLOSE_NOWRITE: //0x10
			r = append(r, "FAN_CLOSE_NOWRITE")
			mask = mask &^ unix.FAN_CLOSE_NOWRITE
		case (mask & unix.FAN_OPEN) == unix.FAN_OPEN: //0x20
			r = append(r, "FAN_OPEN")
			mask = mask &^ unix.FAN_OPEN
		case (mask & unix.FAN_MOVED_FROM) == unix.FAN_MOVED_FROM: //0x40
			r = append(r, "FAN_MOVED_FROM")
			mask = mask &^ unix.FAN_MOVED_FROM
		case (mask & unix.FAN_MOVED_TO) == unix.FAN_MOVED_TO: //0x80
			r = append(r, "FAN_MOVED_TO")
			mask = mask &^ unix.FAN_MOVED_TO
		case (mask & unix.FAN_CREATE) == unix.FAN_CREATE: //0x100
			r = append(r, "FAN_CREATE")
			mask = mask &^ unix.FAN_CREATE
		case (mask & unix.FAN_DELETE) == unix.FAN_DELETE: //0x200
			r = append(r, "FAN_DELETE")
			mask = mask &^ unix.FAN_DELETE
		case (mask & unix.FAN_DELETE_SELF) == unix.FAN_DELETE_SELF: //0x400
			r = append(r, "FAN_DELETE_SELF")
			mask = mask &^ unix.FAN_DELETE_SELF
		case (mask & unix.FAN_MOVE_SELF) == unix.FAN_MOVE_SELF: //0x800
			r = append(r, "FAN_MOVE_SELF")
			mask = mask &^ unix.FAN_MOVE_SELF
		case (mask & unix.FAN_OPEN_EXEC) == unix.FAN_OPEN_EXEC: //0x1000
			r = append(r, "FAN_OPEN_EXEC")
			mask = mask &^ unix.FAN_OPEN_EXEC
		case (mask & unix.FAN_RENAME) == unix.FAN_RENAME: //0x10000000
			r = append(r, "FAN_RENAME")
			mask = mask &^ unix.FAN_RENAME

		case (mask & unix.FAN_AUDIT) == unix.FAN_AUDIT:
			r = append(r, "FAN_AUDIT")
			mask = mask &^ unix.FAN_AUDIT
		case (mask & unix.FAN_ONDIR) == unix.FAN_ONDIR:
			r = append(r, "FAN_ONDIR")
			mask = mask &^ unix.FAN_ONDIR
		case (mask & unix.FAN_INFO) == unix.FAN_INFO:
			r = append(r, "FAN_INFO")
			mask = mask &^ unix.FAN_INFO
		default:
			r = append(r, fmt.Sprintf("0x%016x", mask))
			mask = 0
		}
		if mask == 0 {
			break
		}
	}

	return r
}
