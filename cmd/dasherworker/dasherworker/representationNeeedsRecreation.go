package dasherworker

import (
	"os"
	"time"
)

func FileModTime(fname DirFile) (time.Time, error) {
	if fi, err := os.Stat(fname.String()); err != nil {
		return time.Time{}, err
	} else {
		return fi.ModTime(), nil
	}
}

/*
func representationNeedsRecreation(ctx context.Context, streamno int, m scrape.Msp, mFile DirFile, dir, DashDir string) (bool, error) {
	//This is executed in activity context
	inFname, err := InputFName(streamno, m)
	if err != nil {
		return false, err
	}
	drFname := DasherReadyFilename2(inFname, strconv.Itoa(streamno))
	outDFname := NewDirFile(DashDir, drFname+"-fragmented.mp4")

	//representation does not exist yet.
	if _, err := os.Stat(outDFname.String()); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
	}

	outFnameTime, err := FileModTime(outDFname)
	if err != nil {
		return false, err
	}

	inDFname := NewDirFile(dir, inFname)
	inFnameTime, err := FileModTime(inDFname)
	if err != nil {
		return false, err
	}
	// representation vs source file
	if outFnameTime.Before(inFnameTime) {
		slog.Info("representationNeedsRecreation", "reason", "source newer")
		return true, nil
	}

	mFileTime, err := FileModTime(mFile)
	if err != nil {
		return false, err
	}
	//representation vs msp file
	if outFnameTime.Before(mFileTime) {
		return true, nil
	}

	//FIXME Test agains the representation Encode() Activity's verison here. (Should be stored in the dash dir)
	//code.....
	// https://github.com/earthboundkid/versioninfo.git

	//Default
	return false, nil
}*/
