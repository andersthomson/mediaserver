package dasherworker

func DasherReadyFilename2(basename, streamIdx string) string {
	return basename + "-encoded-" + streamIdx + ".mp4"
}
