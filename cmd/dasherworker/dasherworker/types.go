package dasherworker

import "strconv"

type GopMs float64

func (g GopMs) String() string {
	return strconv.FormatFloat(float64(g), 'f', 0, 64)
}
