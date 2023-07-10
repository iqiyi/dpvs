package types

import "strings"

func TrimRightZeros(s string) string {
	idx := strings.IndexByte(s, 0)
	if idx >= 0 {
		return s[:idx]
	}
	return s
}
