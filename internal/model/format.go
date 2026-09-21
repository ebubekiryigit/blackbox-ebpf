package model

import (
	"fmt"
	"time"
)

// Application releases do not imply a storage or control protocol bump.
// Format v1's bucket layout and legacy interval interpretation are immutable.
const (
	FormatVersion        = 1
	OldestReadableFormat = 1
	ProtocolVersion      = 1
	HistogramBuckets     = 11
	HistogramMinNS       = uint64(time.Millisecond)
	LegacyPollIntervalNS = uint64(time.Second)
)

type UnsupportedFormatError struct{ Found int }

func (e *UnsupportedFormatError) Error() string {
	return fmt.Sprintf("unsupported capture format %d; this binary reads formats %d–%d and writes %d; use a compatible analyzer (application version is independent)", e.Found, OldestReadableFormat, FormatVersion, FormatVersion)
}
func CheckReadableFormat(v int) error {
	if v < OldestReadableFormat || v > FormatVersion {
		return &UnsupportedFormatError{v}
	}
	return nil
}
