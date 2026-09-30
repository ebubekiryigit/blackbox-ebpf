package model

import (
	"fmt"
	"time"
)

// Application releases do not imply a storage or control protocol bump.
// Before v1, format 1 uses CLOCK_BOOTTIME and one capture-time wall anchor.
// Development captures written with earlier clock semantics are not supported.
const (
	FormatVersion        = 1
	ProtocolVersion      = 1
	HistogramBuckets     = 11
	HistogramMinNS       = uint64(time.Millisecond)
	LegacyPollIntervalNS = uint64(time.Second)
)

type UnsupportedFormatError struct{ Found int }

func (e *UnsupportedFormatError) Error() string {
	return fmt.Sprintf("unsupported capture format %d; this binary reads and writes format %d; use a compatible analyzer (application version is independent)", e.Found, FormatVersion)
}
func CheckReadableFormat(v int) error {
	if v != FormatVersion {
		return &UnsupportedFormatError{v}
	}
	return nil
}
