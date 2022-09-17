package times

import (
	"testing"
	"time"
)

const (
	day   = time.Hour * 24
	month = day * 30
	year  = day * 365
)

func TestParseDuration(t *testing.T) {
	d, err := ParseDuration("1y2mo37d")
	if err != nil {
		t.Fatal(err)
	}
	exp := year + (2 * month) + (37 * day)
	if d != exp {
		t.Fatal("parsed wrong duration")
	}
}
