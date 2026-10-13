//go:build darwin || linux

package artifactpreflight

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFIFOAcquisitionDoesNotBlock(t *testing.T) {
	path := filepath.Join(realDir(t), "fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	requirement := Requirement{path, digest(goodArtifact)}
	completed := make(chan Acquisition, 1)
	go func() {
		a, err := ReadArtifact(requirement, MaxBytes)
		if err != nil {
			completed <- Acquisition{}
			return
		}
		completed <- a
	}()
	select {
	case a := <-completed:
		if a.Status() != ReadError {
			t.Fatalf("FIFO was not rejected: %#v", a)
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO artifact read blocked")
	}
}
