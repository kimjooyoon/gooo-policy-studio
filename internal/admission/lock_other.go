//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !dragonfly

package admission

import (
	"fmt"
	"os"
)

// Other targets still compile the application, but cannot perform admission.
func acquireLock(string) (*os.File, error) {
	return nil, fmt.Errorf("durable admission requires supported Unix flock")
}

func releaseLock(*os.File) error {
	return fmt.Errorf("durable admission requires supported Unix flock")
}
