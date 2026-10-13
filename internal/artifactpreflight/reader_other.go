//go:build !darwin && !linux

package artifactpreflight

import (
	"fmt"
	"os"
)

// Unsupported hosts fail closed instead of falling back to a potentially
// blocking or symlink-following artifact read.
func openNoFollowNonblock(root *os.Root, name string) (*os.File, error) {
	return nil, fmt.Errorf("guarded artifact reader is supported only on macOS and Linux")
}
