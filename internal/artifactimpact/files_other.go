//go:build !darwin && !linux

package artifactimpact

// Private IO implementation copied from internal/gateclient/files_other.go at base 7ea69d3d98135b27c454161723f1fbb48bf43ee9.
// Original SHA256: 053448ee42ea200ba9ff0cf3d28b995f74dd3e8024acbdcc9f2d8f75cdf51290. Original file remains unchanged.
// The new package owns alias exclusions for a counterfactual report; this is not credential or admission authority.

import "os"

func openPrivateRead(root *os.Root, name string) (*os.File, error) {
	return nil, errPrivateRead
}

func openPrivateCreate(root *os.Root, name string) (*os.File, error) {
	return nil, errPrivateCreate
}

func privateChangeTimeEqual(before, after os.FileInfo) bool {
	return false
}
