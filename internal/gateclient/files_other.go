//go:build !darwin && !linux

package gateclient

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
