//go:build darwin || linux

package gateclient

import (
	"os"
	"reflect"
	"syscall"
)

func openPrivateRead(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func openPrivateCreate(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
}

// Linux names this field Ctim and macOS Ctimespec. Reflection keeps the one
// supported-host file portable while ignoring access time, which our own read
// may update. Change time detects a rewrite followed by restoring mtime.
func privateChangeTime(info os.FileInfo) (int64, int64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, 0, false
	}
	v := reflect.ValueOf(stat).Elem()
	for _, name := range []string{"Ctim", "Ctimespec"} {
		stamp := v.FieldByName(name)
		if !stamp.IsValid() || stamp.Kind() != reflect.Struct {
			continue
		}
		sec, nano := stamp.FieldByName("Sec"), stamp.FieldByName("Nsec")
		if sec.IsValid() && nano.IsValid() && sec.CanInt() && nano.CanInt() {
			return sec.Int(), nano.Int(), true
		}
	}
	return 0, 0, false
}

func privateChangeTimeEqual(before, after os.FileInfo) bool {
	secondsBefore, nanosBefore, okBefore := privateChangeTime(before)
	secondsAfter, nanosAfter, okAfter := privateChangeTime(after)
	return okBefore && okAfter && secondsBefore == secondsAfter && nanosBefore == nanosAfter
}
