package artifactpreflight

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ReadArtifact observes one bounded regular file into owned memory. Acquisitions
// never hold a descriptor open. Runtime failures are reportable non-pass states;
// invalid operator configuration is returned as an error.
func ReadArtifact(requirement Requirement, maxBytes int64) (Acquisition, error) {
	if err := ValidateRequirement(requirement); err != nil {
		return Acquisition{}, err
	}
	if maxBytes < 1 || maxBytes > MaxBytes {
		return Acquisition{}, fmt.Errorf("invalid artifact acquisition limit")
	}
	a := Acquisition{status: ReadError, raw: []byte{}, expectedSHA: requirement.ExpectedSHA256, maxBytes: maxBytes, observedSize: -1}
	f, verify, err := openRegular(requirement.Path)
	if err != nil {
		return a, nil
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return a, nil
	}
	a.observedSize = before.Size()
	if before.Size() > maxBytes {
		a.status = Oversized
		return a, nil
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return a, nil
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || verify(after) != nil {
		return a, nil
	}
	if int64(len(raw)) > maxBytes {
		a.status = Oversized
		a.raw = append([]byte{}, raw...)
		a.observedSize = after.Size()
		return a, nil
	}
	if int64(len(raw)) != after.Size() {
		return a, nil
	}
	a.status, a.raw = ReadSuccess, append([]byte{}, raw...)
	return a, nil
}

func SkipArtifact(requirement Requirement, maxBytes int64) (Acquisition, error) {
	if err := ValidateRequirement(requirement); err != nil {
		return Acquisition{}, err
	}
	if maxBytes < 1 || maxBytes > MaxBytes {
		return Acquisition{}, fmt.Errorf("invalid artifact acquisition limit")
	}
	return Acquisition{status: Skipped, raw: []byte{}, expectedSHA: requirement.ExpectedSHA256, maxBytes: maxBytes, observedSize: -1}, nil
}

type pathIdentity struct {
	path string
	info os.FileInfo
}

// All components are selected through an already-open parent. Post-open
// SameFile checks detect replacement; retained Roots prevent later ancestor
// renames from redirecting child resolution.
func openRegular(path string) (*os.File, func(os.FileInfo) error, error) {
	root, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, nil, err
	}
	defer func() { root.Close() }()
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	var selected []pathIdentity
	abs := string(filepath.Separator)
	for _, part := range parts[:len(parts)-1] {
		info, err := root.Lstat(part)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("artifact parent is not a real directory")
		}
		next, err := root.OpenRoot(part)
		if err != nil {
			return nil, nil, err
		}
		opened, err := next.Stat(".")
		current, err2 := root.Lstat(part)
		if err != nil || err2 != nil || !os.SameFile(info, opened) || !os.SameFile(info, current) || current.Mode()&os.ModeSymlink != 0 {
			next.Close()
			return nil, nil, fmt.Errorf("artifact parent changed while opening")
		}
		abs = filepath.Join(abs, part)
		selected = append(selected, pathIdentity{abs, info})
		root.Close()
		root = next
	}
	base := parts[len(parts)-1]
	info, err := root.Lstat(base)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("artifact is not a real regular file")
	}
	f, err := openNoFollowNonblock(root, base)
	if err != nil {
		return nil, nil, err
	}
	opened, err := f.Stat()
	current, err2 := root.Lstat(base)
	if err != nil || err2 != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || !os.SameFile(info, current) || current.Mode()&os.ModeSymlink != 0 {
		f.Close()
		return nil, nil, fmt.Errorf("artifact changed while opening")
	}
	selected = append(selected, pathIdentity{path, info})
	verify := func(after os.FileInfo) error {
		for _, item := range selected {
			current, err := os.Lstat(item.path)
			if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(item.info, current) {
				return fmt.Errorf("artifact path changed while reading")
			}
		}
		if !os.SameFile(info, after) {
			return fmt.Errorf("artifact descriptor changed")
		}
		return nil
	}
	return f, verify, nil
}
