package gateclient

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Errors intentionally disclose neither an operating-system error nor a path
// supplied by a caller. The CLI maps these private failures to fixed codes.
var (
	errPrivateRead   = errors.New("private file acquisition failed")
	errPrivateLimit  = errors.New("invalid private file byte limit")
	errPrivateCreate = errors.New("private output creation failed")
	errPrivateWrite  = errors.New("private output write or sync failed")
	errPrivateClose  = errors.New("private file close failed")
)

type privatePathIdentity struct {
	path string
	info os.FileInfo
}

type privateParent struct {
	root       *os.Root
	name       string
	full       string
	identities []privatePathIdentity
}

// Administrative directory aliases are resolved once. Thereafter every
// physical component is selected relative to an open parent and its identity
// is checked again. The retained final Root cannot follow a replaced ancestor.
func acquirePrivateParent(path string) (*privateParent, error) {
	if path == "" {
		return nil, errPrivateRead
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, errPrivateRead
	}
	name := filepath.Base(abs)
	if name == "." || name == ".." || name == string(filepath.Separator) {
		return nil, errPrivateRead
	}
	physical, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil || !filepath.IsAbs(physical) {
		return nil, errPrivateRead
	}
	root, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, errPrivateRead
	}
	p := &privateParent{root: root, name: name, full: filepath.Join(physical, name)}
	success := false
	defer func() {
		if !success {
			_ = p.root.Close()
		}
	}()
	info, err := root.Stat(".")
	if err != nil || !info.IsDir() {
		return nil, errPrivateRead
	}
	p.identities = append(p.identities, privatePathIdentity{string(filepath.Separator), info})
	currentPath := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(physical, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		before, err := p.root.Lstat(part)
		if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			return nil, errPrivateRead
		}
		next, err := p.root.OpenRoot(part)
		if err != nil {
			return nil, errPrivateRead
		}
		opened, err := next.Stat(".")
		after, pathErr := p.root.Lstat(part)
		if err != nil || pathErr != nil || !opened.IsDir() || !after.IsDir() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, opened) || !os.SameFile(before, after) {
			_ = next.Close()
			return nil, errPrivateRead
		}
		if err := p.root.Close(); err != nil {
			_ = next.Close()
			return nil, errPrivateRead
		}
		p.root = next
		currentPath = filepath.Join(currentPath, part)
		p.identities = append(p.identities, privatePathIdentity{currentPath, before})
	}
	if p.verify() != nil {
		return nil, errPrivateRead
	}
	success = true
	return p, nil
}

func (p *privateParent) verify() error {
	for _, selected := range p.identities {
		current, err := os.Lstat(selected.path)
		if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(selected.info, current) {
			return errPrivateRead
		}
	}
	opened, err := p.root.Stat(".")
	if err != nil || !opened.IsDir() || !os.SameFile(p.identities[len(p.identities)-1].info, opened) {
		return errPrivateRead
	}
	return nil
}

func (p *privateParent) verifyFile(info os.FileInfo) error {
	if !isPrivateRegular(info) || p.verify() != nil {
		return errPrivateRead
	}
	for _, currentPath := range []string{p.name, p.full} {
		var current os.FileInfo
		var err error
		if currentPath == p.name {
			current, err = p.root.Lstat(currentPath)
		} else {
			current, err = os.Lstat(currentPath)
		}
		if err != nil || !isPrivateRegular(current) || !os.SameFile(info, current) || !stablePrivateMetadata(info, current) {
			return errPrivateRead
		}
	}
	return nil
}

func (p *privateParent) sync() error {
	if p.verify() != nil {
		return errPrivateWrite
	}
	dir, err := p.root.Open(".")
	if err != nil {
		return errPrivateWrite
	}
	info, statErr := dir.Stat()
	if statErr != nil || !info.IsDir() || !os.SameFile(p.identities[len(p.identities)-1].info, info) {
		_ = dir.Close()
		return errPrivateWrite
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil || closeErr != nil || p.verify() != nil {
		return errPrivateWrite
	}
	return nil
}

func isPrivateRegular(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode() == 0o600 && info.Size() >= 0
}

func stablePrivateMetadata(before, after os.FileInfo) bool {
	return isPrivateRegular(before) && isPrivateRegular(after) && os.SameFile(before, after) && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime()) && privateChangeTimeEqual(before, after)
}

type privateInput struct {
	file   *os.File
	parent *privateParent
	before os.FileInfo
}

func openPrivateInput(path string) (*privateInput, error) {
	p, err := acquirePrivateParent(path)
	if err != nil {
		return nil, errPrivateRead
	}
	before, err := p.root.Lstat(p.name)
	if err != nil || !isPrivateRegular(before) {
		_ = p.root.Close()
		return nil, errPrivateRead
	}
	f, err := openPrivateRead(p.root, p.name)
	if err != nil {
		_ = p.root.Close()
		return nil, errPrivateRead
	}
	opened, err := f.Stat()
	if err != nil || !stablePrivateMetadata(before, opened) || p.verifyFile(opened) != nil {
		_ = f.Close()
		_ = p.root.Close()
		return nil, errPrivateRead
	}
	return &privateInput{file: f, parent: p, before: opened}, nil
}

func (p *privateInput) verify() error {
	after, err := p.file.Stat()
	if err != nil || !stablePrivateMetadata(p.before, after) || p.parent.verifyFile(after) != nil {
		return errPrivateRead
	}
	return nil
}

func (p *privateInput) close() error {
	fileErr := p.file.Close()
	parentErr := p.parent.root.Close()
	if fileErr != nil || parentErr != nil {
		return errPrivateClose
	}
	return nil
}

// readPrivate preserves all original bytes, including JSON whitespace. A
// changed descriptor, final path, parent identity or change timestamp fails.
func readPrivate(path string, max int64) ([]byte, error) {
	if max < 1 || max == math.MaxInt64 {
		return nil, errPrivateLimit
	}
	in, err := openPrivateInput(path)
	if err != nil {
		return nil, errPrivateRead
	}
	closed := false
	defer func() {
		if !closed {
			_ = in.close()
		}
	}()
	if in.before.Size() > max {
		return nil, errPrivateRead
	}
	raw, err := io.ReadAll(io.LimitReader(in.file, max+1))
	if err != nil || int64(len(raw)) > max || int64(len(raw)) != in.before.Size() || in.verify() != nil {
		return nil, errPrivateRead
	}
	closed = true
	if in.close() != nil {
		return nil, errPrivateClose
	}
	return raw, nil
}

type privateOutput struct {
	mu        sync.Mutex
	file      *os.File
	parent    *privateParent
	initial   os.FileInfo
	attempted bool
	closed    bool
}

// createPrivate reserves a new private regular file before any POST. Failures
// preserve the exclusively created empty or partial file for inspection.
func createPrivate(path string) (*privateOutput, error) {
	p, err := acquirePrivateParent(path)
	if err != nil {
		return nil, errPrivateCreate
	}
	f, err := openPrivateCreate(p.root, p.name)
	if err != nil {
		_ = p.root.Close()
		return nil, errPrivateCreate
	}
	fail := func() (*privateOutput, error) {
		_ = f.Close()
		_ = p.root.Close()
		return nil, errPrivateCreate
	}
	if f.Chmod(0o600) != nil {
		return fail()
	}
	info, err := f.Stat()
	if err != nil || !isPrivateRegular(info) || info.Size() != 0 || p.verifyFile(info) != nil || f.Sync() != nil || p.sync() != nil {
		return fail()
	}
	after, err := f.Stat()
	if err != nil || !stablePrivateMetadata(info, after) || p.verifyFile(after) != nil {
		return fail()
	}
	return &privateOutput{file: f, parent: p, initial: after}, nil
}

func (p *privateOutput) WriteAndSync(raw []byte) error {
	if p == nil {
		return errPrivateWrite
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.attempted {
		return errPrivateWrite
	}
	p.attempted = true
	before, err := p.file.Stat()
	if err != nil || !stablePrivateMetadata(p.initial, before) || p.parent.verifyFile(before) != nil {
		return errPrivateWrite
	}
	n, err := p.file.Write(raw)
	if err != nil || n != len(raw) {
		return errPrivateWrite
	}
	written, err := p.file.Stat()
	if err != nil || !isPrivateRegular(written) || written.Size() != int64(len(raw)) || !os.SameFile(p.initial, written) || p.parent.verifyFile(written) != nil || p.file.Sync() != nil {
		return errPrivateWrite
	}
	// Read back from the same descriptor, without exporting the bytes. This
	// also catches a same-size corruption that occurred before the final stat.
	reader := io.NewSectionReader(p.file, 0, int64(len(raw)))
	buf := make([]byte, 64<<10)
	for offset := 0; offset < len(raw); {
		length := len(buf)
		if length > len(raw)-offset {
			length = len(raw) - offset
		}
		if _, err := io.ReadFull(reader, buf[:length]); err != nil || !bytes.Equal(buf[:length], raw[offset:offset+length]) {
			return errPrivateWrite
		}
		offset += length
	}
	after, err := p.file.Stat()
	if err != nil || !stablePrivateMetadata(written, after) || p.parent.verifyFile(after) != nil || p.parent.sync() != nil {
		return errPrivateWrite
	}
	final, err := p.file.Stat()
	if err != nil || !stablePrivateMetadata(after, final) || p.parent.verifyFile(final) != nil {
		return errPrivateWrite
	}
	return nil
}

func (p *privateOutput) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	fileErr := p.file.Close()
	parentErr := p.parent.root.Close()
	if fileErr != nil || parentErr != nil {
		return errPrivateClose
	}
	return nil
}
