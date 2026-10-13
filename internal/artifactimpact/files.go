package artifactimpact

// Private IO implementation copied from internal/gateclient/files.go at base 7ea69d3d98135b27c454161723f1fbb48bf43ee9.
// Original SHA256: 1c739901b22d2d6f4d51b76e567be189278160b058c574df3fe4f9944fc98433. Original file remains unchanged.
// The new package owns alias exclusions for a counterfactual report; this is not credential or admission authority.

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
	errPrivateAlias  = errors.New("private output aliases an input or cannot be verified")
)

type privatePathIdentity struct {
	path string
	info os.FileInfo
}

type privateParent struct {
	root       *os.Root
	name       string
	full       string
	logical    string
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
	p := &privateParent{root: root, name: name, full: filepath.Join(physical, name), logical: abs}
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
	// Never select a new target after an administrative parent alias retarget.
	// Revalidation compares with the already pinned physical parent only.
	physical, err := filepath.EvalSymlinks(filepath.Dir(p.logical))
	if err != nil || physical != filepath.Dir(p.full) {
		return errPrivateRead
	}
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

// createPrivate reserves a new private regular file before artifact acquisition. Failures
// preserve the exclusively created empty or partial file for inspection.
func createPrivate(path string) (*privateOutput, error) {
	p, err := acquirePrivateParent(path)
	if err != nil {
		return nil, errPrivateCreate
	}
	return reservePrivate(p, nil)
}

// createPrivateAgainst uses one pinned output parent for alias validation,
// exclusive reservation, and final identity checks. An independent check then
// a second parent resolution would permit a missing artifact to become output.
func createPrivateAgainst(path string, inputs ...string) (*privateOutput, error) {
	p, err := acquirePrivateParent(path)
	if err != nil {
		return nil, errPrivateCreate
	}
	guard, err := acquirePrivateAliasGuard(inputs)
	if err != nil {
		_ = p.root.Close()
		return nil, errPrivateAlias
	}
	out, reserveErr := reservePrivate(p, guard)
	closeErr := guard.close()
	if reserveErr != nil {
		return nil, reserveErr
	}
	if closeErr != nil {
		_ = out.Close()
		return nil, errPrivateCreate
	}
	return out, nil
}

func reservePrivate(p *privateParent, guard *privateAliasGuard) (*privateOutput, error) {
	if p.verify() != nil || guard != nil && guard.check(p) != nil {
		_ = p.root.Close()
		return nil, errPrivateAlias
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
	if err != nil || !isPrivateRegular(info) || info.Size() != 0 || p.verifyFile(info) != nil || guard != nil && guard.check(p) != nil || f.Sync() != nil || p.sync() != nil {
		return fail()
	}
	after, err := f.Stat()
	if err != nil || !stablePrivateMetadata(info, after) || p.verifyFile(after) != nil || guard != nil && guard.check(p) != nil {
		return fail()
	}
	return &privateOutput{file: f, parent: p, initial: after}, nil
}

type privateAliasEntry struct {
	path string
	info os.FileInfo // nil means a particular absent component was observed.
}

type privateAliasGuard struct {
	parents []*privateParent
	entries []privateAliasEntry
	paths   []string
}

// Alias checks inspect directory/final-entry metadata, never artifact contents.
// Missing descendants are resolved against their nearest existing physical
// ancestor; broken final symlinks are followed for exclusion only. The producer
// reader still rejects final symlinks rather than acquiring their bytes.
func acquirePrivateAliasGuard(inputs []string) (*privateAliasGuard, error) {
	g := &privateAliasGuard{}
	fail := func() (*privateAliasGuard, error) {
		_ = g.close()
		return nil, errPrivateAlias
	}
	for _, input := range inputs {
		if input == "" {
			return fail()
		}
		current, err := filepath.Abs(input)
		if err != nil {
			return fail()
		}
		for depth := 0; ; depth++ {
			if depth >= 64 {
				return fail()
			}
			ancestor := filepath.Dir(current)
			missing := []string{}
			for {
				_, err = filepath.EvalSymlinks(ancestor)
				if err == nil {
					break
				}
				if !os.IsNotExist(err) || ancestor == filepath.Dir(ancestor) {
					return fail()
				}
				missing = append([]string{filepath.Base(ancestor)}, missing...)
				ancestor = filepath.Dir(ancestor)
			}
			p, err := acquirePrivateParent(filepath.Join(ancestor, ".artifact-impact-alias-anchor"))
			if err != nil {
				return fail()
			}
			g.parents = append(g.parents, p)
			physicalParent := filepath.Dir(p.full)
			components := append(append([]string{physicalParent}, missing...), filepath.Base(current))
			physical := filepath.Join(components...)
			g.paths = append(g.paths, physical)
			if len(missing) > 0 {
				absent := filepath.Join(physicalParent, missing[0])
				if _, err := os.Lstat(absent); !os.IsNotExist(err) {
					return fail()
				}
				g.entries = append(g.entries, privateAliasEntry{path: absent})
				break
			}
			info, err := p.root.Lstat(filepath.Base(current))
			if os.IsNotExist(err) {
				g.entries = append(g.entries, privateAliasEntry{path: physical})
				break
			}
			if err != nil {
				return fail()
			}
			g.entries = append(g.entries, privateAliasEntry{path: physical, info: info})
			if info.Mode()&os.ModeSymlink == 0 {
				break
			}
			target, err := p.root.Readlink(filepath.Base(current))
			if err != nil {
				return fail()
			}
			if filepath.IsAbs(target) {
				current = filepath.Clean(target)
			} else {
				current = filepath.Join(physicalParent, target)
			}
		}
	}
	if g.verify() != nil {
		return fail()
	}
	return g, nil
}

func (g *privateAliasGuard) verify() error {
	for _, p := range g.parents {
		if p.verify() != nil {
			return errPrivateAlias
		}
	}
	for _, entry := range g.entries {
		current, err := os.Lstat(entry.path)
		if entry.info == nil {
			if !os.IsNotExist(err) {
				return errPrivateAlias
			}
			continue
		}
		if err != nil || !os.SameFile(entry.info, current) || entry.info.Mode() != current.Mode() || entry.info.Size() != current.Size() || !entry.info.ModTime().Equal(current.ModTime()) || !privateChangeTimeEqual(entry.info, current) {
			return errPrivateAlias
		}
	}
	return nil
}

func (g *privateAliasGuard) check(output *privateParent) error {
	if output.verify() != nil || g.verify() != nil {
		return errPrivateAlias
	}
	for _, input := range g.paths {
		if output.full == input {
			return errPrivateAlias
		}
	}
	for _, entry := range g.entries {
		// Creating the first absent ancestor would alter the source namespace
		// even though the complete artifact pathname is a different string.
		if entry.info == nil && output.full == entry.path {
			return errPrivateAlias
		}
	}
	info, err := output.root.Lstat(output.name)
	if err != nil && !os.IsNotExist(err) {
		return errPrivateAlias
	}
	if err == nil {
		for _, entry := range g.entries {
			if entry.info != nil && os.SameFile(info, entry.info) {
				return errPrivateAlias
			}
		}
	}
	return nil
}

func (g *privateAliasGuard) close() error {
	var result error
	for _, p := range g.parents {
		if p.root.Close() != nil {
			result = errPrivateAlias
		}
	}
	g.parents = nil
	return result
}

func rejectOutputAliases(output string, inputs ...string) error {
	p, err := acquirePrivateParent(output)
	if err != nil {
		return errPrivateAlias
	}
	guard, err := acquirePrivateAliasGuard(inputs)
	if err != nil {
		_ = p.root.Close()
		return errPrivateAlias
	}
	checkErr := guard.check(p)
	guardErr, parentErr := guard.close(), p.root.Close()
	if checkErr != nil || guardErr != nil || parentErr != nil {
		return errPrivateAlias
	}
	return nil
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
