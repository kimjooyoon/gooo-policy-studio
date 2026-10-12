package admission

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

const snapshotName = "snapshot.json"
const lockName = "store.lock"

type fileOperations struct {
	write         func(*os.File, []byte) (int, error)
	rename        func(string, string) error
	syncDirectory func(string) error
}

func defaultOperations() fileOperations {
	return fileOperations{
		write:  func(file *os.File, raw []byte) (int, error) { return file.Write(raw) },
		rename: os.Rename,
		syncDirectory: func(dir string) error {
			file, err := os.Open(dir)
			if err != nil {
				return err
			}
			syncErr := file.Sync()
			closeErr := file.Close()
			if syncErr != nil {
				return syncErr
			}
			return closeErr
		},
	}
}

type Store struct {
	mu         sync.Mutex
	dir        string
	lock       *os.File
	state      snapshot
	operations fileOperations
	closed     bool
	failed     bool
}

func privateDirectory(dir string, create bool) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", failure(Unavailable, "store directory is unavailable")
	}
	if create {
		if _, err := os.Lstat(abs); err == nil {
			return "", failure(Conflict, "initialization requires a new state directory")
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", failure(Unavailable, "store directory cannot be inspected")
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
			return "", failure(Unavailable, "store parent directory cannot be created")
		}
		if err := os.Mkdir(abs, 0700); err != nil {
			if errors.Is(err, os.ErrExist) {
				return "", failure(Conflict, "initialization requires a new state directory")
			}
			return "", failure(Unavailable, "store directory cannot be created")
		}
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return "", failure(Unavailable, "store directory must be a private directory with mode 0700")
	}
	return abs, nil
}

// Init requires a new state directory and never replaces an existing snapshot.
// Configuration is authoritative local administrative input; caller commands
// cannot supply it. An incomplete initialization is left for explicit recovery.
func Init(dir string, b Bootstrap) error {
	if err := ValidateBootstrap(b); err != nil {
		return err
	}
	provenance, err := currentProvenance()
	if err != nil {
		return err
	}
	dir, err = privateDirectory(dir, true)
	if err != nil {
		return err
	}
	lock, err := acquireLock(filepath.Join(dir, lockName))
	if err != nil {
		return failure(Unavailable, "exclusive store ownership is unavailable")
	}
	defer releaseLock(lock)
	if _, err := os.Lstat(filepath.Join(dir, snapshotName)); err == nil {
		return failure(Conflict, "store already exists; initialization never overwrites a snapshot")
	} else if !errors.Is(err, os.ErrNotExist) {
		return failure(Unavailable, "existing snapshot cannot be inspected")
	}
	saved := snapshot{Schema: snapshotSchema, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Policy: b.Policy,
		PolicyVersion: version(b.Policy, provenance), Provenance: provenance, Principals: append([]Principal{}, b.Principals...),
		Requests: make([]RequestState, 0, len(b.Requests)), Outcomes: []Outcome{}}
	for _, r := range b.Requests {
		saved.Requests = append(saved.Requests, RequestState{Request: r, Status: Pending, Revision: 1})
	}
	saved.ID = snapshotID(saved)
	if err := persist(dir, saved, defaultOperations()); err != nil {
		return failure(Unavailable, "initial snapshot commit is unavailable; inspect and recover the store before retrying")
	}
	if err := defaultOperations().syncDirectory(filepath.Dir(dir)); err != nil {
		return failure(Unavailable, "initial store directory durability is unavailable; inspect and recover before retrying")
	}
	return nil
}

// Open retains an exclusive process lifetime lock, validates original JSON bytes
// and reconstructs all saved state/receipt bindings before allowing operations.
func Open(dir string) (*Store, error) {
	dir, err := privateDirectory(dir, false)
	if err != nil {
		return nil, err
	}
	lock, err := acquireLock(filepath.Join(dir, lockName))
	if err != nil {
		return nil, failure(Unavailable, "exclusive store ownership is unavailable")
	}
	failed := true
	defer func() {
		if failed {
			_ = releaseLock(lock)
		}
	}()
	saved, err := readSnapshot(dir)
	if err != nil {
		return nil, err
	}
	provenance, err := currentProvenance()
	if err != nil {
		return nil, err
	}
	if err := validateSnapshot(saved, provenance); err != nil {
		return nil, err
	}
	failed = false
	return &Store{dir: dir, lock: lock, state: saved, operations: defaultOperations()}, nil
}

func readSnapshot(dir string) (snapshot, error) {
	path := filepath.Join(dir, snapshotName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return snapshot{}, failure(Unavailable, "snapshot must be a private regular file with mode 0600")
	}
	file, err := os.Open(path)
	if err != nil {
		return snapshot{}, failure(Unavailable, "snapshot cannot be opened")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0600 {
		return snapshot{}, failure(Unavailable, "snapshot changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxSnapshotBytes+1))
	if err != nil {
		return snapshot{}, failure(Unavailable, "snapshot cannot be read")
	}
	var saved snapshot
	if err := jsoninput.Decode(raw, &saved, maxSnapshotBytes); err != nil {
		return snapshot{}, failure(Unavailable, "snapshot JSON is invalid or ambiguous")
	}
	return saved, nil
}

// persist uses a private same-directory temporary file, fsync before rename,
// and directory fsync after rename. A post-rename error has ambiguous durability.
func persist(dir string, saved snapshot, operations fileOperations) error {
	raw, err := json.Marshal(saved)
	if err != nil || len(raw) > maxSnapshotBytes {
		return errors.New("snapshot serialization is unavailable")
	}
	file, err := os.CreateTemp(dir, ".snapshot-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	written, err := operations.write(file, raw)
	if err != nil || written != len(raw) {
		file.Close()
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := operations.rename(name, filepath.Join(dir, snapshotName)); err != nil {
		return err
	}
	return operations.syncDirectory(dir)
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if err := releaseLock(s.lock); err != nil {
		return failure(Unavailable, "store lock could not be cleanly released")
	}
	return nil
}

func (s *Store) available() error {
	if s.closed || s.failed {
		return failure(Unavailable, "store unavailable until restart and validated recovery")
	}
	return nil
}

func (s *Store) authenticate(token string) (Principal, error) {
	if !validToken(token) {
		return Principal{}, failure(Unauthorized, "machine credential is invalid or disabled")
	}
	sum := sha256.Sum256([]byte(token))
	var found Principal
	matched := 0
	for _, p := range s.state.Principals {
		encoded, _ := hex.DecodeString(p.TokenSHA256)
		if subtle.ConstantTimeCompare(sum[:], encoded) == 1 {
			found, matched = p, matched+1
		}
	}
	if matched != 1 || !found.Enabled {
		return Principal{}, failure(Unauthorized, "machine credential is invalid or disabled")
	}
	return found, nil
}

func (s *Store) Inspect(token string) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return View{}, err
	}
	p, err := s.authenticate(token)
	if err != nil {
		return View{}, err
	}
	return View{Schema: ViewSchema, PolicyVersion: s.state.PolicyVersion,
		Principal: PrincipalView{Key: p.Key, Team: p.Team, Active: p.Active, Enabled: p.Enabled, CanExecute: p.CanExecute},
		Requests:  append([]RequestState{}, s.state.Requests...)}, nil
}

// Admit authenticates before returning even a historical idempotent outcome.
// Denials consume a bounded durable outcome slot but leave request state alone.
// No external action occurs, and a consistently rewritten local snapshot is not
// cryptographically distinguishable from one written by this process.
func (s *Store) Admit(token string, c Command) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return Result{}, err
	}
	p, err := s.authenticate(token)
	if err != nil {
		return Result{}, err
	}
	if !p.CanExecute {
		return Result{}, failure(Forbidden, "machine principal has no execution permission")
	}
	if !validKey(c.IdempotencyKey) {
		return Result{}, failure(InvalidInput, "invalid idempotency key")
	}
	for _, out := range s.state.Outcomes {
		if out.PrincipalKey == p.Key && out.Command.IdempotencyKey == c.IdempotencyKey {
			if out.Command != c {
				return Result{}, failure(Conflict, "idempotency key is already bound to a different command")
			}
			result := Result{Replayed: true, Outcome: out}
			if !out.Committed {
				return result, failure(PolicyDenied, "compiled Gooo policy denied the server-owned request")
			}
			return result, nil
		}
	}
	if err := validateCommand(c); err != nil {
		return Result{}, err
	}
	if c.PolicyVersion != s.state.PolicyVersion {
		return Result{}, failure(Conflict, "policy version is stale")
	}
	requestIndex := -1
	for i, r := range s.state.Requests {
		if r.Request.Key == c.RequestID {
			requestIndex = i
			break
		}
	}
	if requestIndex < 0 {
		return Result{}, failure(Conflict, "server-owned request does not exist")
	}
	r := s.state.Requests[requestIndex]
	if r.Revision != c.ExpectedRevision || r.Status != Pending {
		return Result{}, failure(Conflict, "request revision or pending state is stale")
	}
	if len(s.state.Outcomes) >= MaxOutcomes {
		return Result{}, failure(Unavailable, "durable outcome capacity is exhausted; no outcome is evicted")
	}
	receipt, err := policy.Simulate(policy.Input{Request: r.Request, Reviewer: policy.Reviewer{Key: p.Key, Team: p.Team, Active: p.Active}, Before: s.state.Policy, After: s.state.Policy})
	if err != nil || receipt.SourceDigest != s.state.Provenance.SourceDigest || receipt.GeneratedDigest != s.state.Provenance.GeneratedDigest || receipt.CompilerSource != s.state.Provenance.CompilerSource {
		s.failed = true
		return Result{}, failure(Unavailable, "current policy execution does not match the store binding")
	}
	out := Outcome{Schema: OutcomeSchema, Command: c, PrincipalKey: p.Key, PriorRevision: r.Revision, NewRevision: r.Revision,
		PolicyVersion: s.state.PolicyVersion, Receipt: receipt, Committed: receipt.Result.After.Approved, CreatedAt: receipt.CreatedAt, Scope: OutcomeScope}
	next := cloneSnapshot(s.state)
	if out.Committed {
		out.NewRevision++
		next.Requests[requestIndex].Status = Approved
		next.Requests[requestIndex].Revision = out.NewRevision
	}
	out.ID = outcomeID(out)
	next.Outcomes = append(next.Outcomes, out)
	next.ID = snapshotID(next)
	if err := persist(s.dir, next, s.operations); err != nil {
		// Even if rename already happened, discard further operations. The caller
		// must recover and retry the SAME key; the returned error cannot establish
		// that no durable commit occurred. In-memory state is not used as evidence.
		s.failed = true
		return Result{}, failure(Unavailable, "durable commit failed; restart, recover, and retry the same idempotency key")
	}
	s.state = next
	result := Result{Outcome: out}
	if !out.Committed {
		return result, failure(PolicyDenied, "compiled Gooo policy denied the server-owned request")
	}
	return result, nil
}
