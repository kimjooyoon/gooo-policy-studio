//go:build darwin || linux

package artifactimpact

// Private IO implementation copied from internal/gateclient/files_test.go at base 7ea69d3d98135b27c454161723f1fbb48bf43ee9.
// Original SHA256: 73c4aab4cb677e3590211b25f2c92dabd29613e07de64fd7173ca5049f3cf531. Original file remains unchanged.
// The new package owns alias exclusions for a counterfactual report; this is not credential or admission authority.

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func privateTestFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactImpactMissingArtifactCannotBecomeOutput(t *testing.T) {
	dir := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(dir, "missing.json")
	for _, output := range []string{artifact, filepath.Join(alias, "missing.json")} {
		if rejectOutputAliases(output, artifact) == nil {
			t.Fatal("missing artifact/output alias accepted")
		}
		if got, err := createPrivateAgainst(output, artifact); err == nil || got != nil {
			t.Fatal("missing artifact was reserved as a report")
		}
		if _, err := os.Lstat(artifact); !os.IsNotExist(err) {
			t.Fatal("alias rejection changed the missing source")
		}
	}
}

func TestArtifactImpactMissingInputAncestorCannotBecomeOutput(t *testing.T) {
	dir := t.TempDir()
	alias := filepath.Join(t.TempDir(), "parent-alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(dir, "absent-ancestor")
	artifact := filepath.Join(absent, "nested", "artifact.json")
	for _, output := range []string{absent, filepath.Join(alias, "absent-ancestor")} {
		if rejectOutputAliases(output, artifact) == nil {
			t.Fatal("missing input ancestor accepted as report")
		}
		if out, err := createPrivateAgainst(output, artifact); out != nil || err == nil {
			t.Fatal("missing input ancestor reserved as regular output")
		}
		if _, err := os.Lstat(absent); !os.IsNotExist(err) {
			t.Fatal("reservation altered missing input ancestor")
		}
	}
}

func TestArtifactImpactExistingAndBrokenSymlinkAliases(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.json")
	raw := []byte("private source bytes")
	privateTestFile(t, source, raw)
	hardlink := filepath.Join(dir, "existing-hardlink")
	if err := os.Link(source, hardlink); err != nil {
		t.Fatal(err)
	}
	if rejectOutputAliases(hardlink, source) == nil {
		t.Fatal("same-inode input/output alias accepted")
	}
	output := filepath.Join(dir, "missing-report")
	link := filepath.Join(dir, "broken-artifact-link")
	if err := os.Symlink(filepath.Base(output), link); err != nil {
		t.Fatal(err)
	}
	if got, err := createPrivateAgainst(output, source, link); got != nil || err == nil {
		t.Fatal("broken final symlink target was created as output")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("broken symlink target changed")
	}
	got, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("alias check changed original input")
	}
}

func TestArtifactImpactDistinctMissingSourcesRemainMissing(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "case.json")
	privateTestFile(t, input, []byte("case"))
	artifact := filepath.Join(dir, "absent-parent", "artifact.json")
	output := filepath.Join(dir, "report.json")
	out, err := createPrivateAgainst(output, input, artifact)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("complete synthetic report")
	if err := out.WriteAndSync(raw); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("distinct report bytes differ")
	}
	if info, err := os.Stat(output); err != nil || info.Mode() != 0o600 {
		t.Fatal("report not exact private regular600")
	}
	if _, err := os.Lstat(filepath.Dir(artifact)); !os.IsNotExist(err) {
		t.Fatal("report reservation created artifact ancestor")
	}
}

func TestArtifactImpactPinnedOutputParentRejectsRetarget(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "report-parent"), filepath.Join(dir, "artifact-parent")
	for _, path := range []string{first, second} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(dir, "administrative-alias")
	if err := os.Symlink(first, alias); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(alias, "same.json")
	artifact := filepath.Join(second, "same.json")
	p, err := acquirePrivateParent(output)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := acquirePrivateAliasGuard([]string{artifact})
	if err != nil {
		_ = p.root.Close()
		t.Fatal(err)
	}
	defer guard.close()
	if err := guard.check(p); err != nil {
		_ = p.root.Close()
		t.Fatal("initial distinct physical paths rejected")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(second, alias); err != nil {
		t.Fatal(err)
	}
	// This is exactly the check/reserve gap, without an implementation hook.
	if out, err := reservePrivate(p, guard); out != nil || err == nil {
		t.Fatal("parent retarget between check and reservation accepted")
	}
	for _, path := range []string{filepath.Join(first, "same.json"), artifact} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("retarget failure created an output or missing artifact")
		}
	}
}

func TestArtifactImpactInputSymlinkRetargetBeforeReservation(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "report.json")
	link := filepath.Join(dir, "artifact-link")
	if err := os.Symlink("missing-artifact", link); err != nil {
		t.Fatal(err)
	}
	p, err := acquirePrivateParent(output)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := acquirePrivateAliasGuard([]string{link})
	if err != nil {
		_ = p.root.Close()
		t.Fatal(err)
	}
	defer guard.close()
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(output), link); err != nil {
		t.Fatal(err)
	}
	if out, err := reservePrivate(p, guard); out != nil || err == nil {
		t.Fatal("input retarget between check and reservation accepted")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("input retarget failure created output")
	}
}

func TestArtifactImpactAliasErrorsAreStatic(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "private-identity-secret")
	for _, err := range []error{rejectOutputAliases(secretPath, secretPath), rejectOutputAliases(filepath.Join(secretPath, "missing-parent", "out"), secretPath)} {
		if err == nil || strings.Contains(err.Error(), "private-identity-secret") || strings.Contains(err.Error(), "no such") || err.Error() != errPrivateAlias.Error() {
			t.Fatal("alias error was not fixed private code")
		}
	}
}

func TestPrivateFilesReadPreservesBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "command.json")
	raw := []byte(" \n{\"request_id\":\"req\", \"expected_revision\":1}\t\r\n")
	privateTestFile(t, path, raw)
	got, err := readPrivate(path, int64(len(raw)))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("original bytes changed: %v", err)
	}
	got[0] = 'x'
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(unchanged, raw) {
		t.Fatal("returned storage is not independently owned")
	}
}

func TestPrivateFilesRejectUnsafeInputs(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o400, 0o600 | os.ModeSetuid} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret")
			privateTestFile(t, path, []byte("secret"))
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := readPrivate(path, 64); err == nil {
				t.Fatal("unsafe permission bits accepted")
			}
		})
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	privateTestFile(t, path, []byte("secret"))
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{dir, link, filepath.Join(dir, "missing")} {
		if _, err := readPrivate(input, 64); err == nil {
			t.Fatal("nonregular, symlink or missing file accepted")
		}
	}
	if _, err := readPrivate(path, 5); err == nil {
		t.Fatal("oversized input accepted")
	}
	for _, limit := range []int64{-1, 0, math.MaxInt64} {
		if _, err := readPrivate(path, limit); err != errPrivateLimit {
			t.Fatal("unsafe limit did not return a static error")
		}
	}
}

func TestPrivateFilesFIFOIsNonblockingAndRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		_, err := readPrivate(path, 64)
		finished <- err
	}()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO acquisition blocked")
	}
	// Exercise the final-component open flags too: a FIFO replacing a regular
	// file between its lstat and open must not make that open block.
	parent, err := acquirePrivateParent(path)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.root.Close()
	opened := make(chan error, 1)
	go func() {
		f, err := openPrivateRead(parent.root, parent.name)
		if f != nil {
			_ = f.Close()
		}
		opened <- err
	}()
	select {
	case <-opened:
	case <-time.After(2 * time.Second):
		t.Fatal("guarded final-component open blocked")
	}
}

func TestPrivateFilesStableAcquisitionRejectsReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	privateTestFile(t, path, []byte("original"))
	in, err := openPrivateInput(path)
	if err != nil {
		t.Fatal(err)
	}
	defer in.close()
	if err := os.Rename(path, path+".retained"); err != nil {
		t.Fatal(err)
	}
	privateTestFile(t, path, []byte("original"))
	if in.verify() == nil {
		t.Fatal("same-content replacement accepted")
	}
}

func TestPrivateFilesStableAcquisitionRejectsRestoredMtime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	privateTestFile(t, path, []byte("original"))
	in, err := openPrivateInput(path)
	if err != nil {
		t.Fatal(err)
	}
	defer in.close()
	privateTestFile(t, path, []byte("modified"))
	if err := os.Chtimes(path, in.before.ModTime(), in.before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := in.file.Stat()
	if err != nil || in.before.Size() != after.Size() || !in.before.ModTime().Equal(after.ModTime()) {
		t.Fatal("fixture did not preserve size and mtime")
	}
	if in.verify() == nil {
		t.Fatal("rewrite with restored mtime accepted")
	}
}

func TestPrivateFilesPhysicalParentAliasesAndReplacement(t *testing.T) {
	base := t.TempDir()
	physical := filepath.Join(base, "physical")
	if err := os.Mkdir(physical, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(physical, alias); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(alias, "secret")
	privateTestFile(t, path, []byte("original"))
	if got, err := readPrivate(path, 64); err != nil || string(got) != "original" {
		t.Fatal("one-time administrative alias resolution failed")
	}
	in, err := openPrivateInput(path)
	if err != nil {
		t.Fatal(err)
	}
	defer in.close()
	if err := os.Rename(physical, physical+".retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(physical, 0o700); err != nil {
		t.Fatal(err)
	}
	privateTestFile(t, path, []byte("original"))
	if in.verify() == nil {
		t.Fatal("physical ancestor replacement accepted")
	}
}

func TestPrivateFilesOutputExclusiveAndSynced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	out, err := createPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	raw := []byte(" {\"private\":true}\n")
	if err := out.WriteAndSync(raw); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	info, statErr := os.Lstat(path)
	if err != nil || statErr != nil || !bytes.Equal(got, raw) || !isPrivateRegular(info) {
		t.Fatal("private output bytes or permissions differ")
	}
	if err := out.WriteAndSync([]byte("replacement")); err == nil {
		t.Fatal("second write accepted")
	}
	if _, err := createPrivate(path); err == nil {
		t.Fatal("existing private report overwritten")
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil || out.WriteAndSync(raw) == nil {
		t.Fatal("close is not idempotent or closed write accepted")
	}
	unchanged, _ := os.ReadFile(path)
	if !bytes.Equal(unchanged, raw) {
		t.Fatal("existing output changed")
	}
}

func TestPrivateFilesOutputRejectsExistingSpecialPaths(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	privateTestFile(t, target, []byte("keep"))
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{target, link, fifo, dir} {
		if _, err := createPrivate(path); err == nil {
			t.Fatal("existing regular or special path accepted")
		}
	}
	got, _ := os.ReadFile(target)
	if string(got) != "keep" {
		t.Fatal("symlink target changed")
	}
}

func TestPrivateFilesOutputReplacementAndMetadataFailure(t *testing.T) {
	for _, mutation := range []string{"replace", "chmod", "close"} {
		t.Run(mutation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private")
			out, err := createPrivate(path)
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			switch mutation {
			case "replace":
				if err := os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
				privateTestFile(t, path, []byte("keep"))
			case "chmod":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "close":
				if err := out.file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := out.WriteAndSync([]byte("secret")); err != errPrivateWrite {
				t.Fatal("damaged reservation did not fail with a static error")
			}
			got, err := os.ReadFile(path)
			if err != nil || mutation == "replace" && string(got) != "keep" || mutation != "replace" && len(got) != 0 {
				t.Fatal("failed output deleted or overwrote reserved/replacement bytes")
			}
		})
	}
}

func TestPrivateFilesCompetingReservationsHaveOneOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "command")
	start := make(chan struct{})
	results := make(chan *privateOutput, 2)
	var workers sync.WaitGroup
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			out, _ := createPrivate(path)
			results <- out
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	winners := 0
	for out := range results {
		if out != nil {
			winners++
			if out.WriteAndSync([]byte("one owner")) != nil || out.Close() != nil {
				t.Fatal("winning reservation failed")
			}
		}
	}
	if winners != 1 {
		t.Fatal("exclusive output did not choose exactly one owner")
	}
}

func TestPrivateFilesErrorsNeverDisclosePaths(t *testing.T) {
	secret := "private-path-value-must-not-leak"
	path := filepath.Join(t.TempDir(), secret, "missing")
	_, readErr := readPrivate(path, 64)
	_, createErr := createPrivate(path)
	for _, err := range []error{readErr, createErr} {
		if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "no such file") {
			t.Fatal("private operating-system error leaked")
		}
	}
}
