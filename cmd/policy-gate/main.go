package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/gatehttp"
	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	f := flag.NewFlagSet("policy-gate", flag.ContinueOnError)
	f.SetOutput(stderr)
	state := f.String("state", "", "Trusted state directory (required)")
	addr := f.String("addr", "127.0.0.1:8090", "Loopback HTTP listen address")
	initFile := f.String("init", "", "Initialize new state from trusted bootstrap JSON and exit")
	tokenFile := f.String("token-file", "", "New private credential file for one-principal initialization")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *state == "" {
		return errors.New("provide -state and no positional arguments")
	}
	if *initFile != "" {
		return initialize(*state, *initFile, *tokenFile, stdout)
	}
	if *tokenFile != "" {
		return errors.New("-token-file is used only with -init")
	}
	if err := loopback(*addr); err != nil {
		return err
	}
	store, err := admission.Open(*state)
	if err != nil {
		return err
	}
	defer store.Close()
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	s := &http.Server{Handler: gatehttp.Handler(store), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(shutdown)
	}()
	fmt.Fprintf(stdout, "Gooo machine request gate: http://%s\n", ln.Addr())
	if err := s.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func initialize(dir, source, tokenFile string, stdout io.Writer) error {
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	var bootstrap admission.Bootstrap
	if err := jsoninput.Decode(raw, &bootstrap, 1<<20); err != nil {
		return err
	}
	// Artifact locations are administrative init-file paths, never API input.
	// Persist their absolute identity so working-directory changes do not select
	// a different artifact during later admissions.
	if bootstrap.Schema == admission.BootstrapSchemaV2 {
		sourcePath, err := filepath.Abs(source)
		if err != nil {
			return err
		}
		for i := range bootstrap.Artifacts {
			if !filepath.IsAbs(bootstrap.Artifacts[i].Path) {
				bootstrap.Artifacts[i].Path = filepath.Join(filepath.Dir(sourcePath), bootstrap.Artifacts[i].Path)
			}
			// Resolve administrative directory aliases once at initialization;
			// the final artifact itself must never be a symlink. The reader later
			// traverses this persisted physical path without following symlinks.
			parent, err := filepath.EvalSymlinks(filepath.Dir(bootstrap.Artifacts[i].Path))
			if err != nil {
				return errors.New("artifact parent directory must exist at initialization")
			}
			bootstrap.Artifacts[i].Path = filepath.Join(parent, filepath.Base(bootstrap.Artifacts[i].Path))
		}
	}
	if len(bootstrap.Principals) != 1 || bootstrap.Principals[0].TokenSHA256 != "" || tokenFile == "" {
		return errors.New("CLI initialization requires one principal with an empty token_sha256 and a new -token-file")
	}
	statePath, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	credentialPath, err := filepath.Abs(tokenFile)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(statePath, credentialPath)
	if err != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("keep -token-file outside the new state directory")
	}
	if _, err := os.Lstat(dir); err == nil || !os.IsNotExist(err) {
		return errors.New("initialization requires a state directory that does not exist")
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return err
	}
	token := hex.EncodeToString(secret[:])
	digest := sha256.Sum256([]byte(token))
	bootstrap.Principals[0].TokenSHA256 = hex.EncodeToString(digest[:])
	if err := admission.ValidateBootstrap(bootstrap); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(tokenFile), 0o700); err != nil {
		return err
	}
	credential, err := os.OpenFile(tokenFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := credential.Chmod(0o600); err != nil {
		_ = credential.Close()
		return err
	}
	if _, err := io.WriteString(credential, token+"\n"); err != nil {
		_ = credential.Close()
		return err
	}
	if err := credential.Sync(); err != nil {
		_ = credential.Close()
		return err
	}
	if err := credential.Close(); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(tokenFile))
	if err != nil {
		return err
	}
	err = parent.Sync()
	closeErr = parent.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := admission.Init(dir, bootstrap); err != nil {
		// A failed initialization may have persisted a snapshot before a sync
		// error. Preserve the exclusively created credential for recovery.
		return fmt.Errorf("initialization failed; private credential retained at %s: %w", tokenFile, err)
	}
	_, err = fmt.Fprintf(stdout, "Initialized local state. Private credential saved at %s.\n", tokenFile)
	return err
}

func loopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("listen address must contain a literal loopback IP and port")
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || n < 0 || n > 65535 {
		return errors.New("only literal loopback IP addresses and ports 0..65535 are supported")
	}
	return nil
}
