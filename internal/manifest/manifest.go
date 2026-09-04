// Package manifest writes and verifies payload/manifest.sha256.
package manifest

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const FileName = "manifest.sha256"

func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func Write(dir string) (map[string]string, error) {
	hashes := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if rel == FileName {
			return nil
		}
		h, err := HashFile(p)
		if err != nil {
			return err
		}
		hashes[rel] = h
		return nil
	})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(hashes))
	for n := range hashes {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "%s  %s\n", hashes[n], n)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(b.String()), 0o644); err != nil {
		return nil, err
	}
	return hashes, nil
}

func Verify(dir string) (map[string]string, error) {
	f, err := os.Open(filepath.Join(dir, FileName))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	expected := map[string]string{}
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		txt := sc.Text()
		if strings.TrimSpace(txt) == "" {
			continue
		}
		parts := strings.SplitN(txt, "  ", 2)
		if len(parts) != 2 || len(parts[0]) != 64 {
			return nil, fmt.Errorf("%s line %d: malformed", FileName, line)
		}
		expected[parts[1]] = parts[0]
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	var errs []error
	for rel, want := range expected {
		got, err := HashFile(filepath.Join(dir, filepath.FromSlash(rel)))
		switch {
		case errors.Is(err, os.ErrNotExist):
			errs = append(errs, fmt.Errorf("missing: %s", rel))
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", rel, err))
		case got != want:
			errs = append(errs, fmt.Errorf("hash mismatch: %s", rel))
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return expected, nil
}
