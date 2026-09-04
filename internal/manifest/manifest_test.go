package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mk(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestWriteThenVerify(t *testing.T) {
	dir := mk(t, map[string]string{"a.exe": "aaa", "tools/b.exe": "bbb"})
	got, err := Write(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["tools/b.exe"] == "" {
		t.Fatalf("bad hashes: %v", got)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	if !strings.Contains(string(body), "  tools/b.exe\n") {
		t.Fatalf("manifest format wrong:\n%s", body)
	}
	if _, err := Verify(dir); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyDetectsTamperAndMissing(t *testing.T) {
	dir := mk(t, map[string]string{"a.exe": "aaa", "b.exe": "bbb"})
	if _, err := Write(dir); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "a.exe"), []byte("evil"), 0o644)
	os.Remove(filepath.Join(dir, "b.exe"))
	_, err := Verify(dir)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "a.exe") || !strings.Contains(err.Error(), "b.exe") {
		t.Fatalf("error must name both files: %v", err)
	}
}

func TestVerifyRejectsMalformedLine(t *testing.T) {
	dir := mk(t, map[string]string{"manifest.sha256": "not a manifest\n"})
	if _, err := Verify(dir); err == nil {
		t.Fatal("expected parse error")
	}
}
