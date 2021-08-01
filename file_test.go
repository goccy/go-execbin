package execbin_test

import (
	"path/filepath"
	"testing"

	"github.com/goccy/go-execbin"
)

func TestFile(t *testing.T) {
	path := filepath.Join("testdata", "main_macho")
	f, err := execbin.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type() != execbin.MachO {
		t.Fatal("failed to read macho file")
	}
}
