package execbin_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/goccy/go-execbin"
)

func TestMachO(t *testing.T) {
	path := filepath.Join("testdata", "main_macho")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := execbin.NewMachOFile(file)
	if err != nil {
		t.Fatal(err)
	}
	ifaceTypes, err := f.DefinedInterfaceTypes()
	if err != nil {
		t.Fatal(err)
	}
	if len(ifaceTypes) != 1 {
		t.Fatalf("failed to get defined interface types. got types are %d", len(ifaceTypes))
	}
	if !reflect.DeepEqual(ifaceTypes[0], &execbin.InterfaceType{
		Name:        "error",
		Implemented: "runtime.errorString",
		PkgPath:     "",
		Methods: []*execbin.Method{
			&execbin.Method{
				Name:      "Error",
				Signature: "func() string",
				In:        []*execbin.Type{},
				Out: []*execbin.Type{
					&execbin.Type{
						Name:      "string",
						PkgPath:   "",
						IsPointer: false,
					},
				},
			},
		},
	}) {
		t.Fatalf("failed to get defined interface types. got %+v", ifaceTypes[0])
	}
}
