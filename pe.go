package execbin

import (
	"debug/pe"
	"fmt"
	"os"
)

func NewPEFile(f *os.File) (*PEFile, error) {
	exec, err := pe.NewFile(f)
	if err != nil {
		return nil, err
	}
	return &PEFile{
		File:    exec,
		rawFile: f,
	}, nil
}

type PEFile struct {
	File    *pe.File
	rawFile *os.File
}

func (f *PEFile) Type() FileType { return PE }

func (f *PEFile) DefinedInterfaceTypes() ([]*InterfaceType, error) {
	return nil, fmt.Errorf("execbin: not yet supported by pe")
}
