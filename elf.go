package execbin

import (
	"debug/elf"
	"fmt"
	"os"
)

func NewELFFile(f *os.File) (*ELFFile, error) {
	exec, err := elf.NewFile(f)
	if err != nil {
		return nil, err
	}
	return &ELFFile{
		File:    exec,
		rawFile: f,
	}, nil
}

type ELFFile struct {
	File    *elf.File
	rawFile *os.File
}

func (f *ELFFile) Type() FileType { return ELF }

func (f *ELFFile) DefinedInterfaceTypes() ([]*InterfaceType, error) {
	return nil, fmt.Errorf("execbin: not yet supported by elf")
}
