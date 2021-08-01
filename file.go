package execbin

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

type FileType int

const (
	UnknownFormat FileType = iota
	ELF
	MachO
	PE
)

func (t FileType) String() string {
	switch t {
	case ELF:
		return "elf"
	case MachO:
		return "macho"
	case PE:
		return "pe"
	default:
		// fallthrough
	}
	return ""
}

type File interface {
	Type() FileType
	DefinedInterfaceTypes() ([]*InterfaceType, error)
}

func Open(path string) (File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 16)
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, err
	}
	f.Seek(0, 0)
	if bytes.HasPrefix(data, []byte("\x7FELF")) {
		exec, err := NewELFFile(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return exec, nil
	}
	if bytes.HasPrefix(data, []byte("MZ")) {
		exec, err := NewPEFile(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return exec, nil
	}
	if bytes.HasPrefix(data, []byte("\xFE\xED\xFA")) || bytes.HasPrefix(data[1:], []byte("\xFA\xED\xFE")) {
		exec, err := NewMachOFile(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return exec, nil
	}
	return nil, fmt.Errorf("execbin: unknown format")
}
