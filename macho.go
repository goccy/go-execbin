package execbin

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"os"
	"reflect"
	"strings"
	"unsafe"
)

const uintptrSize = 4 << (^uintptr(0) >> 63)

func NewMachOFile(f *os.File) (*MachOFile, error) {
	exec, err := macho.NewFile(f)
	if err != nil {
		return nil, err
	}
	return &MachOFile{
		File:    exec,
		rawFile: f,
	}, nil
}

type MachOFile struct {
	File    *macho.File
	rawFile *os.File
}

func (f *MachOFile) Type() FileType { return MachO }

func (f *MachOFile) detectByteOrder() (bo binary.ByteOrder, e error) {
	dat, err := f.File.Section("__typelink").Data()
	if err != nil {
		e = err
		return
	}
	if len(dat) < 16 {
		e = fmt.Errorf("failed to detect byte order. data length (%d) is smaller than 16", len(dat))
		return
	}
	bigEndian := dat[15] != 0
	if bigEndian {
		return binary.BigEndian, nil
	}
	return binary.LittleEndian, nil
}

func (f *MachOFile) DefinedInterfaceTypes() ([]*InterfaceType, error) {
	var itabSyms []*macho.Symbol
	for _, sym := range f.File.Symtab.Syms {
		sym := sym
		if strings.HasPrefix(sym.Name, "go.itab.") {
			itabSyms = append(itabSyms, &sym)
		}
	}
	bo, err := f.detectByteOrder()
	if err != nil {
		return nil, err
	}
	rodataSect := f.File.Section("__rodata")
	rodata, err := rodataSect.Data()
	if err != nil {
		return nil, err
	}

	var ret []*InterfaceType
	for _, itabSym := range itabSyms {
		splittedNames := strings.Split(itabSym.Name, ",")
		if len(splittedNames) < 2 {
			return nil, fmt.Errorf("failed to get symbol name for itab %s", itabSym.Name)
		}
		itabV, err := f.decodeItab(rodataSect.Addr, rodata, itabSym.Value, bo)
		if err != nil {
			return nil, err
		}
		methods := make([]*Method, 0, len(itabV.inter.mhdr))
		for _, hdr := range itabV.inter.mhdr {
			if int(hdr.name) == int(hdr.ityp) ||
				hdr.name <= 0 || int(hdr.name) > len(rodata) ||
				hdr.ityp <= 0 || int(hdr.ityp) > len(rodata) {
				continue
			}
			text, err := f.nameOffToText(hdr.name, rodata, bo)
			if err != nil {
				return nil, err
			}
			ftype, err := f.decodeFuncType(rodata, uint64(hdr.ityp), bo)
			if err != nil {
				return nil, err
			}
			signature, err := f.nameOffToText(ftype.str, rodata, bo)
			if err != nil {
				return nil, err
			}
			if signature[0] == '*' {
				signature = signature[1:]
			}
			inTypes, err := ftype.in(rodataSect.Addr, rodata, uint64(hdr.ityp), bo)
			if err != nil {
				return nil, err
			}
			in := make([]*Type, 0, len(inTypes))
			for _, t := range inTypes {
				text, err := f.nameOffToText(t.str, rodata, bo)
				if err != nil {
					return nil, err
				}
				var isPointer bool
				if t.kind&kindMask != uint8(reflect.Ptr) {
					text = removePointerFromName(text)
				} else {
					isPointer = true
				}
				pkgPath, typeName := splitPkgPathAndName(text)
				in = append(in, &Type{
					Name:      typeName,
					PkgPath:   pkgPath,
					IsPointer: isPointer,
				})
			}
			outTypes, err := ftype.out(rodataSect.Addr, rodata, uint64(hdr.ityp), bo)
			if err != nil {
				return nil, err
			}
			out := make([]*Type, 0, len(outTypes))
			for _, t := range outTypes {
				text, err := f.nameOffToText(t.str, rodata, bo)
				if err != nil {
					return nil, err
				}
				var isPointer bool
				if t.kind&kindMask != uint8(reflect.Ptr) {
					text = removePointerFromName(text)
				} else {
					isPointer = true
				}
				pkgPath, typeName := splitPkgPathAndName(text)
				out = append(out, &Type{
					Name:      typeName,
					PkgPath:   pkgPath,
					IsPointer: isPointer,
				})
			}
			methods = append(methods, &Method{
				Name:      text,
				Signature: signature,
				In:        in,
				Out:       out,
			})
		}
		typeName := splittedNames[1]
		pkgPath, ifaceName := splitPkgPathAndName(typeName)
		implemented, err := f.nameOffToText(itabV._type.str, rodata, bo)
		if err != nil {
			return nil, err
		}
		implemented = removePointerFromName(implemented)
		ret = append(ret, &InterfaceType{
			Name:        ifaceName,
			Implemented: implemented,
			PkgPath:     pkgPath,
			Methods:     methods,
		})
	}
	return ret, nil
}

func splitPkgPathAndName(name string) (string, string) {
	splittedName := strings.Split(name, ".")
	var (
		pkgPath  string
		typeName string
	)
	if len(splittedName) == 1 {
		typeName = splittedName[0]
	} else {
		pkgPath = splittedName[0]
		typeName = splittedName[1]
	}
	return pkgPath, typeName
}

func removePointerFromName(name string) string {
	if name[0] == '*' {
		return name[1:]
	}
	return name
}

type sliceHeader struct {
	data unsafe.Pointer
	len  int
	cap  int
}

// FYI: https://github.com/golang/go/blob/b8ca6e59eda969c1d3aed9b0c5bd9e99cf0e7dfe/src/runtime/runtime2.go#L893-L899
type itab struct {
	inter *interfacetype
	_type *_type
	hash  uint32
	_     [4]byte
	fun   [1]uintptr
}

// itabVA is type represented by virtual address about itab
type itabVA struct {
	inter unsafe.Pointer
	_type unsafe.Pointer
	hash  uint32
	_     [4]byte
	fun   [1]uintptr
}

// FYI: https://github.com/golang/go/blob/b8ca6e59eda969c1d3aed9b0c5bd9e99cf0e7dfe/src/runtime/type.go#L366-L370
type interfacetype struct {
	typ     _type
	pkgpath name
	mhdr    []imethod
}

// interfacetypeVA is type represented by virtual address about interfacetype
type interfacetypeVA struct {
	typ     _type
	pkgpath name
	mhdr    sliceHeader
}

// FYI: https://github.com/golang/go/blob/b8ca6e59eda969c1d3aed9b0c5bd9e99cf0e7dfe/src/runtime/type.go#L361-L364
type imethod struct {
	name nameOff
	ityp typeOff
}

type tflag uint8
type nameOff int32
type typeOff int32
type textOff int32

const (
	kindMask = (1 << 5) - 1
)

const (
	tflagUncommon      tflag = 1 << 0
	tflagExtraStar     tflag = 1 << 1
	tflagNamed         tflag = 1 << 2
	tflagRegularMemory tflag = 1 << 3
)

type name struct {
	bytes *byte
}

type uncommonType struct {
	pkgPath nameOff
	mcount  uint16
	xcount  uint16
	moff    uint32
	_       uint32
}

// FYI: https://github.com/golang/go/blob/b8ca6e59eda969c1d3aed9b0c5bd9e99cf0e7dfe/src/runtime/type.go#L31-L48
type _type struct {
	size       uintptr
	ptrdata    uintptr
	hash       uint32
	tflag      tflag
	align      uint8
	fieldAlign uint8
	kind       uint8
	equal      unsafe.Pointer
	gcdata     *byte
	str        nameOff
	ptrToThis  typeOff
}

type funcType struct {
	_type
	inCount  uint16
	outCount uint16
}

func (t *funcType) in(rodataAddr uint64, rodata []byte, funcAddr uint64, bo binary.ByteOrder) ([]*_type, error) {
	uadd := functypeSize
	if t.tflag&tflagUncommon != 0 {
		uadd += uint64(unsafe.Sizeof(uncommonType{}))
	}
	if t.inCount == 0 {
		return nil, nil
	}
	var ret []*_type
	addr := funcAddr + uint64(uadd)
	for i := 0; i < int(t.inCount); i++ {
		offset := uint64(i * uintptrSize)
		var typeAddr uint64
		if err := binary.Read(bytes.NewReader(rodata[addr+offset:addr+offset+uintptrSize]), bo, &typeAddr); err != nil {
			return nil, err
		}
		typ, err := decodeType(rodataAddr, rodata, typeAddr, bo)
		if err != nil {
			return nil, err
		}
		ret = append(ret, typ)
	}
	return ret, nil
}

func (t *funcType) out(rodataAddr uint64, rodata []byte, funcAddr uint64, bo binary.ByteOrder) ([]*_type, error) {
	uadd := functypeSize
	if t.tflag&tflagUncommon != 0 {
		uadd += uint64(unsafe.Sizeof(uncommonType{}))
	}
	outCount := t.outCount & (1<<15 - 1)
	if outCount == 0 {
		return nil, nil
	}
	var ret []*_type
	addr := funcAddr + uint64(uadd) + uint64(t.inCount)*uintptrSize
	for i := 0; i < int(outCount); i++ {
		offset := uint64(i * uintptrSize)
		var typeAddr uint64
		if err := binary.Read(bytes.NewReader(rodata[addr+offset:addr+offset+uintptrSize]), bo, &typeAddr); err != nil {
			return nil, err
		}
		typ, err := decodeType(rodataAddr, rodata, typeAddr, bo)
		if err != nil {
			return nil, err
		}
		ret = append(ret, typ)
	}
	return ret, nil
}

var (
	itabSize          = uint64(unsafe.Sizeof(itab{}))
	interfacetypeSize = uint64(unsafe.Sizeof(interfacetype{}))
	imethodSize       = uint64(unsafe.Sizeof(imethod{}))
	typeSize          = uint64(unsafe.Sizeof(_type{}))
	functypeSize      = uint64(unsafe.Sizeof(funcType{}))
)

func (f *MachOFile) decodeFuncType(rodata []byte, funcAddr uint64, bo binary.ByteOrder) (*funcType, error) {
	var v [7]int64
	if err := binary.Read(bytes.NewReader(rodata[funcAddr:funcAddr+functypeSize]), bo, &v); err != nil {
		return nil, err
	}
	return (*funcType)(unsafe.Pointer(&v)), nil
}

func (f *MachOFile) decodeItab(rodataAddr uint64, rodata []byte, itabAddr uint64, bo binary.ByteOrder) (*itab, error) {
	va, err := f.decodeItabVA(rodata, itabAddr-rodataAddr, bo)
	if err != nil {
		return nil, err
	}
	inter, err := f.decodeInterfacetype(rodataAddr, rodata, uint64(uintptr(va.inter)), bo)
	if err != nil {
		return nil, err
	}
	_type, err := decodeType(rodataAddr, rodata, uint64(uintptr(va._type)), bo)
	if err != nil {
		return nil, err
	}
	return &itab{
		inter: inter,
		_type: _type,
		hash:  va.hash,
		fun:   va.fun,
	}, nil
}

func (f *MachOFile) decodeItabVA(rodata []byte, offset uint64, bo binary.ByteOrder) (*itabVA, error) {
	var v [4]uint64
	if err := binary.Read(bytes.NewReader(rodata[offset:offset+itabSize]), bo, &v); err != nil {
		return nil, err
	}
	return (*itabVA)(unsafe.Pointer(&v)), nil
}

func decodeType(rodataAddr uint64, rodata []byte, typeAddr uint64, bo binary.ByteOrder) (*_type, error) {
	offset := typeAddr - rodataAddr
	var v [6]uint64
	if err := binary.Read(bytes.NewReader(rodata[offset:offset+typeSize]), bo, &v); err != nil {
		return nil, err
	}
	return (*_type)(unsafe.Pointer(&v)), nil
}

func (f *MachOFile) decodeInterfacetype(rodataAddr uint64, rodata []byte, interAddr uint64, bo binary.ByteOrder) (*interfacetype, error) {
	va, err := f.decodeInterfacetypeVA(rodata, interAddr-rodataAddr, bo)
	if err != nil {
		return nil, err
	}
	mhdr, err := f.decodeIMethods(rodataAddr, rodata, va.mhdr, bo)
	if err != nil {
		return nil, err
	}
	return &interfacetype{
		typ:     va.typ,
		pkgpath: va.pkgpath,
		mhdr:    mhdr,
	}, nil
}

func (f *MachOFile) decodeInterfacetypeVA(rodata []byte, offset uint64, bo binary.ByteOrder) (*interfacetypeVA, error) {
	var v [10]int64
	if err := binary.Read(bytes.NewReader(rodata[offset:offset+interfacetypeSize]), bo, &v); err != nil {
		return nil, err
	}
	return (*interfacetypeVA)(unsafe.Pointer(&v)), nil
}

func (f *MachOFile) decodeIMethods(rodataAddr uint64, rodata []byte, mhdr sliceHeader, bo binary.ByteOrder) ([]imethod, error) {
	start := uint64(uintptr(mhdr.data) - uintptr(rodataAddr))
	end := start
	var methods []imethod
	for i := uint64(0); i < uint64(mhdr.len); i++ {
		start += i * imethodSize
		end += (i + 1) * imethodSize
		var hdr uint64
		if err := binary.Read(bytes.NewReader(rodata[start:end]), bo, &hdr); err != nil {
			return nil, err
		}
		methods = append(methods, *(*imethod)(unsafe.Pointer(&hdr)))
	}
	return methods, nil
}

func (f *MachOFile) nameOffToText(name nameOff, data []byte, bo binary.ByteOrder) (string, error) {
	var hdr [4]byte
	if err := binary.Read(bytes.NewReader(data[name:name+4]), bo, &hdr); err != nil {
		return "", err
	}
	var text string
	textHeader := (*sliceHeader)(unsafe.Pointer(&text))
	textHeader.data = unsafe.Pointer(&data[name+3])
	textHeader.len = int(hdr[1])<<8 | int(hdr[2])
	return text, nil
}
