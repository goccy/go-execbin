package execbin

type InterfaceType struct {
	Name        string
	Implemented string
	PkgPath     string
	Methods     []*Method
}

type Method struct {
	Name      string
	Signature string
	In        []*Type
	Out       []*Type
}

type Type struct {
	Name      string
	PkgPath   string
	IsPointer bool
}
