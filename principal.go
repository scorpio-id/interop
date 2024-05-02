package main

// #cgo LDFLAGS: -lkrb5
// #include <stdlib.h>
// #include <stdio.h>
// #include <errno.h>
// #include <string.h>

/*

#include "./data.h"
#include "./errno-base.h"

static inline krb5_data* data_pointer_at_index(krb5_data *array, int index)
{
   return &array[index];
}

// MIT curiously doesn't supply a principal builder w/o va_list
// BE CAREFUL!
// This function assumes realm and components are allocated on the heap
// and takes ownership of the data *IFF* the return value is 0:
// When no error, *Don't* free realm/components your self
// Call krb5_free_principal on the resulting principal instead.
// This is to avoid multiple copies Govalue->Cvalue->KerberosValue
krb5_error_code
krb5_build_principal_allocated_data(krb5_context context,
                          krb5_principal * princ,
                          krb5_int32 name_type,
                          unsigned int rlen,
                          char * realm,
                          unsigned int clen,
                          krb5_data *components)
{
    krb5_principal p;

    if (!components)
        return EINVAL;

    p = malloc(sizeof(krb5_principal_data));
    if (p == NULL)
        return ENOMEM;

    p->type = name_type;
    p->magic = KV5M_PRINCIPAL;
    p->realm = make_data(realm, rlen);
    p->data = components;
    p->length = clen;

    *princ = p;

    return 0;
}

*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// principal.go begins here ...
type Principal struct {
	c *Context
	p C.krb5_principal // pointer type
}

func newPrincipalFromC(c *Context, p C.krb5_principal) *Principal {
	cp := &Principal{c, p}
	runtime.SetFinalizer(cp, (*Principal).free)
	return cp
}

func (p *Principal) free() {
	C.krb5_free_principal(p.c.toC(), p.p)
	p.p = nil
}

func (kc *Context) ParseName(name string) (*Principal, error) {
	var cp C.krb5_principal
	cname := C.CString(name)
	code := C.krb5_parse_name(kc.toC(), cname, &cp)
	if code != 0 {
		return nil, ErrorCode(code)
	}
	return newPrincipalFromC(kc, cp), nil
}

func (kc *Context) BuildPrincipal(nameType int32, realm string, components ...string) (*Principal, error) {
	var code C.krb5_error_code
	var cp C.krb5_principal

	comp_count := uint(len(components))

	//components_data := C.make_data_array(comp_count)
	components_data := makeKrb5DataArray(comp_count)

	if components_data == nil {
		return nil, ErrorCode(C.ENOMEM)
	}

	realm_data := C.CString(realm)
	if realm_data == nil {
		code = C.ENOMEM
	} else {

		for i, s := range components {
			data := unsafe.Pointer(C.CString(s))
			if data == nil {
				code = C.ENOMEM
				break
			}
			setKrb5DataArrayIdx(components_data, i, data, uint(len(s)))
			//C.set_data_array_idx(components_data, C.int(i), data, C.uint(len(s)))
		}
	}

	if code == 0 {
		code = C.krb5_build_principal_allocated_data(kc.toC(),
			&cp,
			C.krb5_int32(nameType),
			C.uint(len(realm)),
			realm_data,
			C.uint(comp_count),
			components_data,
		)
	}

	// Cleanup
	if code != 0 {
		freeKrb5DataArrayWithContent(components_data, comp_count)
		C.free(unsafe.Pointer(realm_data))
		return nil, ErrorCode(code)
	}

	return newPrincipalFromC(kc, cp), nil
}


func (p *Principal) Realm() string {
	return C.GoStringN(p.p.realm.data, C.int(p.p.realm.length))
}

func (p *Principal) Name() []string {
	elements := int(p.p.length)
	s := make ([]string,elements)
	for i, _ := range s {
		var dp *C.krb5_data
		dp = C.data_pointer_at_index(p.p.data, C.int(i))
		data := *dp
		s[i] = C.GoStringN(data.data, C.int(data.length))
	}

	return s
}

func (p *Principal) NameType() int32 {
	return int32(p.p._type)
}

func (p *Principal) UnparseName() (ret string, err error) {
	var cs *C.char
	code := C.krb5_unparse_name(p.c.toC(), p.p, &cs)
	if code != 0 {
		err = ErrorCode(code)
		return
	}
	ret =  C.GoString(cs)
	C.krb5_free_unparsed_name(p.c.toC(), cs)
	return

}

func (p *Principal) String() string {
	str, err := p.UnparseName()
	if err == nil {
		return str
	}
	return err.Error()
}

// context.go begins here ...
// MIT libkrb5 krb5_error_code.
type ErrorCode C.krb5_error_code

func (e ErrorCode) Code() int32 {
	return int32(e)
}

func (e ErrorCode) Error() string {
 	var cmsg *C.char
	cmsg = C.krb5_get_error_message(nil, C.krb5_error_code(e))
	gostr := C.GoString(cmsg)
	C.krb5_free_error_message(nil, cmsg) // seems like a NOOP
	return gostr
}

// Context is libkrb5 krb5_context and has all global operations a methods
// No method on Context or any returned objects are go-routine safe.

type Context struct {
	kctx unsafe.Pointer // a krb5_context
}

func (kc *Context) ErrorMessage(e ErrorCode) string {
	var cmsg *C.char
	cmsg = C.krb5_get_error_message(kc.toC(), C.krb5_error_code(e))
	gostr := C.GoString(cmsg)
	C.krb5_free_error_message(kc.toC(), cmsg)
	return gostr
}

func (kc *Context) toC() C.krb5_context {
	return C.krb5_context(kc.kctx)
}

// InitContext must be called to use Kerberos. It provides access to all global methods.
func InitContext() (ctx *Context, err error) {
	var kc C.krb5_context
	code := C.krb5_init_secure_context(&kc)
 	if code != 0 {
		err = ErrorCode(code)
		return
	}
	ctx = &Context{kctx: unsafe.Pointer(kc)}
	runtime.SetFinalizer(ctx, freeContext)
	return
}

// libkrb5 seems to make all free operations safe to call twice by
// making them a NOP if the pointer is nil.
func freeContext(kc *Context) {
	if kc.kctx != nil {
		C.krb5_free_context(C.krb5_context(kc.kctx))
	}
	kc.kctx = nil
}

func (kc *Context) Timeofday() (seconds, microseconds int32, err error) {
	var cs  C.krb5_timestamp
	var cms C.krb5_int32

	code := C.krb5_us_timeofday(kc.toC(), &cs, &cms)
	if code != 0 {
		err = ErrorCode(code)
		return
	}
	return int32(cs), int32(cms), nil
}

func (kc *Context) GetDefaultRealm() (realm string, err error) {
	var cstring *C.char
	code := C.krb5_get_default_realm(kc.toC(), &cstring)
	if code != 0 {
		err = ErrorCode(code)
		return
	}
	realm = C.GoString(cstring)
	C.krb5_free_default_realm(kc.toC(), cstring)
	return
}

func (kc *Context) SetDefaultRealm(realm string) (err error) {
	var cstring *C.char

	cstring = C.CString(realm)

	code := C.krb5_set_default_realm(kc.toC(), cstring)
	if code != 0 {
		err = ErrorCode(code)
		return
	}
	C.free(unsafe.Pointer(cstring))
	return
}

// main.go begins here ...
func main() {
	kctx, e := InitContext()
	if e != nil {
		fmt.Println(e)
	}

	var realm = "REALM"
	var components = []string{"some", "random", "principal"}
	var pnamestr = "some/random/principal@REALM"

	p1, err := kctx.BuildPrincipal(NT_PRINCIPAL, realm, components...)
	if err != nil {
		fmt.Println(err)
	}

	if p1.String() != pnamestr {
		fmt.Printf("Principal build failed, %s != %s\n", p1, pnamestr)
	}

	str, err := p1.UnparseName()
	if err != nil {
		fmt.Println(err)
	}

	p2, err := kctx.ParseName(str)
	if err != nil {
		fmt.Println(err)
	}

	nt, comp, r := p2.NameType(), p2.Name(), p2.Realm()

	var fail bool
	for i, c := range comp {
		if c != components[i] {
			fail = true
		}
	}

	if nt != NT_PRINCIPAL || r != realm || fail {
		fmt.Println("Principal ParseName Failed\n")
	}
}