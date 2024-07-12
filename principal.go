package main

// #cgo CFLAGS: -I /interop/mit/src/include
// #cgo LDFLAGS: -L /interop/mit/src/lib -Wl,-rpath,$ORIGIN
// #include <stdlib.h>
// #include <stdio.h>
// #include <errno.h>
// #include <string.h>
/*

#include "./data.h"
#include "./errno-base.h"
#include "./mit/src/lib/kadm5/admin.h"

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

static uint32_t api;
static krb5_boolean rpc;

static krb5_context context;

#define ADMIN_PASSWORD "resetme"
#define USER_PASSWORD "resetme"

static void *
get_handle(char *client)
{
    void *handle;
    char *service, *pass;

    if (client == NULL)
        return NULL;

    if (*client == '$') {
        service = KADM5_CHANGEPW_SERVICE;
        client++;
    } else {
        service = KADM5_ADMIN_SERVICE;
    }
    pass = (strcmp(client, "user") == 0) ? USER_PASSWORD : ADMIN_PASSWORD;

    check(kadm5_init(context, client, pass, service, NULL,
                     KADM5_STRUCT_VERSION, api, NULL, &handle));
    return handle;
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

// main.go begins here ...
func main() {
	kctx, e := InitContext()
	if e != nil {
		fmt.Println(e)
	}

	fmt.Println("we're running!")

	var realm = "SCORPIO.IO"
	var components = []string{"some", "random", "principal"}
	var pnamestr = "some/random/principal@SCORPIO.IO"

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

	// var handle *C.server_handle

	// handle := C.kadm5_init(kctx, "scorpio/admin", "resetme", "kadmin/admin", nil, C.KADM5_STRUCT_VERSION, C.api, nil, &handle)

	// C.kadm5_create_principal(handle, &p1, C.KADM5_PRINCIPAL, "resetme")
}