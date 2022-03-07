package main

/*
#ifndef _CORAZA_UTILS_H_
#define _CORAZA_UTILS_H_

#endif
*/
import "net/url"

import "C"

//export coraza_url_decode
func coraza_url_decode(input *C.char, out **C.char) C.int {
	s := C.GoString(input)
	u, err := url.Parse(s)
	if err != nil {
		return 0
	}
	*out = C.CString(u.String())
	return 0
}

func main() {}

