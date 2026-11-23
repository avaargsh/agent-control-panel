package authorityhttp

import "reflect"

// Distinguish a nil interface from a typed nil source. No reflection on
// request data; used solely for safe construction of an authority service.
func nilReaderInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
