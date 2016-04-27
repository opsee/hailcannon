package util

import (
	"fmt"
	"reflect"

	log "github.com/sirupsen/logrus"
)

type Validatable interface {
	Validate() error
}

type Validator struct{}

func (this *Validator) Validate(caller Validatable) error {
	v := reflect.ValueOf(caller).Elem()
	missing := []string{}

	for i := 0; i < v.NumField(); i++ {
		typef := v.Type().Field(i)
		if typef.Tag.Get("required") == "true" {
			if IsZero(v.Field(i)) {
				log.WithFields(log.Fields{"validator": "Validate", "type": typef.Name}).Info(typef.Name, " is required.")
				missing = append(missing, typef.Name)
			}
		}
	}

	if len(missing) > 0 {
		missingnos := StringSpliceCat(", ", missing)
		return fmt.Errorf("Missing %s", missingnos)
	}
	return nil
}

func IsZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Func, reflect.Map, reflect.Slice:
		return v.IsNil()
	case reflect.Array:
		z := true
		for i := 0; i < v.Len(); i++ {
			z = z && IsZero(v.Index(i))
		}
		return z
	case reflect.Struct:
		z := true
		for i := 0; i < v.NumField(); i++ {
			z = z && IsZero(v.Field(i))
		}
		return z
	}
	// Compare other types directly:
	z := reflect.Zero(v.Type())
	return v.Interface() == z.Interface()
}

// faster string concatenation
func StringSpliceCat(seperator string, splice []string) string {
	// get size of buffer
	size := 0
	for i, _ := range splice {
		size += len(splice[i])
	}
	// add seperator
	size += len(seperator)*len(splice) - 1

	bs := make([]byte, size)
	bl := 0

	for n := 0; n < len(splice); n++ {
		bl += copy(bs[bl:], splice[n])
		if n < len(splice)-1 {
			bl += copy(bs[bl:], seperator)
		}
	}
	return string(bs[:len(bs)-1])
}
