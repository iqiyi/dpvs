package settings

import (
	"errors"
	"fmt"
	"strings"
)

func MergedError(errs []error) error {
	if len(errs) <= 0 {
		return nil
	}
	var msg []string
	for _, e := range errs {
		msg = append(msg, e.Error())
	}
	return errors.New(fmt.Sprintf("errors: %s", strings.Join(msg, "\n")))
}
