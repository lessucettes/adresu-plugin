//go:build !unix

package main

import "os"

func prepareStdin() (*os.File, error) {
	return os.Stdin, nil
}
