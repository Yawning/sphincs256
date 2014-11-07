// zerobytes.go - sphincs256/ref/zerobytes.[h,c]

// Package utils implements utility functions for the SPHINCS-256 signature
// algorithm.
package utils

// Zerobytes sets all the bytes in slice to 0x00.
func Zerobytes(r []byte) []byte {
	for i := 0; i < len(r); i++ {
		r[i] = 0
	}
	return r
}
