// hash.go - sphincs256/ref/hash.[h,c]
//
// Note: The choice of digest algorithms here seems sort of arbitrary.  In
// theory SHA256/SHA512 can also be used, however this implementation uses
// BLAKE256/BLAKE512 to be consistent with the original.

// Package hash implements the various hash functions used by the SPHINCS-256
// HORST and WOTS signature schemes.
package hash

import (
	"github.com/dchest/blake256"
	"github.com/dchest/blake512"

	"github.com/yawning/sphincs256/chacha"
	"github.com/yawning/sphincs256/utils"
)

const (
	Size = 32
	hashc = "expand 32-byte to 64-byte state!"
)

func Varlen(out, in []byte) {
	h := blake256.New()
	h.Write(in)
	tmp := h.Sum(nil)
	copy(out[:], tmp[:])
	utils.Zerobytes(tmp[:])
}

func Msg(out, in []byte) {
	h := blake512.New()
	h.Write(in)
	tmp := h.Sum(nil)
	copy(out[:], tmp[:])
	utils.Zerobytes(tmp[:])
}

func Hash_2n_n(out, in []byte) {
	var x [64]byte
	for i := 0; i < 32; i++ {
		x[i] = in[i]
		x[i+32] = hashc[i]
	}
	chacha.Permute(&x, &x)
	for i := 0; i < 32; i++ {
		x[i] ^= in[i+32]
	}
	chacha.Permute(&x, &x)
	copy(out[:Size], x[:])
}

func Hash_2n_n_mask(out, in, mask []byte) {
	var buf [2 * Size]byte
	for i := 0; i < len(buf); i++ {
		buf[i] = in[i] ^ mask[i]
	}
	Hash_2n_n(out, buf[:])
}

func Hash_n_n(out, in []byte) {
	var x [64]byte
	for i := 0; i < 32; i++ {
		x[i] = in[i]
		x[i+32] = hashc[i]
	}
	chacha.Permute(&x, &x)
	copy(out[:Size], x[:])
}

func Hash_n_n_mask(out, in, mask []byte) {
	var buf [Size]byte
	for i := 0; i < len(buf); i++ {
		buf[i] = in[i] ^ mask[i]
	}
	Hash_n_n(out, buf[:])
}

func init() {
	if Size != 32 {
		panic("current code only supports 32-byte hashes")
	}
}
