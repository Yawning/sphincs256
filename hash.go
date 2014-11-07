// hash.go - sphincs256/ref/hash.[h,c]
//
// Note: The choice of digest algorithms here seems sort of arbitrary.  In
// theory SHA256/SHA512 can also be used, however this implementation uses
// BLAKE256/BLAKE512 to be consistent with the original.

package sphincs256

import (
	"github.com/dchest/blake256"
	"github.com/dchest/blake512"

	"github.com/yawning/sphincs256/chacha"
)

const (
	hashc = "expand 32-byte to 64-byte state!"
)

func varlenHash(out, in []byte) {
	h := blake256.New()
	h.Write(in)
	tmp := h.Sum(nil)
	copy(out[:], tmp[:])
	zerobytes(tmp[:])
}

func msgHash(out, in []byte) {
	h := blake512.New()
	h.Write(in)
	tmp := h.Sum(nil)
	copy(out[:], tmp[:])
	zerobytes(tmp[:])
}

func hash2nN(out, in []byte) {
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
	for i := 0; i < 32; i++ {
		out[i] = x[i]
	}
}

func hash2nNMask(out, in, mask []byte) {
	var buf [2 * hashBytes]byte
	for i := 0; i < len(buf); i++ {
		buf[i] = in[i] ^ mask[i]
	}
	hash2nN(out, buf[:])
}

func hashNN(out, in []byte) {
	var x [64]byte
	for i := 0; i < 32; i++ {
		x[i] = in[i]
		x[i+32] = hashc[i]
	}
	chacha.Permute(&x, &x)
	for i := 0; i < 32; i++ {
		out[i] = x[i]
	}
}

func hashNNMask(out, in, mask []byte) {
	var buf [hashBytes]byte
	for i := 0; i < len(buf); i++ {
		buf[i] = in[i] ^ mask[i]
	}
	hashNN(out, buf[:])
}

func init() {
	if hashBytes != 32 {
		panic("Current code only supports 32-byte hashes")
	}
}
