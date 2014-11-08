// +build !i386,!amd64

package chacha

import (
	"encoding/binary"
)

// Permute is the modified permutation variant of the salsa20_wordtobyte()
// routine, used by SPHINCS-256's hashing.
func Permute(buf *[64]byte) {
	var x [16]uint32
	for i := 0; i < len(x); i++ {
		x[i] = binary.LittleEndian.Uint32(buf[4*i:])
	}
	doRounds(&x)
	// for (i = 0;i < 16;++i) x[i] = PLUS(x[i],input[i]); // XXX: Bad idea if we later xor the input to the state?
	for i := 0; i < len(x); i++ {
		binary.LittleEndian.PutUint32(buf[4*i:], x[i])
	}
}
