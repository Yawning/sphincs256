// +build i386 amd64

package chacha

import (
	"unsafe"
)

func Permute(x *[64]byte) {
	// Yes, this uses unsafe to bypass the type system.  It's ok since x will
	// always be valid, and this lets us pass x directly into the round
	// function skipping endian conversion sillyness.
	doRounds((*[16]uint32)(unsafe.Pointer(x)))
}
