// chacha.go - sphincs256/ref/permute.[h,c], prg.[h,c]

// Package chacha implements the ChaCha12 stream cipher along with the
// SPHINCS-256 permutation function.  It is only suitable for use as part of
// the "sphincs256" package and should not be used for anything else.
//
// The implementation is based off the SUPERCOP "ref" portable C implementation
// with the macros inlined.
package chacha

import (
	"encoding/binary"
	"strconv"
)

const (
	sigma        = "expand 32-byte k"
	tau          = "expand 16-byte k"
	chachaRounds = 12
)

type ctx struct {
	input [16]uint32
}

func (x *ctx) ivSetup(iv []byte) {
	x.input[12] = 0
	x.input[13] = 0
	x.input[14] = binary.LittleEndian.Uint32(iv[0:])
	x.input[15] = binary.LittleEndian.Uint32(iv[4:])
}

func (x *ctx) encryptBytes(m []byte, c []byte) {
	var output [64]byte
	bytes := len(m)
	cc := c
	mm := m

	if bytes <= 0 {
		return
	}
	for {
		salsa20WordToByte(&output, &x.input)
		x.input[12]++
		if x.input[12] == 0 {
			x.input[13]++
			/* stopping at 2^70 bytes per nonce is the user's responsibility */
		}
		if bytes <= len(output) {
			for i := 0; i < bytes; i++ {
				cc[i] = mm[i] ^ output[i]
			}
			return
		}
		for i := 0; i < len(output); i++ {
			cc[i] = mm[i] ^ output[i]
		}
		bytes -= 64
		cc = cc[64:]
		mm = mm[64:]
	}
}

func (x *ctx) keystreamBytes(stream []byte) {
	for i := 0; i < len(stream); i++ {
		stream[i] = 0
	}
	x.encryptBytes(stream, stream)
}

func newCtx(k []byte) *ctx {
	var constants []byte
	x := &ctx{}

	x.input[4] = binary.LittleEndian.Uint32(k[0:])
	x.input[5] = binary.LittleEndian.Uint32(k[4:])
	x.input[6] = binary.LittleEndian.Uint32(k[8:])
	x.input[7] = binary.LittleEndian.Uint32(k[12:])
	switch len(k) * 8 {
	case 256:
		constants = []byte(sigma)
		k = k[16:]
	case 128:
		constants = []byte(tau)
	default:
		panic("chacha12: invalid key size " + strconv.Itoa(len(k)))
	}
	x.input[8] = binary.LittleEndian.Uint32(k[0:])
	x.input[9] = binary.LittleEndian.Uint32(k[4:])
	x.input[10] = binary.LittleEndian.Uint32(k[8:])
	x.input[11] = binary.LittleEndian.Uint32(k[12:])
	x.input[0] = binary.LittleEndian.Uint32(constants[0:])
	x.input[1] = binary.LittleEndian.Uint32(constants[4:])
	x.input[2] = binary.LittleEndian.Uint32(constants[8:])
	x.input[3] = binary.LittleEndian.Uint32(constants[12:])
	return x
}

func keystreamBytes(c, n, k []byte) {
	ctx := newCtx(k)
	ctx.ivSetup(n)
	ctx.keystreamBytes(c)
}

// Prg is the SPHINCS-256 entropy expansion routine.  It fills 'r' with the
// ChaCha12 keystream for key 'k', with an all zero nonce.
func Prg(r []byte, k []byte) {
	var prgNonce [8]byte
	if len(k) != 32 {
		panic("key length != seedBytes: " + strconv.Itoa(len(k)))
	}
	keystreamBytes(r, prgNonce[:], k)
}

func doRounds(x *[16]uint32) {
	x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 := x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15]

	for i := chachaRounds; i > 0; i -= 2 {
		var xx uint32

		// quarterround(x, 0, 4, 8, 12)
		x0 += x4
		xx = x12 ^ x0
		x12 = (xx << 16) | (xx >> 16)
		x8 += x12
		xx = x4 ^ x8
		x4 = (xx << 12) | (xx >> 20)
		x0 += x4
		xx = x12 ^ x0
		x12 = (xx << 8) | (xx >> 24)
		x8 += x12
		xx = x4 ^ x8
		x4 = (xx << 7) | (xx >> 25)

		// quarterround(x, 1, 5, 9, 13)
		x1 += x5
		xx = x13 ^ x1
		x13 = (xx << 16) | (xx >> 16)
		x9 += x13
		xx = x5 ^ x9
		x5 = (xx << 12) | (xx >> 20)
		x1 += x5
		xx = x13 ^ x1
		x13 = (xx << 8) | (xx >> 24)
		x9 += x13
		xx = x5 ^ x9
		x5 = (xx << 7) | (xx >> 25)

		// quarterround(x, 2, 6, 10, 14)
		x2 += x6
		xx = x14 ^ x2
		x14 = (xx << 16) | (xx >> 16)
		x10 += x14
		xx = x6 ^ x10
		x6 = (xx << 12) | (xx >> 20)
		x2 += x6
		xx = x14 ^ x2
		x14 = (xx << 8) | (xx >> 24)
		x10 += x14
		xx = x6 ^ x10
		x6 = (xx << 7) | (xx >> 25)

		// quarterround(x, 3, 7, 11, 15)
		x3 += x7
		xx = x15 ^ x3
		x15 = (xx << 16) | (xx >> 16)
		x11 += x15
		xx = x7 ^ x11
		x7 = (xx << 12) | (xx >> 20)
		x3 += x7
		xx = x15 ^ x3
		x15 = (xx << 8) | (xx >> 24)
		x11 += x15
		xx = x7 ^ x11
		x7 = (xx << 7) | (xx >> 25)

		// quarterround(x, 0, 5, 10, 15)
		x0 += x5
		xx = x15 ^ x0
		x15 = (xx << 16) | (xx >> 16)
		x10 += x15
		xx = x5 ^ x10
		x5 = (xx << 12) | (xx >> 20)
		x0 += x5
		xx = x15 ^ x0
		x15 = (xx << 8) | (xx >> 24)
		x10 += x15
		xx = x5 ^ x10
		x5 = (xx << 7) | (xx >> 25)

		// quarterround(x, 1, 6, 11, 12)
		x1 += x6
		xx = x12 ^ x1
		x12 = (xx << 16) | (xx >> 16)
		x11 += x12
		xx = x6 ^ x11
		x6 = (xx << 12) | (xx >> 20)
		x1 += x6
		xx = x12 ^ x1
		x12 = (xx << 8) | (xx >> 24)
		x11 += x12
		xx = x6 ^ x11
		x6 = (xx << 7) | (xx >> 25)

		// quarterround(x, 2, 7, 8, 13)
		x2 += x7
		xx = x13 ^ x2
		x13 = (xx << 16) | (xx >> 16)
		x8 += x13
		xx = x7 ^ x8
		x7 = (xx << 12) | (xx >> 20)
		x2 += x7
		xx = x13 ^ x2
		x13 = (xx << 8) | (xx >> 24)
		x8 += x13
		xx = x7 ^ x8
		x7 = (xx << 7) | (xx >> 25)

		// quarterround(x, 3, 4, 9, 14)
		x3 += x4
		xx = x14 ^ x3
		x14 = (xx << 16) | (xx >> 16)
		x9 += x14
		xx = x4 ^ x9
		x4 = (xx << 12) | (xx >> 20)
		x3 += x4
		xx = x14 ^ x3
		x14 = (xx << 8) | (xx >> 24)
		x9 += x14
		xx = x4 ^ x9
		x4 = (xx << 7) | (xx >> 25)
	}
	x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15] = x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15
}

func salsa20WordToByte(output *[64]byte, input *[16]uint32) {
	var x [16]uint32
	copy(x[:], input[:])
	doRounds(&x)
	for i := 0; i < len(x); i++ {
		x[i] += input[i]
		binary.LittleEndian.PutUint32(output[4*i:], x[i])
	}
}
