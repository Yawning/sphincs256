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
	var xx uint32

	// Note: Unrolling this doesn't seem to help much.
	for i := chachaRounds; i > 0; i -= 2 {
		// quarterround(x, 0, 4, 8, 12)
		x[0] += x[4]
		xx = x[12] ^ x[0]
		x[12] = (xx << 16) | (xx >> 16)
		x[8] += x[12]
		xx = x[4] ^ x[8]
		x[4] = (xx << 12) | (xx >> 20)
		x[0] += x[4]
		xx = x[12] ^ x[0]
		x[12] = (xx << 8) | (xx >> 24)
		x[8] += x[12]
		xx = x[4] ^ x[8]
		x[4] = (xx << 7) | (xx >> 25)

		// quarterround(x, 1, 5, 9, 13)
		x[1] += x[5]
		xx = x[13] ^ x[1]
		x[13] = (xx << 16) | (xx >> 16)
		x[9] += x[13]
		xx = x[5] ^ x[9]
		x[5] = (xx << 12) | (xx >> 20)
		x[1] += x[5]
		xx = x[13] ^ x[1]
		x[13] = (xx << 8) | (xx >> 24)
		x[9] += x[13]
		xx = x[5] ^ x[9]
		x[5] = (xx << 7) | (xx >> 25)

		// quarterround(x, 2, 6, 10, 14)
		x[2] += x[6]
		xx = x[14] ^ x[2]
		x[14] = (xx << 16) | (xx >> 16)
		x[10] += x[14]
		xx = x[6] ^ x[10]
		x[6] = (xx << 12) | (xx >> 20)
		x[2] += x[6]
		xx = x[14] ^ x[2]
		x[14] = (xx << 8) | (xx >> 24)
		x[10] += x[14]
		xx = x[6] ^ x[10]
		x[6] = (xx << 7) | (xx >> 25)

		// quarterround(x, 3, 7, 11, 15)
		x[3] += x[7]
		xx = x[15] ^ x[3]
		x[15] = (xx << 16) | (xx >> 16)
		x[11] += x[15]
		xx = x[7] ^ x[11]
		x[7] = (xx << 12) | (xx >> 20)
		x[3] += x[7]
		xx = x[15] ^ x[3]
		x[15] = (xx << 8) | (xx >> 24)
		x[11] += x[15]
		xx = x[7] ^ x[11]
		x[7] = (xx << 7) | (xx >> 25)

		// quarterround(x, 0, 5, 10, 15)
		x[0] += x[5]
		xx = x[15] ^ x[0]
		x[15] = (xx << 16) | (xx >> 16)
		x[10] += x[15]
		xx = x[5] ^ x[10]
		x[5] = (xx << 12) | (xx >> 20)
		x[0] += x[5]
		xx = x[15] ^ x[0]
		x[15] = (xx << 8) | (xx >> 24)
		x[10] += x[15]
		xx = x[5] ^ x[10]
		x[5] = (xx << 7) | (xx >> 25)

		// quarterround(x, 1, 6, 11, 12)
		x[1] += x[6]
		xx = x[12] ^ x[1]
		x[12] = (xx << 16) | (xx >> 16)
		x[11] += x[12]
		xx = x[6] ^ x[11]
		x[6] = (xx << 12) | (xx >> 20)
		x[1] += x[6]
		xx = x[12] ^ x[1]
		x[12] = (xx << 8) | (xx >> 24)
		x[11] += x[12]
		xx = x[6] ^ x[11]
		x[6] = (xx << 7) | (xx >> 25)

		// quarterround(x, 2, 7, 8, 13)
		x[2] += x[7]
		xx = x[13] ^ x[2]
		x[13] = (xx << 16) | (xx >> 16)
		x[8] += x[13]
		xx = x[7] ^ x[8]
		x[7] = (xx << 12) | (xx >> 20)
		x[2] += x[7]
		xx = x[13] ^ x[2]
		x[13] = (xx << 8) | (xx >> 24)
		x[8] += x[13]
		xx = x[7] ^ x[8]
		x[7] = (xx << 7) | (xx >> 25)

		// quarterround(x, 3, 4, 9, 14)
		x[3] += x[4]
		xx = x[14] ^ x[3]
		x[14] = (xx << 16) | (xx >> 16)
		x[9] += x[14]
		xx = x[4] ^ x[9]
		x[4] = (xx << 12) | (xx >> 20)
		x[3] += x[4]
		xx = x[14] ^ x[3]
		x[14] = (xx << 8) | (xx >> 24)
		x[9] += x[14]
		xx = x[4] ^ x[9]
		x[4] = (xx << 7) | (xx >> 25)
	}
}

// Permute is the modified permutation variant of the salsa20_wordtobyte()
// routine, used by SPHINCS-256's hashing.
func Permute(output, input *[64]byte) {
	var x [16]uint32
	for i := 0; i < len(x); i++ {
		x[i] = binary.LittleEndian.Uint32(input[4*i:])
	}
	doRounds(&x)
	// for (i = 0;i < 16;++i) x[i] = PLUS(x[i],input[i]); // XXX: Bad idea if we later xor the input to the state?
	for i := 0; i < len(x); i++ {
		binary.LittleEndian.PutUint32(output[4*i:], x[i])
	}
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
