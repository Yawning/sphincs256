// wots.go - sphincs256/ref/wots.[h,c]

package wots

import (
	"github.com/yawning/sphincs256/chacha"
	"github.com/yawning/sphincs256/hash"
)

const (
	SeedBytes = 32

	LogW = 4
	W    = 1 << LogW
	L1   = (256 + LogW - 1) / LogW
	//	L = 133 // for W == 4
	//	L = 90 // for W == 8
	L        = 67 // for W == 16
	LogL     = 7  // for W == 16
	SigBytes = L * hash.Size
)

func expandSeed(outseeds []byte, inseed []byte) {
//	outseeds = outseeds[:L*hash.Size]
//	inseed = inseed[:SeedBytes]
	chacha.Prg(outseeds[0:L*hash.Size], inseed[0:SeedBytes])
}

func genChain(out, seed []byte, masks []byte, chainlen int) {
//	out = out[:hash.Size]
//	seed = seed[:hash.Size]

	copy(out[0:hash.Size], seed[0:hash.Size])
	for i := 0; i < chainlen && i < W; i++ {
		mask := masks[i*hash.Size:]
		hash.Hash_n_n_mask(out[:], out[:], mask)
	}
}

func Pkgen(pk []byte, sk []byte, masks []byte) {
//	pk = pk[:L*hash.Size]
//	sk = sk[:SeedBytes]
//	masks = masks[:(W-1)*hash.Size]

	expandSeed(pk, sk)
	for i := 0; i < L; i++ {
		genChain(pk[i*hash.Size:], pk[i*hash.Size:], masks, W-1)
	}
}

func Sign(sig []byte, msg *[hash.Size]byte, sk *[SeedBytes]byte, masks []byte) {
//	sig = sig[:L*hash.Size]
//	masks = masks[:(W-1)*hash.Size]

	var basew [L]int
	var c, i int
	switch W {
	case 16:
		for i = 0; i < L1; i += 2 {
			basew[i] = int(msg[i/2] & 0xf)
			basew[i+1] = int(msg[i/2] >> 4)
			c += W - 1 - basew[i]
			c += W - 1 - basew[i+1]
		}
		for ; i < L; i++ {
			basew[i] = c & 0xf
			c >>= 4
		}

		expandSeed(sig, sk[:])
		for i = 0; i < L; i++ {
			genChain(sig[i*hash.Size:], sig[i*hash.Size:], masks, basew[i])
		}
	case 4:
		for i = 0; i < L1; i += 4 {
			basew[i] = int(msg[i/4] & 0x3)
			basew[i+1] = int((msg[i/4] >> 2) & 0x3)
			basew[i+2] = int((msg[i/4] >> 4) & 0x3)
			basew[i+3] = int((msg[i/4] >> 6) & 0x3)
			c += W - 1 - basew[i]
			c += W - 1 - basew[i+1]
			c += W - 1 - basew[i+2]
			c += W - 1 - basew[i+3]
		}
		for ; i < L; i++ {
			basew[i] = c & 0xf
			c >>= 4
		}

		expandSeed(sig, sk[:])
		for i = 0; i < L; i++ {
			genChain(sig[i*hash.Size:], sig[i*hash.Size:], masks, basew[i])
		}
	default:
		panic("not yet implemented")
	}
}

func Verify(pk *[L * hash.Size]byte, sig []byte, msg *[hash.Size]byte, masks []byte) {
//	sig = sig[:L*hash.Size]
//	masks = masks[:(W-1)*hash.Size]

	var basew [L]int
	var c, i int
	switch W {
	case 16:
		for i = 0; i < L1; i += 2 {
			basew[i] = int(msg[i/2] & 0xf)
			basew[i+1] = int(msg[i/2] >> 4)
			c += W - 1 - basew[i]
			c += W - 1 - basew[i+1]
		}
		for ; i < L; i++ {
			basew[i] = c & 0xf
			c >>= 4
		}

		for i = 0; i < L; i++ {
			genChain(pk[i*hash.Size:], sig[i*hash.Size:], masks[basew[i]*hash.Size:], W-1-basew[i])
		}
	case 4:
		for i = 0; i < L1; i += 4 {
			basew[i] = int(msg[i/4] & 0x3)
			basew[i+1] = int((msg[i/4] >> 2) & 0x3)
			basew[i+2] = int((msg[i/4] >> 4) & 0x3)
			basew[i+3] = int((msg[i/4] >> 6) & 0x3)
			c += W - 1 - basew[i]
			c += W - 1 - basew[i+1]
			c += W - 1 - basew[i+2]
			c += W - 1 - basew[i+3]
		}
		for ; i < L; i++ {
			basew[i] = c & 0xf
			c >>= 4
		}

		for i = 0; i < L; i++ {
			genChain(pk[i*hash.Size:], sig[i*hash.Size:], masks[basew[i]*hash.Size:], W-1-basew[i])
		}
	default:
		panic("not yet implemented")
	}
}
