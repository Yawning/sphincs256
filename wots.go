// wots.go - sphincs256/ref/wots.[h,c]

package sphincs256

import "github.com/yawning/sphincs256/chacha"

func wotsExpandSeed(outseeds []byte, inseed []byte) {
	outseeds = outseeds[:wotsL*hashBytes]
	inseed = inseed[:seedBytes]

	chacha.Prg(outseeds, inseed[:])
}

func genChain(out, seed []byte, masks []byte, chainlen int) {
	out = out[:hashBytes]
	seed = seed[:hashBytes]

	for i := 0; i < hashBytes; i++ {
		out[i] = seed[i]
	}
	for i := 0; i < chainlen && i < wotsW; i++ {
		mask := masks[i*hashBytes:]
		hashNNMask(out[:], out[:], mask)
	}
}

func wotsPkgen(pk []byte, sk []byte, masks []byte) {
	pk = pk[:wotsL*hashBytes]
	sk = sk[:seedBytes]
	masks = masks[:(wotsW-1)*hashBytes]

	wotsExpandSeed(pk, sk)
	for i := 0; i < wotsL; i++ {
		genChain(pk[i*hashBytes:], pk[i*hashBytes:], masks, wotsW-1)
	}
}

func wotsSign(sig []byte, msg *[hashBytes]byte, sk *[seedBytes]byte, masks []byte) {
	sig = sig[:wotsL*hashBytes]
	masks = masks[:(wotsW-1)*hashBytes]

	var basew [wotsL]int
	var c, i int
	switch wotsW {
	case 16:
		for i = 0; i < wotsL1; i += 2 {
			basew[i] = int(msg[i/2] & 0xf)
			basew[i+1] = int(msg[i/2] >> 4)
			c += wotsW - 1 - basew[i]
			c += wotsW - 1 - basew[i+1]
		}
		for ; i < wotsL; i++ {
			basew[i] = c & 0xf
			c >>= 4
		}

		wotsExpandSeed(sig, sk[:])
		for i = 0; i < wotsL; i++ {
			genChain(sig[i*hashBytes:], sig[i*hashBytes:], masks, basew[i])
		}
	case 4:
		for i = 0; i < wotsL1; i += 4 {
			basew[i] = int(msg[i/4] & 0x3)
			basew[i+1] = int((msg[i/4] >> 2) & 0x3)
			basew[i+2] = int((msg[i/4] >> 4) & 0x3)
			basew[i+3] = int((msg[i/4] >> 6) & 0x3)
			c += wotsW - 1 - basew[i]
			c += wotsW - 1 - basew[i+1]
			c += wotsW - 1 - basew[i+2]
			c += wotsW - 1 - basew[i+3]
		}
		for ; i < wotsL; i++ {
			basew[i] = c & 0xf
			c >>= 4
		}

		wotsExpandSeed(sig, sk[:])
		for i = 0; i < wotsL; i++ {
			genChain(sig[i*hashBytes:], sig[i*hashBytes:], masks, basew[i])
		}
	default:
		panic("not yet implemented")
	}
}

func wotsVerify(pk *[wotsL * hashBytes]byte, sig []byte, msg *[hashBytes]byte, masks []byte) {
	sig = sig[:wotsL*hashBytes]
	masks = masks[:(wotsW-1)*hashBytes]

	var basew [wotsL]int
	var c, i int
	switch wotsW {
	case 16:
		for i = 0; i < wotsL1; i += 2 {
			basew[i] = int(msg[i/2] & 0xf)
			basew[i+1] = int(msg[i/2] >> 4)
			c += wotsW - 1 - basew[i]
			c += wotsW - 1 - basew[i+1]
		}
		for ; i < wotsL; i++ {
			basew[i] = c & 0xf
			c >>= 4
		}

		for i = 0; i < wotsL; i++ {
			genChain(pk[i*hashBytes:], sig[i*hashBytes:], masks[basew[i]*hashBytes:], wotsW-1-basew[i])
		}
	case 4:
		for i = 0; i < wotsL1; i += 4 {
			basew[i] = int(msg[i/4] & 0x3)
			basew[i+1] = int((msg[i/4] >> 2) & 0x3)
			basew[i+2] = int((msg[i/4] >> 4) & 0x3)
			basew[i+3] = int((msg[i/4] >> 6) & 0x3)
			c += wotsW - 1 - basew[i]
			c += wotsW - 1 - basew[i+1]
			c += wotsW - 1 - basew[i+2]
			c += wotsW - 1 - basew[i+3]
		}
		for ; i < wotsL; i++ {
			basew[i] = c & 0xf
			c >>= 4
		}

		for i = 0; i < wotsL; i++ {
			genChain(pk[i*hashBytes:], sig[i*hashBytes:], masks[basew[i]*hashBytes:], wotsW-1-basew[i])
		}
	default:
		panic("not yet implemented")
	}
}
