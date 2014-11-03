// horst.go - sphincs256/ref/horst.[h,c]

package sphincs256

func horstExpandSeed(outseeds []byte, inseed *[seedBytes]byte) {
	outseeds = outseeds[:horstT*horstSkBytes]
	prg(outseeds, inseed[:])
}

func horstSign(sig []byte, pk *[hashBytes]byte, sigbytes *uint64, m []byte, seed *[seedBytes]byte, masks []byte, mHash []byte) {
	masks = masks[:2*horstLogT*hashBytes]
	mHash = mHash[:msgHashBytes]

	var sk [horstT * horstSkBytes]byte
	sigpos := 0

	horstExpandSeed(sk[:], seed)

	// Build the whole tree and save it.
	var tree [(2*horstT - 1) * hashBytes]byte // replace by something more memory-efficient?

	// Generate pk leaves.
	for i := 0; i < horstT; i++ {
		hashNN(tree[(horstT-1+i)*hashBytes:], sk[i*horstSkBytes:])
	}

	var offsetIn, offsetOut uint64
	for i := uint(0); i < horstLogT; i++ {
		offsetIn = (1 << (horstLogT - i)) - 1
		offsetOut = (1 << (horstLogT - i - 1)) - 1
		for j := uint64(0); j < 1<<(horstLogT-i-1); j++ {
			hash2nNMask(tree[(offsetOut+j)*hashBytes:], tree[(offsetIn+2*j)*hashBytes:], masks[2*i*hashBytes:])
		}
	}

	// First write 64 hashes from level 10 to the signature.
	for j := 63 * hashBytes; j < 127*hashBytes; j++ {
		sig[sigpos] = tree[j]
		sigpos++
	}

	// Signature consists of horstK parts; each part of secret key and
	// horstLogT-4 auth-path hashes.
	for i := 0; i < horstK; i++ {
		idx := uint(mHash[2*i]) + (uint(mHash[2*i+1]) << 8)

		for k := uint(0); k < horstSkBytes; k++ {
			sig[sigpos] = sk[idx*horstSkBytes+k]
			sigpos++
		}

		idx += horstT - 1
		for j := 0; j < horstLogT-6; j++ {
			// neighbor node
			if idx&1 != 0 {
				idx = idx + 1
			} else {
				idx = idx - 1
			}
			for k := uint(0); k < hashBytes; k++ {
				sig[sigpos] = tree[idx*hashBytes+k]
				sigpos++
			}
			idx = (idx - 1) / 2 // parent node
		}
	}

	for i := 0; i < hashBytes; i++ {
		pk[i] = tree[i]
	}
	*sigbytes = horstSigBytes
}

func horstVerify(pk, sig, m, masks, mHash []byte) int {
	masks = masks[:2*horstLogT*hashBytes]
	mHash = mHash[:msgHashBytes]

	// XXX/Yawning: I have no idea why this has a clear cutfail case and a
	// return value if the calling code doesn't ever actually check it.
	var buffer [32 * hashBytes]byte
	level10 := sig
	sig = sig[64*hashBytes:]

	for i := 0; i < horstK; i++ {
		idx := uint(mHash[2*i]) + (uint(mHash[2*i+1]) << 8)

		if idx&1 == 0 {
			hashNN(buffer[:], sig)
			for k := 0; k < hashBytes; k++ {
				buffer[hashBytes+k] = sig[horstSkBytes+k]
			}
		} else {
			hashNN(buffer[hashBytes:], sig)
			for k := 0; k < hashBytes; k++ {
				buffer[k] = sig[horstSkBytes+k]
			}
		}
		sig = sig[horstSkBytes+hashBytes:]

		for j := 1; j < horstLogT-6; j++ {
			idx = idx >> 1 // parent node

			if idx&1 == 0 {
				hash2nNMask(buffer[:], buffer[:], masks[2*(j-1)*hashBytes:])
				for k := 0; k < hashBytes; k++ {
					buffer[hashBytes+k] = sig[k]
				}
			} else {
				hash2nNMask(buffer[hashBytes:], buffer[:], masks[2*(j-1)*hashBytes:])
				for k := 0; k < hashBytes; k++ {
					buffer[k] = sig[k]
				}
			}
			sig = sig[hashBytes:]
		}

		idx = idx >> 1 // parent node
		hash2nNMask(buffer[:], buffer[:], masks[2*(horstLogT-7)*hashBytes:])

		for k := uint(0); k < hashBytes; k++ {
			if level10[idx*hashBytes+k] != buffer[k] {
				goto fail // XXX/Yawning: Gratuitious goto...
			}
		}
	}

	// Compute root from level10
	for j := 0; j < 32; j++ {
		hash2nNMask(buffer[j*hashBytes:], level10[2*j*hashBytes:], masks[2*(horstLogT-6)*hashBytes:])
	}
	// Hash from level 11 to 12
	for j := 0; j < 16; j++ {
		hash2nNMask(buffer[j*hashBytes:], buffer[2*j*hashBytes:], masks[2*(horstLogT-5)*hashBytes:])
	}
	// Hash from level 12 to 13
	for j := 0; j < 8; j++ {
		hash2nNMask(buffer[j*hashBytes:], buffer[2*j*hashBytes:], masks[2*(horstLogT-4)*hashBytes:])
	}
	// Hash from level 13 to 14
	for j := 0; j < 4; j++ {
		hash2nNMask(buffer[j*hashBytes:], buffer[2*j*hashBytes:], masks[2*(horstLogT-3)*hashBytes:])
	}
	// Hash from level 14 to 15
	for j := 0; j < 2; j++ {
		hash2nNMask(buffer[j*hashBytes:], buffer[2*j*hashBytes:], masks[2*(horstLogT-2)*hashBytes:])
	}
	// Hash from level 15 to 16
	hash2nNMask(pk, buffer[:], masks[2*(horstLogT-1)*hashBytes:])
	masks = masks[:2*horstLogT*hashBytes]

	return 0

fail:
	for k := 0; k < hashBytes; k++ {
		pk[k] = 0
	}
	return -1
}

func init() {
	if horstSkBytes != hashBytes {
		panic("need to have horstSkBytes == hashBytes")
	}
	if horstK != msgHashBytes/2 {
		panic("need to have horstK == msgHashBytes/2")
	}
}
