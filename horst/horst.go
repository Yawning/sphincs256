// horst.go - sphincs256/ref/horst.[h,c]

package horst

import (
	"github.com/yawning/sphincs256/chacha"
	"github.com/yawning/sphincs256/hash"
)

const (
	SeedBytes = 32

	LogT     = 16
	T        = 1 << LogT
	K        = 32
	SkBytes  = 32
	SigBytes = 64*hash.Size + (((LogT-6)*hash.Size)+SkBytes)*K
)

func horstExpandSeed(outseeds []byte, inseed *[SeedBytes]byte) {
	outseeds = outseeds[:T*SkBytes]
	chacha.Prg(outseeds, inseed[:])
}

func Sign(sig []byte, pk *[hash.Size]byte, sigbytes *uint64, m []byte, seed *[SeedBytes]byte, masks []byte, mHash []byte) {
	masks = masks[:2*LogT*hash.Size]
	mHash = mHash[:hash.MsgSize]

	var sk [T * SkBytes]byte
	sigpos := 0

	horstExpandSeed(sk[:], seed)

	// Build the whole tree and save it.
	var tree [(2*T - 1) * hash.Size]byte // replace by something more memory-efficient?

	// Generate pk leaves.
	for i := 0; i < T; i++ {
		hash.Hash_n_n(tree[(T-1+i)*hash.Size:], sk[i*SkBytes:])
	}

	var offsetIn, offsetOut uint64
	for i := uint(0); i < LogT; i++ {
		offsetIn = (1 << (LogT - i)) - 1
		offsetOut = (1 << (LogT - i - 1)) - 1
		for j := uint64(0); j < 1<<(LogT-i-1); j++ {
			hash.Hash_2n_n_mask(tree[(offsetOut+j)*hash.Size:], tree[(offsetIn+2*j)*hash.Size:], masks[2*i*hash.Size:])
		}
	}

	// First write 64 hashes from level 10 to the signature.
	for j := 63 * hash.Size; j < 127*hash.Size; j++ {
		sig[sigpos] = tree[j]
		sigpos++
	}

	// Signature consists of horstK parts; each part of secret key and
	// LogT-4 auth-path hashes.
	for i := 0; i < K; i++ {
		idx := uint(mHash[2*i]) + (uint(mHash[2*i+1]) << 8)

		for k := uint(0); k < SkBytes; k++ {
			sig[sigpos] = sk[idx*SkBytes+k]
			sigpos++
		}

		idx += T - 1
		for j := 0; j < LogT-6; j++ {
			// neighbor node
			if idx&1 != 0 {
				idx = idx + 1
			} else {
				idx = idx - 1
			}
			for k := uint(0); k < hash.Size; k++ {
				sig[sigpos] = tree[idx*hash.Size+k]
				sigpos++
			}
			idx = (idx - 1) / 2 // parent node
		}
	}

	for i := 0; i < hash.Size; i++ {
		pk[i] = tree[i]
	}
	*sigbytes = SigBytes
}

func Verify(pk, sig, m, masks, mHash []byte) int {
	masks = masks[:2*LogT*hash.Size]
	mHash = mHash[:hash.MsgSize]

	// XXX/Yawning: I have no idea why this has a clear cutfail case and a
	// return value if the calling code doesn't ever actually check it.
	var buffer [32 * hash.Size]byte
	level10 := sig
	sig = sig[64*hash.Size:]

	for i := 0; i < K; i++ {
		idx := uint(mHash[2*i]) + (uint(mHash[2*i+1]) << 8)

		if idx&1 == 0 {
			hash.Hash_n_n(buffer[:], sig)
			for k := 0; k < hash.Size; k++ {
				buffer[hash.Size+k] = sig[SkBytes+k]
			}
		} else {
			hash.Hash_n_n(buffer[hash.Size:], sig)
			for k := 0; k < hash.Size; k++ {
				buffer[k] = sig[SkBytes+k]
			}
		}
		sig = sig[SkBytes+hash.Size:]

		for j := 1; j < LogT-6; j++ {
			idx = idx >> 1 // parent node

			if idx&1 == 0 {
				hash.Hash_2n_n_mask(buffer[:], buffer[:], masks[2*(j-1)*hash.Size:])
				for k := 0; k < hash.Size; k++ {
					buffer[hash.Size+k] = sig[k]
				}
			} else {
				hash.Hash_2n_n_mask(buffer[hash.Size:], buffer[:], masks[2*(j-1)*hash.Size:])
				for k := 0; k < hash.Size; k++ {
					buffer[k] = sig[k]
				}
			}
			sig = sig[hash.Size:]
		}

		idx = idx >> 1 // parent node
		hash.Hash_2n_n_mask(buffer[:], buffer[:], masks[2*(LogT-7)*hash.Size:])

		for k := uint(0); k < hash.Size; k++ {
			if level10[idx*hash.Size+k] != buffer[k] {
				goto fail // XXX/Yawning: Gratuitious goto...
			}
		}
	}

	// Compute root from level10
	for j := 0; j < 32; j++ {
		hash.Hash_2n_n_mask(buffer[j*hash.Size:], level10[2*j*hash.Size:], masks[2*(LogT-6)*hash.Size:])
	}
	// Hash from level 11 to 12
	for j := 0; j < 16; j++ {
		hash.Hash_2n_n_mask(buffer[j*hash.Size:], buffer[2*j*hash.Size:], masks[2*(LogT-5)*hash.Size:])
	}
	// Hash from level 12 to 13
	for j := 0; j < 8; j++ {
		hash.Hash_2n_n_mask(buffer[j*hash.Size:], buffer[2*j*hash.Size:], masks[2*(LogT-4)*hash.Size:])
	}
	// Hash from level 13 to 14
	for j := 0; j < 4; j++ {
		hash.Hash_2n_n_mask(buffer[j*hash.Size:], buffer[2*j*hash.Size:], masks[2*(LogT-3)*hash.Size:])
	}
	// Hash from level 14 to 15
	for j := 0; j < 2; j++ {
		hash.Hash_2n_n_mask(buffer[j*hash.Size:], buffer[2*j*hash.Size:], masks[2*(LogT-2)*hash.Size:])
	}
	// Hash from level 15 to 16
	hash.Hash_2n_n_mask(pk, buffer[:], masks[2*(LogT-1)*hash.Size:])
	masks = masks[:2*LogT*hash.Size]

	return 0

fail:
	for k := 0; k < hash.Size; k++ {
		pk[k] = 0
	}
	return -1
}

func init() {
	if SkBytes != hash.Size {
		panic("need to have HORST_SKBYTES == HASH_BYTES")
	}
	if K != hash.MsgSize/2 {
		panic("need to have HORST_K == MSGHASH_BYTES/2")
	}
}
