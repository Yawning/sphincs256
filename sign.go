// sign.go - sphincs256/ref/sign.c

// Package sphincs256 implements the SPHINCS-256 practical stateless hash-based
// signature scheme.
package sphincs256

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	bigintBytes = (totalTreeHeight - subtreeHeight + 7) / 8

	// PublicKeySize is the length of a SPHINCS-256 public key in bytes.
	PublicKeySize = (nMasks + 1) * hashBytes

	// PrivateKeySize is the length of a SPINCS-256 private key in bytes.
	PrivateKeySize = seedBytes + PublicKeySize - hashBytes + skRandSeedBytes

	cryptoBytes = messageHashSeedBytes + (totalTreeHeight+7)/8 + horstSigBytes + (totalTreeHeight/subtreeHeight)*wotsSigBytes + totalTreeHeight*hashBytes
)

type leafaddr struct {
	level   int
	subtree uint64
	subleaf int
}

func getSeed(seed, sk []byte, a *leafaddr) {
	seed = seed[:seedBytes]

	var buffer [seedBytes + 8]byte

	for i := 0; i < seedBytes; i++ {
		buffer[i] = sk[i]
	}

	// 4 bits to encode level.
	t := uint64(a.level)
	// 55 bits to encode subtree.
	t |= a.subtree << 4
	// 5 bits to encode leaf.
	t |= uint64(a.subleaf) << 59

	for i := uint64(0); i < 8; i++ {
		buffer[seedBytes+i] = byte((t >> (8 * i)) & 0xff)
	}
	varlenHash(seed, buffer[:])
}

func lTree(leaf, wotsPk, masks []byte) {
	l := wotsL
	for i := 0; i < wotsLogL; i++ {
		for j := 0; j < l>>1; j++ {
			hash2nNMask(wotsPk[j*hashBytes:], wotsPk[j*2*hashBytes:], masks[i*2*hashBytes:])
		}

		if l&1 != 0 {
			copy(wotsPk[(l>>1)*hashBytes:((l>>1)+1)*hashBytes], wotsPk[(l-1)*hashBytes:])
			l = (l >> 1) + 1
		} else {
			l = l >> 1
		}
	}
	copy(leaf[:hashBytes], wotsPk[:])
}

func genLeafWots(leaf, masks, sk []byte, a *leafaddr) {
	var seed [seedBytes]byte
	var pk [wotsL * hashBytes]byte

	getSeed(seed[:], sk, a)
	wotsPkgen(pk[:], seed[:], masks)
	lTree(leaf, pk[:], masks)
}

func treehash(node []byte, height int, sk []byte, leaf *leafaddr, masks []byte) {
	a := *leaf
	stack := make([]byte, (height+1)*hashBytes)
	stacklevels := make([]uint, height+1)
	var stackoffset, maskoffset uint

	lastnode := a.subleaf + (1 << uint(height))

	for ; a.subleaf < lastnode; a.subleaf++ {
		genLeafWots(stack[stackoffset*hashBytes:], masks, sk, &a)
		stacklevels[stackoffset] = 0
		stackoffset++
		for stackoffset > 1 && stacklevels[stackoffset-1] == stacklevels[stackoffset-2] {
			// Masks.
			maskoffset = 2 * (stacklevels[stackoffset-1] + wotsLogL) * hashBytes
			hash2nNMask(stack[(stackoffset-2)*hashBytes:], stack[(stackoffset-2)*hashBytes:], masks[maskoffset:])
			stacklevels[stackoffset-2]++
			stackoffset--
		}
	}
	for i := 0; i < hashBytes; i++ {
		node[i] = stack[i]
	}
}

func validateAuthpath(root, leaf *[hashBytes]byte, leafidx uint, authpath, masks []byte, height uint) {
	var buffer [2 * hashBytes]byte

	if leafidx&1 != 0 {
		for j := 0; j < hashBytes; j++ {
			buffer[hashBytes+j] = leaf[j]
		}
		for j := 0; j < hashBytes; j++ {
			buffer[j] = authpath[j]
		}
	} else {
		for j := 0; j < hashBytes; j++ {
			buffer[j] = leaf[j]
		}
		for j := 0; j < hashBytes; j++ {
			buffer[hashBytes+j] = authpath[j]
		}
	}
	authpath = authpath[hashBytes:]

	for i := uint(0); i < height-1; i++ {
		leafidx >>= 1
		if leafidx&1 != 0 {
			hash2nNMask(buffer[hashBytes:], buffer[:], masks[2*(wotsLogL+i)*hashBytes:])
			for j := 0; j < hashBytes; j++ {
				buffer[j] = authpath[j]
			}
		} else {
			hash2nNMask(buffer[:], buffer[:], masks[2*(wotsLogL+i)*hashBytes:])
			for j := 0; j < hashBytes; j++ {
				buffer[hashBytes+j] = authpath[j]
			}

		}
		authpath = authpath[hashBytes:]
	}
	hash2nNMask(root[:], buffer[:], masks[2*(wotsLogL+height-1)*hashBytes:])
}

func computeAuthpathWots(root *[hashBytes]byte, authpath []byte, a *leafaddr, sk, masks []byte, height uint) {
	ta := *a
	var tree [2 * (1 << subtreeHeight) * hashBytes]byte
	var seed [(1 << subtreeHeight) * seedBytes]byte
	var pk [(1 << subtreeHeight) * wotsL * hashBytes]byte

	// Level 0.
	for ta.subleaf = 0; ta.subleaf < 1<<subtreeHeight; ta.subleaf++ {
		getSeed(seed[ta.subleaf*seedBytes:], sk, &ta)
	}
	for ta.subleaf = 0; ta.subleaf < 1<<subtreeHeight; ta.subleaf++ {
		wotsPkgen(pk[ta.subleaf*wotsL*hashBytes:], seed[ta.subleaf*seedBytes:], masks)
	}
	for ta.subleaf = 0; ta.subleaf < 1<<subtreeHeight; ta.subleaf++ {
		lTree(tree[(1<<subtreeHeight)*hashBytes+ta.subleaf*hashBytes:], pk[ta.subleaf*wotsL*hashBytes:], masks)
	}

	// Tree.
	level := 0
	for i := 1 << subtreeHeight; i > 0; i >>= 1 {
		for j := 0; j < i; j += 2 {
			hash2nNMask(tree[(i>>1)*hashBytes+(j>>1)*hashBytes:], tree[i*hashBytes+j*hashBytes:], masks[2*(wotsLogL+level)*hashBytes:])
		}
		level++
	}

	// Copy authpath.
	idx := a.subleaf
	for i := uint(0); i < height; i++ {
		dst := authpath[i*hashBytes : (i+1)*hashBytes]
		src := tree[((1<<subtreeHeight)>>i)*hashBytes+((idx>>i)^1)*hashBytes:]
		copy(dst[:], src[:])
	}

	// Copy root.
	copy(root[:], tree[hashBytes:])
}

// GenerateKey generates a public/private key pair using randomness from rand.
func GenerateKey(rand io.Reader) (publicKey *[PublicKeySize]byte, privateKey *[PrivateKeySize]byte, err error) {
	privateKey = new([PrivateKeySize]byte)
	publicKey = new([PublicKeySize]byte)
	_, err = io.ReadFull(rand, privateKey[:])
	if err != nil {
		return nil, nil, err
	}
	copy(publicKey[:nMasks*hashBytes], privateKey[seedBytes:])

	// Initialization of top-subtree address.
	a := leafaddr{level: nLevels - 1, subtree: 0, subleaf: 0}

	// Construct top subtree.
	treehash(publicKey[nMasks*hashBytes:], subtreeHeight, privateKey[:], &a, publicKey[:])
	return
}

// Sign signs the message with privateKey and returns the combined signature and
// message.
func Sign(privateKey *[PrivateKeySize]byte, message []byte) []byte {
	// Figure out how long the returned buffer needs to be, and rename some
	// things to match crypto_sign.
	mlen := len(message)
	smlenExpected := cryptoBytes + mlen
	sm := make([]byte, smlenExpected)
	m := message
	ret := sm

	var leafidx uint64
	var r [messageHashSeedBytes]byte
	var mH [msgHashBytes]byte
	var tsk [PrivateKeySize]byte
	var root [hashBytes]byte
	var seed [seedBytes]byte
	var masks [nMasks * hashBytes]byte
	for i := 0; i < PrivateKeySize; i++ {
		tsk[i] = privateKey[i]
	}

	// Create leafidx deterministically.
	{
		// Shift scratch upwards so we can reuse msg later.
		scratch := sm[cryptoBytes-skRandSeedBytes:]

		// Copy message to scratch backwards to handle m = sm overlap.
		for i := mlen; i > 0; i-- {
			scratch[skRandSeedBytes+i-1] = m[i-1]
		}
		// Copy secret random seed to scratch.
		copy(scratch[:skRandSeedBytes], tsk[PrivateKeySize-skRandSeedBytes:])

		// XXX/Yawning: The original code doesn't do endian conversion when
		// using rnd.  This is probably wrong, so do the Right Thing(TM).
		var rnd [64]byte
		msgHash(rnd[:], scratch[:skRandSeedBytes+mlen]) // XXX: Why Blake 512?

		leafidx = binary.LittleEndian.Uint64(rnd[0:]) & 0xfffffffffffffff
		copy(r[:], rnd[16:])

		// Prepare msgHash
		scratch = sm[cryptoBytes-messageHashSeedBytes-PublicKeySize:]

		// Copy R.
		copy(scratch[:], r[:])

		// Construct and copy pk.
		a := leafaddr{level: nLevels - 1, subtree: 0, subleaf: 0}
		pk := scratch[messageHashSeedBytes:]
		copy(pk[:nMasks*hashBytes], tsk[seedBytes:])
		treehash(pk[nMasks*hashBytes:], subtreeHeight, tsk[:], &a, pk)

		// Message already on the right spot.
		msgHash(mH[:], scratch[:mlen+messageHashSeedBytes+PublicKeySize])
	}

	// Use unique value $d$ for HORST address.
	a := leafaddr{level: nLevels, subleaf: int(leafidx & ((1 << subtreeHeight) - 1)), subtree: leafidx >> subtreeHeight}

	smlen := 0

	for i := 0; i < messageHashSeedBytes; i++ {
		sm[i] = r[i]
	}

	sm = sm[messageHashSeedBytes:]
	smlen += messageHashSeedBytes

	copy(masks[:], tsk[seedBytes:])
	for i := uint64(0); i < (totalTreeHeight+7)/8; i++ {
		sm[i] = byte((leafidx >> (8 * i)) & 0xff)
	}

	sm = sm[(totalTreeHeight+7)/8:]
	smlen += (totalTreeHeight + 7) / 8

	getSeed(seed[:], tsk[:], &a)
	var horstSigbytes uint64
	horstSign(sm, &root, &horstSigbytes, m, &seed, masks[:], mH[:])

	sm = sm[horstSigbytes:]
	smlen += int(horstSigbytes)

	for i := 0; i < nLevels; i++ {
		a.level = i

		getSeed(seed[:], tsk[:], &a) // XXX: Don't use the same address as for horst_sign here!
		wotsSign(sm, &root, &seed, masks[:])
		sm = sm[wotsSigBytes:]
		smlen += wotsSigBytes

		computeAuthpathWots(&root, sm, &a, tsk[:], masks[:], subtreeHeight)
		sm = sm[subtreeHeight*hashBytes:]
		smlen += subtreeHeight * hashBytes

		a.subleaf = int(a.subtree & ((1 << subtreeHeight) - 1))
		a.subtree >>= subtreeHeight
	}

	smlen += mlen

	zerobytes(tsk[:])

	if smlen != smlenExpected {
		panic("signature length mismatch")
	}

	return ret[:smlen]
}

// Open takes a signed message and public key and returns the message if the
// signature is valid.
func Open(publicKey *[PublicKeySize]byte, message []byte) (body []byte, err error) {
	sm := message
	smlen := len(message)
	pk := publicKey[:]
	mlen := smlen - cryptoBytes

	var leafidx uint64
	var wotsPk [wotsL * hashBytes]byte
	var pkhash [hashBytes]byte
	var root [hashBytes]byte
	var sig [cryptoBytes]byte
	var tpk [PublicKeySize]byte
	var mH [msgHashBytes]byte

	if smlen < cryptoBytes {
		return nil, fmt.Errorf("sphincs256: message length is too short to be valid")
	}
	m := make([]byte, smlen)

	for i := 0; i < PublicKeySize; i++ {
		tpk[i] = pk[i]
	}

	// Construct message hash.
	{
		var r [messageHashSeedBytes]byte
		for i := 0; i < messageHashSeedBytes; i++ {
			r[i] = sm[i]
		}

		scratch := m

		copy(sig[:], sm[:])
		copy(scratch[messageHashSeedBytes+PublicKeySize:], sm[cryptoBytes:cryptoBytes+mlen])

		// Copy R.
		copy(scratch[:], r[:])

		// Copy Public Key.
		copy(scratch[messageHashSeedBytes:], tpk[:])

		msgHash(mH[:], scratch[:mlen+messageHashSeedBytes+PublicKeySize])
	}
	sigp := sig[:]

	sigp = sigp[messageHashSeedBytes:]
	smlen -= messageHashSeedBytes

	for i := uint64(0); i < (totalTreeHeight+7)/8; i++ {
		leafidx |= uint64(sigp[i]) << (8 * i)
	}

	// XXX/Yawning: Check the return value?
	horstVerify(root[:], sigp[(totalTreeHeight+7)/8:], sigp[cryptoBytes-messageHashSeedBytes:], tpk[:], mH[:])

	sigp = sigp[(totalTreeHeight+7)/8:]
	smlen -= (totalTreeHeight + 7) / 8

	sigp = sigp[horstSigBytes:]
	smlen -= horstSigBytes

	for i := 0; i < nLevels; i++ {
		wotsVerify(&wotsPk, sigp, &root, tpk[:])

		sigp = sigp[wotsSigBytes:]
		smlen -= wotsSigBytes

		lTree(pkhash[:], wotsPk[:], tpk[:])
		validateAuthpath(&root, &pkhash, uint(leafidx&0x1f), sigp, tpk[:], subtreeHeight)
		leafidx >>= 5

		sigp = sigp[subtreeHeight*hashBytes:]
		smlen -= subtreeHeight * hashBytes
	}

	for i := 0; i < hashBytes; i++ {
		if root[i] != tpk[i+nMasks*hashBytes] {
			goto fail
		}
	}

	if mlen != smlen {
		panic("message length mismatch")
	}
	for i := 0; i < mlen; i++ {
		m[i] = m[i+messageHashSeedBytes+PublicKeySize]
	}

	return m[:mlen], nil

fail:
	for i := 0; i < mlen; i++ {
		m[i] = 0
	}
	return nil, fmt.Errorf("sphics256: signature verification failed")
}

func init() {
	if totalTreeHeight-subtreeHeight > 64 {
		panic("totalTreeHeight-subtreeHeight must be at most 64")
	}
	if nLevels > 15 || nLevels < 8 {
		// XXX/Yawning: The original code's compile time check for this
		// invariant is broken.
		panic("need to have 8 <= nLevels <= 15")
	}
	if subtreeHeight != 5 {
		panic("need to have subtreeHeight == 5")
	}
	if totalTreeHeight != 60 {
		panic("need to have totalTreeHeight == 60")
	}
	if seedBytes != hashBytes {
		panic("need to have seedBytes == hashBytes")
	}
	if messageHashSeedBytes != 32 {
		panic("need to have messageHashSeedBytes == 32")
	}
}
