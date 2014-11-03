// params.go - sphincs256/ref/params.h

package sphincs256

const (
	subtreeHeight   = 5
	totalTreeHeight = 60
	nLevels         = totalTreeHeight / subtreeHeight
	seedBytes       = 32
	wotsLogW        = 4

	skRandSeedBytes      = 32
	messageHashSeedBytes = 32

	horstLogT     = 16
	horstT        = 1 << horstLogT
	horstK        = 32
	horstSkBytes  = 32
	horstSigBytes = 64*hashBytes + (((horstLogT-6)*hashBytes)+horstSkBytes)*horstK

	wotsW  = 1 << wotsLogW
	wotsL1 = (256 + wotsLogW - 1) / wotsLogW
	//	wotsL = 133 // for wotsW == 4
	//	wotsL = 90 // for wotsW == 8
	wotsL        = 67 // for wotsW == 16
	wotsLogL     = 7  // for wotsW == 16
	wotsSigBytes = wotsL * hashBytes

	hashBytes    = 32 // Has to be log(horstT)*horstK/8
	msgHashBytes = 64

	nMasks = 2 * horstLogT // has to be the max of (2*(subtreeHeight+wotsLogL)) and (wotsW-1) and 2*horstLogT
)
