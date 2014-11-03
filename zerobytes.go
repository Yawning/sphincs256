// zerobytes.go - sphincs256/ref/zerobytes.[h,c]

package sphincs256

func zerobytes(r []byte) []byte {
	for i := 0; i < len(r); i++ {
		r[i] = 0
	}
	return r
}
