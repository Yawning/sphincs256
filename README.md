### SPHINCS: practical stateless hash-based signatures
#### Yawning Angel (yawning at schwanenlied dot me)

This is a straight forward port of the ref SPHINCS-256 implementation from
SUPERCOP (20141014).  Regardless of how "new" the primitive is ("very" as of
this writing), the port was done by someone that got bored and probably should
not be used by anybody.  There is no warranty.

Dependencies:
 * https://github.com/dchest/blake256
 * https://github.com/dchest/blake512

Implementor's notes:
 * Unlike the SUPERCOP signature algorithms, this implementation produces
   detached signatures.  "signature | message" is byte for byte identical to the
   SUPERCOP output so use append() if you want that.
 * It is possible to replace the digest functions used, as long as certain
   minimal properties (in particular second pre-image resistance) are present
   in the replacement algorithms and the digest lengths are identical.
 * As far as the port goes, it is rather naive and mostly emphasizes correctness
   over anything else.  Since this is based off the reference implementation and
   is using pure Go for everything, it is extremely slow.  If better performance
   is desired, send a patch to use the "avx2" code.
 * Minimal testing vs the base SUPERCOP "ref" implementation was done, however
   correctness is not guaranteed.  I am to blame for any errors.

TODO:
 * Make it go fast.

[sphincs](http://sphincs.cr.yp.to/sphincs-20141001.pdf) 26pp. (PDF)
Daniel J. Bernstein, Daira Hopwood, Andreas Hülsing, Tanja Lange,
Ruben Niederhagen, Louiza Papachristodoulou, Peter Schwabe,
Zooko Wilcox-O'Hearn. SPHINCS: practical stateless hash-based signatures.
Date: 2014.10.01.
