package kyber

import "crypto/rand"

func randombytes(outlen int) []byte {
	out := make([]byte, outlen)
	rand.Read(out[:outlen]) //randombytes(buf, KYBER_SYMBYTES) to generate the seed
	return out
}
