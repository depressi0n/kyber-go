package kyber

import (
	"golang.org/x/crypto/sha3"
)

const SHAKE128_RATE = 168
const XOF_BLOCKBYTES = SHAKE128_RATE

type xof_state sha3.ShakeHash

func newXof_state() xof_state {
	state := sha3.NewShake128()
	return state
}

func xof_absorb(state sha3.ShakeHash, in []byte) { // use shake128 to instantiate xof
	state.Write(in)
}

func xof_squeezeblocks(hash []byte, outblocks int, state sha3.ShakeHash) { // use shake128 to instantiate xof
	(state).Read(hash[:outblocks*SHAKE128_RATE])
}

func hash_h(in []byte, inlen int) [KYBER_SYMBYTES]byte { // output [KYBER_SYMBYTES]byte
	return sha3.Sum256(in[:inlen])
}

func hash_g(in []byte, inlen int) [2 * KYBER_SYMBYTES]byte {
	return sha3.Sum512(in[:inlen])
}

func prf(out []byte, outlen int, key []byte, nonce byte) {
	sha3.ShakeSum256(out[:outlen], append(key[:KYBER_SYMBYTES], nonce))
}

func kdf(out []byte, outlen int, in []byte, inlen int) {
	sha3.ShakeSum256(out[:outlen], in[:inlen])
}
