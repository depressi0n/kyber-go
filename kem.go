package kyber

import (
	"crypto/subtle"
)

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - params *Parameters: Kem parameters struct
*
* Returns:     - pk []byte: output public key
*                (KYBER_PUBLICKEYBYTES bytes)
*              - sk []byte: output private key
*                (KYBER_SECRETKEYBYTES bytes)
**************************************************/
func Crypto_kem_keypair(params *Parameters) ([]byte, []byte) {
	pk := make([]byte, params.KYBER_PUBLICKEYBYTES)
	sk := make([]byte, params.KYBER_SECRETKEYBYTES)

	indcpa_pk, indcpa_sk := Indcpa_keypair(params)
	copy(pk, indcpa_pk)
	subtle.ConstantTimeCopy(1, sk[:params.KYBER_INDCPA_SECRETKEYBYTES], indcpa_sk[:])

	pos := params.KYBER_INDCPA_SECRETKEYBYTES + params.KYBER_INDCPA_PUBLICKEYBYTES
	copy(sk[params.KYBER_INDCPA_SECRETKEYBYTES:pos], indcpa_pk)

	hpk := hash_h(pk, params.KYBER_PUBLICKEYBYTES)
	copy(sk[pos:pos+KYBER_SYMBYTES], hpk[:])

	/* Value z for pseudo-random output on reject */
	z := randombytes(KYBER_SYMBYTES)
	subtle.ConstantTimeCopy(1, sk[(params.KYBER_SECRETKEYBYTES-KYBER_SYMBYTES):], z)

	return pk, sk
}

/*************************************************
* Name:        crypto_kem_keypair_with_recovery
*
* Description: Generates public and private key with input seed
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - seed []byte: input seed
*                (of length KYBER_SYMBYTES bytes)
*
* Returns:     - pk []byte: output public key
*                (KYBER_PUBLICKEYBYTES bytes)
*              - sk []byte: output private key
*                (KYBER_SECRETKEYBYTES bytes)
**************************************************/
func Crypto_kem_keypair_with_recovery(params *Parameters, seed []byte) ([]byte, []byte) {

	pk := make([]byte, params.KYBER_PUBLICKEYBYTES)
	sk := make([]byte, params.KYBER_SECRETKEYBYTES)

	indcpa_pk, indcpa_sk := Indcpa_keypair_with_recovery(params, seed)
	copy(pk, indcpa_pk)
	subtle.ConstantTimeCopy(1, sk[:params.KYBER_INDCPA_SECRETKEYBYTES], indcpa_sk[:])

	pos := params.KYBER_INDCPA_SECRETKEYBYTES + params.KYBER_INDCPA_PUBLICKEYBYTES
	copy(sk[params.KYBER_INDCPA_SECRETKEYBYTES:pos], indcpa_pk)

	hpk := hash_h(pk, params.KYBER_PUBLICKEYBYTES)
	copy(sk[pos:pos+KYBER_SYMBYTES], hpk[:])

	/* Value z for pseudo-random output on reject */
	z := randombytes(KYBER_SYMBYTES)
	subtle.ConstantTimeCopy(1, sk[(params.KYBER_SECRETKEYBYTES-KYBER_SYMBYTES):], z)
	return pk, sk
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - pk []byte: input public key
*                (of length KYBER_PUBLICKEYBYTES bytes)
*
* Returns      - ct []byte: output cipher text
*                (KYBER_CIPHERTEXTBYTES bytes)
*              - ss []byte: output shared secret
*                (KYBER_SSBYTES bytes)
**************************************************/
func Crypto_kem_enc(params *Parameters, pk []byte) ([]byte, []byte) {
	//ct := make([]byte, params.KYBER_CIPHERTEXTBYTES)
	ss := make([]byte, KYBER_SSBYTES)

	buf := make([]byte, 2*KYBER_SYMBYTES)

	var hash_pk [KYBER_SYMBYTES]byte
	var hash_m [KYBER_SYMBYTES]byte
	var hash_c [KYBER_SYMBYTES]byte

	/* Will contain key, coins */
	var kr [2 * KYBER_SYMBYTES]byte

	m := randombytes(KYBER_SYMBYTES)

	/* Don't release system RNG output */
	hash_m = hash_h(m, KYBER_SYMBYTES)

	/* Multitarget countermeasure for coins + contributory KEM */
	hash_pk = hash_h(pk, params.KYBER_PUBLICKEYBYTES)

	copy(buf[:KYBER_SYMBYTES], hash_m[:])
	copy(buf[KYBER_SYMBYTES:], hash_pk[:])

	kr = hash_g(buf, 2*KYBER_SYMBYTES)

	/* coins are in kr+KYBER_SYMBYTES */
	ct := Indcpa_enc(params, hash_m[:], pk, kr[KYBER_SYMBYTES:])

	/* overwrite coins in kr with H(c) */
	hash_c = hash_h(ct, params.KYBER_CIPHERTEXTBYTES)
	copy(kr[KYBER_SYMBYTES:], hash_c[:])

	/* hash concatenation of pre-k and H(c) to k */
	kdf(ss, KYBER_SSBYTES, kr[:], 2*KYBER_SYMBYTES)
	return ct, ss
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - ct []byte: input cipher text
*                (of length KYBER_CIPHERTEXTBYTES bytes)
*              - sk []byte: input private key
*                (of length KYBER_SECRETKEYBYTES bytes)
*
* Returns      - ss []byte: output shared secret
*                (KYBER_SSBYTES bytes)
* On failure, ss will contain a pseudo-random value.
**************************************************/
func Crypto_kem_dec(params *Parameters, ct []byte, sk []byte) []byte {
	ss := make([]byte, KYBER_SYMBYTES)

	var fail int
	var kr [2 * KYBER_SYMBYTES]byte
	//var cmp = make([]byte, params.KYBER_CIPHERTEXTBYTES)
	pk := make([]byte, params.KYBER_PUBLICKEYBYTES)
	copy(pk, sk[params.KYBER_INDCPA_SECRETKEYBYTES:])

	buf := Indcpa_dec(params, ct, sk)

	/* Multitarget countermeasure for coins + contributory KEM */
	buf = append(buf, sk[params.KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES:params.KYBER_SECRETKEYBYTES-KYBER_SYMBYTES]...)

	kr = hash_g(buf, 2*KYBER_SYMBYTES)

	/* coins are in kr+KYBER_SYMBYTES */
	cmp := Indcpa_enc(params, buf, pk, kr[KYBER_SYMBYTES:])

	fail = subtle.ConstantTimeCompare(ct[:params.KYBER_CIPHERTEXTBYTES], cmp) // 1 means equal 0 means different

	/* overwrite coins in kr with H(c) */
	hash_c := hash_h(ct, params.KYBER_CIPHERTEXTBYTES)
	copy(kr[KYBER_SYMBYTES:], hash_c[:])

	/* Overwrite pre-k with z on re-encryption failure */
	subtle.ConstantTimeCopy(1-fail, kr[:KYBER_SYMBYTES], sk[params.KYBER_SECRETKEYBYTES-KYBER_SYMBYTES:params.KYBER_SECRETKEYBYTES])

	/* hash concatenation of pre-k and H(c) to k */
	kdf(ss, KYBER_SYMBYTES, kr[:], 2*KYBER_SYMBYTES)
	return ss
}
