package kyber

const GEN_MATRIX_NBLOCKS = ((12*KYBER_N/8*(1<<12)/KYBER_Q + XOF_BLOCKBYTES) / XOF_BLOCKBYTES)

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - pk *polyvec: pointer to the input public-key polyvec
*              - seed []byte: input public seed
*                (of length KYBER_SYMBYTES bytes)
*
* Returns      - r []byte: output serialized public key
*                (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
**************************************************/
func pack_pk(params *Parameters, pk *polyvec, seed []byte) []byte { //uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES], const uint8_t seed[KYBER_SYMBYTES]
	r := make([]byte, params.KYBER_INDCPA_PUBLICKEYBYTES)
	copy(r[:params.KYBER_POLYVECBYTES], polyvec_tobytes(params, pk))
	copy(r[params.KYBER_POLYVECBYTES:], seed)
	return r
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - packedpk []byte: serialized public key
*                (KYBER_INDCPA_PUBLICKEYBYTES bytes)
*
* Returns      - pk *polyvec: pointer to output public-key polynomial vector
*              - seed []byte: output seed to generate matrix A
*                (KYBER_SYMBYTES bytes)
**************************************************/
func unpack_pk(params *Parameters, packedpk []byte) (*polyvec, []byte) { //uint8_t seed[KYBER_SYMBYTES], const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES]
	seed := make([]byte, KYBER_SYMBYTES)
	pk := polyvec_frombytes(params, packedpk)
	copy(seed, packedpk[params.KYBER_POLYVECBYTES:])
	return pk, seed
}

/*
************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - sk *polyvec: pointer to input vector of polynomials (secret key)
*
* Returns      - r []byte: output serialized secret key
*                (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
*************************************************
 */
func pack_sk(params *Parameters, sk *polyvec) []byte { //uint8_t r[KYBER_INDCPA_SECRETKEYBYTES]
	r := polyvec_tobytes(params, sk)
	return r
}

/*
************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key; inverse of pack_sk
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - packedsk []byte: input serialized secret key
*                (KYBER_INDCPA_SECRETKEYBYTES bytes)
*
* Returns      - sk *polyvec: pointer to output vector of polynomials (secret key)
*************************************************
 */
func unpack_sk(params *Parameters, packedsk []byte) *polyvec { //const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES]
	sk := polyvec_frombytes(params, packedsk)
	return sk
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - b *polyvec: pointer to the input vector of polynomials b
*              - v *poly: pointer to the input polynomial v
*
* Returns      - r []byte: output serialized ciphertext
*                (of length KYBER_INDCPA_BYTES bytes)
**************************************************/
func pack_ciphertext(params *Parameters, b *polyvec, v *poly) []byte { //uint8_t r[KYBER_INDCPA_BYTES]
	r := polyvec_compress(params, b)
	r = append(r, poly_compress(params, v)...)
	return r
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - c []byte: input serialized ciphertext
*                (of length KYBER_INDCPA_BYTES bytes)
*
* Returns      - b *polyvec: pointer to output vector of polynomials b
*              - poly *v: pointer to the output polynomial v
**************************************************/
func unpack_ciphertext(params *Parameters, c []byte) (*polyvec, *poly) { //const uint8_t c[KYBER_INDCPA_BYTES]
	b := polyvec_decompress(params, c)
	v := poly_decompress(params, c[params.KYBER_POLYVECCOMPRESSEDBYTES:])
	return b, v
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - len int: requested number of output 16-bit integers (uniform mod q)
*              - buf []byte: input buffer (assumed to be uniformly random bytes)
*              - buflen int: length of input buffer in bytes
*
* Returns:     - r []int16: output buffer
*              - ctr int: number of sampled 16-bit integers (at most len)
**************************************************/
func rej_uniform(len int, buf []byte, buflen int) ([]int16, int) {
	var ctr, pos int
	var val0, val1 uint16
	r := make([]int16, len)
	i := 0
	for ctr < len && pos+3 <= buflen {
		val0 = ((uint16(buf[pos+0]) >> 0) | (uint16(buf[pos+1]) << 8)) & 0xFFF
		val1 = ((uint16(buf[pos+1]) >> 4) | (uint16(buf[pos+2]) << 4)) & 0xFFF
		pos += 3
		i++

		if val0 < KYBER_Q {
			r[ctr] = int16(val0)
			ctr++
		}

		if ctr < len && val1 < KYBER_Q {
			r[ctr] = int16(val1)
			ctr++
		}

	}

	return r, ctr
}

/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - seed []byte: input seed
*              - transposed int: deciding whether A or A^T is generated
*
* Returns      - a []*polyvec: pointer to ouptput matrix A
**************************************************/
// Not static for benchmarking
func gen_matrix(params *Parameters, seed []byte, transposed int) []*polyvec {
	tmpseed := make([]byte, KYBER_SYMBYTES)
	copy(tmpseed, seed)

	a := make([]*polyvec, params.KYBER_K)
	buflen := GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES
	buf := make([]byte, buflen+2)

	for i := 0; i < params.KYBER_K; i++ {
		a[i] = newPolyvec(params)
		for j := 0; j < params.KYBER_K; j++ {
			state := newXof_state()
			if transposed == 1 {
				xof_absorb(state, append(tmpseed[:KYBER_SYMBYTES], byte(i), byte(j)))
			} else {
				xof_absorb(state, append(tmpseed[:KYBER_SYMBYTES], byte(j), byte(i)))
			}
			xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, state)

			buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES

			tempr, ctr := rej_uniform(KYBER_N, buf, buflen)
			copy(a[i].vec[j].coeffs[:KYBER_N], tempr)

			for ctr < KYBER_N {

				off := buflen % 3
				for k := 0; k < off; k++ {
					buf[k] = buf[buflen-off+k]
				}

				xof_squeezeblocks(buf[off:], 1, state)

				buflen = off + XOF_BLOCKBYTES

				tempr, tmpctr := rej_uniform(KYBER_N-ctr, buf, buflen)
				copy(a[i].vec[j].coeffs[ctr:], tempr[:KYBER_N-ctr])
				ctr = ctr + tmpctr
				//ctr += rej_uniform(a[i].vec[j].coeffs[ctr:], KYBER_N-ctr, buf, buflen, 0)
			}

		}
	}
	return a
}

func gen_a(params *Parameters, seed []byte) []*polyvec {
	return gen_matrix(params, seed, 0)
}

func gen_at(params *Parameters, seed []byte) []*polyvec {
	return gen_matrix(params, seed, 1)
}

/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - params *Parameters: Kem parameters struct
*
* Returns      - pk []byte: ouptput public key
*                (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - sk []byte: ouptput private key
*                (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/
func Indcpa_keypair(params *Parameters) ([]byte, []byte) {
	var buf [2 * KYBER_SYMBYTES]byte
	//var publicseed = buf[:KYBER_SYMBYTES]
	publicseed := buf[:KYBER_SYMBYTES]
	noiseseed := buf[KYBER_SYMBYTES:]

	skpv := newPolyvec(params)
	e := newPolyvec(params)
	pkpv := newPolyvec(params)

	copy(publicseed, randombytes(KYBER_SYMBYTES))
	buf = hash_g(publicseed, KYBER_SYMBYTES) //hash_g(buf, buf, KYBER_SYMBYTES);
	a := gen_a(params, publicseed)
	nonce := byte(0)
	for i := 0; i < params.KYBER_K; i++ {
		poly_getnoise_eta1(params, &skpv.vec[i], noiseseed, nonce)
		nonce++
	}
	for i := 0; i < params.KYBER_K; i++ {
		poly_getnoise_eta1(params, &e.vec[i], noiseseed, nonce)
		nonce++
	}

	polyvec_ntt(params, skpv)
	polyvec_ntt(params, e)

	// matrix-vector multiplication
	for i := 0; i < params.KYBER_K; i++ {
		polyvec_basemul_acc_montgomery(params, &pkpv.vec[i], a[i], skpv)
		poly_tomont(&pkpv.vec[i])
	}

	polyvec_add(params, pkpv, pkpv, e)
	polyvec_reduce(params, pkpv)

	sk := pack_sk(params, skpv)
	pk := pack_pk(params, pkpv, publicseed)

	return pk, sk
}

/*************************************************
* Name:        indcpa_keypair_with_recovery
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber with input seeds
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - seed []byte: input seed
*                (of length KYBER_SYMBYTES bytes)
*
* Returns      - pk []byte: ouptput public key
*                (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - sk []byte: ouptput private key
*                (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/
func Indcpa_keypair_with_recovery(params *Parameters, seed []byte) ([]byte, []byte) {

	var buf [2 * KYBER_SYMBYTES]byte
	publicseed := buf[:KYBER_SYMBYTES]
	noiseseed := buf[KYBER_SYMBYTES:]

	skpv := newPolyvec(params)
	e := newPolyvec(params)
	pkpv := newPolyvec(params)

	copy(publicseed, seed[:KYBER_SYMBYTES])
	buf = hash_g(publicseed, KYBER_SYMBYTES) //hash_g(buf, buf, KYBER_SYMBYTES);

	a := gen_a(params, publicseed)

	nonce := byte(0)
	for i := 0; i < params.KYBER_K; i++ {
		poly_getnoise_eta1(params, &skpv.vec[i], noiseseed, nonce)
		nonce++
	}
	for i := 0; i < params.KYBER_K; i++ {
		poly_getnoise_eta1(params, &e.vec[i], noiseseed, nonce)
		nonce++
	}

	polyvec_ntt(params, skpv)
	polyvec_ntt(params, e)

	// matrix-vector multiplication
	for i := 0; i < params.KYBER_K; i++ {
		polyvec_basemul_acc_montgomery(params, &pkpv.vec[i], a[i], skpv)
		poly_tomont(&pkpv.vec[i])
	}

	polyvec_add(params, pkpv, pkpv, e)
	polyvec_reduce(params, pkpv)

	sk := pack_sk(params, skpv)
	pk := pack_pk(params, pkpv, publicseed)

	return pk, sk
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - m []byte: input message
*                (of length KYBER_INDCPA_MSGBYTES bytes)
*              - pk []byte: input public key
*                (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - coins []byte: input random coins used as seed
*                (of length KYBER_SYMBYTES) to deterministically generate all randomness
*
* Returns      - c []byte: output ciphertext
*                (of length KYBER_INDCPA_BYTES bytes)
**************************************************/
func Indcpa_enc(params *Parameters, m []byte, pk []byte, coins []byte) []byte { //uint8_t c[KYBER_INDCPA_BYTES], const uint8_t m[KYBER_INDCPA_MSGBYTES], const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES], const uint8_t coins[KYBER_SYMBYTES]

	sp := newPolyvec(params)
	ep := newPolyvec(params)
	b := newPolyvec(params)
	epp := new(poly)
	nonce := byte(0)

	k := new(poly)
	v := new(poly)

	pkpv, seed := unpack_pk(params, pk)

	poly_frommsg(k, m)

	at := gen_at(params, seed)

	for i := 0; i < params.KYBER_K; i++ {
		poly_getnoise_eta1(params, &sp.vec[i], coins, nonce)
		nonce++
	}

	for i := 0; i < params.KYBER_K; i++ {
		poly_getnoise_eta2(&ep.vec[i], coins, nonce)
		nonce++
	}
	poly_getnoise_eta2(epp, coins, nonce)
	nonce++

	polyvec_ntt(params, sp)

	// matrix-vector multiplication
	for i := 0; i < params.KYBER_K; i++ {
		polyvec_basemul_acc_montgomery(params, &b.vec[i], at[i], sp)
	}

	polyvec_basemul_acc_montgomery(params, v, pkpv, sp)

	polyvec_invntt_tomont(params, b)
	poly_invntt_tomont(v)

	polyvec_add(params, b, b, ep)
	poly_add(v, v, epp)
	poly_add(v, v, k)
	polyvec_reduce(params, b)
	poly_reduce(v)

	c := pack_ciphertext(params, b, v)

	return c
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - c []byte: input cipher text
*                (of length KYBER_INDCPA_BYTES bytes)
*              - sk []byte: input private key
*                (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
*
* Returns      - m []byte: output decrypted message
*                (KYBER_INDCPA_MSGBYTES bytes)
**************************************************/
func Indcpa_dec(params *Parameters, c []byte, sk []byte) []byte { //uint8_t m[KYBER_INDCPA_MSGBYTES], const uint8_t c[KYBER_INDCPA_BYTES], const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]
	m := make([]byte, KYBER_INDCPA_MSGBYTES)

	mp := new(poly)

	b, v := unpack_ciphertext(params, c)
	skpv := unpack_sk(params, sk)

	polyvec_ntt(params, b)

	polyvec_basemul_acc_montgomery(params, mp, skpv, b)
	poly_invntt_tomont(mp)

	poly_sub(mp, v, mp)

	poly_reduce(mp)

	poly_tomsg(m, mp)
	return m
}
