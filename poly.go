package kyber

type poly struct {
	coeffs [KYBER_N]int16
}

/*************************************************
* Name:        poly_compress
*
* Description: Compression and subsequent serialization of a polynomial
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - a *poly: pointer to input polynomial
*
* Returns      - r []byte: output byte array
*                (of length KYBER_POLYCOMPRESSEDBYTES)
**************************************************/
func poly_compress(params *Parameters, a *poly) []byte { //uint8_t r[KYBER_POLYCOMPRESSEDBYTES]
	var u int16
	var d0 uint32
	var t [8]uint8
	r := make([]byte, params.KYBER_POLYCOMPRESSEDBYTES)

	switch params.KYBER_POLYCOMPRESSEDBYTES {
	case 128:
		z := 0
		for i := 0; i < KYBER_N/8; i++ {
			for j := 0; j < 8; j++ {
				// map to positive standard representatives
				u = a.coeffs[8*i+j]
				u += (u >> 15) & KYBER_Q
				/*    t[j] = ((((uint16_t)u << 4) + KYBER_Q/2)/KYBER_Q) & 15; */
				d0 = uint32(u) << 4
				d0 += 1665
				d0 *= 80635
				d0 >>= 28
				t[j] = uint8(d0 & 0xf)
			}

			r[z+0] = t[0] | (t[1] << 4)
			r[z+1] = t[2] | (t[3] << 4)
			r[z+2] = t[4] | (t[5] << 4)
			r[z+3] = t[6] | (t[7] << 4)
			//r += 4
			z = z + 4
		}
		return r
	case 160:
		z := 0
		for i := 0; i < KYBER_N/8; i++ {
			for j := 0; j < 8; j++ {
				// map to positive standard representatives
				u = a.coeffs[8*i+j]
				u += (u >> 15) & KYBER_Q
				/*      t[j] = ((((uint32_t)u << 5) + KYBER_Q/2)/KYBER_Q) & 31; */
				d0 = uint32(u) << 5
				d0 += 1664
				d0 *= 40318
				d0 >>= 27
				t[j] = uint8(d0 & 0x1f)
			}

			r[z+0] = (t[0] >> 0) | (t[1] << 5)
			r[z+1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7)
			r[z+2] = (t[3] >> 1) | (t[4] << 4)
			r[z+3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6)
			r[z+4] = (t[6] >> 2) | (t[7] << 3)
			//r += 5
			z = z + 5
		}
		return r
	default:
		panic("KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}")
	}
}

/*************************************************
* Name:        poly_decompress
*
* Description: De-serialization and subsequent decompression of a polynomial;
*              approximate inverse of poly_compress
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - a []byte: input byte array
*                (of length KYBER_POLYCOMPRESSEDBYTES bytes)
*
* Returns      - r *poly: pointer to output polynomial
**************************************************/
func poly_decompress(params *Parameters, a []byte) *poly { //const uint8_t a[KYBER_POLYCOMPRESSEDBYTES]
	r := new(poly)
	switch params.KYBER_POLYCOMPRESSEDBYTES {
	case 128:
		z := 0
		for i := 0; i < KYBER_N/2; i++ {
			r.coeffs[2*i+0] = int16(((uint16(a[z]&15) * KYBER_Q) + 8) >> 4)
			r.coeffs[2*i+1] = int16(((uint16(a[z]>>4) * KYBER_Q) + 8) >> 4)
			//a += 1;
			z++
		}
		return r
	case 160:
		var t [8]uint8
		z := 0
		for i := 0; i < KYBER_N/8; i++ {
			t[0] = (a[z+0] >> 0)
			t[1] = (a[z+0] >> 5) | (a[z+1] << 3)
			t[2] = (a[z+1] >> 2)
			t[3] = (a[z+1] >> 7) | (a[z+2] << 1)
			t[4] = (a[z+2] >> 4) | (a[z+3] << 4)
			t[5] = (a[z+3] >> 1)
			t[6] = (a[z+3] >> 6) | (a[z+4] << 2)
			t[7] = (a[z+4] >> 3)
			//a += 5
			z = z + 5

			for j := 0; j < 8; j++ {
				r.coeffs[8*i+j] = int16(((uint32(t[j]&31) * KYBER_Q) + 16) >> 5)
			}
		}
		return r
	default:
		panic("KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}")
	}
}

/*************************************************
* Name:        poly_tobytes
*
* Description: Serialization of a polynomial
*
* Arguments:   - r []byte: output byte array
*                (needs space for KYBER_POLYBYTES bytes)
*              - a *poly: pointer to input polynomial
**************************************************/
func poly_tobytes(r []byte, a *poly) { // uint8_t r[KYBER_POLYBYTES]
	var t0, t1 uint16

	for i := 0; i < KYBER_N/2; i++ {
		// map to positive standard representatives
		t0 = uint16(a.coeffs[2*i])
		t0 += uint16((int16(t0) >> 15) & KYBER_Q)
		t1 = uint16(a.coeffs[2*i+1])
		t1 += uint16((int16(t1) >> 15) & KYBER_Q)
		r[3*i+0] = byte(t0 >> 0)
		r[3*i+1] = byte((t0 >> 8) | (t1 << 4))
		r[3*i+2] = byte((t1 >> 4))
	}
}

/*************************************************
* Name:        poly_frombytes
*
* Description: De-serialization of a polynomial;
*              inverse of poly_tobytes
*
* Arguments:   - r *poly: pointer to output polynomial
*              - a []byte: input byte array
*                (of KYBER_POLYBYTES bytes)
**************************************************/
func poly_frombytes(r *poly, a []byte) { //const uint8_t a[KYBER_POLYBYTES]
	for i := 0; i < KYBER_N/2; i++ {
		r.coeffs[2*i] = int16(uint16(a[3*i+0]>>0) | ((uint16(a[3*i+1]) << 8) & 0xFFF))
		r.coeffs[2*i+1] = int16(uint16(a[3*i+1]>>4) | ((uint16(a[3*i+2]) << 4) & 0xFFF))
	}
}

/*************************************************
* Name:        poly_frommsg
*
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - r *poly: pointer to output polynomial
*              - msg []byte: input message
*                (of KYBER_INDCPA_MSGBYTES bytes)
**************************************************/
func poly_frommsg(r *poly, msg []byte) { //const uint8_t msg[KYBER_INDCPA_MSGBYTES]
	var mask int16

	if KYBER_INDCPA_MSGBYTES != (KYBER_N / 8) {
		panic("KYBER_INDCPA_MSGBYTES must be equal to KYBER_N/8 bytes!")
	}

	for i := 0; i < KYBER_N/8; i++ {
		for j := 0; j < 8; j++ {
			mask = -int16((msg[i] >> j) & 1)
			r.coeffs[8*i+j] = mask & ((KYBER_Q + 1) / 2)
		}
	}
}

/*************************************************
* Name:        poly_tomsg
*
* Description: Convert polynomial to 32-byte message
*
* Arguments:   - msg []byte: output message
*                (of KYBER_INDCPA_MSGBYTES bytes)
*              - a *poly: pointer to input polynomial
**************************************************/
func poly_tomsg(msg []byte, a *poly) { //uint8_t msg[KYBER_INDCPA_MSGBYTES]
	var t uint32

	for i := 0; i < KYBER_N/8; i++ {
		msg[i] = 0
		for j := 0; j < 8; j++ {
			t = uint32(a.coeffs[8*i+j])
			// t += ((int16_t)t >> 15) & KYBER_Q;
			// t  = (((t << 1) + KYBER_Q/2)/KYBER_Q) & 1;
			t <<= 1
			t += 1665
			t *= 80635
			t >>= 28
			t &= 1
			msg[i] = msg[i] | byte(t<<j)
		}
	}
}

/*************************************************
* Name:        poly_getnoise_eta1
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter KYBER_ETA1
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - r *poly: pointer to output polynomial
*              - seed []byte: input seed
*                (of length KYBER_SYMBYTES bytes)
*              - nonce byte: one-byte input nonce
**************************************************/
func poly_getnoise_eta1(params *Parameters, r *poly, seed []byte, nonce byte) {
	buf := make([]byte, params.KYBER_ETA1*KYBER_N/4)
	prf(buf, len(buf), seed[:KYBER_SYMBYTES], nonce)
	poly_cbd_eta1(params, r, buf)
}

/*************************************************
* Name:        poly_getnoise_eta2
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter KYBER_ETA2
*
* Arguments:   - r *poly: pointer to output polynomial
*              - seed []byte: pointer to input seed
*                (of length KYBER_SYMBYTES bytes)
*              - nonce byte: one-byte input nonce
**************************************************/
func poly_getnoise_eta2(r *poly, seed []byte, nonce byte) { //const uint8_t seed[KYBER_SYMBYTES]
	buf := make([]byte, KYBER_ETA2*KYBER_N/4)
	prf(buf, len(buf), seed, nonce)
	poly_cbd_eta2(r, buf)
}

/*************************************************
* Name:        poly_ntt
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - r *poly: pointer to in/output polynomial
**************************************************/
func poly_ntt(r *poly) {
	ntt(r.coeffs[:])
	poly_reduce(r)
}

/*************************************************
* Name:        poly_invntt_tomont
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT)
*              of a polynomial in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - r *poly: pointer to in/output polynomial
**************************************************/
func poly_invntt_tomont(r *poly) {
	invntt(r.coeffs[:])
}

/*************************************************
* Name:        poly_reduce
*
* Description: Applies Barrett reduction to all coefficients of a polynomial
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - r *poly: pointer to input/output polynomial
**************************************************/
func poly_reduce(r *poly) {
	for i := 0; i < KYBER_N; i++ {
		r.coeffs[i] = barrett_reduce(r.coeffs[i])
	}
}

/*************************************************
* Name:        poly_basemul_montgomery
*
* Description: Multiplication of two polynomials in NTT domain
*
* Arguments:   - r *poly: pointer to output polynomial
*              - a *poly: pointer to first input polynomial
*              - b *poly: pointer to second input polynomial
**************************************************/
func poly_basemul_montgomery(r *poly, a *poly, b *poly) {
	for i := 0; i < KYBER_N/4; i++ {
		basemul(r.coeffs[4*i:4*i+2], a.coeffs[4*i:4*i+2], b.coeffs[4*i:4*i+2], zetas[64+i])
		basemul(r.coeffs[4*i+2:4*i+4], a.coeffs[4*i+2:4*i+4], b.coeffs[4*i+2:4*i+4], -zetas[64+i])
	}
}

/*************************************************
* Name:        poly_tomont
*
* Description: Inplace conversion of all coefficients of a polynomial
*              from normal domain to Montgomery domain
*
* Arguments:   - r *poly: pointer to input/output polynomial
**************************************************/
func poly_tomont(r *poly) {
	f := int16((uint64(1) << 32) % KYBER_Q)
	for i := 0; i < KYBER_N; i++ {
		r.coeffs[i] = montgomery_reduce(int32(r.coeffs[i]) * int32(f))
	}
}

/*************************************************
* Name:        poly_add
*
* Description: Add two polynomials; no modular reduction is performed
*
* Arguments: - r *poly: pointer to output polynomial
*            - a *poly: pointer to first input polynomial
*            - b *poly: pointer to second input polynomial
**************************************************/
func poly_add(r *poly, a *poly, b *poly) {
	for i := 0; i < KYBER_N; i++ {
		r.coeffs[i] = a.coeffs[i] + b.coeffs[i]
	}
}

/*************************************************
* Name:        poly_sub
*
* Description: Subtract two polynomials; no modular reduction is performed
*
* Arguments: - r *poly: pointer to output polynomial
*            - a *poly: pointer to first input polynomial
*            - b *poly: pointer to second input polynomial
**************************************************/
func poly_sub(r *poly, a *poly, b *poly) {
	for i := 0; i < KYBER_N; i++ {
		r.coeffs[i] = a.coeffs[i] - b.coeffs[i]
	}
}
