package kyber

import "fmt"

type polyvec struct {
	vec []poly // [KYBER_K]poly
}

func newPolyvec(params *Parameters) *polyvec {
	var pv polyvec
	pv.vec = make([]poly, params.KYBER_K)
	return &pv
}

/*************************************************
* Name:        polyvec_compress
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYVECCOMPRESSEDBYTES)
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
func polyvec_compress(params *Parameters, a *polyvec) []byte { //uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES]
	var d0 uint64
	r := make([]byte, params.KYBER_POLYVECCOMPRESSEDBYTES)
	switch params.KYBER_POLYVECCOMPRESSEDBYTES {
	case (params.KYBER_K * 352):
		var t [8]uint16
		z := 0
		for i := 0; i < params.KYBER_K; i++ {
			for j := 0; j < KYBER_N/8; j++ {
				for k := 0; k < 8; k++ {
					t[k] = uint16(a.vec[i].coeffs[8*j+k])
					t[k] += uint16((int16(t[k]) >> 15) & KYBER_Q)
					/*      t[k]  = ((((uint32_t)t[k] << 11) + KYBER_Q/2)/KYBER_Q) & 0x7ff; */
					d0 = uint64(t[k])
					d0 <<= 11
					d0 += 1664
					d0 *= 645084
					d0 >>= 31
					t[k] = uint16(d0 & 0x7ff)
				}
				r[z+0] = byte(t[0] >> 0)
				r[z+1] = byte((t[0] >> 8) | (t[1] << 3))
				r[z+2] = byte((t[1] >> 5) | (t[2] << 6))
				r[z+3] = byte(t[2] >> 2)
				r[z+4] = byte((t[2] >> 10) | (t[3] << 1))
				r[z+5] = byte((t[3] >> 7) | (t[4] << 4))
				r[z+6] = byte((t[4] >> 4) | (t[5] << 7))
				r[z+7] = byte(t[5] >> 1)
				r[z+8] = byte((t[5] >> 9) | (t[6] << 2))
				r[z+9] = byte((t[6] >> 6) | (t[7] << 5))
				r[z+10] = byte(t[7] >> 3)
				//r += 11
				z = z + 11
			}
		}
		return r
	case (params.KYBER_K * 320):
		var t [4]uint16
		z := 0
		for i := 0; i < params.KYBER_K; i++ {
			for j := 0; j < KYBER_N/4; j++ {
				for k := 0; k < 4; k++ {
					t[k] = uint16(a.vec[i].coeffs[4*j+k])
					t[k] += uint16((int16(t[k]) >> 15) & KYBER_Q)
					d0 = uint64(t[k])
					d0 <<= 10
					d0 += 1665
					d0 *= 1290167
					d0 >>= 32
					t[k] = uint16(d0 & 0x3ff)
				}

				r[z+0] = byte(t[0] >> 0)
				r[z+1] = byte((t[0] >> 8) | (t[1] << 2))
				r[z+2] = byte((t[1] >> 6) | (t[2] << 4))
				r[z+3] = byte((t[2] >> 4) | (t[3] << 6))
				r[z+4] = byte(t[3] >> 2)
				//r += 5
				z = z + 5
			}
		}
		return r
	default:
		errorString := fmt.Sprintf("KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*%d, 352*%d}", params.KYBER_K, params.KYBER_K)
		panic(errorString)
	}
}

/*************************************************
* Name:        polyvec_decompress
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of polyvec_compress
*
* Arguments:   - polyvec *r:       pointer to output vector of polynomials
*              - const uint8_t *a: pointer to input byte array
*                                  (of length KYBER_POLYVECCOMPRESSEDBYTES)
**************************************************/
func polyvec_decompress(params *Parameters, a []byte) *polyvec { //const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]
	r := newPolyvec(params)
	switch params.KYBER_POLYVECCOMPRESSEDBYTES {
	case (params.KYBER_K * 352):
		var t [8]uint16
		z := 0
		for i := 0; i < params.KYBER_K; i++ {
			for j := 0; j < KYBER_N/8; j++ {
				t[0] = uint16(a[z+0]>>0) | (uint16(a[z+1]) << 8)
				t[1] = uint16(a[z+1]>>3) | (uint16(a[z+2]) << 5)
				t[2] = uint16(a[z+2]>>6) | (uint16(a[z+3]) << 2) | (uint16(a[z+4]) << 10)
				t[3] = uint16(a[z+4]>>1) | (uint16(a[z+5]) << 7)
				t[4] = uint16(a[z+5]>>4) | (uint16(a[z+6]) << 4)
				t[5] = uint16(a[z+6]>>7) | (uint16(a[z+7]) << 1) | (uint16(a[z+8]) << 9)
				t[6] = uint16(a[z+8]>>2) | (uint16(a[z+9]) << 6)
				t[7] = uint16(a[z+9]>>5) | (uint16(a[z+10]) << 3)
				//a += 11
				z = z + 11

				for k := 0; k < 8; k++ {
					r.vec[i].coeffs[8*j+k] = int16((uint32(t[k]&0x7FF)*KYBER_Q + 1024) >> 11)
				}
			}
		}
	case (params.KYBER_K * 320):
		var t [4]uint16
		z := 0
		for i := 0; i < params.KYBER_K; i++ {
			for j := 0; j < KYBER_N/4; j++ {
				t[0] = uint16(a[z+0]>>0) | (uint16(a[z+1]) << 8)
				t[1] = uint16(a[z+1]>>2) | (uint16(a[z+2]) << 6)
				t[2] = uint16(a[z+2]>>4) | (uint16(a[z+3]) << 4)
				t[3] = uint16(a[z+3]>>6) | (uint16(a[z+4]) << 2)
				z = z + 5
				//a += 5

				for k := 0; k < 4; k++ {
					r.vec[i].coeffs[4*j+k] = int16((uint32(t[k]&0x3FF)*KYBER_Q + 512) >> 10)
				}
			}
		}
	default:
		errorString := fmt.Sprintf("KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*%d, 352*%d}", params.KYBER_K, params.KYBER_K)
		panic(errorString)
	}
	return r
}

/*************************************************
* Name:        polyvec_tobytes
*
* Description: Serialize vector of polynomials
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - a *polyvec: pointer to input vector of polynomials
*
* Returns      - r []byte: output byte array
*                (needs space for KYBER_POLYVECBYTES)
**************************************************/
func polyvec_tobytes(params *Parameters, a *polyvec) []byte { //uint8_t r[KYBER_POLYVECBYTES]
	r := make([]byte, params.KYBER_POLYVECBYTES)
	for i := 0; i < params.KYBER_K; i++ {
		poly_tobytes(r[i*KYBER_POLYBYTES:], &a.vec[i])
	}
	return r
}

/*************************************************
* Name:        polyvec_frombytes
*
* Description: De-serialize vector of polynomials;
*              inverse of polyvec_tobytes
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - a []byte]: input vector of polynomials
*                (of length KYBER_POLYVECBYTES)
*
* Returns      - r *polyvec: pointer to output byte array
**************************************************/
func polyvec_frombytes(params *Parameters, a []byte) *polyvec { //const uint8_t a[KYBER_POLYVECBYTES]
	r := newPolyvec(params)
	for i := 0; i < params.KYBER_K; i++ {
		poly_frombytes(&r.vec[i], a[i*KYBER_POLYBYTES:])
	}
	return r
}

/*************************************************
* Name:        polyvec_ntt
*
* Description: Apply forward NTT to all elements of a vector of polynomials
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - r *polyvec: pointer to in/output vector of polynomials
**************************************************/
func polyvec_ntt(params *Parameters, r *polyvec) {
	for i := 0; i < params.KYBER_K; i++ {
		poly_ntt(&r.vec[i])
	}
}

/*************************************************
* Name:        polyvec_invntt_tomont
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
*              and multiply by Montgomery factor 2^16
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - r *polyvec: pointer to in/output vector of polynomials
**************************************************/
func polyvec_invntt_tomont(params *Parameters, r *polyvec) {
	for i := 0; i < params.KYBER_K; i++ {
		poly_invntt_tomont(&r.vec[i])
	}
}

/*************************************************
* Name:        polyvec_basemul_acc_montgomery
*
* Description: Multiply elements of a and b in NTT domain, accumulate into r,
*              and multiply by 2^-16.
*
* Arguments: - params *Parameters: Kem parameters struct
*            - r *poly: pointer to output polynomial
*            - a *polyvec: pointer to first input vector of polynomials
*            - b *polyvec: pointer to second input vector of polynomials
**************************************************/
func polyvec_basemul_acc_montgomery(params *Parameters, r *poly, a *polyvec, b *polyvec) {
	t := new(poly)

	poly_basemul_montgomery(r, &a.vec[0], &b.vec[0])
	for i := 1; i < params.KYBER_K; i++ {
		poly_basemul_montgomery(t, &a.vec[i], &b.vec[i])
		poly_add(r, r, t)
	}

	poly_reduce(r)
}

/*************************************************
* Name:        polyvec_reduce
*
* Description: Applies Barrett reduction to each coefficient
*              of each element of a vector of polynomials;
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - params *Parameters: Kem parameters struct
*              - r *polyvec: pointer to input/output polynomial
**************************************************/
func polyvec_reduce(params *Parameters, r *polyvec) {
	for i := 0; i < params.KYBER_K; i++ {
		poly_reduce(&r.vec[i])
	}
}

/*************************************************
* Name:        polyvec_add
*
* Description: Add vectors of polynomials
*
* Arguments: - params *Parameters: Kem parameters struct
*            - r *polyvec: pointer to output vector of polynomials
*            - a *polyvec: pointer to first input vector of polynomials
*            - b *polyvec: pointer to second input vector of polynomials
**************************************************/
func polyvec_add(params *Parameters, r *polyvec, a *polyvec, b *polyvec) {
	for i := 0; i < params.KYBER_K; i++ {
		poly_add(&r.vec[i], &a.vec[i], &b.vec[i])
	}
}
