package kyber

/*************************************************
* Name:        load32_littleendian
*
* Description: load 4 bytes into a 32-bit integer
*              in little-endian order
*
* Arguments:   - x []byte: input byte array
*
* Returns 32-bit unsigned integer loaded from x
**************************************************/
func load32_littleendian(x []byte) uint32 {
	var r uint32
	r = uint32(x[0])
	r |= uint32(x[1]) << 8
	r |= uint32(x[2]) << 16
	r |= uint32(x[3]) << 24
	return r
}

/*************************************************
* Name:        load24_littleendian
*
* Description: load 3 bytes into a 32-bit integer
*              in little-endian order.
*              This function is only needed for Kyber-512
*
* Arguments:   - x []byte: input byte array
*
* Returns 32-bit unsigned integer loaded from x (most significant byte is zero)
**************************************************/
func load24_littleendian(x []byte) uint32 { //if KYBER_ETA1 == 3. const uint8_t x[3]
	var r uint32
	r = uint32(x[0])
	r |= uint32(x[1]) << 8
	r |= uint32(x[2]) << 16
	return r
}

/*************************************************
* Name:        cbd2
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=2
*
* Arguments:   - r *poly : pointer to output polynomial
*              - buf []byte: input byte array
*                (2*KYBER_N/4 bytes)
**************************************************/
func cbd2(r *poly, buf []byte) { // buf [2*KYBER_N/4]byte
	var t, d uint32
	var a, b int16
	for i := 0; i < KYBER_N/8; i++ {
		t = load32_littleendian(buf[4*i:])
		d = t & 0x55555555
		d += (t >> 1) & 0x55555555

		for j := 0; j < 8; j++ {
			a = int16((d >> (4*j + 0)) & 0x3)
			b = int16((d >> (4*j + 2)) & 0x3)
			r.coeffs[8*i+j] = a - b
		}
	}
}

/*************************************************
* Name:        cbd3
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=3.
*              This function is only needed for Kyber-512
*
* Arguments:   - r *poly: pointer to output polynomial
*              - buf []byte: input byte array
**************************************************/
func cbd3(r *poly, buf []byte) { //if KYBER_ETA1 == 3. buf [3 * KYBER_N / 4]byte
	var t, d uint32
	var a, b int16

	for i := 0; i < KYBER_N/4; i++ {
		t = load24_littleendian(buf[3*i:])

		d = t & 0x00249249
		d += (t >> 1) & 0x00249249
		d += (t >> 2) & 0x00249249

		for j := 0; j < 4; j++ {
			a = int16((d >> (6*j + 0)) & 0x7)
			b = int16((d >> (6*j + 3)) & 0x7)
			r.coeffs[4*i+j] = a - b
		}
	}
}

func poly_cbd_eta1(params *Parameters, r *poly, buf []byte) { //buf [KYBER_ETA1 * KYBER_N / 4]byte
	switch params.KYBER_ETA1 {
	case 2:
		cbd2(r, buf)
	case 3:
		cbd3(r, buf)
	default:
		panic("This implementation requires eta1 in {2,3}")
	}
}

func poly_cbd_eta2(r *poly, buf []byte) { //const uint8_t buf[KYBER_ETA2*KYBER_N/4]
	if KYBER_ETA2 == 2 {
		cbd2(r, buf)
	} else {
		panic("This implementation requires eta2 = 2")
	}
}
