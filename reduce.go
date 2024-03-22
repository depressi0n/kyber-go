package kyber

const QINV = -3327 // q^-1 mod 2^16

/*************************************************
* Name:        montgomery_reduce
*
* Description: Montgomery reduction; given a 32-bit integer a, computes
*              16-bit integer congruent to a * R^-1 mod q, where R=2^16
*
* Arguments:   - a int32: input integer to be reduced;
*                           has to be in {-q2^15,...,q2^15-1}
*
* Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
**************************************************/
func montgomery_reduce(a int32) int16 {
	var t = int16(a * QINV)
	t = int16((a - int32(t)*int32(KYBER_Q)) >> 16)
	return t
}

/*************************************************
* Name:        barrett_reduce
*
* Description: Barrett reduction; given a 16-bit integer a, computes
*              centered representative congruent to a mod q in {-(q-1)/2,...,(q-1)/2}
*
* Arguments:   - a int16: input integer to be reduced
*
* Returns:     integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
**************************************************/
func barrett_reduce(a int16) int16 {
	var t, v int16
	v = int16((uint32(1<<26) + uint32(KYBER_Q/2)) / uint32(KYBER_Q))

	t = int16((int32(v)*int32(a) + (1 << 25)) >> 26)
	t *= KYBER_Q
	return a - t
}
