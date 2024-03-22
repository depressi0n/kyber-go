package kyber

var zetas = [128]int16{
	-1044, -758, -359, -1517, 1493, 1422, 287, 202,
	-171, 622, 1577, 182, 962, -1202, -1474, 1468,
	573, -1325, 264, 383, -829, 1458, -1602, -130,
	-681, 1017, 732, 608, -1542, 411, -205, -1571,
	1223, 652, -552, 1015, -1293, 1491, -282, -1544,
	516, -8, -320, -666, -1618, -1162, 126, 1469,
	-853, -90, -271, 830, 107, -1421, -247, -951,
	-398, 961, -1508, -725, 448, -1065, 677, -1275,
	-1103, 430, 555, 843, -1251, 871, 1550, 105,
	422, 587, 177, -235, -291, -460, 1574, 1653,
	-246, 778, 1159, -147, -777, 1483, -602, 1119,
	-1590, 644, -872, 349, 418, 329, -156, -75,
	817, 1097, 603, 610, 1322, -1285, -1465, 384,
	-1215, -136, 1218, -1335, -874, 220, -1187, -1659,
	-1185, -1530, -1278, 794, -1510, -854, -870, 478,
	-108, -308, 996, 991, 958, -1460, 1522, 1628,
}

/*************************************************
* Name:        fqmul
*
* Description: Multiplication followed by Montgomery reduction
*
* Arguments:   - a int16: first factor
*              - b int16: second factor
*
* Returns 16-bit integer congruent to a*b*R^{-1} mod q
**************************************************/
func fqmul(a int16, b int16) int16 {
	return montgomery_reduce(int32(a) * int32(b))
}

/*************************************************
* Name:        ntt
*
* Description: Inplace number-theoretic transform (NTT) in Rq.
*              input is in standard order, output is in bitreversed order
*
* Arguments:   - r []int16: input/output vector of elements of Zq
*              ([256]int16)
**************************************************/
func ntt(r []int16) {
	var len, start, j, k uint
	var t, zeta int16

	k = 1
	for len = 128; len >= 2; len >>= 1 {
		for start = 0; start < 256; start = j + len {
			zeta = zetas[k]
			k++
			for j = start; j < start+len; j++ {
				t = fqmul(zeta, r[j+len])
				r[j+len] = r[j] - t
				r[j] = r[j] + t
			}
		}
	}
}

/*************************************************
* Name:        invntt_tomont
*
* Description: Inplace inverse number-theoretic transform in Rq and
*              multiplication by Montgomery factor 2^16.
*              Input is in bitreversed order, output is in standard order
*
* Arguments:   - r []int16: input/output vector of elements of Zq
*              ([256]int16)
**************************************************/
func invntt(r []int16) { //int16_t r[256]
	var t, zeta int16
	var f int16 = 1441 // mont^2/128
	var k uint = 127
	var start, len, j uint

	for len = 2; len <= 128; len <<= 1 {
		for start = 0; start < 256; start = j + len {
			zeta = zetas[k]
			k--
			for j = start; j < start+len; j++ {
				t = r[j]
				r[j] = barrett_reduce(t + r[j+len])
				r[j+len] = r[j+len] - t
				r[j+len] = fqmul(zeta, r[j+len])
			}
		}
	}

	for j = 0; j < 256; j++ {
		r[j] = fqmul(r[j], f)
	}
}

/*************************************************
* Name:        basemul
*
* Description: Multiplication of polynomials in Zq[X]/(X^2-zeta)
*              used for multiplication of elements in Rq in NTT domain
*
* Arguments:   - r []int16: output polynomial ([2]int16)
*              - a []int16: the first factor ([2]int16)
*              - b []int16: the second factor ([2]int16)
*              - zeta int16: integer defining the reduction polynomial
**************************************************/
func basemul(r []int16, a []int16, b []int16, zeta int16) {
	r[0] = fqmul(a[1], b[1])
	r[0] = fqmul(r[0], zeta)
	r[0] += fqmul(a[0], b[0])
	r[1] = fqmul(a[0], b[1])
	r[1] += fqmul(a[1], b[0])
}
