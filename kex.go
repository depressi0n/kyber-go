package kyber

const (
	CRYPTO_BYTES = KYBER_SSBYTES
	KEX_SSBYTES  = KYBER_SSBYTES
)

type KexParameters struct {
	KemParams              *Parameters
	CRYPTO_SECRETKEYBYTES  int
	CRYPTO_PUBLICKEYBYTES  int
	CRYPTO_CIPHERTEXTBYTES int

	KEX_UAKE_SENDABYTES int
	KEX_UAKE_SENDBBYTES int

	KEX_AKE_SENDABYTES int
	KEX_AKE_SENDBBYTES int
}

func NewKexParameters(k int) *KexParameters {
	var kexpp KexParameters
	kexpp.KemParams = NewParameters(k)
	kexpp.CRYPTO_SECRETKEYBYTES = kexpp.KemParams.KYBER_SECRETKEYBYTES
	kexpp.CRYPTO_PUBLICKEYBYTES = kexpp.KemParams.KYBER_PUBLICKEYBYTES
	kexpp.CRYPTO_CIPHERTEXTBYTES = kexpp.KemParams.KYBER_CIPHERTEXTBYTES

	kexpp.KEX_UAKE_SENDABYTES = kexpp.KemParams.KYBER_PUBLICKEYBYTES + kexpp.KemParams.KYBER_CIPHERTEXTBYTES
	kexpp.KEX_UAKE_SENDBBYTES = (kexpp.KemParams.KYBER_CIPHERTEXTBYTES)

	kexpp.KEX_AKE_SENDABYTES = (kexpp.KemParams.KYBER_PUBLICKEYBYTES + kexpp.KemParams.KYBER_CIPHERTEXTBYTES)
	kexpp.KEX_AKE_SENDBBYTES = (2 * kexpp.KemParams.KYBER_CIPHERTEXTBYTES)

	return &kexpp
}

func Kex_uake_initA(kexpp *KexParameters, pkb []byte) ([]byte, []byte, []byte) {
	send := make([]byte, kexpp.KEX_UAKE_SENDABYTES)
	pk, sk := Crypto_kem_keypair(kexpp.KemParams)
	copy(send, pk)
	ct, tk := Crypto_kem_enc(kexpp.KemParams, pkb)
	copy(send[kexpp.CRYPTO_PUBLICKEYBYTES:], ct)
	return send, tk, sk
}

func Kex_uake_sharedB(kexpp *KexParameters, recv []byte, skb []byte) ([]byte, []byte) {
	k := make([]byte, KYBER_SSBYTES)
	buf := make([]byte, 2*CRYPTO_BYTES)
	send, ss := Crypto_kem_enc(kexpp.KemParams, recv)
	copy(buf, ss)
	copy(buf[CRYPTO_BYTES:], Crypto_kem_dec(kexpp.KemParams, recv[kexpp.CRYPTO_PUBLICKEYBYTES:], skb))
	kdf(k, len(k), buf, 2*CRYPTO_BYTES)
	return send, k
}

func Kex_uake_sharedA(kexpp *KexParameters, recv []byte, tk []byte, sk []byte) []byte {
	k := make([]byte, KYBER_SSBYTES)
	buf := make([]byte, 2*CRYPTO_BYTES)
	copy(buf, Crypto_kem_dec(kexpp.KemParams, recv, sk))
	for i := 0; i < CRYPTO_BYTES; i++ {
		buf[i+CRYPTO_BYTES] = tk[i]
	}
	kdf(k, len(k), buf, 2*CRYPTO_BYTES)
	return k
}

func Kex_ake_initA(kexpp *KexParameters, pkb []byte) ([]byte, []byte, []byte) {
	send := make([]byte, kexpp.KEX_UAKE_SENDABYTES)
	pk, sk := Crypto_kem_keypair(kexpp.KemParams)

	copy(send, pk)
	ct, tk := Crypto_kem_enc(kexpp.KemParams, pkb)
	copy(send[kexpp.CRYPTO_PUBLICKEYBYTES:], ct)
	return send, tk, sk
}

func Kex_ake_sharedB(kexpp *KexParameters, recv []byte, skb []byte, pka []byte) ([]byte, []byte) {
	k := make([]byte, KYBER_SSBYTES)
	send := make([]byte, kexpp.KEX_AKE_SENDBBYTES)
	buf := make([]byte, 3*CRYPTO_BYTES)
	ct, ss := Crypto_kem_enc(kexpp.KemParams, recv)
	copy(send, ct)
	copy(buf, ss)
	ct2, ss2 := Crypto_kem_enc(kexpp.KemParams, pka)
	copy(send[kexpp.CRYPTO_CIPHERTEXTBYTES:], ct2)
	copy(buf[CRYPTO_BYTES:], ss2)
	copy(buf[2*CRYPTO_BYTES:], Crypto_kem_dec(kexpp.KemParams, recv[kexpp.CRYPTO_PUBLICKEYBYTES:], skb))
	kdf(k, len(k), buf, 3*CRYPTO_BYTES)
	return send, k
}

func Kex_ake_sharedA(kexpp *KexParameters, recv []byte, tk []byte, sk []byte, ska []byte) []byte {
	k := make([]byte, KYBER_SSBYTES)
	buf := make([]byte, 3*CRYPTO_BYTES)

	copy(buf, Crypto_kem_dec(kexpp.KemParams, recv, sk))
	copy(buf[CRYPTO_BYTES:], Crypto_kem_dec(kexpp.KemParams, recv[kexpp.CRYPTO_CIPHERTEXTBYTES:], ska))
	for i := 0; i < CRYPTO_BYTES; i++ {
		buf[i+2*CRYPTO_BYTES] = tk[i]
	}
	kdf(k, len(k), buf, 3*CRYPTO_BYTES)
	return k
}
