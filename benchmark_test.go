package kyber

import (
	"testing"
)

func benchmarkCrypto_kem_keypair(b *testing.B, kyber_k int) {
	params := NewParameters(kyber_k)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Crypto_kem_keypair(params)
	}
}

func benchmarkCrypto_kem_enc(b *testing.B, kyber_k int) {
	params := NewParameters(kyber_k)
	pk, _ := Crypto_kem_keypair(params)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Crypto_kem_enc(params, pk)
	}
}

func benchmarkCrypto_kem_dec(b *testing.B, kyber_k int) {
	params := NewParameters(kyber_k)
	pk, sk := Crypto_kem_keypair(params)
	ct, _ := Crypto_kem_enc(params, pk)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Crypto_kem_dec(params, ct, sk)
	}
}
func BenchmarkCrypto_kem_keypair_512(b *testing.B) {
	benchmarkCrypto_kem_keypair(b, 2)
}
func BenchmarkCrypto_kem_enc_512(b *testing.B) {
	benchmarkCrypto_kem_enc(b, 2)
}
func BenchmarkCrypto_kem_dec_512(b *testing.B) {
	benchmarkCrypto_kem_dec(b, 2)
}

func BenchmarkCrypto_kem_keypair_768(b *testing.B) {
	benchmarkCrypto_kem_keypair(b, 3)
}
func BenchmarkCrypto_kem_enc_768(b *testing.B) {
	benchmarkCrypto_kem_enc(b, 3)
}
func BenchmarkCrypto_kem_dec_768(b *testing.B) {
	benchmarkCrypto_kem_dec(b, 3)
}

func BenchmarkCrypto_kem_keypair_1024(b *testing.B) {
	benchmarkCrypto_kem_keypair(b, 4)
}
func BenchmarkCrypto_kem_enc_1024(b *testing.B) {
	benchmarkCrypto_kem_enc(b, 4)
}
func BenchmarkCrypto_kem_dec_1024(b *testing.B) {
	benchmarkCrypto_kem_dec(b, 4)
}
