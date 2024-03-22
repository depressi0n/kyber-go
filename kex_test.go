package kyber

import (
	"bytes"
	"fmt"
	"testing"
)

const KEXTESTN = 1000

func test_uake(kyber_k int) {
	zero := make([]byte, KEX_SSBYTES)

	params_kem := NewParameters(kyber_k)
	pkb, skb := Crypto_kem_keypair(params_kem) // Generate static key for Bob

	// Perform unilaterally authenticated key exchange

	params_kex := NewKexParameters(kyber_k)
	label := 0
	for i := 0; i < KEXTESTN; i++ {
		uake_senda, tk, eska := Kex_uake_initA(params_kex, pkb) // Run by Alice

		uake_sendb, kb := Kex_uake_sharedB(params_kex, uake_senda, skb) // Run by Bob

		ka := Kex_uake_sharedA(params_kex, uake_sendb, tk, eska) // Run by Alice

		if !bytes.Equal(ka, kb) {
			fmt.Printf("Error in UAKE\n")
			label = 1
			break
		}

		if bytes.Equal(ka, zero) {
			fmt.Printf("Error: UAKE produces zero key\n")
			label = 1
			break
		}
	}

	if label == 0 {
		fmt.Printf("KEX-UAKE-%s: Correct\n", params_kem.KYBER_NAME)
		fmt.Printf("KEX_UAKE_SENDABYTES: %d\n", params_kex.KEX_UAKE_SENDABYTES)
		fmt.Printf("KEX_UAKE_SENDBBYTES: %d\n", params_kex.KEX_UAKE_SENDBBYTES)
	} else {
		fmt.Printf("KEX-UAKE-%s: Incorrect\n", params_kem.KYBER_NAME)
	}
	fmt.Println()

}

func test_ake(kyber_k int) {
	zero := make([]byte, KEX_SSBYTES)

	params_kem := NewParameters(kyber_k)
	pkb, skb := Crypto_kem_keypair(params_kem) // Generate static key for Bob

	pka, ska := Crypto_kem_keypair(params_kem) // Generate static key for Alice

	// Perform unilaterally authenticated key exchange

	params_ake := NewKexParameters(kyber_k)
	label := 0
	for i := 0; i < KEXTESTN; i++ {
		ake_senda, tk, eska := Kex_ake_initA(params_ake, pkb) // Run by Alice

		ake_sendb, kb := Kex_ake_sharedB(params_ake, ake_senda, skb, pka) // Run by Bob

		ka := Kex_ake_sharedA(params_ake, ake_sendb, tk, eska, ska) // Run by Alice

		if !bytes.Equal(ka, kb) {
			fmt.Printf("Error in AKE\n")
			label = 1
			break
		}

		if bytes.Equal(ka, zero) {
			fmt.Printf("Error: AKE produces zero key\n")
			label = 1
			break
		}

	}

	if label == 0 {
		fmt.Printf("KEX-AKE-%s: Correct\n", params_kem.KYBER_NAME)
		fmt.Printf("KEX_AKE_SENDABYTES: %d\n", params_ake.KEX_AKE_SENDABYTES)
		fmt.Printf("KEX_AKE_SENDBBYTES: %d\n", params_ake.KEX_AKE_SENDBBYTES)

	} else {
		fmt.Printf("KEX-AKE-%s: Incorrect\n", params_kem.KYBER_NAME)
	}
	fmt.Println()

}

func TestKex(t *testing.T) {
	fmt.Printf("\n--------- Test KEX Correctness----------\nTest %d times.\n", KEXTESTN)
	test_uake(2)
	test_uake(3)
	test_uake(4)

	test_ake(2)
	test_ake(3)
	test_ake(4)

}
