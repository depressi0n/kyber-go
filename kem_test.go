package kyber

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const TESTN = 1000

type ERRCOUNT struct {
	pk       int
	sk       int
	ct       int
	ss       int
	ss2      int
	dec_fail int
}

// Just for testing kem_enc result with C version
func crypto_kem_enc_testwithseed(params *Parameters, pk []byte, m []byte) ([]byte, []byte) {
	//ct := make([]byte, params.KYBER_CIPHERTEXTBYTES)
	ss := make([]byte, KYBER_SSBYTES)

	buf := make([]byte, 2*KYBER_SYMBYTES)
	//m := make([]byte, KYBER_SYMBYTES)
	var hash_pk [KYBER_SYMBYTES]byte
	var hash_m [KYBER_SYMBYTES]byte
	var hash_c [KYBER_SYMBYTES]byte

	/* Will contain key, coins */
	var kr [2 * KYBER_SYMBYTES]byte

	//randombytes(m, KYBER_SYMBYTES)

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

func convertInputString(line string) []byte {
	buf := strings.Split(line, " ")
	buf2 := strings.TrimSpace(buf[2])
	buf3 := []byte(buf2)
	seed := make([]byte, hex.DecodedLen(len(buf3)))
	hex.Decode(seed, buf3)
	return seed
}

func compare_with_C_txt(t *testing.T, params *Parameters) {
	err_count := new(ERRCOUNT)
	filename := "test_" + params.KYBER_NAME + ".txt"

	fp, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()

	reader := bufio.NewReader(fp)
	for i := 0; i < TESTN; i++ {

		line, _ := reader.ReadString('\n')

		seed := convertInputString(line)

		line, _ = reader.ReadString('\n')
		filepk := convertInputString(line)

		line, _ = reader.ReadString('\n')
		filesk := convertInputString(line)

		pk, sk := Crypto_kem_keypair_with_recovery(params, seed)

		if !bytes.Equal(filepk, pk) {
			err_count.pk++
		}

		if !bytes.Equal(filesk[:len(filesk)-KYBER_SYMBYTES], sk[:len(sk)-KYBER_SYMBYTES]) { //Don't compare the last KYBER_SYMBYTES bytes because they are random numbers
			err_count.sk++
		}

		line, _ = reader.ReadString('\n')
		m := convertInputString(line)
		line, _ = reader.ReadString('\n')
		filess := convertInputString(line)
		line, _ = reader.ReadString('\n')
		filect := convertInputString(line)

		ct, ss := crypto_kem_enc_testwithseed(params, pk, m)
		if !bytes.Equal(filess, ss) {
			err_count.ss++
		}
		if !bytes.Equal(filect, ct) {
			err_count.ct++
		}

		ss2 := Crypto_kem_dec(params, ct, sk)

		line, _ = reader.ReadString('\n')
		filess2 := convertInputString(line)
		if !bytes.Equal(filess2, ss2) {
			err_count.ss2++
		}

		if !bytes.Equal(ss, ss2) {
			err_count.dec_fail++
		}

	}

	if (err_count.pk == 0) && (err_count.sk == 0) && (err_count.ct == 0) && (err_count.ss == 0) && (err_count.ss2 == 0) && (err_count.dec_fail == 0) {
		fmt.Printf("%s Correct\n", params.KYBER_NAME)
	} else {
		fmt.Printf("%s Incorrect\n", params.KYBER_NAME)
		fmt.Printf("Error count: %+v\n", err_count)
	}
}

func kem_correctness(params *Parameters) {
	err_count := new(ERRCOUNT)
	for i := 0; i < TESTN; i++ {
		pk, sk := Crypto_kem_keypair(params)

		ct, ss := Crypto_kem_enc(params, pk)

		ss2 := Crypto_kem_dec(params, ct, sk)

		if !bytes.Equal(ss, ss2) {
			err_count.dec_fail++
		}

	}

	if err_count.dec_fail == 0 {
		fmt.Printf("%s Correct\n", params.KYBER_NAME)
	} else {
		fmt.Printf("%s Incorrect\n", params.KYBER_NAME)
		fmt.Printf("Decryption fails %d times\n\n", err_count.dec_fail)
	}

}

func kem_speed(params *Parameters) {
	var end time.Duration
	end = 0
	for i := 0; i < TESTN; i++ {
		start := time.Now()
		_, _ = Crypto_kem_keypair(params)
		end += time.Since(start)
	}
	fmt.Printf("%s kyber_keypair:%s\n", params.KYBER_NAME, end/TESTN)

	end = 0
	pk, _ := Crypto_kem_keypair(params)
	for i := 0; i < TESTN; i++ {

		start := time.Now()
		_, _ = Crypto_kem_enc(params, pk)
		end += time.Since(start)
	}
	fmt.Printf("%s kyber_encaps:%s\n", params.KYBER_NAME, end/TESTN)

	end = 0
	pk, sk := Crypto_kem_keypair(params)
	ct, _ := Crypto_kem_enc(params, pk)
	for i := 0; i < TESTN; i++ {

		start := time.Now()
		_ = Crypto_kem_dec(params, ct, sk)
		end += time.Since(start)
	}
	fmt.Printf("%s kyber_decaps:%s\n", params.KYBER_NAME, end/TESTN)
}

func Test_Kem_with_C(t *testing.T) {
	fmt.Printf("\n--------- KEM Compare with C version ---------\nTest %d times.\n", TESTN)

	params_512 := NewParameters(2)
	compare_with_C_txt(t, params_512)

	params_768 := NewParameters(3)
	compare_with_C_txt(t, params_768)

	params_1024 := NewParameters(4)
	compare_with_C_txt(t, params_1024)
}

func Test_Kem(t *testing.T) { //test kem correctness
	fmt.Printf("\n--------- Test KEM Correctness----------\nTest %d times.\n", TESTN)
	params_512 := NewParameters(2)
	kem_correctness(params_512)

	params_768 := NewParameters(3)
	kem_correctness(params_768)

	params_1024 := NewParameters(4)
	kem_correctness(params_1024)

}

func Test_Speed(t *testing.T) {
	fmt.Printf("\n--------- Test KEM Speed ----------\nTest %d times.\n", TESTN)
	params_512 := NewParameters(2)
	kem_speed(params_512)
	fmt.Println()

	params_768 := NewParameters(3)
	kem_speed(params_768)
	fmt.Println()

	params_1024 := NewParameters(4)
	kem_speed(params_1024)
	fmt.Println()
}
