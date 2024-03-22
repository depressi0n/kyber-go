This library is the Go version of Kyber, which is based on the C implementation of Kyber-ref at https://github.com/pq-crystals/kyber.

How to use kem  
1. Define the security level of kyber  
    params := NewParameters(2) // Kyber512  
    params := NewParameters(3) // Kyber768  
    params := NewParameters(4) // Kyber1024  

2. Generate keys  
    pk, sk := Crypto_kem_keypair(params)  

3. Encapsulate the shared secret  
    ct, ss := Crypto_kem_enc(params, pk)  

4. Decapsulate the shared secret  
    ss2 := Crypto_kem_dec(params, ct, sk)  

Test  
1. kem_test.go  
    (1) The function Test_Kem_with_C() compares the result with the C implementation. The result data of C implementation is in .txt files, including 1000 sets of data.  

    (2) The function Test_Kem() tests the correctness of kem.  

    (3) The function Test_Speed() tests the running time of keygen, encaps, decaps of kem.  

2. kex_test.go  
Test the correctness of key exchange and AKE.  

3. benchmark_test.go  
Benchmarks of kem's keygen, encaps, decaps.  


