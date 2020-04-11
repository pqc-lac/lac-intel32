#include "api.h"
#include "rand.h"
#include <string.h>

//Alice send: generate pk and sk, and send pk and cca kem ciphertext of pk_b to Bob
int crypto_ake_alice_send(uint8_t *pk,uint8_t *sk, uint8_t *pk_b, uint8_t *sk_a, uint8_t *c, uint8_t *k1)
{
	uint8_t seed[SEED_LEN],buf[CRYPTO_SECRETKEYBYTES+SEED_LEN];

	//call key generation algorithm to get pk and sk
	kg(pk,sk);
	// compute seed=hash(random_seed|sk_a)
	random_bytes(buf,SEED_LEN);
	memcpy(buf+SEED_LEN,sk_a,CRYPTO_SECRETKEYBYTES);
	gen_seed(buf,CRYPTO_SECRETKEYBYTES+SEED_LEN,seed);
	// call cca secure kem with seed to generate k1
	kem_enc_fo_seed(pk_b,k1,c,seed);
	
	return 0;
}
// Bob receive: receive  pk, randomly choose m, and encryrpt m with pk to generate c, k1. k=HASH(pk_a,pk_b,pk,c3,k1,k2,k3)
int crypto_ake_bob_receive(uint8_t *pk_b, uint8_t *sk_b, uint8_t *pk_a, uint8_t *pk, uint8_t *c_in,uint8_t *c_out , uint8_t *k)
{
	uint8_t k1[MESSAGE_LEN],k2[MESSAGE_LEN],k3[MESSAGE_LEN];
	uint8_t in[3*MESSAGE_LEN+3*PK_LEN+CIPHER_LEN],seed[SEED_LEN];
	uint8_t buf[CRYPTO_SECRETKEYBYTES+SEED_LEN];
	unsigned long long clen;
	
	// compute seed=hash(random_seed|sk_b)
	random_bytes(buf,SEED_LEN);
	memcpy(buf+SEED_LEN,sk_b,CRYPTO_SECRETKEYBYTES);
	gen_seed(buf,CRYPTO_SECRETKEYBYTES+SEED_LEN,seed);
	//call cca secure kem to generate k2 
	kem_enc_fo_seed(pk_a,k2,c_out,seed);
	
	//call cpa kem algorithm to generate k3
	random_bytes(k3,MESSAGE_LEN);
	pke_enc(pk,k3,MESSAGE_LEN,c_out+CIPHER_LEN,&clen);
	
	//decrypt c_in to get k1
	kem_dec_fo(pk_b,sk_b,c_in,k1);
	
	//compy pk_a,pk_b,pk to buf
	memcpy(in,pk_a,PK_LEN);
	memcpy(in+PK_LEN,pk_b,PK_LEN);
	memcpy(in+2*PK_LEN,pk,PK_LEN);
	
	//copy c3 to to buffer
	memcpy(in+3*PK_LEN,c_out+CIPHER_LEN,CIPHER_LEN);
	//copy k1,k2,k3 to buf
	memcpy(in+3*PK_LEN+CIPHER_LEN,k1,MESSAGE_LEN);
	memcpy(in+3*PK_LEN+CIPHER_LEN+MESSAGE_LEN,k2,MESSAGE_LEN);
	memcpy(in+3*PK_LEN+CIPHER_LEN+2*MESSAGE_LEN,k3,MESSAGE_LEN);
	// compute session key k=HASH(pk_a,pk_b,pk,c3,k1,k2,k3)
	hash_to_k(in,3*MESSAGE_LEN+3*PK_LEN+CIPHER_LEN,k);
	
	return 0;
}
//Alice receive: receive c, and decrypt to get k2, k3 and comute k=HASH(pk_a,pk_b,pk,c3,k1,k2,k3)
int crypto_ake_alice_receive(uint8_t *pk_a, uint8_t *sk_a, uint8_t *pk_b, uint8_t *pk, uint8_t *sk, uint8_t *c1, uint8_t *c_in, uint8_t *k1, uint8_t *k)
{
	uint8_t k2[MESSAGE_LEN],k3[MESSAGE_LEN];
	uint8_t in[3*MESSAGE_LEN+3*PK_LEN+CIPHER_LEN];
	unsigned long long  mlen;

	//decrypt c of cca kem to get k2
	kem_dec_fo(pk_a,sk_a,c_in,k2);
	
	//decrypt c of cpa pke to get k3
	pke_dec(sk,c_in+CIPHER_LEN,CIPHER_LEN,k3,&mlen);
	
	//copy pk_a,pk_b,pk to buf
	memcpy(in,pk_a,PK_LEN);
	memcpy(in+PK_LEN,pk_b,PK_LEN);
	memcpy(in+2*PK_LEN,pk,PK_LEN);
	//copy c3 to buf
	memcpy(in+3*PK_LEN,c_in+CIPHER_LEN,CIPHER_LEN);
	// copy k1,k2,k3 to buf
	memcpy(in+3*PK_LEN+CIPHER_LEN,k1,MESSAGE_LEN);
	memcpy(in+3*PK_LEN+CIPHER_LEN+MESSAGE_LEN,k2,MESSAGE_LEN);
	memcpy(in+3*PK_LEN+CIPHER_LEN+2*MESSAGE_LEN,k3,MESSAGE_LEN);
	// compute session key k=HASH(pk_a,pk_b,pk,c3,k1,k2,k3)
	hash_to_k(in,3*MESSAGE_LEN+3*PK_LEN+CIPHER_LEN,k);
	
	return 0;
}