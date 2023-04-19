 /*
 ============================================================================
 Name        : shared.h
 Author      : Sobuno
 Version     : 0.1
 Description : Common functions for the SHA-256 prover and verifier
 ============================================================================
 */
/*
 *  @brief This is the main implementation file of the signature scheme. All of
 *  the LowMC MPC code is here as well as lower-level versions of sign and
 *  verify that are called by the signature API.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */
/*
 *
 * Author: Tan Teik Guan
 * Description : KKW for SHA256
 *
 * Copyright pQCee 2023. All rights reserved
 *
 * “Commons Clause” License Condition v1.0
 *
 * The Software is provided to you by the Licensor under the License, as defined below, subject to the following
 * condition.
 *
 * Without limiting other conditions in the License, the grant of rights under the License will not include, and
 * the License does not grant to you, the right to Sell the Software.
 *
 * For purposes of the foregoing, “Sell” means practicing any or all of the rights granted to you under the License
 * to provide to third parties, for a fee or other consideration (including without limitation fees for hosting or
 * consulting/ support services related to the Software), a product or service whose value derives, entirely or
 * substantially, from the functionality of the Software. Any license notice or attribution required by the License
 * must also include this Commons Clause License Condition notice.
 *
 * Software: KKW_ECC
 *
 * License: MIT 1.0
 *
 * Licensor: pQCee Pte Ltd
 *
 */

#ifndef SHARED_H_
#define SHARED_H_
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#ifdef _WIN32
#include <openssl/applink.c>
#endif
#include <openssl/rand.h>
#include <gmp.h>

#define VERBOSE FALSE
#define ToBytes(x) (x == 0)? 0:((x-1)/8+1)
#define WORD_SIZE_BITS 32
/*
// secp256r1 or prime256v1 parameters
#define CURVE_P "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
#define CURVE_N "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
#define CURVE_A "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"
#define CURVE_B "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
#define CURVE_Gx "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
#define CURVE_Gy "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
*/
// secp256k1 parameters
#define CURVE_FULL "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF"
#define CURVE_P "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
#define CURVE_N "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
#define CURVE_A "0000000000000000000000000000000000000000000000000000000000000000"
#define CURVE_B "0000000000000000000000000000000000000000000000000000000000000007"
#define CURVE_Gx "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
#define CURVE_Gy "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"

static const uint32_t hA[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

static const uint32_t k[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
		0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
		0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6,
		0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
		0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
		0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
		0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
		0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
		0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814,
		0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

//#define ySize 736
#define ySize (16)
//#define rSize 2912 
#define rSize (16)  
#define NUM_PARTIES 32 
#define NUM_ROUNDS 10 
#define SHA256_INPUTS 64
#define ECC_INPUTS 32
#define ECC_PUBKEY_LENGTH 32 
#define NUM_ONLINE 4 // out of NUM_ROUNDS

typedef struct {
	uint32_t y[ySize];
} View;

typedef struct {
	unsigned char rsseed[16];
	unsigned char H[SHA256_DIGEST_LENGTH];
	unsigned char masterkeys[NUM_ROUNDS-NUM_ONLINE][16];
	unsigned char H2[NUM_ROUNDS-NUM_ONLINE][SHA256_DIGEST_LENGTH];
	unsigned char keys[NUM_ONLINE][NUM_PARTIES-1][16];
	unsigned char com[NUM_ONLINE][SHA256_DIGEST_LENGTH];
	unsigned char auxBits[NUM_ONLINE][rSize];
	unsigned char maskedInput[NUM_ONLINE][ECC_INPUTS];
	View views[NUM_ONLINE];
} z;

#define RIGHTROTATE(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b)   x= (b)&1 ? (x)|(1 << (i)) : (x)&(~(1 << (i)))

// prototype from hash.c
// to implement using sha256 instead of sha3

#define MAX_DIGEST_SIZE 64
#define SHA256_DIGEST_SIZE 32


void printdigest(unsigned char * digest);
void Compute_RAND(unsigned char * output, int size, unsigned char * seed, int seedLen)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	char * namestr = "pQCee AStablish";
	char * tempptr = output;
	uint32_t count = 1;

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, namestr, strlen(namestr));
	SHA256_Update(&ctx, &seedLen, sizeof(int));
	SHA256_Update(&ctx, seed, seedLen);
	SHA256_Update(&ctx, &size, sizeof(int));
	SHA256_Final(hash, &ctx);
	while (size > 0)
	{
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, &count, sizeof(int));
		SHA256_Update(&ctx, &seedLen, sizeof(int));
		SHA256_Update(&ctx, seed, seedLen);
		SHA256_Update(&ctx, hash, sizeof(hash));
		SHA256_Final(hash, &ctx);
		if (size >= SHA256_DIGEST_LENGTH)
		{
			memcpy(tempptr,hash,SHA256_DIGEST_LENGTH);
			tempptr += SHA256_DIGEST_LENGTH;
		}
		else
			memcpy(tempptr,hash,size);
		size -= SHA256_DIGEST_LENGTH;
		count++;
	}
}

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

/*
EVP_CIPHER_CTX setupAES(unsigned char key[16]) {
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);


	unsigned char *iv = (unsigned char *)"01234567890123456";

	if(1 != EVP_EncryptInit_ex(&ctx, EVP_aes_128_ctr(), NULL, key, iv))
		handleErrors();

	return ctx;


}
*/
void getAllRandomness(unsigned char key[16], unsigned char *randomness) {
	//Generate randomness: We use 728*32 bit of randomness per key.
	//Since AES block size is 128 bit, we need to run 728*32/128 = 182 iterations

	EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
	unsigned char * iv = (unsigned char *) "01234567890123456";
	EVP_CIPHER_CTX_init(ctx);
	//ctx = setupAES(key);
	unsigned char *plaintext =
			(unsigned char *)"0000000000000000";
	int len;
	if (1 != EVP_EncryptInit_ex(ctx,EVP_aes_128_ctr(),NULL,key,iv))
		handleErrors();

	for(int j=0;j<(rSize/16);j++) {
		if(1 != EVP_EncryptUpdate(ctx, &randomness[j*16], &len, plaintext, strlen ((char *)plaintext)))
			handleErrors();

	}
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);
}

void init_EVP() {
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	//OPENSSL_config(NULL);
}

void cleanup_EVP() {
	EVP_cleanup();
	ERR_free_strings();
}

void H3(unsigned char finalhash[SHA256_DIGEST_LENGTH], int s, int es[NUM_ROUNDS]) {

	unsigned char hash[SHA256_DIGEST_LENGTH];
	int i = NUM_ROUNDS;
	int j;
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, finalhash, SHA256_DIGEST_LENGTH);
	SHA256_Update(&ctx, &i, sizeof(int));
	SHA256_Update(&ctx, &s, sizeof(int));
	SHA256_Final(hash, &ctx);

	//Pick bits from hash
	memset(es,0,sizeof(int)*NUM_ROUNDS);
	int bitTracker = 0;
	while(s>0) {
		if(bitTracker >= 32) { //Generate new hash as we have run out of bits in the previous hash
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, hash, sizeof(hash));
			SHA256_Update(&ctx, &s, sizeof(int));
			SHA256_Final(hash, &ctx);
			bitTracker = 0;
		}
		memcpy((unsigned char *)&i,&hash[bitTracker],4);
		if (i < 0)
			i *= -1;
		bitTracker+=4;
		i %= NUM_ROUNDS;
		if (bitTracker >= 32)
			continue;
		if (es[i] == 0)
		{
			memcpy((unsigned char *)&j,&hash[bitTracker],4);
			if (j < 0)
				j *= -1;
			bitTracker+=4;
			j %= (NUM_PARTIES-1);
			es[i] = j+1;
			s--;
		}
	}

}

// from Picnic Project
//
/* For an input bit b = 0 or 1, return the word of all b bits, i.e.,
 * extend(1) = 0xFFFFFFFFFFFFFFFF
 * extend(0) = 0x0000000000000000
 * Assumes inputs are always 0 or 1.  If this doesn't hold, add "& 1" to the
 * input.
 */
static uint32_t extend(uint8_t bit)
{
    return ~(bit - 1);
}


/* Get one bit from a byte array */
uint8_t getBit(const uint8_t* array, uint32_t bitNumber)
{
	return (array[bitNumber / 8] >> (7 - (bitNumber % 8))) & 0x01;
}

uint8_t getBit32(uint32_t value, uint32_t bitNumber)
{
	return (value>>(31-bitNumber))&0x01;
}

void setBit32(uint32_t * value, uint32_t bitNumber, uint8_t b)
{
	*value = (b&1)? (*value)|(1<<(31-bitNumber)) : (*value)&(~(1<<(31-bitNumber)));
}

uint8_t getParityFromWordArray(uint32_t * array, uint32_t size, uint32_t bitNumber)
{
	uint8_t parity = 0;

	for (int i=0;i<size;i++)
	{
		parity ^= getBit32(array[i],bitNumber);
	}
	return parity;
}


/* Get one bit from a 32-bit int array for all parties*/
uint32_t getBitFromWordArray(const uint32_t* array, uint32_t size, uint32_t bitNumber)
{
	if (size == 1)
	{
		return getBit32(array[0], bitNumber);
	}
	else
	{
		return getBit32(array[size-1], bitNumber) | (getBitFromWordArray(array,size-1,bitNumber)<<1);
	}
	
}

/* Set a specific bit in a byte array to a given value */
void setBit(uint8_t* bytes, uint32_t bitNumber, uint8_t val)
{
	bytes[bitNumber / 8] = (bytes[bitNumber >> 3]
				& ~(1 << (7 - (bitNumber % 8)))) | (val << (7 - (bitNumber % 8)));
}

int toEndian32(int pos)
{
	static int init = 0;
	static uint32_t a[32];
	int count;
	if (!init)
	{
		for (int i = 0 ; i < 32; i++)
		{
			a[i] = 0;
			count = 32;
			setBit((unsigned char *)&a[i],i,1);
			while (a[i] > 0)
			{
				a[i]>>=1;
				count--;
			}
			a[i] = count;
		}
		init =1 ;
	}
	return a[pos]; 
}


static uint32_t parity32(uint32_t x)
{
	uint32_t y = x ^ (x >> 1);

	y ^= (y >> 2);
	y ^= (y >> 4);
	y ^= (y >> 8);
	y ^= (y >> 16);
	return y & 1;
}

static uint32_t int32ToWord(uint32_t x[NUM_PARTIES], int posn)
{
	uint32_t shares;

	for (size_t i = 0; i < NUM_PARTIES;i++) // NUM_PARTIES = 32 
	{
		uint8_t bit = getBit32(x[i],posn);
		setBit32(&shares,i,bit);
	}
	return shares;

}

static uint32_t tapesToWord(unsigned char * randomness[NUM_PARTIES],int * randCount)
{
	uint32_t shares;

	for (size_t i = 0; i < NUM_PARTIES;i++) // NUM_PARTIES = 32 
	{
		uint8_t bit = getBit(randomness[i],*randCount);
		setBit32(&shares,i,bit);
	}
	*randCount += 1;

	return shares;  
}


int ecInvMod(MP_INT * inv, MP_INT * k, MP_INT * p)
{
	MP_INT t1,t2,s1,s2,r1,r2;
	MP_INT q,temp1,temp2;
	
	mpz_init(&t1);
	mpz_init(&t2);
	mpz_init(&s1);
	mpz_init(&s2);
	mpz_init(&r1);
	mpz_init(&r2);
	mpz_init(&q);
	mpz_init(&temp1);
	mpz_init(&temp2);

	if (mpz_cmp_ui(k,0)<0)
	{
		mpz_neg(&t2,k);
		ecInvMod(&t1,&t2,p);
		mpz_sub(inv,p,&t1);
	}
	else
	{
		mpz_set_ui(&s1,0);
		mpz_set_ui(&s2,1);
		mpz_set_ui(&t1,1);
		mpz_set_ui(&t2,0);
		mpz_set(&r1,p);
		mpz_set(&r2,k);

		while (mpz_cmp_ui(&r1,0))
		{
			mpz_div(&q,&r2,&r1);

			mpz_mul(&temp1,&q,&r1);
			mpz_sub(&temp2,&r2,&temp1);
			mpz_set(&r2,&r1);
			mpz_mod(&r1,&temp2,p);

			mpz_mul(&temp1,&q,&s1);
			mpz_sub(&temp2,&s2,&temp1);
			mpz_set(&s2,&s1);
			mpz_mod(&s1,&temp2,p);
			mpz_mul(&temp1,&q,&t1);
			mpz_sub(&temp2,&t2,&temp1);
			mpz_set(&t2,&t1);
			mpz_mod(&t1,&temp2,p);

		}

		mpz_mod(inv,&s2,p);

	}

	mpz_clear(&t1);
	mpz_clear(&t2);
	mpz_clear(&s1);
	mpz_clear(&s2);
	mpz_clear(&r1);
	mpz_clear(&r2);
	mpz_clear(&q);
	mpz_clear(&temp1);
	mpz_clear(&temp2);
	return 0;

}

int ecAddPoint(MP_INT * x1, MP_INT * y1, MP_INT * x2, MP_INT * y2)
{
	MP_INT a,b,l;
	MP_INT t1,t2;
	MP_INT x3,y3;
	MP_INT p;

	mpz_init(&l);
	mpz_init(&t1);
	mpz_init(&t2);
	mpz_init(&x3);
	mpz_init(&y3);
	mpz_init_set_str(&a,CURVE_A,16);
	mpz_init_set_str(&b,CURVE_B,16);
	mpz_init_set_str(&p,CURVE_P,16);

	if (!mpz_cmp_ui(x1,0) && (!mpz_cmp_ui(y1,0)))
	{
		mpz_set(x1,x2);
		mpz_set(y1,y2);
	}
	else if (mpz_cmp_ui(x2,0) || (mpz_cmp_ui(y2,0)))
	{
		if (mpz_cmp(x1,x2))    // not equal
		{
			mpz_sub(&t2,x1,x2);
			mpz_mod(&t1,&t2,&p);
			ecInvMod(&l,&t1,&p);

			mpz_sub(&t2,y1,y2);
			mpz_mod(&t1,&t2,&p);
			mpz_mul(&t2,&l,&t1);
			mpz_mod(&l,&t2,&p);

		}
		else
		{
			mpz_mul_ui(&t2,y1,2);
			mpz_mod(&t1,&t2,&p);
			ecInvMod(&l,&t1,&p);

			mpz_mul(&t1,x1,x1);
			mpz_mod(&t2,&t1,&p);
			mpz_mul_ui(&t1,&t2,3);
			mpz_add(&t2,&t1,&a);

			mpz_mul(&t1,&l,&t2);
			mpz_mod(&l,&t1,&p);

		}
		mpz_mul(&t1,&l,&l);
		mpz_mod(&t2,&t1,&p);
		mpz_sub(&t1,&t2,x2);
		mpz_sub(&t2,&t1,x1);
		mpz_mod(&x3,&t2,&p);

		mpz_sub(&t2,x2,&x3);
		mpz_mod(&t1,&t2,&p);
		mpz_mul(&t2,&l,&t1);
		mpz_mod(&t1,&t2,&p);
		mpz_sub(&t2,&t1,y2);
		mpz_mod(&y3,&t2,&p);

		mpz_set(x1,&x3);
		mpz_set(y1,&y3);
	}

	mpz_clear(&l);
	mpz_clear(&a);
	mpz_clear(&b);
	mpz_clear(&p);
	mpz_clear(&t1);
	mpz_clear(&t2);
	mpz_clear(&x3);
	mpz_clear(&y3);

	return 0;
}

int ecSubPoint(MP_INT * x1, MP_INT * y1, MP_INT * x2, MP_INT * y2)
{
	MP_INT temp;
	mpz_init(&temp);
	mpz_mul_ui(&temp,y2,-1);
	ecAddPoint(x1,y1,x2,&temp);
	mpz_clear(&temp);
	return 0;
	
}

int ecMul(MP_INT * x, MP_INT * y, MP_INT * m)
{
	MP_INT x2,y2;
	unsigned long long i;
	int loop;
	MP_INT x1,y1;

	MP_INT multiple;

	mpz_init_set(&multiple,m);
	mpz_init_set(&x2,x);
	mpz_init_set(&y2,y);
	mpz_init_set_ui(&x1,0);
	mpz_init_set_ui(&y1,0);

	while (mpz_cmp_ui(&multiple,0))
	{
		i = mpz_get_ui(&multiple);
		mpz_div_2exp(&multiple,&multiple,64);
		for (loop = 0;loop < 64; loop++)
		{
			if (i & 0x01)
			{
				ecAddPoint(&x1,&y1,&x2,&y2);
			}
			ecAddPoint(&x2,&y2,&x2,&y2);
			i>>=1;
		}
	}
	mpz_set(x,&x1);
	mpz_set(y,&y1);

	mpz_clear(&x2);
	mpz_clear(&x1);
	mpz_clear(&y2);
	mpz_clear(&y1);
	mpz_clear(&multiple);
	return 0;

}


void mpc_RIGHTROTATE(uint32_t x[NUM_PARTIES], int j, uint32_t z[NUM_PARTIES]) {

	for (int i=0; i < NUM_PARTIES;i++)
		z[i] = RIGHTROTATE(x[i], j);
}

void mpc_RIGHTSHIFT(uint32_t x[NUM_PARTIES], int j, uint32_t z[NUM_PARTIES]) {
	for (int i=0; i < NUM_PARTIES;i++)
		z[i] = x[i] >> j;
}

void mpc_NEGATE(uint32_t x[NUM_PARTIES], uint32_t z[NUM_PARTIES]) 
{
	for (int i=0; i < NUM_PARTIES;i++)
		z[i] = ~x[i];
}

void mpc_XOR(uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES]) 
{
	for (int i=0; i < NUM_PARTIES;i++)
		z[i] = x[i] ^ y[i];
}

int32_t aux_bit_AND(uint8_t mask_a, uint8_t mask_b, unsigned char* randomness[NUM_PARTIES], int *randCount)
{
	uint32_t output_mask = tapesToWord(randomness,randCount);

	size_t lastParty = NUM_PARTIES-1;
	uint32_t and_helper = tapesToWord(randomness,randCount);
	setBit32(&and_helper,NUM_PARTIES-1,0);
	uint8_t aux_bit = (mask_a & mask_b) ^ parity32(and_helper);
	setBit(randomness[lastParty], *randCount-1,aux_bit);

	return output_mask;
} 	

void aux_AND(uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount) 
{
	uint8_t mask_a,mask_b;
	uint32_t output_mask; // NUM_PARTIES=32

	for (int i = 0; i < 32;i++) 
	{
		mask_a = getParityFromWordArray(x,NUM_PARTIES,i);  
		mask_b = getParityFromWordArray(y,NUM_PARTIES,i);  

		output_mask = aux_bit_AND(mask_a,mask_b,randomness,randCount);

		for (int j = (NUM_PARTIES-1); j >= 0 ; j--)
		{
			setBit32(&z[j],i,output_mask & 0x01);
			output_mask>>=1;
		}
	}


}

void aux_ADD(uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount) {

	uint32_t aANDb, prev_carry = 0;
	uint32_t carry[NUM_PARTIES] = {0};
	uint8_t mask_a, mask_b;

	// sum = x ^ y ^ c
	// carry = ((x ^ c) & (y ^ c)) ^ c
	memset(carry,0,sizeof(uint32_t)*NUM_PARTIES);
	for (int i = 31; i > 0; i--)
	{
		prev_carry = getBitFromWordArray(carry,NUM_PARTIES,i);
		mask_a = parity32(getBitFromWordArray(x,NUM_PARTIES,i) ^ prev_carry);  
		mask_b = parity32(getBitFromWordArray(y,NUM_PARTIES,i) ^ prev_carry);  

		aANDb = aux_bit_AND(mask_a,mask_b,randomness,randCount);
		aANDb ^= prev_carry;
		{
			for (int j = (NUM_PARTIES-1); j >= 0; j--)
			{
				setBit32(&carry[j],i-1,(aANDb & 0x01));
				aANDb>>=1;
			}
		}
	}

	for (int i=0;i<NUM_PARTIES;i++)
		z[i] = x[i]^y[i]^carry[i];


}

void aux_MAJ(uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char * randomness[NUM_PARTIES], int* randCount) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];

	mpc_XOR(a, b, t0);
	mpc_XOR(a, c, t1);
	aux_AND(t0, t1, z, randomness, randCount);
	mpc_XOR(z, a, z);
}


void aux_CH(uint32_t e[NUM_PARTIES], uint32_t f[NUM_PARTIES], uint32_t g[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char * randomness[NUM_PARTIES], int* randCount) {
	uint32_t t0[NUM_PARTIES]; 

	//e & (f^g) ^ g
	mpc_XOR(f,g,t0);
	aux_AND(e,t0,t0, randomness, randCount);
	mpc_XOR(t0,g,z);

}


int computeAuxTape(unsigned char *randomness[NUM_PARTIES],unsigned char shares[NUM_PARTIES][ECC_INPUTS])
{
	int randCount = 0;

	return 0;
}


#define CH(e,f,g) ((e & f) ^ ((~e) & g))

void printbits(uint32_t n) {
	if (n) {
		printbits(n >> 1);
		printf("%d", n & 1);
	}

}

int mpc_AND_verify(uint32_t x_state, uint32_t y_state, uint32_t * z_state, uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) 
{
	uint8_t a, b;
	uint32_t mask_a, mask_b;
	uint32_t aANDb, and_helper;
	uint32_t s_shares;

	for (int i=0;i < 32;i++)
	{
		aANDb = tapesToWord(randomness,randCount);
		and_helper = tapesToWord(randomness,randCount);
		a = getBit32(x_state,i);
		b = getBit32(y_state,i);
		mask_a = getBitFromWordArray(x,NUM_PARTIES,i);
		mask_b = getBitFromWordArray(y,NUM_PARTIES,i);


		s_shares = (extend(a) & mask_b) ^ (extend(b) & mask_a) ^ and_helper ^ aANDb;
		setBit32(&s_shares,unopenParty,getBit32(views[unopenParty].y[*countY],i));

		for (int j = (NUM_PARTIES-1); j >= 0 ; j--)
		{
			setBit32(&z[j],i,aANDb & 0x01);
			aANDb >>=1;
		}
		setBit32(z_state,i,parity32(s_shares)^(a&b));
		// write s_shares to view									                 
		for (int j = (NUM_PARTIES-1); j >= 0 ; j--)
		{
			setBit32(&views[j].y[*countY],i,s_shares & 0x01);
			s_shares >>=1;
		}
	}

	*countY+=1;
	return 0;
}

void mpc_AND(uint32_t x_state, uint32_t y_state, uint32_t * z_state, uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) 
{
	uint8_t a, b;
	uint32_t mask_a, mask_b;
	uint32_t aANDb, and_helper;
	uint32_t s_shares;

	for (int i=0;i < 32;i++)
	{
		aANDb = tapesToWord(randomness,randCount);
		and_helper = tapesToWord(randomness,randCount);
		a = getBit32(x_state,i);
		b = getBit32(y_state,i);
		mask_a = getBitFromWordArray(x,NUM_PARTIES,i);
		mask_b = getBitFromWordArray(y,NUM_PARTIES,i);


		s_shares = (extend(a) & mask_b) ^ (extend(b) & mask_a) ^ and_helper ^ aANDb;
		for (int j = (NUM_PARTIES-1); j >= 0 ; j--)
		{
			setBit32(&z[j],i,aANDb & 0x01);
			aANDb >>=1;
		}
		setBit32(z_state,i,parity32(s_shares)^(a&b));
		// write s_shares to view									                 
		for (int j = (NUM_PARTIES-1); j >= 0 ; j--)
		{
			setBit32(&views[j].y[*countY],i,s_shares & 0x01);
			s_shares >>=1;
		}
	}

	*countY+=1;
}

int mpc_ADD_verify(uint32_t x_state, uint32_t y_state, uint32_t * z_state, uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {

// sum = x^y^c
// carry = ((x^c)&(y^c))^c
//
	uint32_t aANDb, and_helper;
	uint32_t mask_a, mask_b, mask_c = 0;
	uint32_t carry[NUM_PARTIES] = {0};
	uint8_t a, b, c = 0;
	uint32_t s_shares;
	uint32_t val;

	*z_state = 0;
	for (int i=31; i>=0; i--)
	{
		a = getBit32(x_state,i) ^ c;
		b = getBit32(y_state,i) ^ c;
		setBit32(z_state,i,a^b^c);
		if (i>0)
		{
			mask_c = getBitFromWordArray(carry,NUM_PARTIES,i);
			mask_a = getBitFromWordArray(x,NUM_PARTIES,i) ^ mask_c;
			mask_b = getBitFromWordArray(y,NUM_PARTIES,i) ^ mask_c;

			aANDb = tapesToWord(randomness,randCount);
			and_helper = tapesToWord(randomness,randCount);
			s_shares = (extend(a) & mask_b) ^ (extend(b) & mask_a) ^ and_helper ^ aANDb;
			setBit32(&s_shares,unopenParty,getBit32(views[unopenParty].y[*countY],i));
			c = parity32(s_shares)^(a&b)^c;
			aANDb ^= mask_c;

			for (int j = (NUM_PARTIES-1); j >= 0 ; j--)
			{
				setBit32(&views[j].y[*countY],i,s_shares & 0x01);
				s_shares >>=1;
				setBit32(&carry[j],i-1,aANDb & 0x01);
				aANDb >>=1;
			}
		}
	}
	*countY+= 1;
	for (int i=0;i<NUM_PARTIES;i++)
		z[i] = x[i]^y[i]^carry[i];

	return 0;
}

void mpc_ADD(uint32_t x_state, uint32_t y_state, uint32_t * z_state, uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char* randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) {

// sum = x^y^c
// carry = ((x^c)&(y^c))^c
//
	uint32_t aANDb, and_helper;
	uint32_t mask_a, mask_b, mask_c = 0;
	uint32_t carry[NUM_PARTIES] = {0};
	uint8_t a, b, c = 0;
	uint32_t s_shares;
	uint32_t val;

	*z_state = 0;
	for (int i=31; i>=0; i--)
	{
		a = getBit32(x_state,i) ^ c;
		b = getBit32(y_state,i) ^ c;
		setBit32(z_state,i,a^b^c);
		if (i>0)
		{
			mask_c = getBitFromWordArray(carry,NUM_PARTIES,i);
			mask_a = getBitFromWordArray(x,NUM_PARTIES,i) ^ mask_c;
			mask_b = getBitFromWordArray(y,NUM_PARTIES,i) ^ mask_c;

			aANDb = tapesToWord(randomness,randCount);
			and_helper = tapesToWord(randomness,randCount);
			s_shares = (extend(a) & mask_b) ^ (extend(b) & mask_a) ^ and_helper ^ aANDb;
			c = parity32(s_shares)^(a&b)^c;
			aANDb ^= mask_c;

			for (int j = (NUM_PARTIES-1); j >= 0 ; j--)
			{
				setBit32(&views[j].y[*countY],i,s_shares & 0x01);
				s_shares >>=1;
				setBit32(&carry[j],i-1,aANDb & 0x01);
				aANDb >>=1;
			}
		}
	}
	*countY+= 1;
	for (int i=0;i<NUM_PARTIES;i++)
		z[i] = x[i]^y[i]^carry[i];

}



int mpc_MAJ_verify(uint32_t a_state, uint32_t b_state, uint32_t c_state, uint32_t * z_state, uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char* randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t0_state, t1_state;

	mpc_XOR(a, b, t0);
	t0_state = a_state ^ b_state;

	mpc_XOR(a, c, t1);
	t1_state = a_state ^ c_state;

	if (mpc_AND_verify(t0_state, t1_state, z_state, t0, t1, z, randomness, randCount, views, countY, unopenParty))
		return -1;
	mpc_XOR(z, a, z);
	*z_state = a_state ^ (*z_state);
	return 0;
}

void mpc_MAJ(uint32_t a_state, uint32_t b_state, uint32_t c_state, uint32_t * z_state, uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];
	uint32_t t0_state, t1_state;

	mpc_XOR(a, b, t0);
	t0_state = a_state ^ b_state;

	mpc_XOR(a, c, t1);
	t1_state = a_state ^ c_state;

	mpc_AND(t0_state, t1_state, z_state, t0, t1, z, randomness, randCount, views, countY);
	mpc_XOR(z, a, z);
	*z_state = a_state ^ (*z_state);
}


int mpc_CH_verify(uint32_t e_state, uint32_t f_state, uint32_t g_state, uint32_t *z_state, uint32_t e[NUM_PARTIES], uint32_t f[NUM_PARTIES], uint32_t g[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char* randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t0_state;

	//e & (f^g) ^ g
	mpc_XOR(f,g,t0);
	t0_state = f_state ^ g_state;

	if (mpc_AND_verify(e_state, t0_state, &t0_state, e,t0,t0, randomness, randCount, views, countY, unopenParty))
		return -1;
	mpc_XOR(t0,g,z);
	*z_state = t0_state ^ g_state;

	return 0;
}

void mpc_CH(uint32_t e_state, uint32_t f_state, uint32_t g_state, uint32_t *z_state, uint32_t e[NUM_PARTIES], uint32_t f[NUM_PARTIES], uint32_t g[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char *randomness[NUM_PARTIES], int* randCount, View views[NUM_PARTIES], int* countY) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t0_state;

	//e & (f^g) ^ g
	mpc_XOR(f,g,t0);
	t0_state = f_state ^ g_state;

	mpc_AND(e_state, t0_state, &t0_state, e,t0,t0, randomness, randCount, views, countY);
	mpc_XOR(t0,g,z);
	*z_state = t0_state ^ g_state;

}

static uint32_t consol(uint32_t array[NUM_PARTIES])
{
	uint32_t ret = 0;
	for (int i = 0; i<NUM_PARTIES;i++)
		ret ^= array[i];
	return ret;
}



int mpc_compute(unsigned char masked_result[2][ECC_PUBKEY_LENGTH], unsigned char masked_input[ECC_INPUTS], unsigned char shares[NUM_PARTIES][ECC_INPUTS], unsigned char * inputs, int numBytes, unsigned char *randomness[NUM_PARTIES], View views[NUM_PARTIES], unsigned char party_result[2][NUM_PARTIES][ECC_PUBKEY_LENGTH], int* countY) 
{

	int randCount=0;

	MP_INT pubkey[2][NUM_PARTIES];
	MP_INT w[NUM_PARTIES];
	MP_INT w_state;
	MP_INT pubkey_state[2];
	MP_INT tempInt;
	MP_INT a,b,n,mod;
	int k;
	char tempstr[ECC_INPUTS*2 + 1];

	mpz_init_set_str(&n,CURVE_N,16);
	mpz_init_set_str(&mod,CURVE_P,16);

	mpz_init(&w_state);
	mpz_init_set_str(&pubkey_state[0],CURVE_Gx,16);
	mpz_init_set_str(&pubkey_state[1],CURVE_Gy,16);

	for (int i = 0; i < NUM_PARTIES; i++) {
		mpz_init(&w[i]);
		mpz_init_set_str(&pubkey[0][i],CURVE_Gx,16);
		mpz_init_set_str(&pubkey[1][i],CURVE_Gy,16);
		mpz_import(&w[i],ECC_INPUTS,1,1,0,0,shares[i]);
	}
	if (inputs) // prove
	{
		mpz_import(&w_state,numBytes,1,1,0,0,inputs);
		for (int i = 0; i < NUM_PARTIES; i++) {
			mpz_sub(&w_state,&w_state,&w[i]);
			mpz_mod(&w_state,&w_state,&n);
		}
		k = ECC_INPUTS;
		memset(masked_input,0,ECC_INPUTS);
		mpz_export(masked_input,(size_t *)&k,1,1,0,0,&w_state);
		if (k < ECC_INPUTS)
		{
			memset(masked_input,0,ECC_INPUTS);
			mpz_export(&masked_input[ECC_INPUTS-k],(size_t *)&k,1,1,0,0,&w_state);
		}
	}
	else
	{
		mpz_import(&w_state,ECC_INPUTS,1,1,0,0,masked_input);
	}


	for (int i = 0; i < NUM_PARTIES; i++)
	{
		ecMul(&pubkey[0][i],&pubkey[1][i],&w[i]);
	}

	ecMul(&pubkey_state[0],&pubkey_state[1],&w_state);

	k = ECC_PUBKEY_LENGTH;
	memset(masked_result[0],0,ECC_PUBKEY_LENGTH);
	mpz_export(masked_result[0],(size_t *)&k,1,1,0,0,&pubkey_state[0]);
	if (k < ECC_PUBKEY_LENGTH)
	{
		memset(masked_result[0],0,ECC_PUBKEY_LENGTH);
		mpz_export(&masked_result[0][ECC_PUBKEY_LENGTH-k],(size_t *)&k,1,1,0,0,&pubkey_state[0]);
	}

	k = ECC_PUBKEY_LENGTH;
	memset(masked_result[1],0,ECC_PUBKEY_LENGTH);
	mpz_export(masked_result[1],(size_t *)&k,1,1,0,0,&pubkey_state[1]);
	if (k < ECC_PUBKEY_LENGTH)
	{
		memset(masked_result[1],0,ECC_PUBKEY_LENGTH);
		mpz_export(&masked_result[1][ECC_PUBKEY_LENGTH-k],(size_t *)&k,1,1,0,0,&pubkey_state[1]);
	}

	for (int i = 0; i < NUM_PARTIES; i++)
	{
		k = ECC_PUBKEY_LENGTH;
		memset(party_result[0][i],0,ECC_PUBKEY_LENGTH);
		mpz_export(party_result[0][i],(size_t *)&k,1,1,0,0,&pubkey[0][i]);
		if (k < ECC_PUBKEY_LENGTH)
		{
			memset(party_result[0][i],0,ECC_PUBKEY_LENGTH);
			mpz_export(&party_result[0][i][ECC_PUBKEY_LENGTH-k],(size_t *)&k,1,1,0,0,&pubkey[0][i]);
		}
		k = ECC_PUBKEY_LENGTH;
		memset(party_result[1][i],0,ECC_PUBKEY_LENGTH);
		mpz_export(party_result[1][i],(size_t *)&k,1,1,0,0,&pubkey[1][i]);
		if (k < ECC_PUBKEY_LENGTH)
		{
			memset(party_result[1][i],0,ECC_PUBKEY_LENGTH);
			mpz_export(&party_result[1][i][ECC_PUBKEY_LENGTH-k],(size_t *)&k,1,1,0,0,&pubkey[1][i]);
		}
	}

	for (int j = 0; j< ECC_PUBKEY_LENGTH; j+=4)
	{
		for (int i = 0; i < NUM_PARTIES; i++)
		{
			uint32_t tempi;
			if (inputs)
			{
				memcpy(&tempi,&party_result[0][i][j],4);
				views[i].y[*countY] = tempi;
				memcpy(&tempi,&party_result[1][i][j],4);
				views[i].y[*countY+1] = tempi;
			}
			else
			{
				if (i == numBytes)
				{
					tempi = views[i].y[*countY];
					memcpy(&party_result[0][i][j],&tempi,4);
					tempi = views[i].y[*countY+1];
					memcpy(&party_result[1][i][j],&tempi,4);
				}
				else
				{
					memcpy(&tempi,&party_result[0][i][j],4);
					views[i].y[*countY] = tempi;
					memcpy(&tempi,&party_result[1][i][j],4);
					views[i].y[*countY+1] = tempi;
				}
			}
		}
		*countY+=2;
	}

	mpz_clear(&mod);
	mpz_clear(&n);
	mpz_clear(&w_state);
	mpz_clear(&pubkey_state[0]);
	mpz_clear(&pubkey_state[1]);
	for (int i = 0; i < NUM_PARTIES; i++)
	{
		mpz_clear(&w[i]);
		mpz_clear(&pubkey[0][i]);
		mpz_clear(&pubkey[1][i]);
	}

	return 0;
}

void printdigest(unsigned char * digest)
{
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x",digest[i]);
	printf("\n");
}

#endif /* SHARED_H_ */
