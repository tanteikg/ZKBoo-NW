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
 * Software: KKW_SHA256
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
#include "omp.h"

#define VERBOSE FALSE
#define ToBytes(x) (x == 0)? 0:((x-1)/8+1)
#define WORD_SIZE_BITS 32

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
#define ySize (728 + 8)
//#define rSize 2912 
#define rSize (45392/8) // 2912*2 = 5824 
#define NUM_PARTIES 32 
#define NUM_ROUNDS 28 
#define SHA256_INPUTS 64
#define NUM_ONLINE 7  // out of NUM_ROUNDS

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
	unsigned char maskedInput[NUM_ONLINE][SHA256_INPUTS];
	View views[NUM_ONLINE];
} z;

#define RIGHTROTATE(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b)   x= (b)&1 ? (x)|(1 << (i)) : (x)&(~(1 << (i)))

// prototype from hash.c
// to implement using sha256 instead of sha3

#define MAX_DIGEST_SIZE 64
#define SHA256_DIGEST_SIZE 32


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
void getAllRandomness(unsigned char key[16], unsigned char randomness[rSize]) {
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

uint32_t getRandom32(unsigned char randomness[rSize], int randCount) {
	uint32_t ret;
	memcpy(&ret, &randomness[randCount/8], 4);
	return ret;
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

omp_lock_t *locks;

void openmp_locking_callback(int mode, int type, char *file, int line)
{
  if (mode & CRYPTO_LOCK)
  {
    omp_set_lock(&locks[type]);
  }
  else
  {
    omp_unset_lock(&locks[type]);
  }
}


unsigned long openmp_thread_id(void)
{
  return (unsigned long)omp_get_thread_num();
}

void openmp_thread_setup(void)
{
  int i;

  locks = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(omp_lock_t));
  for (i=0; i<CRYPTO_num_locks(); i++)
  {
    omp_init_lock(&locks[i]);
  }

  CRYPTO_set_id_callback((unsigned long (*)())openmp_thread_id);
  CRYPTO_set_locking_callback((void (*)())openmp_locking_callback);
}

void openmp_thread_cleanup(void)
{
  int i;

  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for (i=0; i<CRYPTO_num_locks(); i++)
    omp_destroy_lock(&locks[i]);
  OPENSSL_free(locks);
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

static uint32_t tapesToWord(unsigned char randomness[NUM_PARTIES][rSize],int * randCount)
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

int32_t aux_bit_AND(uint8_t mask_a, uint8_t mask_b, unsigned char randomness[NUM_PARTIES][rSize], int *randCount)
{
	uint32_t output_mask = tapesToWord(randomness,randCount);

	size_t lastParty = NUM_PARTIES-1;
	uint32_t and_helper = tapesToWord(randomness,randCount);
	setBit32(&and_helper,NUM_PARTIES-1,0);
	uint8_t aux_bit = (mask_a & mask_b) ^ parity32(and_helper);
	setBit(randomness[lastParty], *randCount-1,aux_bit);

	return output_mask;
} 	

void aux_AND(uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char randomness[NUM_PARTIES][rSize], int* randCount) 
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

void aux_ADD(uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char randomness[NUM_PARTIES][rSize], int* randCount) {

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

void aux_MAJ(uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char randomness[NUM_PARTIES][rSize], int* randCount) {
	uint32_t t0[NUM_PARTIES];
	uint32_t t1[NUM_PARTIES];

	mpc_XOR(a, b, t0);
	mpc_XOR(a, c, t1);
	aux_AND(t0, t1, z, randomness, randCount);
	mpc_XOR(z, a, z);
}


void aux_CH(uint32_t e[NUM_PARTIES], uint32_t f[NUM_PARTIES], uint32_t g[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char randomness[NUM_PARTIES][rSize], int* randCount) {
	uint32_t t0[NUM_PARTIES]; 

	//e & (f^g) ^ g
	mpc_XOR(f,g,t0);
	aux_AND(e,t0,t0, randomness, randCount);
	mpc_XOR(t0,g,z);

}


int computeAuxTape(unsigned char randomness[NUM_PARTIES][rSize],unsigned char shares[NUM_PARTIES][SHA256_INPUTS])
{
	int randCount = 0;

	uint32_t w[64][NUM_PARTIES];

	memset(w,0,sizeof(int32_t)*64*NUM_PARTIES);
	for (int i = 0; i < NUM_PARTIES; i++) {
		for (int j = 0; j < 16; j++) {
			w[j][i] = (shares[i][j * 4] << 24) | (shares[i][j * 4 + 1] << 16)
							| (shares[i][j * 4 + 2] << 8) | shares[i][j * 4 + 3];
		}
	}

	uint32_t s0[NUM_PARTIES], s1[NUM_PARTIES];
	uint32_t t0[NUM_PARTIES], t1[NUM_PARTIES];
	for (int j = 16; j < 64; j++) {
		//s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^ (w[i][j-15] >> 3);
		mpc_RIGHTROTATE(w[j-15], 7, t0);

		mpc_RIGHTROTATE(w[j-15], 18, t1);
		mpc_XOR(t0, t1, t0);
		mpc_RIGHTSHIFT(w[j-15], 3, t1);
		mpc_XOR(t0, t1, s0);

		//s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^ (w[i][j-2] >> 10);
		mpc_RIGHTROTATE(w[j-2], 17, t0);
		mpc_RIGHTROTATE(w[j-2], 19, t1);

		mpc_XOR(t0, t1, t0);
		mpc_RIGHTSHIFT(w[j-2], 10, t1);
		mpc_XOR(t0, t1, s1);
		//w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];
		aux_ADD(w[j-16], s0, t1, randomness, &randCount);
		aux_ADD(w[j-7], t1, t1, randomness, &randCount);
		aux_ADD(t1, s1, w[j], randomness, &randCount);

	}

	uint32_t a[NUM_PARTIES];
	uint32_t b[NUM_PARTIES];
	uint32_t c[NUM_PARTIES];
	uint32_t d[NUM_PARTIES];
	uint32_t e[NUM_PARTIES];
	uint32_t f[NUM_PARTIES];
	uint32_t g[NUM_PARTIES];
	uint32_t h[NUM_PARTIES];
	for (int i = 0; i < NUM_PARTIES;i++)
	{
		a[i] = hA[0];
		b[i] = hA[1];
		c[i] = hA[2];
		d[i] = hA[3];
		e[i] = hA[4];
		f[i] = hA[5];
		g[i] = hA[6];
		h[i] = hA[7];
	}

	uint32_t temp1[NUM_PARTIES], temp2[NUM_PARTIES], temp3[NUM_PARTIES], maj[NUM_PARTIES];

	for (int i = 0; i < 64; i++) {
		//s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
		mpc_RIGHTROTATE(e, 6, t0);
		mpc_RIGHTROTATE(e, 11, t1);
		mpc_XOR(t0, t1, t0);

		mpc_RIGHTROTATE(e, 25, t1);
		mpc_XOR(t0, t1, s1);


		//ch = (e & f) ^ ((~e) & g);
		//temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

		//t0 = h + s1

		aux_ADD(h, s1, t0, randomness, &randCount);


		aux_CH(e, f, g, t1, randomness, &randCount);

		//t1 = t0 + t1 (h+s1+ch)
		aux_ADD(t0, t1, t1, randomness, &randCount);

		for (int j = 0; j < NUM_PARTIES; j++)
			temp3[j] = k[i];	
		aux_ADD(t1, temp3, t1, randomness, &randCount);

		aux_ADD(t1, w[i], temp1, randomness, &randCount);

		//s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
		mpc_RIGHTROTATE(a, 2, t0);
		mpc_RIGHTROTATE(a, 13, t1);
		mpc_XOR(t0, t1, t0);
		mpc_RIGHTROTATE(a, 22, t1);
		mpc_XOR(t0, t1, s0);


		aux_MAJ(a, b, c, maj, randomness, &randCount);

		//temp2 = s0+maj;
		aux_ADD(s0, maj, temp2, randomness, &randCount);

		memcpy(h, g, sizeof(uint32_t) * NUM_PARTIES);
		memcpy(g, f, sizeof(uint32_t) * NUM_PARTIES);
		memcpy(f, e, sizeof(uint32_t) * NUM_PARTIES);
		//e = d+temp1;
		aux_ADD(d, temp1, e, randomness, &randCount);
		memcpy(d, c, sizeof(uint32_t) * NUM_PARTIES);
		memcpy(c, b, sizeof(uint32_t) * NUM_PARTIES);
		memcpy(b, a, sizeof(uint32_t) * NUM_PARTIES);
		//a = temp1+temp2;

		aux_ADD(temp1, temp2, a, randomness, &randCount);
	}
	uint32_t hHa[8][NUM_PARTIES];
	for (int i = 0;i < 8;i++)
	{
		for (int j = 0;j < NUM_PARTIES;j++)
			hHa[i][j] = hA[i];
	}
	aux_ADD(hHa[0], a, hHa[0], randomness, &randCount);
	aux_ADD(hHa[1], b, hHa[1], randomness, &randCount);
	aux_ADD(hHa[2], c, hHa[2], randomness, &randCount);
	aux_ADD(hHa[3], d, hHa[3], randomness, &randCount);
	aux_ADD(hHa[4], e, hHa[4], randomness, &randCount);
	aux_ADD(hHa[5], f, hHa[5], randomness, &randCount);
	aux_ADD(hHa[6], g, hHa[6], randomness, &randCount);
	aux_ADD(hHa[7], h, hHa[7], randomness, &randCount);

//	printf("computeAuxTape: randCount %d\n",randCount);
	return 0;


}


#define CH(e,f,g) ((e & f) ^ ((~e) & g))

void printbits(uint32_t n) {
	if (n) {
		printbits(n >> 1);
		printf("%d", n & 1);
	}

}

int mpc_AND_verify(uint32_t x_state, uint32_t y_state, uint32_t * z_state, uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char randomness[NUM_PARTIES][rSize], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) 
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

void mpc_AND(uint32_t x_state, uint32_t y_state, uint32_t * z_state, uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char randomness[NUM_PARTIES][rSize], int* randCount, View views[NUM_PARTIES], int* countY) 
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

int mpc_ADD_verify(uint32_t x_state, uint32_t y_state, uint32_t * z_state, uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char randomness[NUM_PARTIES][rSize], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {

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

void mpc_ADD(uint32_t x_state, uint32_t y_state, uint32_t * z_state, uint32_t x[NUM_PARTIES], uint32_t y[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char randomness[NUM_PARTIES][rSize], int* randCount, View views[NUM_PARTIES], int* countY) {

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



int mpc_MAJ_verify(uint32_t a_state, uint32_t b_state, uint32_t c_state, uint32_t * z_state, uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char randomness[NUM_PARTIES][rSize], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {
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

void mpc_MAJ(uint32_t a_state, uint32_t b_state, uint32_t c_state, uint32_t * z_state, uint32_t a[NUM_PARTIES], uint32_t b[NUM_PARTIES], uint32_t c[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char randomness[NUM_PARTIES][rSize], int* randCount, View views[NUM_PARTIES], int* countY) {
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


int mpc_CH_verify(uint32_t e_state, uint32_t f_state, uint32_t g_state, uint32_t *z_state, uint32_t e[NUM_PARTIES], uint32_t f[NUM_PARTIES], uint32_t g[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char randomness[NUM_PARTIES][rSize], int* randCount, View views[NUM_PARTIES], int* countY, int unopenParty) {
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

void mpc_CH(uint32_t e_state, uint32_t f_state, uint32_t g_state, uint32_t *z_state, uint32_t e[NUM_PARTIES], uint32_t f[NUM_PARTIES], uint32_t g[NUM_PARTIES], uint32_t z[NUM_PARTIES], unsigned char randomness[NUM_PARTIES][rSize], int* randCount, View views[NUM_PARTIES], int* countY) {
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



int mpc_sha256(unsigned char masked_result[SHA256_DIGEST_LENGTH], unsigned char masked_input[SHA256_INPUTS], unsigned char shares[NUM_PARTIES][SHA256_INPUTS], unsigned char * inputs, int numBytes, unsigned char randomness[NUM_PARTIES][rSize], View views[NUM_PARTIES], unsigned char party_result[NUM_PARTIES][SHA256_DIGEST_LENGTH], int* countY) 
{

	if ((inputs) && (numBytes > 55))
	{	
		printf("Input too long, aborting!");
		return -1;
	}

	int randCount=0;

	uint32_t w_state[64] = {0};
	uint32_t w[64][NUM_PARTIES] = {0};
	memset(w,0,sizeof(int32_t)*64*NUM_PARTIES);
	memset(w_state,0,sizeof(int32_t)*64);

	for (int i = 0; i < NUM_PARTIES; i++) {
		for (int j = 0; j < 16; j++) {
			w[j][i] = (shares[i][j * 4] << 24) | (shares[i][j * 4 + 1] << 16)
							| (shares[i][j * 4 + 2] << 8) | shares[i][j * 4 + 3];
			w_state[j] ^= w[j][i];
		}
	}

	if (inputs) // prove
	{
		inputs[numBytes] = 0x80;
		inputs[62] = (numBytes *8) >> 8;
		inputs[63] = (numBytes * 8);
		for (int j = 0; j < 16; j++) {
			w_state[j] ^= (inputs[j * 4] << 24) | (inputs[j * 4 + 1] << 16)
								| (inputs[j * 4 + 2] << 8) | inputs[j * 4 + 3];
		}

		memcpy(masked_input, (unsigned char *) w_state, 64);
	}
	else // verify
		memcpy((unsigned char *)w_state,masked_input,64);

	uint32_t s0[NUM_PARTIES], s1[NUM_PARTIES];
	uint32_t t0[NUM_PARTIES], t1[NUM_PARTIES];
	uint32_t s0_state, s1_state;
	uint32_t t0_state, t1_state;

	for (int j = 16; j < 64; j++) {
		//s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^ (w[i][j-15] >> 3);
		mpc_RIGHTROTATE(w[j-15], 7, t0);
		t0_state = RIGHTROTATE(w_state[j-15],7);
		mpc_RIGHTROTATE(w[j-15], 18, t1);
		t1_state = RIGHTROTATE(w_state[j-15],18);

		mpc_XOR(t0, t1, t0);
		t0_state = t0_state^t1_state;

		mpc_RIGHTSHIFT(w[j-15], 3, t1);
		t1_state = w_state[j-15] >> 3;

		mpc_XOR(t0, t1, s0);
		s0_state = t0_state^t1_state;

		//s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^ (w[i][j-2] >> 10);
		mpc_RIGHTROTATE(w[j-2], 17, t0);
		t0_state = RIGHTROTATE(w_state[j-2],17);

		mpc_RIGHTROTATE(w[j-2], 19, t1);
		t1_state = RIGHTROTATE(w_state[j-2],19);

		mpc_XOR(t0, t1, t0);
		t0_state = t0_state^t1_state;

		mpc_RIGHTSHIFT(w[j-2], 10, t1);
		t1_state = w_state[j-2] >> 10;

		mpc_XOR(t0, t1, s1);
		s1_state = t0_state^t1_state;
		//w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];
		if (inputs)
		{
			mpc_ADD(w_state[j-16],s0_state,&t1_state,w[j-16], s0, t1, randomness, &randCount, views, countY);
			mpc_ADD(w_state[j-7],t1_state,&t1_state, w[j-7], t1, t1, randomness, &randCount, views, countY);
			mpc_ADD(t1_state, s1_state, &(w_state[j]), t1, s1, w[j], randomness, &randCount, views, countY);
		}
		else
		{
			if (mpc_ADD_verify(w_state[j-16],s0_state,&t1_state,w[j-16], s0, t1, randomness, &randCount, views, countY, numBytes))
				return -1;
			if (mpc_ADD_verify(w_state[j-7],t1_state,&t1_state, w[j-7], t1, t1, randomness, &randCount, views, countY, numBytes))
				return -1;
			if (mpc_ADD_verify(t1_state, s1_state, &(w_state[j]), t1, s1, w[j], randomness, &randCount, views, countY, numBytes))
				return -1;
		}

	}
	uint32_t a[NUM_PARTIES];
	uint32_t b[NUM_PARTIES];
	uint32_t c[NUM_PARTIES];
	uint32_t d[NUM_PARTIES];
	uint32_t e[NUM_PARTIES];
	uint32_t f[NUM_PARTIES];
	uint32_t g[NUM_PARTIES];
	uint32_t h[NUM_PARTIES];
	uint32_t a_state = hA[0];
	uint32_t b_state = hA[1];
	uint32_t c_state = hA[2];
	uint32_t d_state = hA[3];
	uint32_t e_state = hA[4];
	uint32_t f_state = hA[5];
	uint32_t g_state = hA[6];
	uint32_t h_state = hA[7];

	for (int i = 0; i < NUM_PARTIES; i++)
	{
		a[i] = hA[0];
		b[i] = hA[1];
		c[i] = hA[2];
		d[i] = hA[3];
		e[i] = hA[4];
		f[i] = hA[5];
		g[i] = hA[6];
		h[i] = hA[7];
	}

	uint32_t temp1[NUM_PARTIES], temp2[NUM_PARTIES], temp3[NUM_PARTIES], maj[NUM_PARTIES];
	uint32_t temp1_state, temp2_state, temp3_state, maj_state;
	for (int i = 0; i < 64; i++) {
		//s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
		mpc_RIGHTROTATE(e, 6, t0);
		t0_state = RIGHTROTATE(e_state,6);

		mpc_RIGHTROTATE(e, 11, t1);
		t1_state = RIGHTROTATE(e_state,11);

		mpc_XOR(t0, t1, t0);
		t0_state = t0_state^t1_state;

		mpc_RIGHTROTATE(e, 25, t1);
		t1_state = RIGHTROTATE(e_state,25);

		mpc_XOR(t0, t1, s1);
		s1_state = t0_state^t1_state;


		//ch = (e & f) ^ ((~e) & g);
		//temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

		//t0 = h + s1

		for (int j = 0; j < NUM_PARTIES;j++)
			temp3[j] = k[i];
		temp3_state = k[i];
		if (inputs)
		{
			mpc_ADD(h_state, s1_state, &t0_state, h, s1, t0, randomness, &randCount, views,countY);

			mpc_CH(e_state, f_state, g_state, &t1_state, e, f, g, t1, randomness, &randCount, views, countY);

		//t1 = t0 + t1 (h+s1+ch)
			mpc_ADD(t0_state, t1_state, &t1_state, t0, t1, t1, randomness, &randCount, views, countY);

			mpc_ADD(t1_state, temp3_state, &t1_state, t1,temp3, t1, randomness, &randCount, views, countY);

			mpc_ADD(t1_state, w_state[i], &temp1_state, t1, w[i], temp1, randomness, &randCount, views, countY);
		}
		else
		{
			if (mpc_ADD_verify(h_state, s1_state, &t0_state, h, s1, t0, randomness, &randCount, views,countY, numBytes) )
				return -1;

			if (mpc_CH_verify(e_state, f_state, g_state, &t1_state, e, f, g, t1, randomness, &randCount, views, countY, numBytes))
				return -1;

		//t1 = t0 + t1 (h+s1+ch)
			if (mpc_ADD_verify(t0_state, t1_state, &t1_state, t0, t1, t1, randomness, &randCount, views, countY, numBytes))
				return -1;

			if (mpc_ADD_verify(t1_state, temp3_state, &t1_state, t1,temp3, t1, randomness, &randCount, views, countY, numBytes))
				return -1;

			if (mpc_ADD_verify(t1_state, w_state[i], &temp1_state, t1, w[i], temp1, randomness, &randCount, views, countY, numBytes))
				return -1;

		}

		//s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
		mpc_RIGHTROTATE(a, 2, t0);
		t0_state = RIGHTROTATE(a_state,2);

		mpc_RIGHTROTATE(a, 13, t1);
		t1_state = RIGHTROTATE(a_state,13);

		mpc_XOR(t0, t1, t0);
		t0_state = t0_state^t1_state;

		mpc_RIGHTROTATE(a, 22, t1);
		t1_state = RIGHTROTATE(a_state,22);

		mpc_XOR(t0, t1, s0);
		s0_state = t0_state^t1_state;

		if (inputs)
		{
			mpc_MAJ(a_state, b_state, c_state, &maj_state, a, b, c, maj, randomness, &randCount, views, countY);

		//temp2 = s0+maj;
			mpc_ADD(s0_state, maj_state, &temp2_state, s0, maj, temp2, randomness, &randCount, views, countY);
		}
		else
		{
			if (mpc_MAJ_verify(a_state, b_state, c_state, &maj_state, a, b, c, maj, randomness, &randCount, views, countY, numBytes))
				return -1;
			if (mpc_ADD_verify(s0_state, maj_state, &temp2_state, s0, maj, temp2, randomness, &randCount, views, countY, numBytes))
				return -1;

		}

		memcpy(h,g,sizeof(uint32_t) * NUM_PARTIES);
		memcpy(g,f,sizeof(uint32_t) * NUM_PARTIES);
		memcpy(f,e,sizeof(uint32_t) * NUM_PARTIES);
		h_state = g_state;
		g_state = f_state;
		f_state = e_state;
		//e = d+temp1;
		if (inputs)
		{
			mpc_ADD(d_state, temp1_state, &e_state, d, temp1, e, randomness, &randCount, views, countY);
		}
		else
		{
			if (mpc_ADD_verify(d_state, temp1_state, &e_state, d, temp1, e, randomness, &randCount, views, countY, numBytes))
				return -1;
		}
		memcpy(d,c,sizeof(uint32_t) * NUM_PARTIES);
		memcpy(c,b,sizeof(uint32_t) * NUM_PARTIES);
		memcpy(b,a,sizeof(uint32_t) * NUM_PARTIES);
		d_state = c_state;
		c_state = b_state;
		b_state = a_state;
		//a = temp1+temp2;

		if (inputs)
		{
			mpc_ADD(temp1_state, temp2_state, &a_state, temp1, temp2, a, randomness, &randCount, views, countY);
		}
		else
		{
			if (mpc_ADD_verify(temp1_state, temp2_state, &a_state, temp1, temp2, a, randomness, &randCount, views, countY, numBytes))
				return -1;
		}

	}
	uint32_t hHa[8][NUM_PARTIES];
	uint32_t hHa_state[8];
	for (int i = 0;i < 8;i++)
	{
		hHa_state[i] = hA[i];
		for (int j = 0; j < NUM_PARTIES;j++)
			hHa[i][j] = hA[i];
	}
	if (inputs)
	{
		mpc_ADD(hHa_state[0], a_state, &hHa_state[0], hHa[0], a, hHa[0], randomness, &randCount, views, countY);
		mpc_ADD(hHa_state[1], b_state, &hHa_state[1], hHa[1], b, hHa[1], randomness, &randCount, views, countY);
		mpc_ADD(hHa_state[2], c_state, &hHa_state[2], hHa[2], c, hHa[2], randomness, &randCount, views, countY);
		mpc_ADD(hHa_state[3], d_state, &hHa_state[3], hHa[3], d, hHa[3], randomness, &randCount, views, countY);
		mpc_ADD(hHa_state[4], e_state, &hHa_state[4], hHa[4], e, hHa[4], randomness, &randCount, views, countY);
		mpc_ADD(hHa_state[5], f_state, &hHa_state[5], hHa[5], f, hHa[5], randomness, &randCount, views, countY);
		mpc_ADD(hHa_state[6], g_state, &hHa_state[6], hHa[6], g, hHa[6], randomness, &randCount, views, countY);
		mpc_ADD(hHa_state[7], h_state, &hHa_state[7], hHa[7], h, hHa[7], randomness, &randCount, views, countY);
	}
	else
	{
		if (mpc_ADD_verify(hHa_state[0], a_state, &hHa_state[0], hHa[0], a, hHa[0], randomness, &randCount, views, countY, numBytes))
			return -1;
		if (mpc_ADD_verify(hHa_state[1], b_state, &hHa_state[1], hHa[1], b, hHa[1], randomness, &randCount, views, countY, numBytes))
			return -1;
		if (mpc_ADD_verify(hHa_state[2], c_state, &hHa_state[2], hHa[2], c, hHa[2], randomness, &randCount, views, countY, numBytes))
			return -1;
		if (mpc_ADD_verify(hHa_state[3], d_state, &hHa_state[3], hHa[3], d, hHa[3], randomness, &randCount, views, countY, numBytes))
			return -1;
		if (mpc_ADD_verify(hHa_state[4], e_state, &hHa_state[4], hHa[4], e, hHa[4], randomness, &randCount, views, countY, numBytes))
			return -1;
		if (mpc_ADD_verify(hHa_state[5], f_state, &hHa_state[5], hHa[5], f, hHa[5], randomness, &randCount, views, countY, numBytes))
			return -1;
		if (mpc_ADD_verify(hHa_state[6], g_state, &hHa_state[6], hHa[6], g, hHa[6], randomness, &randCount, views, countY, numBytes))
			return -1;
		if (mpc_ADD_verify(hHa_state[7], h_state, &hHa_state[7], hHa[7], h, hHa[7], randomness, &randCount, views, countY, numBytes))
			return -1;
	}

	for (int i = 0; i < 8; i++)
	{
		for (int j = 0; j < NUM_PARTIES; j++)
		{
			if (inputs)
			{
				views[j].y[*countY] = hHa[i][j];
			}
			else
			{
				if (j == numBytes)
					hHa[i][j] = views[j].y[*countY];
				else
					views[j].y[*countY] = hHa[i][j];
			}
		}
		*countY+=1;
	}
	for (int i = 0; i < 8; i++) {
		mpc_RIGHTSHIFT(hHa[i], 24, t0);
		t0_state = hHa_state[i] >> 24;

		for (int j = 0;j< NUM_PARTIES;j++)
			party_result[j][i * 4] = t0[j];
		masked_result[i*4] = t0_state;

		mpc_RIGHTSHIFT(hHa[i], 16, t0);
		t0_state = hHa_state[i] >> 16;
		for (int j = 0;j< NUM_PARTIES;j++)
			party_result[j][i * 4 + 1] = t0[j];
		masked_result[i*4+1] = t0_state;

		mpc_RIGHTSHIFT(hHa[i], 8, t0);
		t0_state = hHa_state[i] >> 8;
		for (int j = 0;j< NUM_PARTIES;j++)
			party_result[j][i * 4 + 2] = t0[j];
		masked_result[i*4+2] = t0_state;

		for (int j = 0;j< NUM_PARTIES;j++)
			party_result[j][i * 4 + 3] = hHa[i][j];
		masked_result[i*4+3] = hHa_state[i];
	}
//	printf("mpc_sha256: randCount %d\n",randCount);

	return 0;
}

void printdigest(unsigned char * digest)
{
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x",digest[i]);
	printf("\n");
}

#endif /* SHARED_H_ */
