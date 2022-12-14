/*
 * Name: sharedripe.h
 * Author: Tan Teik Guan
 * Description: Common functions for RIPEMD160 
 *
 * Copyright pQCee 2022. All rights reserved
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
 * Software: MPC_RIPEMD160 
 *
 * License: MIT 1.0 
 *
 * Licensor: pQCee Pte Ltd 
 *
 */

/*
 ============================================================================
 Name        : shared.h
 Author      : Sobuno
 Version     : 0.1
 Description : Common functions for the SHA-256 prover and verifier
 ============================================================================
 */

#ifndef SHARED_H_
#define SHARED_H_
#include <openssl/ripemd.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#ifdef _WIN32
#include <openssl/applink.c>
#endif
#include <openssl/rand.h>
#include "omp.h"

#define VERBOSE 1 

static const uint32_t hA[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
static const uint32_t hG =  0x5a827999;
static const uint32_t hH =  0x6ed9eba1;
static const uint32_t hI =  0x8f1bbcdc;
static const uint32_t hJ =  0xa953fd4e;

static const uint32_t hGG =  0x7a6d76e9;
static const uint32_t hHH =  0x6d703ef3;
static const uint32_t hII =  0x5c4dd124;
static const uint32_t hJJ =  0x50a28be6;

//#define ySize 736
#define ySize 879 
#define rSize 3496 

typedef struct {
	unsigned char x[64];
	uint32_t y[ySize];
} View;

typedef struct {
	uint32_t yp[3][5];
	unsigned char h[3][20];
} a;

typedef struct {
	unsigned char ke[16];
	unsigned char ke1[16];
	View ve;
	View ve1;
	unsigned char re[4];
	unsigned char re1[4];
} z;

#define LEFTROTATE(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b)   x= (b)&1 ? (x)|((uint32_t)1 << (i)) : (x)&(~((uint32_t)1 << (i)))


void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

void getAllRandomness(unsigned char key[16], unsigned char randomness[rSize]) {
	//Generate randomness: We use 728*32 bit of randomness per key.
	//Since AES block size is 128 bit, we need to run 728*32/128 = 182 iterations

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
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
	memcpy(&ret, &randomness[randCount], 4);
	return ret;
}

uint64_t getRandom64(unsigned char randomness[rSize], int randCount) {
	uint64_t ret;

	memcpy(&ret, &(randomness[randCount]), 8);
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

void H(unsigned char k[16], View v, unsigned char r[4], unsigned char hash[RIPEMD160_DIGEST_LENGTH]) {
	RIPEMD160_CTX ctx;
	RIPEMD160_Init(&ctx);
	RIPEMD160_Update(&ctx, k, 16);
	RIPEMD160_Update(&ctx, &v, sizeof(v));
	RIPEMD160_Update(&ctx, r, 4);
	RIPEMD160_Final(hash, &ctx);
}


void H3(uint32_t y[5], a* as, int s, int* es) {

	unsigned char hash[RIPEMD160_DIGEST_LENGTH];
	RIPEMD160_CTX ctx;
	RIPEMD160_Init(&ctx);
	RIPEMD160_Update(&ctx, y, 20);
	RIPEMD160_Update(&ctx, as, sizeof(a)*s);
	RIPEMD160_Final(hash, &ctx);

	//Pick bits from hash
	int i = 0;
	int bitTracker = 0;
	while(i < s) {
		if(bitTracker >= RIPEMD160_DIGEST_LENGTH*8) { //Generate new hash as we have run out of bits in the previous hash
			RIPEMD160_Init(&ctx);
			RIPEMD160_Update(&ctx, hash, sizeof(hash));
			RIPEMD160_Final(hash, &ctx);
			bitTracker = 0;
		}

		int b1 = GETBIT(hash[bitTracker/8], bitTracker % 8);
		int b2 = GETBIT(hash[(bitTracker+1)/8], (bitTracker+1) % 8);
		if(b1 == 0) {
			if(b2 == 0) {
				es[i] = 0;
				bitTracker += 2;
				i++;
			} else {
				es[i] = 1;
				bitTracker += 2;
				i++;
			}
		} else {
			if(b2 == 0) {
				es[i] = 2;
				bitTracker += 2;
				i++;
			} else {
				bitTracker += 2;
			}
		}
	}

}

void output(View v, uint32_t* result) {
	memcpy(result, &v.y[ySize - 5], 20);
}

void reconstruct(uint32_t* y0, uint32_t* y1, uint32_t* y2, uint32_t* result) {
	for (int i = 0; i < 5; i++) {
		result[i] = y0[i] ^ y1[i] ^ y2[i];
	}
}

void mpc_XOR2(uint32_t x[2], uint32_t y[2], uint32_t z[2]) {
	z[0] = x[0] ^ y[0];
	z[1] = x[1] ^ y[1];
}

void mpc_NEGATE2(uint32_t x[2], uint32_t z[2]) {
	z[0] = ~x[0];
	z[1] = ~x[1];
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


int mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][rSize], int* randCount, int* countY) {
	uint32_t r[2] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount) };
	*randCount += 4;

	uint32_t t = 0;

	t = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
	if(ve.y[*countY] != t) {
		return 1;
	}
	z[0] = t;
	z[1] = ve1.y[*countY];

	(*countY)++;
	return 0;
}


int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][rSize], int* randCount, int* countY) {
	uint32_t r[2] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount) };
	*randCount += 4;

	uint8_t a[2], b[2];

	uint8_t t;

	for(int i=0;i<31;i++)
	{
		a[0]=GETBIT(x[0]^ve.y[*countY],i);
		a[1]=GETBIT(x[1]^ve1.y[*countY],i);

		b[0]=GETBIT(y[0]^ve.y[*countY],i);
		b[1]=GETBIT(y[1]^ve1.y[*countY],i);

		t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
		if(GETBIT(ve.y[*countY],i+1) != (t ^ (a[0]&b[0]) ^ GETBIT(ve.y[*countY],i) ^ GETBIT(r[0],i))) {
			return 1;
		}
	}

	z[0]=x[0]^y[0]^ve.y[*countY];
	z[1]=x[1]^y[1]^ve1.y[*countY];
	(*countY)++;
	return 0;
}

void mpc_LEFTROTATE2(uint32_t x[], int i, uint32_t z[]) {
	z[0] = LEFTROTATE(x[0], i);
	z[1] = LEFTROTATE(x[1], i);
}

void mpc_RIGHTSHIFT2(uint32_t x[2], int i, uint32_t z[2]) {
	z[0] = x[0] >> i;
	z[1] = x[1] >> i;
}

int mpc_OR_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][rSize], int* randCount, int* countY) 
{
	uint32_t t0[3];
	uint32_t t1[3];
	uint32_t t2[3];

	mpc_NEGATE2(x,t0);
	mpc_NEGATE2(y,t1);
	if (mpc_AND_verify(t0,t1,t2,ve,ve1,randomness,randCount,countY) == 1)
	{
		return 1;
	}
	mpc_NEGATE2(t2,z);
	return 0;
}

void mpc_F2(uint32_t x1[2], uint32_t x2[2], uint32_t x3[2], uint32_t z[2])
{
	uint32_t t0[2] = { 0 };

	mpc_XOR2(x1,x2,t0);
	mpc_XOR2(t0,x3,z);
}

int mpc_G2(uint32_t x1[2], uint32_t x2[2], uint32_t x3[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][rSize], int * randCount, int* countY) {
	uint32_t t0[2] = { 0 };
	uint32_t t1[2] = { 0 };
	uint32_t t2[2] = { 0 };

	if (mpc_AND_verify(x1,x2,t0,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	mpc_NEGATE2(x1,t1);
	if (mpc_AND_verify(t1,x3,t2,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_OR_verify(t0,t2,z,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	return 0;
}

int mpc_H2(uint32_t x1[2], uint32_t x2[2], uint32_t x3[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][rSize], int * randCount, int* countY) {
	uint32_t t0[2] = { 0 };
	uint32_t t1[2] = { 0 };

        mpc_NEGATE2(x2,t0);
	if (mpc_OR_verify(x1,t0,t1,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	mpc_XOR2(t1,x3,z);
	return 0;

}


int mpc_I2(uint32_t x1[2], uint32_t x2[2], uint32_t x3[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][rSize], int * randCount, int* countY) {
	uint32_t t0[2] = { 0 };
	uint32_t t1[2] = { 0 };
	uint32_t t2[2] = { 0 };

	if (mpc_AND_verify(x1,x3,t0,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	mpc_NEGATE2(x3,t1);
	if (mpc_AND_verify(x2,t1,t2,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_OR_verify(t0,t2,z,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	return 0;
}


int mpc_J2(uint32_t x1[2], uint32_t x2[2], uint32_t x3[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][rSize], int * randCount, int* countY) {
	uint32_t t0[2] = { 0 };
	uint32_t t1[2] = { 0 };

        mpc_NEGATE2(x3,t0);
	if (mpc_OR_verify(x2,t0,t1,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	mpc_XOR2(t1,x1,z);
	return 0;
}

int mpc_FF2(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t d[2], uint32_t e[2], uint32_t x[2], uint32_t s, View ve, View ve1, unsigned char randomness[2][rSize], int * randCount, int* countY)
{
	uint32_t t0[2] = { 0 };
	uint32_t t1[2] = { 0 };
	uint32_t t2[2] = { 0 };
	uint32_t t3[2] = { 0 };

	mpc_F2(b,c,d,t0);
	if (mpc_ADD_verify(t0,x,t1,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_ADD_verify(t1,a,t2,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	mpc_LEFTROTATE2(t2,s,t3);
	if (mpc_ADD_verify(t3,e,a,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	mpc_LEFTROTATE2(c,10,c);
	return 0;

}

int mpc_GG2(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t d[2], uint32_t e[2], uint32_t x[2], uint32_t s, uint32_t C, View ve, View ve1, unsigned char randomness[2][rSize], int * randCount, int* countY)
{
	uint32_t Cbuf[2] = {C,C};
	uint32_t t0[2] = { 0 };
	uint32_t t1[2] = { 0 };
	uint32_t t2[2] = { 0 };
	uint32_t t3[2] = { 0 };
	uint32_t t4[2] = { 0 };

	if(mpc_G2(b,c,d,t0,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_ADD_verify(t0,x,t1,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_ADD_verify(t1,Cbuf,t2,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_ADD_verify(t2,a,t3,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	mpc_LEFTROTATE2(t3,s,t4);
	if (mpc_ADD_verify(t4,e,a,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	mpc_LEFTROTATE2(c,10,c);
	return 0;
}

int mpc_HH2(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t d[2], uint32_t e[2], uint32_t x[2], uint32_t s, uint32_t C, View ve, View ve1, unsigned char randomness[2][rSize], int * randCount, int* countY)
{
	uint32_t Cbuf[2] = {C,C};
	uint32_t t0[2] = { 0 };
	uint32_t t1[2] = { 0 };
	uint32_t t2[2] = { 0 };
	uint32_t t3[2] = { 0 };
	uint32_t t4[2] = { 0 };

	if(mpc_H2(b,c,d,t0,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_ADD_verify(t0,x,t1,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_ADD_verify(t1,Cbuf,t2,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_ADD_verify(t2,a,t3,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	mpc_LEFTROTATE2(t3,s,t4);
	if (mpc_ADD_verify(t4,e,a,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	mpc_LEFTROTATE2(c,10,c);
	return 0;
}

int mpc_II2(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t d[2], uint32_t e[2], uint32_t x[2], uint32_t s, uint32_t C, View ve, View ve1, unsigned char randomness[2][rSize], int * randCount, int* countY)
{
	uint32_t Cbuf[2] = {C,C};
	uint32_t t0[2] = { 0 };
	uint32_t t1[2] = { 0 };
	uint32_t t2[2] = { 0 };
	uint32_t t3[2] = { 0 };
	uint32_t t4[2] = { 0 };

	if(mpc_I2(b,c,d,t0,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_ADD_verify(t0,x,t1,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_ADD_verify(t1,Cbuf,t2,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_ADD_verify(t2,a,t3,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	mpc_LEFTROTATE2(t3,s,t4);
	if (mpc_ADD_verify(t4,e,a,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	mpc_LEFTROTATE2(c,10,c);
	return 0;
}

int mpc_JJ2(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t d[2], uint32_t e[2], uint32_t x[2], uint32_t s, uint32_t C, View ve, View ve1, unsigned char randomness[2][rSize], int * randCount, int* countY)
{
	uint32_t Cbuf[2] = {C,C};
	uint32_t t0[2] = { 0 };
	uint32_t t1[2] = { 0 };
	uint32_t t2[2] = { 0 };
	uint32_t t3[2] = { 0 };
	uint32_t t4[2] = { 0 };

	if(mpc_J2(b,c,d,t0,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_ADD_verify(t0,x,t1,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_ADD_verify(t1,Cbuf,t2,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_ADD_verify(t2,a,t3,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	mpc_LEFTROTATE2(t3,s,t4);
	if (mpc_ADD_verify(t4,e,a,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	mpc_LEFTROTATE2(c,10,c);
	return 0;
}

int verify(a a, int e, z z) {
	unsigned char* hash = malloc(RIPEMD160_DIGEST_LENGTH);
	H(z.ke, z.ve, z.re, hash);

	if (memcmp(a.h[e], hash, 20) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	H(z.ke1, z.ve1, z.re1, hash);
	if (memcmp(a.h[(e + 1) % 3], hash, 20) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	free(hash);

	uint32_t* result = malloc(20);
	output(z.ve, result);
	if (memcmp(a.yp[e], result, 20) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}

	output(z.ve1, result);
	if (memcmp(a.yp[(e + 1) % 3], result, 20) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}

	free(result);
	unsigned char randomness[2][rSize];
	getAllRandomness(z.ke, randomness[0]);
	getAllRandomness(z.ke1, randomness[1]);

	int* randCount = calloc(1, sizeof(int));
	int* countY = calloc(1, sizeof(int));

	uint32_t X[16][2];
	for (int j = 0; j < 16; j++) {
		X[j][0] =  ((uint32_t)z.ve.x[j * 4 + 0] << 0) | ((uint32_t)z.ve.x[j * 4 + 1] << 8)
			| ((uint32_t)z.ve.x[j * 4 + 2] << 16) | ((uint32_t)z.ve.x[j * 4 + 3] << 24);
		X[j][1] =  ((uint32_t)z.ve1.x[j * 4 + 0] << 0) | ((uint32_t)z.ve1.x[j * 4 + 1] << 8)
			| ((uint32_t)z.ve1.x[j * 4 + 2] << 16) | ((uint32_t)z.ve1.x[j * 4 + 3] << 24);
	}

	uint32_t buf[5][2] = {{ hA[0],hA[0] },
				{hA[1],hA[1]},
				{hA[2],hA[2]},
				{hA[3],hA[3]},
				{hA[4],hA[4]}};

	uint32_t s0[2], s1[2];
	uint32_t t0[2], t1[2];
	uint32_t aa[2] = { hA[0],hA[0] };
	uint32_t bb[2] = { hA[1],hA[1] };
	uint32_t cc[2] = { hA[2],hA[2] };
	uint32_t dd[2] = { hA[3],hA[3] };
	uint32_t ee[2] = { hA[4],hA[4] };
	uint32_t aaa[2] = { hA[0],hA[0] };
	uint32_t bbb[2] = { hA[1],hA[1] };
	uint32_t ccc[2] = { hA[2],hA[2] };
	uint32_t ddd[2] = { hA[3],hA[3] };
	uint32_t eee[2] = { hA[4],hA[4] };
	uint32_t temp1[3], temp2[3], maj[3];

	// round 1 
	if (mpc_FF2(aa, bb, cc, dd, ee, X[0], 11, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ee, aa, bb, cc, dd, X[1], 14, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(dd, ee, aa, bb, cc, X[2], 15, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(cc, dd, ee, aa, bb, X[3], 12, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(bb, cc, dd, ee, aa, X[4], 5, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(aa, bb, cc, dd, ee, X[5], 8, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ee, aa, bb, cc, dd, X[6], 7, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(dd, ee, aa, bb, cc, X[7], 9, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(cc, dd, ee, aa, bb, X[8], 11, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(bb, cc, dd, ee, aa, X[9], 13, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(aa, bb, cc, dd, ee, X[10], 14, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ee, aa, bb, cc, dd, X[11], 15, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(dd, ee, aa, bb, cc, X[12], 6, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(cc, dd, ee, aa, bb, X[13], 7, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(bb, cc, dd, ee, aa, X[14], 9, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(aa, bb, cc, dd, ee, X[15], 8, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;

	// round 2
	if (mpc_GG2(ee, aa, bb, cc, dd, X[7], 7, hG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(dd, ee, aa, bb, cc, X[4], 6, hG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(cc, dd, ee, aa, bb, X[13], 8, hG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(bb, cc, dd, ee, aa, X[1], 13, hG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(aa, bb, cc, dd, ee, X[10], 11, hG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ee, aa, bb, cc, dd, X[6], 9, hG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(dd, ee, aa, bb, cc, X[15], 7, hG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(cc, dd, ee, aa, bb, X[3], 15, hG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(bb, cc, dd, ee, aa, X[12], 7, hG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(aa, bb, cc, dd, ee, X[0], 12, hG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ee, aa, bb, cc, dd, X[9], 15, hG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(dd, ee, aa, bb, cc, X[5], 9, hG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(cc, dd, ee, aa, bb, X[2], 11, hG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(bb, cc, dd, ee, aa, X[14], 7, hG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(aa, bb, cc, dd, ee, X[11], 13, hG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ee, aa, bb, cc, dd, X[8], 12, hG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;

	// round 3
	
	if (mpc_HH2(dd, ee, aa, bb, cc, X[3], 11, hH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(cc, dd, ee, aa, bb, X[10], 13, hH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(bb, cc, dd, ee, aa, X[14], 6, hH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(aa, bb, cc, dd, ee, X[4], 7, hH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ee, aa, bb, cc, dd, X[9], 14, hH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(dd, ee, aa, bb, cc, X[15], 9, hH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(cc, dd, ee, aa, bb, X[8], 13, hH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(bb, cc, dd, ee, aa, X[1], 15, hH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(aa, bb, cc, dd, ee, X[2], 14, hH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ee, aa, bb, cc, dd, X[7], 8, hH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(dd, ee, aa, bb, cc, X[0], 13, hH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(cc, dd, ee, aa, bb, X[6], 6, hH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(bb, cc, dd, ee, aa, X[13], 5, hH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(aa, bb, cc, dd, ee, X[11], 12, hH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ee, aa, bb, cc, dd, X[5], 7, hH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(dd, ee, aa, bb, cc, X[12], 5, hH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;

	// round 4
	
	if (mpc_II2(cc, dd, ee, aa, bb, X[1], 11, hI, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(bb, cc, dd, ee, aa, X[9], 12, hI, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(aa, bb, cc, dd, ee, X[11], 14, hI, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ee, aa, bb, cc, dd, X[10], 15, hI, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(dd, ee, aa, bb, cc, X[0], 14, hI, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(cc, dd, ee, aa, bb, X[8], 15, hI, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(bb, cc, dd, ee, aa, X[12], 9, hI, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(aa, bb, cc, dd, ee, X[4], 8, hI, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ee, aa, bb, cc, dd, X[13], 9, hI, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(dd, ee, aa, bb, cc, X[3], 14, hI, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(cc, dd, ee, aa, bb, X[7], 5, hI, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(bb, cc, dd, ee, aa, X[15], 6, hI, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(aa, bb, cc, dd, ee, X[14], 8, hI, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ee, aa, bb, cc, dd, X[5], 6, hI, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(dd, ee, aa, bb, cc, X[6], 5, hI, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(cc, dd, ee, aa, bb, X[2], 12, hI, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;

	// round 5

	if (mpc_JJ2(bb, cc, dd, ee, aa, X[4], 9, hJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(aa, bb, cc, dd, ee, X[0], 15, hJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ee, aa, bb, cc, dd, X[5], 5, hJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(dd, ee, aa, bb, cc, X[9], 11, hJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(cc, dd, ee, aa, bb, X[7], 6, hJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(bb, cc, dd, ee, aa, X[12], 8, hJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(aa, bb, cc, dd, ee, X[2], 13, hJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ee, aa, bb, cc, dd, X[10], 12, hJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(dd, ee, aa, bb, cc, X[14], 5, hJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(cc, dd, ee, aa, bb, X[1], 12, hJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(bb, cc, dd, ee, aa, X[3], 13, hJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(aa, bb, cc, dd, ee, X[8], 14, hJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ee, aa, bb, cc, dd, X[11], 11, hJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(dd, ee, aa, bb, cc, X[6], 8, hJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(cc, dd, ee, aa, bb, X[15], 5, hJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(bb, cc, dd, ee, aa, X[13], 6, hJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;

	// alt round 1
	if (mpc_JJ2(aaa, bbb, ccc, ddd, eee, X[5], 8, hJJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(eee, aaa, bbb, ccc, ddd, X[14], 9, hJJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ddd, eee, aaa, bbb, ccc, X[7], 9, hJJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ccc, ddd, eee, aaa, bbb, X[0], 11, hJJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(bbb, ccc, ddd, eee, aaa, X[9], 13, hJJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(aaa, bbb, ccc, ddd, eee, X[2], 15, hJJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(eee, aaa, bbb, ccc, ddd, X[11], 15, hJJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ddd, eee, aaa, bbb, ccc, X[4], 5, hJJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ccc, ddd, eee, aaa, bbb, X[13], 7, hJJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(bbb, ccc, ddd, eee, aaa, X[6], 7, hJJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(aaa, bbb, ccc, ddd, eee, X[15], 8, hJJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(eee, aaa, bbb, ccc, ddd, X[8], 11, hJJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ddd, eee, aaa, bbb, ccc, X[1], 14, hJJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ccc, ddd, eee, aaa, bbb, X[10], 14, hJJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(bbb, ccc, ddd, eee, aaa, X[3], 12, hJJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(aaa, bbb, ccc, ddd, eee, X[12], 6, hJJ, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;

	// alt round 2

	if (mpc_II2(eee, aaa, bbb, ccc, ddd, X[6], 9, hII, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ddd, eee, aaa, bbb, ccc, X[11], 13, hII, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ccc, ddd, eee, aaa, bbb, X[3], 15, hII, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(bbb, ccc, ddd, eee, aaa, X[7], 7, hII, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(aaa, bbb, ccc, ddd, eee, X[0], 12, hII, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(eee, aaa, bbb, ccc, ddd, X[13], 8, hII, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ddd, eee, aaa, bbb, ccc, X[5], 9, hII, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ccc, ddd, eee, aaa, bbb, X[10], 11, hII, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(bbb, ccc, ddd, eee, aaa, X[14], 7, hII, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(aaa, bbb, ccc, ddd, eee, X[15], 7, hII, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(eee, aaa, bbb, ccc, ddd, X[8], 12, hII, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ddd, eee, aaa, bbb, ccc, X[12], 7, hII, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ccc, ddd, eee, aaa, bbb, X[4], 6, hII, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(bbb, ccc, ddd, eee, aaa, X[9], 15, hII, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(aaa, bbb, ccc, ddd, eee, X[1], 13, hII, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(eee, aaa, bbb, ccc, ddd, X[2], 11, hII, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;

	// alt round 3
	if (mpc_HH2(ddd, eee, aaa, bbb, ccc, X[15], 9, hHH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ccc, ddd, eee, aaa, bbb, X[5], 7, hHH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(bbb, ccc, ddd, eee, aaa, X[1], 15, hHH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(aaa, bbb, ccc, ddd, eee, X[3], 11, hHH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(eee, aaa, bbb, ccc, ddd, X[7], 8, hHH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ddd, eee, aaa, bbb, ccc, X[14], 6, hHH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ccc, ddd, eee, aaa, bbb, X[6], 6, hHH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(bbb, ccc, ddd, eee, aaa, X[9], 14, hHH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(aaa, bbb, ccc, ddd, eee, X[11], 12, hHH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(eee, aaa, bbb, ccc, ddd, X[8], 13, hHH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ddd, eee, aaa, bbb, ccc, X[12], 5, hHH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ccc, ddd, eee, aaa, bbb, X[2], 14, hHH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(bbb, ccc, ddd, eee, aaa, X[10], 13, hHH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(aaa, bbb, ccc, ddd, eee, X[0], 13, hHH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(eee, aaa, bbb, ccc, ddd, X[4], 7, hHH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ddd, eee, aaa, bbb, ccc, X[13], 5, hHH, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;

	// alt round 4
	if (mpc_GG2(ccc, ddd, eee, aaa, bbb, X[8], 15, hGG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(bbb, ccc, ddd, eee, aaa, X[6], 5, hGG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(aaa, bbb, ccc, ddd, eee, X[4], 8, hGG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(eee, aaa, bbb, ccc, ddd, X[1], 11, hGG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ddd, eee, aaa, bbb, ccc, X[3], 14, hGG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ccc, ddd, eee, aaa, bbb, X[11], 14, hGG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(bbb, ccc, ddd, eee, aaa, X[15], 6, hGG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(aaa, bbb, ccc, ddd, eee, X[0], 14, hGG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(eee, aaa, bbb, ccc, ddd, X[5], 6, hGG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ddd, eee, aaa, bbb, ccc, X[12], 9, hGG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ccc, ddd, eee, aaa, bbb, X[2], 12, hGG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(bbb, ccc, ddd, eee, aaa, X[13], 9, hGG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(aaa, bbb, ccc, ddd, eee, X[9], 12, hGG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(eee, aaa, bbb, ccc, ddd, X[7], 5, hGG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ddd, eee, aaa, bbb, ccc, X[10], 15, hGG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ccc, ddd, eee, aaa, bbb, X[14], 8, hGG, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;

	// alt round 5
	if (mpc_FF2(bbb, ccc, ddd, eee, aaa, X[12], 8, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(aaa, bbb, ccc, ddd, eee, X[15], 5, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(eee, aaa, bbb, ccc, ddd, X[10], 12, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ddd, eee, aaa, bbb, ccc, X[4], 9, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ccc, ddd, eee, aaa, bbb, X[1], 12, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(bbb, ccc, ddd, eee, aaa, X[5], 5, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(aaa, bbb, ccc, ddd, eee, X[8], 14, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(eee, aaa, bbb, ccc, ddd, X[7], 6, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ddd, eee, aaa, bbb, ccc, X[6], 8, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ccc, ddd, eee, aaa, bbb, X[2], 13, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(bbb, ccc, ddd, eee, aaa, X[13], 6, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(aaa, bbb, ccc, ddd, eee, X[14], 5, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(eee, aaa, bbb, ccc, ddd, X[0], 15, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ddd, eee, aaa, bbb, ccc, X[3], 13, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ccc, ddd, eee, aaa, bbb, X[9], 11, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(bbb, ccc, ddd, eee, aaa, X[11], 11, z.ve, z.ve1, randomness, randCount, countY) == 1)
		return 1;

	 if (mpc_ADD_verify(cc,buf[1],t0,z.ve,z.ve1,randomness,randCount,countY)==1)
		 return 1;
	if (mpc_ADD_verify(t0,ddd,t1,z.ve,z.ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_ADD_verify(dd,buf[2],t0,z.ve,z.ve1,randomness,randCount,countY) ==1)
		return 1;
	if (mpc_ADD_verify(t0,eee,buf[1],z.ve,z.ve1,randomness,randCount,countY) ==1)
		return 1;
	if (mpc_ADD_verify(ee,buf[3],t0,z.ve,z.ve1,randomness,randCount,countY)==1)
		return 1;
	if (mpc_ADD_verify(t0,aaa,buf[2],z.ve,z.ve1,randomness,randCount,countY)==1)
		return 1;
	if (mpc_ADD_verify(aa,buf[4],t0,z.ve,z.ve1,randomness,randCount,countY)==1)
		return 1;
	if (mpc_ADD_verify(t0,bbb,buf[3],z.ve,z.ve1,randomness,randCount,countY)==1)
		return 1;
	if (mpc_ADD_verify(bb,buf[0],t0,z.ve,z.ve1,randomness,randCount,countY)== 1)
		return 1;
	if (mpc_ADD_verify(t0,ccc,buf[4],z.ve,z.ve1,randomness,randCount,countY)==1)
		return 1;

	free(randCount);
	free(countY);

	return 0;
}


#endif /* SHARED_H_ */
