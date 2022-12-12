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
	uint64_t y[ySize];
} View;

typedef struct {
	uint64_t yp[3][8];
	unsigned char h[3][64];
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


void H3(uint32_t y[8], a* as, int s, int* es) {

	unsigned char hash[RIPEMD160_DIGEST_LENGTH];
	RIPEMD160_CTX ctx;
	RIPEMD160_Init(&ctx);
	RIPEMD160_Update(&ctx, y, 64);
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

	uint64_t t = 0;

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

	/*
	uint64_t w[16][2];
	for (int j = 0; j < 16; j++) {
		w[j][0] = ((uint64_t)z.ve.x[j * 8] << 56) | ((uint64_t)z.ve.x[j * 8 + 1] << 48)
			| ((uint64_t)z.ve.x[j * 8 + 2] << 40) | ((uint64_t)z.ve.x[j * 8 + 3] << 32)
			| ((uint64_t)z.ve.x[j * 8 + 4] << 24) | ((uint64_t)z.ve.x[j * 8 + 5] << 16)
			| ((uint64_t)z.ve.x[j * 8 + 6] << 8) | (uint64_t)z.ve.x[j * 8 + 7];
		w[j][1] = ((uint64_t)z.ve1.x[j * 8] << 56) | ((uint64_t)z.ve1.x[j * 8 + 1] << 48)
			| ((uint64_t)z.ve1.x[j * 8 + 2] << 40) | ((uint64_t)z.ve1.x[j * 8 + 3] << 32)
			| ((uint64_t)z.ve1.x[j * 8 + 4] << 24) | ((uint64_t)z.ve1.x[j * 8 + 5] << 16)
			| ((uint64_t)z.ve1.x[j * 8 + 6] << 8) | (uint64_t)z.ve1.x[j * 8 + 7];
	}

	uint64_t s0[2], s1[2];
	uint64_t t0[2], t1[2];
	uint64_t va[2] = { hA[0],hA[0] };
	uint64_t vb[2] = { hA[1],hA[1] };
	uint64_t vc[2] = { hA[2],hA[2] };
	uint64_t vd[2] = { hA[3],hA[3] };
	uint64_t ve[2] = { hA[4],hA[4] };
	uint64_t vf[2] = { hA[5],hA[5] };
	uint64_t vg[2] = { hA[6],hA[6] };
	uint64_t vh[2] = { hA[7],hA[7] };
	uint64_t temp1[3], temp2[3], maj[3];
	for (int i = 0; i < 80; i++) 
	{
		if (i>=16) 
		{
			mpc_RIGHTROTATE2(W(i+14), 19, t0);
			mpc_RIGHTROTATE2(W(i+14), 61, t1);
			mpc_XOR2(t0, t1, t0);
			mpc_RIGHTSHIFT2(W(i+14), 6, t1);
			mpc_XOR2(t0, t1, s0);

			mpc_RIGHTROTATE2(W(i+1), 1, t0);
			mpc_RIGHTROTATE2(W(i+1), 8, t1);
			mpc_XOR2(t0, t1, t0);
			mpc_RIGHTSHIFT2(W(i+1),7,t1);
			mpc_XOR2(t0, t1, s1);

		//w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];

			if(mpc_ADD_verify(W(i+9), s0, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
				return 1;
			}


			if(mpc_ADD_verify(s1, t1, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
				return 1;
			}
			if(mpc_ADD_verify(W(i), t1, W(i), z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
				return 1;
			}

		}

		//s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
		mpc_RIGHTROTATE2(ve, 14, t0);
		mpc_RIGHTROTATE2(ve, 18, t1);
		mpc_XOR2(t0, t1, t0);
		mpc_RIGHTROTATE2(ve, 41, t1);
		mpc_XOR2(t0, t1, s1);




		//ch = (e & f) ^ ((~e) & g);
		//temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

		//t0 = h + s1

		if(mpc_ADD_verify(vh, s1, t0, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}

		if(mpc_CH_verify(ve, vf, vg, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}

		//t1 = t0 + t1 (h+s1+ch)
		if(mpc_ADD_verify(t0, t1, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}



		t0[0] = k[i];
		t0[1] = k[i];
		if(mpc_ADD_verify(t1, t0, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}


		if(mpc_ADD_verify(t1, W(i), temp1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}

		//s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
		mpc_RIGHTROTATE2(va, 28, t0);
		mpc_RIGHTROTATE2(va, 34, t1);
		mpc_XOR2(t0, t1, t0);
		mpc_RIGHTROTATE2(va, 39, t1);
		mpc_XOR2(t0, t1, s0);

		//maj = (a & (b ^ c)) ^ (b & c);
		//(a & b) ^ (a & c) ^ (b & c)

		if(mpc_MAJ_verify(va, vb, vc, maj, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}

		//temp2 = s0+maj;
		if(mpc_ADD_verify(s0, maj, temp2, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}



		memcpy(vh, vg, sizeof(uint64_t) * 2);
		memcpy(vg, vf, sizeof(uint64_t) * 2);
		memcpy(vf, ve, sizeof(uint64_t) * 2);
		//e = d+temp1;
		if(mpc_ADD_verify(vd, temp1, ve, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}

		memcpy(vd, vc, sizeof(uint64_t) * 2);
		memcpy(vc, vb, sizeof(uint64_t) * 2);
		memcpy(vb, va, sizeof(uint64_t) * 2);
		//a = temp1+temp2;

		if(mpc_ADD_verify(temp1, temp2, va, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}
	}

	uint64_t hHa[8][3] = { { hA[0],hA[0],hA[0]  }, { hA[1],hA[1],hA[1] }, { hA[2],hA[2],hA[2] }, { hA[3],hA[3],hA[3] },
			{ hA[4],hA[4],hA[4] }, { hA[5],hA[5],hA[5] }, { hA[6],hA[6],hA[6] }, { hA[7],hA[7],hA[7] } };
	if(mpc_ADD_verify(hHa[0], va, hHa[0], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[1], vb, hHa[1], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[2], vc, hHa[2], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[3], vd, hHa[3], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[4], ve, hHa[4], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[5], vf, hHa[5], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[6], vg, hHa[6], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[7], vh, hHa[7], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
*/
	free(randCount);
	free(countY);

	return 0;
}


#endif /* SHARED_H_ */
