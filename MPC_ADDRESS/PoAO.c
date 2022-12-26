/*
 * Author: Tan Teik Guan
 * Description : ZKBoo for proof of address ownership 
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
 * Software: PoAO 
 *
 * License: MIT 1.0 
 *
 * Licensor: pQCee Pte Ltd 
 *
 */
 
/*
 ============================================================================
 Name        : MPC_SHA256.c
 Author      : Sobuno
 Version     : 0.1
 Description : MPC SHA256 for one block only
 ============================================================================
 */

//#include <emscripten.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "PoAO.h"
#include "sha256.h"

#define CH(e,f,g) ((e & f) ^ ((~e) & g))



/*
 ============================================================================
 Name        : shared.h
 Author      : Sobuno
 Version     : 0.1
 Description : Common functions for the SHA-256 prover and verifier
 ============================================================================
 */


#define VERBOSE 1 

#define RIGHTROTATE(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define LEFTROTATE(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b)   x= (b)&1 ? (x)|((uint32_t)1 << (i)) : (x)&(~((uint32_t)1 << (i)))

int debug = 0;

static int RAND_bytes(unsigned char * buf, int numBytes)
{
	while (numBytes-- > 0)
	{
		*buf = (unsigned char) (rand() & 0xFF);
		buf++;
	}
	return 1;
}
/*
void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
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
*/

static void getAllRandomness(unsigned char key[16], unsigned char randomness[rSize]) {
	//Generate randomness: We use 728*32 bit of randomness per key.
	//Since AES block size is 128 bit, we need to run 728*32/128 = 182 iterations

	SHA256_CTX ctx;
	unsigned char * iv = (unsigned char *) "01234567890123456";
	unsigned char *plaintext =
			(unsigned char *)"0000000000000000";
	unsigned char hashbuf[SHA256_BLOCK_SIZE];
	int len;
	sha256_init(&ctx);
	sha256_update(&ctx,iv,strlen((char *)iv));
	sha256_update(&ctx,plaintext,strlen((char *)plaintext));
	sha256_update(&ctx,key,16);
	sha256_final(&ctx,hashbuf);
	for(int j=0;j<(rSize/16);j++) {
		sha256_init(&ctx);
		sha256_update(&ctx,hashbuf,SHA256_BLOCK_SIZE);
		sha256_final(&ctx,hashbuf);
		memcpy(&randomness[j*16],hashbuf,16);
	}
}

static uint32_t getRandom32(unsigned char randomness[rSize], int randCount) {
	uint32_t ret;
	memcpy(&ret, &randomness[randCount], 4);
	return ret;
}

static uint64_t getRandom64(unsigned char randomness[rSize], int randCount) {
	uint64_t ret;

	memcpy(&ret, &(randomness[randCount]), 8);
	return ret;
}

static int getRandom256(unsigned char * randomness, int randCount, unsigned char outbuf[32]) {

	if (outbuf)
	{
		memcpy(outbuf, &randomness[randCount], 32);
		return 0;
	}
	else
		return -1;
}


static void H(unsigned char k[16], View *v, unsigned char r[4], unsigned char hash[RIPEMD160_DIGEST_LENGTH]) {
	SHA256_CTX ctx;
	unsigned char shahash[SHA256_DIGEST_LENGTH];

	sha256_init(&ctx);
	sha256_update(&ctx, k, 16);
	sha256_update(&ctx, (unsigned char *) v, sizeof(View));
	sha256_update(&ctx, r, 4);
	sha256_final(&ctx, shahash);

	ripemd160(shahash,SHA256_DIGEST_LENGTH,hash);
}


static void H3(char * msg, uint32_t y[5], a* as, int s, int* es) {

	unsigned char shahash[SHA256_DIGEST_LENGTH];
	unsigned char hash[RIPEMD160_DIGEST_LENGTH];
	SHA256_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, (unsigned char *)msg, strlen(msg));
	sha256_update(&ctx, (unsigned char *)y, 20);
	sha256_update(&ctx, (unsigned char *)as, sizeof(a)*s);
	sha256_final(&ctx, shahash);
	
	ripemd160(shahash,SHA256_DIGEST_LENGTH,hash);

	if (debug)
	{
		printf("hash3 is [%02x %02x %02x]\n",hash[0],hash[1],hash[2]);
	}
	//Pick bits from hash
	int i = 0;
	int bitTracker = 0;
	while(i < s) {
		if(bitTracker >= RIPEMD160_DIGEST_LENGTH*8) { //Generate new hash as we have run out of bits in the previous hash
			sha256_init(&ctx);
			sha256_update(&ctx, hash, sizeof(hash));
			sha256_final(&ctx,shahash);
			ripemd160(shahash,SHA256_DIGEST_LENGTH,hash);
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

static void output(View v, uint32_t* result) {
	memcpy(result, &v.y[ySize - 5], 20);
}

static void reconstruct(uint32_t* y0, uint32_t* y1, uint32_t* y2, uint32_t* result) {
	for (int i = 0; i < 5; i++) {
		result[i] = y0[i] ^ y1[i] ^ y2[i];
	}
}

static void mpc_XOR2(uint32_t x[2], uint32_t y[2], uint32_t z[2]) {
	z[0] = x[0] ^ y[0];
	z[1] = x[1] ^ y[1];
}

static void mpc_NEGATE2(uint32_t x[2], uint32_t z[2]) {
	z[0] = ~x[0];
	z[1] = ~x[1];
}

static int mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View* ve, View* ve1, unsigned char *randomness[2], int* randCount, int* countY) {
	uint32_t r[2] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount) };
	*randCount += 4;

	uint32_t t = 0;

	t = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
	if(ve->y[*countY] != t) {
		return 1;
	}
	z[0] = t;
	z[1] = ve1->y[*countY];

	*countY += 1;
	return 0;
}


static int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View *ve, View* ve1, unsigned char *randomness[2], int* randCount, int* countY) {
	uint32_t r[2] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount) };
	*randCount += 4;

	uint8_t a[2], b[2];

	uint8_t t;
	
	for(int i=0;i<31;i++)
	{
		a[0]=GETBIT(x[0]^ve->y[*countY],i);
		a[1]=GETBIT(x[1]^ve1->y[*countY],i);

		b[0]=GETBIT(y[0]^ve->y[*countY],i);
		b[1]=GETBIT(y[1]^ve1->y[*countY],i);

		t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
		if(GETBIT(ve->y[*countY],i+1) != (t ^ (a[0]&b[0]) ^ GETBIT(ve->y[*countY],i) ^ GETBIT(r[0],i))) {
			return 1;
		}
	}

	z[0]=x[0]^y[0]^ve->y[*countY];
	z[1]=x[1]^y[1]^ve1->y[*countY];
	*countY +=1;
	return 0;
}

static void mpc_RIGHTROTATE2(uint32_t x[], int i, uint32_t z[]) {
	z[0] = RIGHTROTATE(x[0], i);
	z[1] = RIGHTROTATE(x[1], i);
}

static void mpc_LEFTROTATE2(uint32_t x[], int i, uint32_t z[]) {
	z[0] = LEFTROTATE(x[0], i);
	z[1] = LEFTROTATE(x[1], i);
}

static void mpc_RIGHTSHIFT2(uint32_t x[2], int i, uint32_t z[2]) {
	z[0] = x[0] >> i;
	z[1] = x[1] >> i;
}

static int mpc_OR_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View *ve, View *ve1, unsigned char * randomness[2], int* randCount, int* countY) 
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

static int mpc_MAJ_verify(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t z[3], View * ve, View* ve1, unsigned char * randomness[2], int* randCount, int* countY) {
	uint32_t t0[3];
	uint32_t t1[3];

	mpc_XOR2(a, b, t0);
	mpc_XOR2(a, c, t1);
	if(mpc_AND_verify(t0, t1, z, ve, ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	mpc_XOR2(z, a, z);
	return 0;
}

static int mpc_CH_verify(uint32_t e[2], uint32_t f[2], uint32_t g[2], uint32_t z[2], View * ve, View *ve1, unsigned char * randomness[2], int* randCount, int* countY) {
	uint32_t t0[3];

	mpc_XOR2(f,g,t0);
	if(mpc_AND_verify(e, t0, t0, ve, ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	mpc_XOR2(t0,g,z);

	return 0;
}


static void mpc_F2(uint32_t x1[2], uint32_t x2[2], uint32_t x3[2], uint32_t z[2])
{
	uint32_t t0[2] = { 0 };

	mpc_XOR2(x1,x2,t0);
	mpc_XOR2(t0,x3,z);
}

static int mpc_G2(uint32_t x1[2], uint32_t x2[2], uint32_t x3[2], uint32_t z[2], View *ve, View* ve1, unsigned char * randomness[2], int * randCount, int* countY) {
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

static int mpc_H2(uint32_t x1[2], uint32_t x2[2], uint32_t x3[2], uint32_t z[2], View *ve, View* ve1, unsigned char * randomness[2], int * randCount, int* countY) {
	uint32_t t0[2] = { 0 };
	uint32_t t1[2] = { 0 };

        mpc_NEGATE2(x2,t0);
	if (mpc_OR_verify(x1,t0,t1,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	mpc_XOR2(t1,x3,z);
	return 0;

}


static int mpc_I2(uint32_t x1[2], uint32_t x2[2], uint32_t x3[2], uint32_t z[2], View *ve, View* ve1, unsigned char *randomness[2], int * randCount, int* countY) {
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


static int mpc_J2(uint32_t x1[2], uint32_t x2[2], uint32_t x3[2], uint32_t z[2], View *ve, View* ve1, unsigned char * randomness[2], int * randCount, int* countY) {
	uint32_t t0[2] = { 0 };
	uint32_t t1[2] = { 0 };

        mpc_NEGATE2(x3,t0);
	if (mpc_OR_verify(x2,t0,t1,ve,ve1,randomness,randCount,countY) == 1)
		return 1;
	mpc_XOR2(t1,x1,z);
	return 0;
}

static int mpc_FF2(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t d[2], uint32_t e[2], uint32_t x[2], uint32_t s, View *ve, View *ve1, unsigned char *randomness[2], int * randCount, int* countY)
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

static int mpc_GG2(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t d[2], uint32_t e[2], uint32_t x[2], uint32_t s, uint32_t C, View *ve, View* ve1, unsigned char *randomness[2], int * randCount, int* countY)
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

static int mpc_HH2(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t d[2], uint32_t e[2], uint32_t x[2], uint32_t s, uint32_t C, View *ve, View *ve1, unsigned char *randomness[2], int * randCount, int* countY)
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

static int mpc_II2(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t d[2], uint32_t e[2], uint32_t x[2], uint32_t s, uint32_t C, View *ve, View *ve1, unsigned char *randomness[2], int * randCount, int* countY)
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

static int mpc_JJ2(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t d[2], uint32_t e[2], uint32_t x[2], uint32_t s, uint32_t C, View *ve, View* ve1, unsigned char* randomness[2], int * randCount, int* countY)
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

static void mpc_RIGHTSHIFT(uint32_t x[3], int i, uint32_t z[3]) {
	z[0] = x[0] >> i;
	z[1] = x[1] >> i;
	z[2] = x[2] >> i;
}

static int mpc_verify(a* as, int e, z * zp) {
	int j;
	unsigned char hash[RIPEMD160_DIGEST_LENGTH];
	z zs;

	memcpy(&zs,zp,sizeof(z));
	H(zs.ke, &(zs.ve), zs.re, hash);

	if (memcmp(as->h[e], hash, 20) != 0) {
		return 1;
	}
	H(zs.ke1, &(zs.ve1), zs.re1, hash);
	if (memcmp(as->h[(e + 1) % 3], hash, 20) != 0) {
		return 1;
	}

	uint32_t result[5];
	output(zs.ve, result);
	if (memcmp(as->yp[e], result, 20) != 0) {
		return 1;
	}

	output(zs.ve1, result);
	if (memcmp(as->yp[(e + 1) % 3], result, 20) != 0) {
		return 1;
	}
	unsigned char* randomness[2];
	randomness[0] = malloc(rSize);
	randomness[1] = malloc(rSize);
	getAllRandomness(zs.ke, randomness[0]);
	getAllRandomness(zs.ke1, randomness[1]);

	int *randCount =calloc(1,sizeof(int)) ;
	int *countY = calloc(1,sizeof(int)) ;
	*randCount = 0;
	*countY = 0;
	uint32_t w[64][2];

	for (j = 0; j < 16; j++) {
		w[j][0] = (zs.ve.x[j * 4] << 24) | (zs.ve.x[j * 4 + 1] << 16)
				| (zs.ve.x[j * 4 + 2] << 8) | zs.ve.x[j * 4 + 3];
		w[j][1] = (zs.ve1.x[j * 4] << 24) | (zs.ve1.x[j * 4 + 1] << 16)
				| (zs.ve1.x[j * 4 + 2] << 8) | zs.ve1.x[j * 4 + 3];
	}
	uint32_t s0[2], s1[2];
	uint32_t t0[2], t1[2];

	for (j = 16; j < 64; j++) 
	{
		mpc_RIGHTROTATE2(w[j-15], 7, t0);
		mpc_RIGHTROTATE2(w[j-15], 18, t1);
		mpc_XOR2(t0, t1, t0);
		mpc_RIGHTSHIFT2(w[j-15], 3, t1);
		mpc_XOR2(t0, t1, s0);

		//s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^ (w[i][j-2] >> 10);
		mpc_RIGHTROTATE2(w[j-2], 17, t0);
		mpc_RIGHTROTATE2(w[j-2], 19, t1);
		mpc_XOR2(t0, t1, t0);
		mpc_RIGHTSHIFT2(w[j-2],10,t1);
		mpc_XOR2(t0, t1, s1);
		//w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];
		if(mpc_ADD_verify(w[j-16], s0, t1, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
 			return 1;
		}

		if(mpc_ADD_verify(w[j-7], t1, t1, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
			return 1;
		}
		if(mpc_ADD_verify(t1, s1, w[j], &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
			return 1;
		}

	}

	uint32_t va[2] = { hA[0],hA[0] };
	uint32_t vb[2] = { hA[1],hA[1] };
	uint32_t vc[2] = { hA[2],hA[2] };
	uint32_t vd[2] = { hA[3],hA[3] };
	uint32_t ve[2] = { hA[4],hA[4] };
	uint32_t vf[2] = { hA[5],hA[5] };
	uint32_t vg[2] = { hA[6],hA[6] };
	uint32_t vh[2] = { hA[7],hA[7] };
	uint32_t temp1[3], temp2[3], maj[3];
	for (int i = 0; i < 64; i++) {
		//s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
		mpc_RIGHTROTATE2(ve, 6, t0);
		mpc_RIGHTROTATE2(ve, 11, t1);
		mpc_XOR2(t0, t1, t0);
		mpc_RIGHTROTATE2(ve, 25, t1);
		mpc_XOR2(t0, t1, s1);

                //ch = (e & f) ^ ((~e) & g);
                //temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

                //t0 = h + s1
		if(mpc_ADD_verify(vh, s1, t0, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
    			return 1;
		}
                if(mpc_CH_verify(ve, vf, vg, t1, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
   			return 1;
		}

		//t1 = t0 + t1 (h+s1+ch)
		if(mpc_ADD_verify(t0, t1, t1, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
   			return 1;
		}

		t0[0] = k[i];
		t0[1] = k[i];
		if(mpc_ADD_verify(t1, t0, t1, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
 			return 1;
		}

		if(mpc_ADD_verify(t1, w[i], temp1, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
    			return 1;
		}

		//s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
		mpc_RIGHTROTATE2(va, 2, t0);
		mpc_RIGHTROTATE2(va, 13, t1);
		mpc_XOR2(t0, t1, t0);
		mpc_RIGHTROTATE2(va, 22, t1);
		mpc_XOR2(t0, t1, s0);

                //maj = (a & (b ^ c)) ^ (b & c);
                //(a & b) ^ (a & c) ^ (b & c)

		if(mpc_MAJ_verify(va, vb, vc, maj, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
  			return 1;
		}

                //temp2 = s0+maj;
		if(mpc_ADD_verify(s0, maj, temp2, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
     			return 1;
		}

		memcpy(vh, vg, sizeof(uint32_t) * 2);
		memcpy(vg, vf, sizeof(uint32_t) * 2);
 		memcpy(vf, ve, sizeof(uint32_t) * 2);
                //e = d+temp1;
		if(mpc_ADD_verify(vd, temp1, ve, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
      			return 1;
		}

  		memcpy(vd, vc, sizeof(uint32_t) * 2);
		memcpy(vc, vb, sizeof(uint32_t) * 2);
		memcpy(vb, va, sizeof(uint32_t) * 2);
                //a = temp1+temp2;

		if(mpc_ADD_verify(temp1, temp2, va, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
   			return 1;
 		}
	}

	uint32_t hHa[8][3] = { { hA[0],hA[0],hA[0]  }, { hA[1],hA[1],hA[1] }, { hA[2],hA[2],hA[2] }, { hA[3],hA[3],hA[3]
 },
			{ hA[4],hA[4],hA[4] }, { hA[5],hA[5],hA[5] }, { hA[6],hA[6],hA[6] }, { hA[7],hA[7],hA[7] } };
	if(mpc_ADD_verify(hHa[0], va, hHa[0], &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	if(mpc_ADD_verify(hHa[1], vb, hHa[1], &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	if(mpc_ADD_verify(hHa[2], vc, hHa[2], &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	if(mpc_ADD_verify(hHa[3], vd, hHa[3], &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	if(mpc_ADD_verify(hHa[4], ve, hHa[4], &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	if(mpc_ADD_verify(hHa[5], vf, hHa[5], &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	if(mpc_ADD_verify(hHa[6], vg, hHa[6], &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	if(mpc_ADD_verify(hHa[7], vh, hHa[7], &zs.ve, &zs.ve1, randomness, randCount, countY) == 1) {
		return 1;
	}

	unsigned char sharesults[2][32];
	for (int i = 0; i < 8; i++) 
	{
		mpc_RIGHTSHIFT(hHa[i], 24, t0);
		sharesults[0][i * 4] = t0[0];
		sharesults[1][i * 4] = t0[1];
		mpc_RIGHTSHIFT(hHa[i], 16, t0);
		sharesults[0][i * 4 + 1] = t0[0];
		sharesults[1][i * 4 + 1] = t0[1];
		mpc_RIGHTSHIFT(hHa[i], 8, t0);
		sharesults[0][i * 4 + 2] = t0[0];
		sharesults[1][i * 4 + 2] = t0[1];
		sharesults[0][i * 4 + 3] = hHa[i][0];
		sharesults[1][i * 4 + 3] = hHa[i][1];
	}	
	uint32_t X[16][2];
	unsigned char* chunks[3];
	int numBits = 32 * 8;
	for (int i = 0; i < 2; i++) {
		chunks[i] = calloc(64, 1); // 16 * 4 bytes
		memset(chunks[i],0,64);
		memcpy(chunks[i], sharesults[i], 32);
		chunks[i][32] = 0x80;
		chunks[i][56] = numBits ;
		chunks[i][57] = numBits >> 8;
		chunks[i][58] = numBits >> 16;
		chunks[i][59] = numBits >> 24;
		for (int j = 0; j < 16; j++) 
		{
			X[j][i] = ((uint32_t)chunks[i][j * 4 + 0] << 0) | ((uint32_t)chunks[i][j * 4 + 1] << 8)
				| ((uint32_t)chunks[i][j * 4 + 2] << 16) | ((uint32_t)chunks[i][j * 4 + 3] << 24);
		}

		free(chunks[i]);
	}

	uint32_t buf[5][2] = {{ hRIPE[0],hRIPE[0] },
				{hRIPE[1],hRIPE[1]},
				{hRIPE[2],hRIPE[2]},
				{hRIPE[3],hRIPE[3]},
				{hRIPE[4],hRIPE[4]}};

	uint32_t aa[2] = { hRIPE[0],hRIPE[0] };
	uint32_t bb[2] = { hRIPE[1],hRIPE[1] };
	uint32_t cc[2] = { hRIPE[2],hRIPE[2] };
	uint32_t dd[2] = { hRIPE[3],hRIPE[3] };
	uint32_t ee[2] = { hRIPE[4],hRIPE[4] };
	uint32_t aaa[2] = { hRIPE[0],hRIPE[0] };
	uint32_t bbb[2] = { hRIPE[1],hRIPE[1] };
	uint32_t ccc[2] = { hRIPE[2],hRIPE[2] };
	uint32_t ddd[2] = { hRIPE[3],hRIPE[3] };
	uint32_t eee[2] = { hRIPE[4],hRIPE[4] };

	// round 1 
	if (mpc_FF2(aa, bb, cc, dd, ee, X[0], 11, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ee, aa, bb, cc, dd, X[1], 14, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(dd, ee, aa, bb, cc, X[2], 15, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(cc, dd, ee, aa, bb, X[3], 12, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(bb, cc, dd, ee, aa, X[4], 5, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(aa, bb, cc, dd, ee, X[5], 8, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ee, aa, bb, cc, dd, X[6], 7, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(dd, ee, aa, bb, cc, X[7], 9, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(cc, dd, ee, aa, bb, X[8], 11, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(bb, cc, dd, ee, aa, X[9], 13, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(aa, bb, cc, dd, ee, X[10], 14, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ee, aa, bb, cc, dd, X[11], 15, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(dd, ee, aa, bb, cc, X[12], 6, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(cc, dd, ee, aa, bb, X[13], 7, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(bb, cc, dd, ee, aa, X[14], 9, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(aa, bb, cc, dd, ee, X[15], 8, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;

	// round 2
	if (mpc_GG2(ee, aa, bb, cc, dd, X[7], 7, hG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(dd, ee, aa, bb, cc, X[4], 6, hG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(cc, dd, ee, aa, bb, X[13], 8, hG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(bb, cc, dd, ee, aa, X[1], 13, hG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(aa, bb, cc, dd, ee, X[10], 11, hG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ee, aa, bb, cc, dd, X[6], 9, hG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(dd, ee, aa, bb, cc, X[15], 7, hG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(cc, dd, ee, aa, bb, X[3], 15, hG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(bb, cc, dd, ee, aa, X[12], 7, hG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(aa, bb, cc, dd, ee, X[0], 12, hG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ee, aa, bb, cc, dd, X[9], 15, hG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(dd, ee, aa, bb, cc, X[5], 9, hG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(cc, dd, ee, aa, bb, X[2], 11, hG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(bb, cc, dd, ee, aa, X[14], 7, hG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(aa, bb, cc, dd, ee, X[11], 13, hG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ee, aa, bb, cc, dd, X[8], 12, hG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;

	// round 3
	
	if (mpc_HH2(dd, ee, aa, bb, cc, X[3], 11, hH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(cc, dd, ee, aa, bb, X[10], 13, hH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(bb, cc, dd, ee, aa, X[14], 6, hH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(aa, bb, cc, dd, ee, X[4], 7, hH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ee, aa, bb, cc, dd, X[9], 14, hH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(dd, ee, aa, bb, cc, X[15], 9, hH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(cc, dd, ee, aa, bb, X[8], 13, hH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(bb, cc, dd, ee, aa, X[1], 15, hH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(aa, bb, cc, dd, ee, X[2], 14, hH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ee, aa, bb, cc, dd, X[7], 8, hH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(dd, ee, aa, bb, cc, X[0], 13, hH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(cc, dd, ee, aa, bb, X[6], 6, hH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(bb, cc, dd, ee, aa, X[13], 5, hH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(aa, bb, cc, dd, ee, X[11], 12, hH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ee, aa, bb, cc, dd, X[5], 7, hH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(dd, ee, aa, bb, cc, X[12], 5, hH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;

	// round 4
	
	if (mpc_II2(cc, dd, ee, aa, bb, X[1], 11, hI, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(bb, cc, dd, ee, aa, X[9], 12, hI, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(aa, bb, cc, dd, ee, X[11], 14, hI, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ee, aa, bb, cc, dd, X[10], 15, hI, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(dd, ee, aa, bb, cc, X[0], 14, hI, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(cc, dd, ee, aa, bb, X[8], 15, hI, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(bb, cc, dd, ee, aa, X[12], 9, hI, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(aa, bb, cc, dd, ee, X[4], 8, hI, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ee, aa, bb, cc, dd, X[13], 9, hI, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(dd, ee, aa, bb, cc, X[3], 14, hI, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(cc, dd, ee, aa, bb, X[7], 5, hI, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(bb, cc, dd, ee, aa, X[15], 6, hI, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(aa, bb, cc, dd, ee, X[14], 8, hI, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ee, aa, bb, cc, dd, X[5], 6, hI, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(dd, ee, aa, bb, cc, X[6], 5, hI, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(cc, dd, ee, aa, bb, X[2], 12, hI, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;

	// round 5

	if (mpc_JJ2(bb, cc, dd, ee, aa, X[4], 9, hJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(aa, bb, cc, dd, ee, X[0], 15, hJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ee, aa, bb, cc, dd, X[5], 5, hJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(dd, ee, aa, bb, cc, X[9], 11, hJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(cc, dd, ee, aa, bb, X[7], 6, hJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(bb, cc, dd, ee, aa, X[12], 8, hJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(aa, bb, cc, dd, ee, X[2], 13, hJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ee, aa, bb, cc, dd, X[10], 12, hJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(dd, ee, aa, bb, cc, X[14], 5, hJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(cc, dd, ee, aa, bb, X[1], 12, hJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(bb, cc, dd, ee, aa, X[3], 13, hJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(aa, bb, cc, dd, ee, X[8], 14, hJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ee, aa, bb, cc, dd, X[11], 11, hJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(dd, ee, aa, bb, cc, X[6], 8, hJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(cc, dd, ee, aa, bb, X[15], 5, hJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(bb, cc, dd, ee, aa, X[13], 6, hJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;

	// alt round 1
	if (mpc_JJ2(aaa, bbb, ccc, ddd, eee, X[5], 8, hJJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(eee, aaa, bbb, ccc, ddd, X[14], 9, hJJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ddd, eee, aaa, bbb, ccc, X[7], 9, hJJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ccc, ddd, eee, aaa, bbb, X[0], 11, hJJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(bbb, ccc, ddd, eee, aaa, X[9], 13, hJJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(aaa, bbb, ccc, ddd, eee, X[2], 15, hJJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(eee, aaa, bbb, ccc, ddd, X[11], 15, hJJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ddd, eee, aaa, bbb, ccc, X[4], 5, hJJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ccc, ddd, eee, aaa, bbb, X[13], 7, hJJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(bbb, ccc, ddd, eee, aaa, X[6], 7, hJJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(aaa, bbb, ccc, ddd, eee, X[15], 8, hJJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(eee, aaa, bbb, ccc, ddd, X[8], 11, hJJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ddd, eee, aaa, bbb, ccc, X[1], 14, hJJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(ccc, ddd, eee, aaa, bbb, X[10], 14, hJJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(bbb, ccc, ddd, eee, aaa, X[3], 12, hJJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_JJ2(aaa, bbb, ccc, ddd, eee, X[12], 6, hJJ, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;

	// alt round 2

	if (mpc_II2(eee, aaa, bbb, ccc, ddd, X[6], 9, hII, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ddd, eee, aaa, bbb, ccc, X[11], 13, hII, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ccc, ddd, eee, aaa, bbb, X[3], 15, hII, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(bbb, ccc, ddd, eee, aaa, X[7], 7, hII, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(aaa, bbb, ccc, ddd, eee, X[0], 12, hII, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(eee, aaa, bbb, ccc, ddd, X[13], 8, hII, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ddd, eee, aaa, bbb, ccc, X[5], 9, hII, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ccc, ddd, eee, aaa, bbb, X[10], 11, hII, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(bbb, ccc, ddd, eee, aaa, X[14], 7, hII, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(aaa, bbb, ccc, ddd, eee, X[15], 7, hII, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(eee, aaa, bbb, ccc, ddd, X[8], 12, hII, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ddd, eee, aaa, bbb, ccc, X[12], 7, hII, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(ccc, ddd, eee, aaa, bbb, X[4], 6, hII, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(bbb, ccc, ddd, eee, aaa, X[9], 15, hII, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(aaa, bbb, ccc, ddd, eee, X[1], 13, hII, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_II2(eee, aaa, bbb, ccc, ddd, X[2], 11, hII, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;

	// alt round 3
	if (mpc_HH2(ddd, eee, aaa, bbb, ccc, X[15], 9, hHH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ccc, ddd, eee, aaa, bbb, X[5], 7, hHH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(bbb, ccc, ddd, eee, aaa, X[1], 15, hHH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(aaa, bbb, ccc, ddd, eee, X[3], 11, hHH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(eee, aaa, bbb, ccc, ddd, X[7], 8, hHH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ddd, eee, aaa, bbb, ccc, X[14], 6, hHH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ccc, ddd, eee, aaa, bbb, X[6], 6, hHH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(bbb, ccc, ddd, eee, aaa, X[9], 14, hHH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(aaa, bbb, ccc, ddd, eee, X[11], 12, hHH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(eee, aaa, bbb, ccc, ddd, X[8], 13, hHH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ddd, eee, aaa, bbb, ccc, X[12], 5, hHH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ccc, ddd, eee, aaa, bbb, X[2], 14, hHH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(bbb, ccc, ddd, eee, aaa, X[10], 13, hHH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(aaa, bbb, ccc, ddd, eee, X[0], 13, hHH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(eee, aaa, bbb, ccc, ddd, X[4], 7, hHH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_HH2(ddd, eee, aaa, bbb, ccc, X[13], 5, hHH, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;

	// alt round 4
	if (mpc_GG2(ccc, ddd, eee, aaa, bbb, X[8], 15, hGG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(bbb, ccc, ddd, eee, aaa, X[6], 5, hGG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(aaa, bbb, ccc, ddd, eee, X[4], 8, hGG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(eee, aaa, bbb, ccc, ddd, X[1], 11, hGG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ddd, eee, aaa, bbb, ccc, X[3], 14, hGG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ccc, ddd, eee, aaa, bbb, X[11], 14, hGG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(bbb, ccc, ddd, eee, aaa, X[15], 6, hGG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(aaa, bbb, ccc, ddd, eee, X[0], 14, hGG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(eee, aaa, bbb, ccc, ddd, X[5], 6, hGG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ddd, eee, aaa, bbb, ccc, X[12], 9, hGG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ccc, ddd, eee, aaa, bbb, X[2], 12, hGG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(bbb, ccc, ddd, eee, aaa, X[13], 9, hGG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(aaa, bbb, ccc, ddd, eee, X[9], 12, hGG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(eee, aaa, bbb, ccc, ddd, X[7], 5, hGG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ddd, eee, aaa, bbb, ccc, X[10], 15, hGG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_GG2(ccc, ddd, eee, aaa, bbb, X[14], 8, hGG, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;

	// alt round 5
	if (mpc_FF2(bbb, ccc, ddd, eee, aaa, X[12], 8, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(aaa, bbb, ccc, ddd, eee, X[15], 5, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(eee, aaa, bbb, ccc, ddd, X[10], 12, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ddd, eee, aaa, bbb, ccc, X[4], 9, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ccc, ddd, eee, aaa, bbb, X[1], 12, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(bbb, ccc, ddd, eee, aaa, X[5], 5, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(aaa, bbb, ccc, ddd, eee, X[8], 14, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(eee, aaa, bbb, ccc, ddd, X[7], 6, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ddd, eee, aaa, bbb, ccc, X[6], 8, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ccc, ddd, eee, aaa, bbb, X[2], 13, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(bbb, ccc, ddd, eee, aaa, X[13], 6, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(aaa, bbb, ccc, ddd, eee, X[14], 5, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(eee, aaa, bbb, ccc, ddd, X[0], 15, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ddd, eee, aaa, bbb, ccc, X[3], 13, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(ccc, ddd, eee, aaa, bbb, X[9], 11, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;
	if (mpc_FF2(bbb, ccc, ddd, eee, aaa, X[11], 11, &zs.ve, &zs.ve1, randomness, randCount, countY) == 1)
		return 1;

	 if (mpc_ADD_verify(cc,buf[1],t0,&zs.ve,&zs.ve1,randomness,randCount,countY)==1)
		 return 1;
	if (mpc_ADD_verify(t0,ddd,t1,&zs.ve,&zs.ve1,randomness,randCount,countY) == 1)
		return 1;
	if (mpc_ADD_verify(dd,buf[2],t0,&zs.ve,&zs.ve1,randomness,randCount,countY) ==1)
		return 1;
	if (mpc_ADD_verify(t0,eee,buf[1],&zs.ve,&zs.ve1,randomness,randCount,countY) ==1)
		return 1;
	if (mpc_ADD_verify(ee,buf[3],t0,&zs.ve,&zs.ve1,randomness,randCount,countY)==1)
		return 1;
	if (mpc_ADD_verify(t0,aaa,buf[2],&zs.ve,&zs.ve1,randomness,randCount,countY)==1)
		return 1;
	if (mpc_ADD_verify(aa,buf[4],t0,&zs.ve,&zs.ve1,randomness,randCount,countY)==1)
		return 1;
	if (mpc_ADD_verify(t0,bbb,buf[3],&zs.ve,&zs.ve1,randomness,randCount,countY)==1)
		return 1;
	if (mpc_ADD_verify(bb,buf[0],t0,&zs.ve,&zs.ve1,randomness,randCount,countY)== 1)
		return 1;
	if (mpc_ADD_verify(t0,ccc,buf[4],&zs.ve,&zs.ve1,randomness,randCount,countY)==1)
		return 1;

	free(countY);
	free(randCount);
	free(randomness[0]);
	free(randomness[1]);

	return 0;
}

static uint32_t rand32() {
	uint32_t x;
	x = rand() & 0xff;
	x |= (rand() & 0xff) << 8;
	x |= (rand() & 0xff) << 16;
	x |= (rand() & 0xff) << 24;

	return x;
}

static uint64_t rand64() {
	uint64_t x;
	x = (uint64_t) rand32();
	x |= (uint64_t)(rand() & 0xff) << 32;
	x |= (uint64_t)(rand() & 0xff) << 40;
	x |= (uint64_t)(rand() & 0xff) << 48;
	x |= (uint64_t)(rand() & 0xff) << 56;

	return x;
}

static void printbits(uint32_t n) {
	if (n) {
		printbits(n >> 1);
		printf("%d", n & 1);
	}

}



static void mpc_XOR(uint32_t x[3], uint32_t y[3], uint32_t z[3]) {
	z[0] = x[0] ^ y[0];
	z[1] = x[1] ^ y[1];
	z[2] = x[2] ^ y[2];
}

static void mpc_AND(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t r[3] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount), getRandom32(randomness[2], *randCount)};
	*randCount += 4;
	uint32_t t[3] = { 0 };

	t[0] = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
	t[1] = (x[1] & y[2]) ^ (x[2] & y[1]) ^ (x[1] & y[1]) ^ r[1] ^ r[2];
	t[2] = (x[2] & y[0]) ^ (x[0] & y[2]) ^ (x[2] & y[2]) ^ r[2] ^ r[0];
	z[0] = t[0];
	z[1] = t[1];
	z[2] = t[2];
	views[0].y[*countY] = z[0];
	views[1].y[*countY] = z[1];
	views[2].y[*countY] = z[2];
	(*countY)++;
}

static void mpc_NEGATE(uint32_t x[3], uint32_t z[3]) {
	z[0] = ~x[0];
	z[1] = ~x[1];
	z[2] = ~x[2];
}



static void mpc_OR(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char * randomness[3], int * randCount, View views[3], int* countY) {
	uint32_t t0[3] = { 0 };
	uint32_t t1[3] = { 0 };
	uint32_t t2[3] = { 0 };

	mpc_NEGATE(x,t0);
	mpc_NEGATE(y,t1);
	mpc_AND(t0,t1,t2,randomness,randCount,views,countY);
	mpc_NEGATE(t2,z);

}

static void mpc_ADD(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t c[3] = { 0 };
	uint32_t r[3] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount), getRandom32(randomness[2], *randCount)};
	*randCount += 4;

	uint8_t a[3], b[3];

	uint8_t t;

	for(int i=0;i<31;i++)
	{
		a[0]=GETBIT(x[0]^c[0],i);
		a[1]=GETBIT(x[1]^c[1],i);
		a[2]=GETBIT(x[2]^c[2],i);

		b[0]=GETBIT(y[0]^c[0],i);
		b[1]=GETBIT(y[1]^c[1],i);
		b[2]=GETBIT(y[2]^c[2],i);

		t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
		SETBIT(c[0],i+1, t ^ (a[0]&b[0]) ^ GETBIT(c[0],i) ^ GETBIT(r[0],i));

		t = (a[1]&b[2]) ^ (a[2]&b[1]) ^ GETBIT(r[2],i);
		SETBIT(c[1],i+1, t ^ (a[1]&b[1]) ^ GETBIT(c[1],i) ^ GETBIT(r[1],i));

		t = (a[2]&b[0]) ^ (a[0]&b[2]) ^ GETBIT(r[0],i);
		SETBIT(c[2],i+1, t ^ (a[2]&b[2]) ^ GETBIT(c[2],i) ^ GETBIT(r[2],i));


	}

	z[0]=x[0]^y[0]^c[0];
	z[1]=x[1]^y[1]^c[1];
	z[2]=x[2]^y[2]^c[2];

	views[0].y[*countY] = c[0];
	views[1].y[*countY] = c[1];
	views[2].y[*countY] = c[2];
	*countY += 1;


}


static void mpc_ADDK(uint32_t x[3], uint32_t y, uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t c[3] = { 0 };
	uint32_t r[3] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount), getRandom32(randomness[2], *randCount)};
	*randCount += 4;

	uint8_t a[3], b[3];

	uint8_t t;

	for(int i=0;i<31;i++)
	{
		a[0]=GETBIT(x[0]^c[0],i);
		a[1]=GETBIT(x[1]^c[1],i);
		a[2]=GETBIT(x[2]^c[2],i);

		b[0]=GETBIT(y^c[0],i);
		b[1]=GETBIT(y^c[1],i);
		b[2]=GETBIT(y^c[2],i);

		t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
		SETBIT(c[0],i+1, t ^ (a[0]&b[0]) ^ GETBIT(c[0],i) ^ GETBIT(r[0],i));

		t = (a[1]&b[2]) ^ (a[2]&b[1]) ^ GETBIT(r[2],i);
		SETBIT(c[1],i+1, t ^ (a[1]&b[1]) ^ GETBIT(c[1],i) ^ GETBIT(r[1],i));

		t = (a[2]&b[0]) ^ (a[0]&b[2]) ^ GETBIT(r[0],i);
		SETBIT(c[2],i+1, t ^ (a[2]&b[2]) ^ GETBIT(c[2],i) ^ GETBIT(r[2],i));


	}

	z[0]=x[0]^y^c[0];
	z[1]=x[1]^y^c[1];
	z[2]=x[2]^y^c[2];


	views[0].y[*countY] = c[0];
	views[1].y[*countY] = c[1];
	views[2].y[*countY] = c[2];
	*countY += 1;

}

static void mpc_RIGHTROTATE(uint32_t x[], int i, uint32_t z[]) {
	z[0] = RIGHTROTATE(x[0], i);
	z[1] = RIGHTROTATE(x[1], i);
	z[2] = RIGHTROTATE(x[2], i);
}





static void mpc_LEFTROTATE(uint32_t x[], int i, uint32_t z[]) {
	z[0] = LEFTROTATE(x[0], i);
	z[1] = LEFTROTATE(x[1], i);
	z[2] = LEFTROTATE(x[2], i);
}

static void mpc_F(uint32_t x1[3], uint32_t x2[3], uint32_t x3[3], uint32_t z[3])
{
	uint32_t t0[3] = { 0 };

	mpc_XOR(x1,x2,t0);
	mpc_XOR(t0,x3,z);
}

static void mpc_G(uint32_t x1[3], uint32_t x2[3], uint32_t x3[3], uint32_t z[3], unsigned char * randomness[3], int * randCount, View views[3], int* countY) {
	uint32_t t0[3] = { 0 };
	uint32_t t1[3] = { 0 };
	uint32_t t2[3] = { 0 };

	mpc_AND(x1,x2,t0,randomness,randCount,views,countY);
	mpc_NEGATE(x1,t1);
	mpc_AND(t1,x3,t2,randomness,randCount,views,countY);
	mpc_OR(t0,t2,z,randomness,randCount,views,countY);
}

static void mpc_H(uint32_t x1[3], uint32_t x2[3], uint32_t x3[3], uint32_t z[3], unsigned char * randomness[3], int * randCount, View views[3], int* countY) {
	uint32_t t0[3] = { 0 };
	uint32_t t1[3] = { 0 };

	mpc_NEGATE(x2,t0);
	mpc_OR(x1,t0,t1,randomness,randCount,views,countY);
	mpc_XOR(t1,x3,z);

}

static void mpc_I(uint32_t x1[3], uint32_t x2[3], uint32_t x3[3], uint32_t z[3], unsigned char * randomness[3], int * randCount, View views[3], int* countY) {
	uint32_t t0[3] = { 0 };
	uint32_t t1[3] = { 0 };
	uint32_t t2[3] = { 0 };

	mpc_AND(x1,x3,t0,randomness,randCount,views,countY);
	mpc_NEGATE(x3,t1);
	mpc_AND(x2,t1,t2,randomness,randCount,views,countY);
	mpc_OR(t0,t2,z,randomness,randCount,views,countY);

}


static void mpc_J(uint32_t x1[3], uint32_t x2[3], uint32_t x3[3], uint32_t z[3], unsigned char * randomness[3], int * randCount, View views[3], int* countY) {
	uint32_t t0[3] = { 0 };
	uint32_t t1[3] = { 0 };

	mpc_NEGATE(x3,t0);
	mpc_OR(x2,t0,t1,randomness,randCount,views,countY);
	mpc_XOR(t1,x1,z);
}

static void mpc_FF(uint32_t a[3], uint32_t b[3], uint32_t c[3], uint32_t d[3], uint32_t e[3], uint32_t x[3], uint32_t s, unsigned char * randomness[3], int * randCount, View views[3], int* countY)
{
	uint32_t t0[3] = { 0 };
	uint32_t t1[3] = { 0 };
	uint32_t t2[3] = { 0 };
	uint32_t t3[3] = { 0 };

	mpc_F(b,c,d,t0);
	mpc_ADD(t0,x,t1,randomness,randCount,views,countY);
	mpc_ADD(t1,a,t2,randomness,randCount,views,countY);
	mpc_LEFTROTATE(t2,s,t3);
	mpc_ADD(t3,e,a,randomness,randCount,views,countY);
	mpc_LEFTROTATE(c,10,c);
}

static void mpc_GG(uint32_t a[3], uint32_t b[3], uint32_t c[3], uint32_t d[3], uint32_t e[3], uint32_t x[3], uint32_t s, uint32_t C, unsigned char * randomness[3], int * randCount, View views[3], int* countY)
{
	uint32_t t0[3] = { 0 };
	uint32_t t1[3] = { 0 };
	uint32_t t2[3] = { 0 };
	uint32_t t3[3] = { 0 };
	uint32_t t4[3] = { 0 };

	mpc_G(b,c,d,t0,randomness,randCount,views,countY);
	mpc_ADD(t0,x,t1,randomness,randCount,views,countY);
	mpc_ADDK(t1,C,t2,randomness,randCount,views,countY);
	mpc_ADD(t2,a,t3,randomness,randCount,views,countY);
	mpc_LEFTROTATE(t3,s,t4);
	mpc_ADD(t4,e,a,randomness,randCount,views,countY);
	mpc_LEFTROTATE(c,10,c);
}

static void mpc_HH(uint32_t a[3], uint32_t b[3], uint32_t c[3], uint32_t d[3], uint32_t e[3], uint32_t x[3], uint32_t s, uint32_t C, unsigned char * randomness[3], int * randCount, View views[3], int* countY)
{
	uint32_t t0[3] = { 0 };
	uint32_t t1[3] = { 0 };
	uint32_t t2[3] = { 0 };
	uint32_t t3[3] = { 0 };
	uint32_t t4[3] = { 0 };

	mpc_H(b,c,d,t0,randomness,randCount,views,countY);
	mpc_ADD(t0,x,t1,randomness,randCount,views,countY);
	mpc_ADDK(t1,C,t2,randomness,randCount,views,countY);
	mpc_ADD(t2,a,t3,randomness,randCount,views,countY);
	mpc_LEFTROTATE(t3,s,t4);
	mpc_ADD(t4,e,a,randomness,randCount,views,countY);
	mpc_LEFTROTATE(c,10,c);
}

static void mpc_II(uint32_t a[3], uint32_t b[3], uint32_t c[3], uint32_t d[3], uint32_t e[3], uint32_t x[3], uint32_t s, uint32_t C, unsigned char * randomness[3], int * randCount, View views[3], int* countY)
{
	uint32_t t0[3] = { 0 };
	uint32_t t1[3] = { 0 };
	uint32_t t2[3] = { 0 };
	uint32_t t3[3] = { 0 };
	uint32_t t4[3] = { 0 };

	mpc_I(b,c,d,t0,randomness,randCount,views,countY);
	mpc_ADD(t0,x,t1,randomness,randCount,views,countY);
	mpc_ADDK(t1,C,t2,randomness,randCount,views,countY);
	mpc_ADD(t2,a,t3,randomness,randCount,views,countY);
	mpc_LEFTROTATE(t3,s,t4);
	mpc_ADD(t4,e,a,randomness,randCount,views,countY);
	mpc_LEFTROTATE(c,10,c);
}

static void mpc_JJ(uint32_t a[3], uint32_t b[3], uint32_t c[3], uint32_t d[3], uint32_t e[3], uint32_t x[3], uint32_t s, uint32_t C, unsigned char * randomness[3], int * randCount, View views[3], int* countY)
{
	uint32_t t0[3] = { 0 };
	uint32_t t1[3] = { 0 };
	uint32_t t2[3] = { 0 };
	uint32_t t3[3] = { 0 };
	uint32_t t4[3] = { 0 };

	mpc_J(b,c,d,t0,randomness,randCount,views,countY);
	mpc_ADD(t0,x,t1,randomness,randCount,views,countY);
	mpc_ADDK(t1,C,t2,randomness,randCount,views,countY);
	mpc_ADD(t2,a,t3,randomness,randCount,views,countY);
	mpc_LEFTROTATE(t3,s,t4);
	mpc_ADD(t4,e,a,randomness,randCount,views,countY);
	mpc_LEFTROTATE(c,10,c);
}

static void mpc_MAJ(uint32_t a[], uint32_t b[3], uint32_t c[3], uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t t0[3];
	uint32_t t1[3];

	mpc_XOR(a, b, t0);
	mpc_XOR(a, c, t1);
	mpc_AND(t0, t1, z, randomness, randCount, views, countY);
	mpc_XOR(z, a, z);
}


static void mpc_CH(uint32_t e[], uint32_t f[3], uint32_t g[3], uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint32_t t0[3];

	mpc_XOR(f,g,t0);
	mpc_AND(e,t0,t0, randomness, randCount, views, countY);
	mpc_XOR(t0,g,z);

}

/*
int mpc_write256(MP_INT val256[3], View views[3], int * countY)
{
	size_t size = 8;
	int i;
	uint32_t buf[3][8];

	for(i = 0; i<3; i++)
	{
		memset(buf[i],0,size*sizeof(uint32_t));
		mpz_export(buf[i],(size_t *)&size, 1, 4, 0, 0, &val256[i]);
		if (size < 8)
		{
			memset(buf[i],0,size*sizeof(uint32_t));
			mpz_export(&(buf[i][8-size]),(size_t *)&size, 1, 4, 0, 0, &val256[i]);
		}
	}
	for (i=0;i<8;i++)
	{
		views[0].y[*countY] = buf[0][i];
		views[1].y[*countY] = buf[1][i];
		views[2].y[*countY] = buf[2][i];
		*countY = *countY + 1;
	}
	return 0;
}

int mpc_ADD_EC(MP_INT x1[3], MP_INT y1[3], MP_INT x2[3], MP_INT y2[3], unsigned char * randomness[3], int * randCount, View views[3], int * countY)
{

	ecAddPoint(&x1[0],&y1[0],&x2[1],&y2[1]);
	ecAddPoint(&x1[1],&y1[1],&x2[2],&y2[2]);
	ecAddPoint(&x1[2],&y1[2],&x2[0],&y2[0]);

	mpc_write256(x1,views,countY);
	mpc_write256(y1,views,countY);
}

int mpc_MUL_EC(unsigned char * Prodx[3], unsigned char * Prody[3], unsigned char * privkey[3],unsigned char *randomness[3], int* randCount, View views[3], int* countY)
{
	MP_INT x[3],y[3];
	MP_INT tx[3],ty[3];
	unsigned long long i[3];  // 64 bit
	int j,loop;
	size_t k;
	MP_INT x1[3],y1[3];
	MP_INT multiple[3];
	MP_INT mod;
	unsigned char tempkey[32];
	MP_INT tempk;

	for (j=0;j<32;j++)
		tempkey[j]=privkey[0][j]^privkey[1][j]^privkey[2][j];
	mpz_init(&tempk);
	mpz_import(&tempk,32,1,1,0,0,tempkey);
	if (debug > 1)
	{
		printf("private key:");
		mpz_out_str(stdout,16,&tempk);
		printf("\n");
	}
	memset(tempkey,0,32);
	mpz_init_set_str(&mod,CURVE_N,16);
	for (j=0;j<3;j++)
	{
		mpz_init(&multiple[j]);
		mpz_init(&tx[j]);
		mpz_init(&ty[j]);
		mpz_init_set_str(&x[j],CURVE_Gx,16);
		mpz_init_set_str(&y[j],CURVE_Gy,16);
		mpz_import(&multiple[j],32,1,1,0,0,privkey[j]);
		mpz_init_set_ui(&x1[j],0);
		mpz_init_set_ui(&y1[j],0);
	}
        // need to adjust multiple[2] to be mod N
	mpz_mod(&multiple[0],&multiple[0],&mod);
	mpz_mod(&multiple[1],&multiple[1],&mod);
	mpz_add(&multiple[2],&multiple[0],&multiple[1]);
	mpz_sub(&multiple[2],&tempk,&multiple[2]);
	mpz_mod(&multiple[2],&multiple[2],&mod);
	mpc_write256(multiple,views,countY);

	for (k = 0; k < 4; k++)
	{
		i[0] = mpz_get_ui(&multiple[0]);
		i[1] = mpz_get_ui(&multiple[1]);
		i[2] = mpz_get_ui(&multiple[2]);
		mpz_div_2exp(&multiple[0],&multiple[0],64);
		mpz_div_2exp(&multiple[1],&multiple[1],64);
		mpz_div_2exp(&multiple[2],&multiple[2],64);
		for (loop = 0;loop < 64; loop++)
		{
			for (j=0;j<3;j++)
			{
				if (i[j] & 0x01)
				{
					mpz_set(&tx[j],&x[j]);
					mpz_set(&ty[j],&y[j]);
				}
				else
                                {
					mpz_set_ui(&tx[j],0);
					mpz_set_ui(&ty[j],0);
				}
				i[j]>>=1;
			}
                        mpc_ADD_EC(x1,y1,tx,ty,randomness,randCount,views,countY);
			if (debug > 1)
			{
				int tt;
				printf("loop %ld:\n",(k*64)+loop);
				for (tt = 0; tt< 3;tt++)
				{
					printf("x %d:",tt);
					mpz_out_str(stdout,16,&x1[tt]);
					printf("\n");
					printf("y %d:",tt);
					mpz_out_str(stdout,16,&y1[tt]);
					printf("\n");
				}
				for (tt = 0; tt< 3;tt++)
				{
					printf("tempx %d:",tt);
					mpz_out_str(stdout,16,&tx[tt]);
					printf("\n");
					printf("tempy %d:",tt);
					mpz_out_str(stdout,16,&ty[tt]);
					printf("\n");
				}
			}

			ecAddPoint(&x[0],&y[0],&x[0],&y[0]);
			ecAddPoint(&x[1],&y[1],&x[1],&y[1]);
			ecAddPoint(&x[2],&y[2],&x[2],&y[2]);
		}
	}

	for (j=0;j<2;j++)
	{
		memset(Prodx[j],0,32);
		memset(Prody[j],0,32);
		k = 32; // just using as a temp variable
		mpz_export(Prodx[j],(size_t *)&k,1,1,0,0,&x1[j]);
		if (k < 32)
		{
			memset(Prodx[j],0,32);
			mpz_export(&(Prodx[j][32-k]),(size_t *)&k,1,1,0,0,&x1[j]);
		}
		k = 32; // just using as a temp variable
		mpz_export(Prody[j],(size_t *)&k,1,1,0,0,&y1[j]);
		if (k < 32)
		{
			memset(Prody[j],0,32);
			mpz_export(&(Prody[j][32-k]),(size_t *)&k,1,1,0,0,&y1[j]);
		}
	}
	{
		// convert back to boolean circuit
		// yucky code!!!
		//
		mpz_set(&x[0],&x1[0]);
		mpz_set(&y[0],&y1[0]);
		ecAddPoint(&x[0],&y[0],&x1[1],&y1[1]);
		ecAddPoint(&x[0],&y[0],&x1[2],&y1[2]);
		k=32;
		mpz_export(tempkey,(size_t *)&k,1,1,0,0,&x[0]);
		if (k < 32)
		{
			memset(tempkey,0,32);
			mpz_export(&(tempkey[32-k]),(size_t *)&k,1,1,0,0,&x[0]);
		}
		for (k=0;k<32;k++)
		{
			Prodx[2][k] = tempkey[k]^Prodx[0][k]^Prodx[1][k]; // to fix
		}

		k=32;
		mpz_export(tempkey,(size_t *)&k,1,1,0,0,&y[0]);
		if (k < 32)
		{
			memset(tempkey,0,32);
			mpz_export(&(tempkey[32-k]),(size_t *)&k,1,1,0,0,&y[0]);
		}
		for (k=0;k<32;k++)
		{
			Prody[2][k] = tempkey[k]^Prody[0][k]^Prody[1][k]; // to fix
		}
	}
        for (j=0;j<3;j++)
	{
		mpz_clear(&x[j]);
		mpz_clear(&x1[j]);
		mpz_clear(&y[j]);
		mpz_clear(&y1[j]);
		mpz_clear(&tx[j]);
		mpz_clear(&ty[j]);
		mpz_clear(&multiple[j]);
	}

	mpz_clear(&mod);
	mpz_clear(&tempk);
	return 0;

}
*/

static int mpc_ripemd160(unsigned char* results[3], unsigned char* inputs[3], int numBits, unsigned char *randomness[3], int * randCount, View views[3], int* countY) {

	if (numBits > 256) {
		printf("Input too long, aborting!");
		return -1;
	}

	int chars = numBits >> 3;
	unsigned char* chunks[3];
	uint32_t X[16][3];
	uint32_t buf[5][3] = {{ hRIPE[0],hRIPE[0],hRIPE[0] },
				{hRIPE[1],hRIPE[1],hRIPE[1]},
				{hRIPE[2],hRIPE[2],hRIPE[2]},
				{hRIPE[3],hRIPE[3],hRIPE[3]},
				{hRIPE[4],hRIPE[4],hRIPE[4]}};

	memset(X,0,16*4*3);
	for (int i = 0; i < 3; i++) {
		chunks[i] = calloc(64, 1); // 16 * 4 bytes 
		memset(chunks[i],0,64);
		memcpy(chunks[i], inputs[i], chars);
		chunks[i][chars] = 0x80;
		chunks[i][56] = numBits ;
		chunks[i][57] = numBits >> 8;
		chunks[i][58] = numBits >> 16;
		chunks[i][59] = numBits >> 24;

	//	memcpy(views[i].x,chunks[i], 64);

		for (int j = 0; j < 16; j++) {
			X[j][i] = ((uint32_t)chunks[i][j * 4 + 0] << 0) | ((uint32_t)chunks[i][j * 4 + 1] << 8)
				| ((uint32_t)chunks[i][j * 4 + 2] << 16) | ((uint32_t)chunks[i][j * 4 + 3] << 24);
			
		}
		

		free(chunks[i]);

	}

	if (debug > 1)
	{
		printf("X ");
		for (int j=0;j<16;j++)
			printf("X[%d] = %02X, ",j,X[j][0]^X[j][1]^X[j][2]);
		printf("\n");
	}

	uint32_t t0[3], t1[3];
	uint32_t aa[3] = { buf[0][0],buf[0][1],buf[0][2] };
	uint32_t bb[3] = { buf[1][0],buf[1][1],buf[1][2] };
	uint32_t cc[3] = { buf[2][0],buf[2][1],buf[2][2] };
	uint32_t dd[3] = { buf[3][0],buf[3][1],buf[3][2] };
	uint32_t ee[3] = { buf[4][0],buf[4][1],buf[4][2] };
	uint32_t aaa[3] = { buf[0][0],buf[0][1],buf[0][2] };
	uint32_t bbb[3] = { buf[1][0],buf[1][1],buf[1][2] };
	uint32_t ccc[3] = { buf[2][0],buf[2][1],buf[2][2] };
	uint32_t ddd[3] = { buf[3][0],buf[3][1],buf[3][2] };
	uint32_t eee[3] = { buf[4][0],buf[4][1],buf[4][2] };
	
	// round 1
	mpc_FF(aa, bb, cc, dd, ee, X[0], 11, randomness, randCount, views, countY);
	mpc_FF(ee, aa, bb, cc, dd, X[1], 14, randomness, randCount, views, countY);
	mpc_FF(dd, ee, aa, bb, cc, X[2], 15, randomness, randCount, views, countY);
	mpc_FF(cc, dd, ee, aa, bb, X[3], 12, randomness, randCount, views, countY);
	mpc_FF(bb, cc, dd, ee, aa, X[4], 5, randomness, randCount, views, countY); 
	mpc_FF(aa, bb, cc, dd, ee, X[5], 8, randomness, randCount, views, countY);
	mpc_FF(ee, aa, bb, cc, dd, X[6], 7, randomness, randCount, views, countY);
	mpc_FF(dd, ee, aa, bb, cc, X[7], 9, randomness, randCount, views, countY);
	mpc_FF(cc, dd, ee, aa, bb, X[8], 11, randomness, randCount, views, countY);
	mpc_FF(bb, cc, dd, ee, aa, X[9], 13, randomness, randCount, views, countY);
	mpc_FF(aa, bb, cc, dd, ee, X[10], 14, randomness, randCount, views, countY);
       	mpc_FF(ee, aa, bb, cc, dd, X[11], 15, randomness, randCount, views, countY);
	mpc_FF(dd, ee, aa, bb, cc, X[12], 6, randomness, randCount, views, countY);
	mpc_FF(cc, dd, ee, aa, bb, X[13], 7, randomness, randCount, views, countY);
	mpc_FF(bb, cc, dd, ee, aa, X[14], 9, randomness, randCount, views, countY);
	mpc_FF(aa, bb, cc, dd, ee, X[15], 8, randomness, randCount, views, countY);

	if (debug)
	{
		printf("round1 ");
		printf("aa = %02X, bb = %02X, cc = %02X, dd = %02X, ee = %02X\n ",aa[0]^aa[1]^aa[2],bb[0]^bb[1]^bb[2],cc[0]^cc[1]^cc[2],dd[0]^dd[1]^dd[2],ee[0]^ee[1]^ee[2]);
	}
	// round 2
	mpc_GG(ee, aa, bb, cc, dd, X[7], 7, hG, randomness, randCount, views, countY);
	mpc_GG(dd, ee, aa, bb, cc, X[4], 6, hG, randomness, randCount, views, countY);
	mpc_GG(cc, dd, ee, aa, bb, X[13], 8, hG, randomness, randCount, views, countY);
	mpc_GG(bb, cc, dd, ee, aa, X[1], 13, hG, randomness, randCount, views, countY);
	mpc_GG(aa, bb, cc, dd, ee, X[10], 11, hG, randomness, randCount, views, countY);
	mpc_GG(ee, aa, bb, cc, dd, X[6], 9, hG, randomness, randCount, views, countY);
	mpc_GG(dd, ee, aa, bb, cc, X[15], 7, hG, randomness, randCount, views, countY);
	mpc_GG(cc, dd, ee, aa, bb, X[3], 15, hG, randomness, randCount, views, countY);
	mpc_GG(bb, cc, dd, ee, aa, X[12], 7, hG, randomness, randCount, views, countY);
	mpc_GG(aa, bb, cc, dd, ee, X[0], 12, hG, randomness, randCount, views, countY);
	mpc_GG(ee, aa, bb, cc, dd, X[9], 15, hG, randomness, randCount, views, countY);
	mpc_GG(dd, ee, aa, bb, cc, X[5], 9, hG, randomness, randCount, views, countY);
	mpc_GG(cc, dd, ee, aa, bb, X[2], 11, hG, randomness, randCount, views, countY);
	mpc_GG(bb, cc, dd, ee, aa, X[14], 7, hG, randomness, randCount, views, countY);
	mpc_GG(aa, bb, cc, dd, ee, X[11], 13, hG, randomness, randCount, views, countY);
	mpc_GG(ee, aa, bb, cc, dd, X[8], 12, hG, randomness, randCount, views, countY);

	if (debug>1)
	{
		printf("round2 ");
		printf("aa = %02X, bb = %02X, cc = %02X, dd = %02X, ee = %02X\n ",aa[0]^aa[1]^aa[2],bb[0]^bb[1]^bb[2],cc[0]^cc[1]^cc[2],dd[0]^dd[1]^dd[2],ee[0]^ee[1]^ee[2]);
	}
	// round 3
	mpc_HH(dd, ee, aa, bb, cc, X[3], 11, hH, randomness, randCount, views, countY);
	mpc_HH(cc, dd, ee, aa, bb, X[10], 13, hH, randomness, randCount, views, countY);
	mpc_HH(bb, cc, dd, ee, aa, X[14], 6, hH, randomness, randCount, views, countY);
	mpc_HH(aa, bb, cc, dd, ee, X[4], 7, hH, randomness, randCount, views, countY);
	mpc_HH(ee, aa, bb, cc, dd, X[9], 14, hH, randomness, randCount, views, countY);
	mpc_HH(dd, ee, aa, bb, cc, X[15], 9, hH, randomness, randCount, views, countY);
	mpc_HH(cc, dd, ee, aa, bb, X[8], 13, hH, randomness, randCount, views, countY);
	mpc_HH(bb, cc, dd, ee, aa, X[1], 15, hH, randomness, randCount, views, countY);
	mpc_HH(aa, bb, cc, dd, ee, X[2], 14, hH, randomness, randCount, views, countY);
	mpc_HH(ee, aa, bb, cc, dd, X[7], 8, hH, randomness, randCount, views, countY);
	mpc_HH(dd, ee, aa, bb, cc, X[0], 13, hH, randomness, randCount, views, countY);
	mpc_HH(cc, dd, ee, aa, bb, X[6], 6, hH, randomness, randCount, views, countY);
	mpc_HH(bb, cc, dd, ee, aa, X[13], 5, hH, randomness, randCount, views, countY);
	mpc_HH(aa, bb, cc, dd, ee, X[11], 12, hH, randomness, randCount, views, countY);
	mpc_HH(ee, aa, bb, cc, dd, X[5], 7, hH, randomness, randCount, views, countY);
	mpc_HH(dd, ee, aa, bb, cc, X[12], 5, hH, randomness, randCount, views, countY);
	if (debug>1)
	{
		printf("round3 ");
		printf("aa = %02X, bb = %02X, cc = %02X, dd = %02X, ee = %02X\n ",aa[0]^aa[1]^aa[2],bb[0]^bb[1]^bb[2],cc[0]^cc[1]^cc[2],dd[0]^dd[1]^dd[2],ee[0]^ee[1]^ee[2]);
	}

	// round 4
	mpc_II(cc, dd, ee, aa, bb, X[1], 11, hI, randomness, randCount, views, countY);
	mpc_II(bb, cc, dd, ee, aa, X[9], 12, hI, randomness, randCount, views, countY);
	mpc_II(aa, bb, cc, dd, ee, X[11], 14, hI, randomness, randCount, views, countY);
	mpc_II(ee, aa, bb, cc, dd, X[10], 15, hI, randomness, randCount, views, countY);
	mpc_II(dd, ee, aa, bb, cc, X[0], 14, hI, randomness, randCount, views, countY);
	mpc_II(cc, dd, ee, aa, bb, X[8], 15, hI, randomness, randCount, views, countY);
	mpc_II(bb, cc, dd, ee, aa, X[12], 9, hI, randomness, randCount, views, countY);
	mpc_II(aa, bb, cc, dd, ee, X[4], 8, hI, randomness, randCount, views, countY);
	mpc_II(ee, aa, bb, cc, dd, X[13], 9, hI, randomness, randCount, views, countY);
	mpc_II(dd, ee, aa, bb, cc, X[3], 14, hI, randomness, randCount, views, countY);
	mpc_II(cc, dd, ee, aa, bb, X[7], 5, hI, randomness, randCount, views, countY);
	mpc_II(bb, cc, dd, ee, aa, X[15], 6, hI, randomness, randCount, views, countY);
	mpc_II(aa, bb, cc, dd, ee, X[14], 8, hI, randomness, randCount, views, countY);
	mpc_II(ee, aa, bb, cc, dd, X[5], 6, hI, randomness, randCount, views, countY);
	mpc_II(dd, ee, aa, bb, cc, X[6], 5, hI, randomness, randCount, views, countY);
	mpc_II(cc, dd, ee, aa, bb, X[2], 12, hI, randomness, randCount, views, countY);

	// round 5
	mpc_JJ(bb, cc, dd, ee, aa, X[4], 9, hJ, randomness, randCount, views, countY);
       	mpc_JJ(aa, bb, cc, dd, ee, X[0], 15, hJ, randomness, randCount, views, countY);
	mpc_JJ(ee, aa, bb, cc, dd, X[5], 5, hJ, randomness, randCount, views, countY);
	mpc_JJ(dd, ee, aa, bb, cc, X[9], 11, hJ, randomness, randCount, views, countY);
	mpc_JJ(cc, dd, ee, aa, bb, X[7], 6, hJ, randomness, randCount, views, countY);
	mpc_JJ(bb, cc, dd, ee, aa, X[12], 8, hJ, randomness, randCount, views, countY);
	mpc_JJ(aa, bb, cc, dd, ee, X[2], 13, hJ, randomness, randCount, views, countY);
	mpc_JJ(ee, aa, bb, cc, dd, X[10], 12, hJ, randomness, randCount, views, countY);
	mpc_JJ(dd, ee, aa, bb, cc, X[14], 5, hJ, randomness, randCount, views, countY);
	mpc_JJ(cc, dd, ee, aa, bb, X[1], 12, hJ, randomness, randCount, views, countY);
	mpc_JJ(bb, cc, dd, ee, aa, X[3], 13, hJ, randomness, randCount, views, countY);
	mpc_JJ(aa, bb, cc, dd, ee, X[8], 14, hJ, randomness, randCount, views, countY);
	mpc_JJ(ee, aa, bb, cc, dd, X[11], 11, hJ, randomness, randCount, views, countY);
	mpc_JJ(dd, ee, aa, bb, cc, X[6], 8, hJ, randomness, randCount, views, countY);
	mpc_JJ(cc, dd, ee, aa, bb, X[15], 5, hJ, randomness, randCount, views, countY);
	mpc_JJ(bb, cc, dd, ee, aa, X[13], 6, hJ, randomness, randCount, views, countY);

	if (debug)
	{
		printf("round5 ");
		printf("aa = %02X, bb = %02X, cc = %02X, dd = %02X, ee = %02X\n ",aa[0]^aa[1]^aa[2],bb[0]^bb[1]^bb[2],cc[0]^cc[1]^cc[2],dd[0]^dd[1]^dd[2],ee[0]^ee[1]^ee[2]);
	}
	// round 1
	mpc_JJ(aaa, bbb, ccc, ddd, eee, X[5], 8, hJJ, randomness, randCount, views, countY);
       	mpc_JJ(eee, aaa, bbb, ccc, ddd, X[14], 9, hJJ, randomness, randCount, views, countY);
	mpc_JJ(ddd, eee, aaa, bbb, ccc, X[7], 9, hJJ, randomness, randCount, views, countY);
	mpc_JJ(ccc, ddd, eee, aaa, bbb, X[0], 11, hJJ, randomness, randCount, views, countY);
	mpc_JJ(bbb, ccc, ddd, eee, aaa, X[9], 13, hJJ, randomness, randCount, views, countY);
	mpc_JJ(aaa, bbb, ccc, ddd, eee, X[2], 15, hJJ, randomness, randCount, views, countY);
	mpc_JJ(eee, aaa, bbb, ccc, ddd, X[11], 15, hJJ, randomness, randCount, views, countY);
	mpc_JJ(ddd, eee, aaa, bbb, ccc, X[4], 5, hJJ, randomness, randCount, views, countY);
	mpc_JJ(ccc, ddd, eee, aaa, bbb, X[13], 7, hJJ, randomness, randCount, views, countY);
	mpc_JJ(bbb, ccc, ddd, eee, aaa, X[6], 7, hJJ, randomness, randCount, views, countY);
	mpc_JJ(aaa, bbb, ccc, ddd, eee, X[15], 8, hJJ, randomness, randCount, views, countY);
	mpc_JJ(eee, aaa, bbb, ccc, ddd, X[8], 11, hJJ, randomness, randCount, views, countY);
	mpc_JJ(ddd, eee, aaa, bbb, ccc, X[1], 14, hJJ, randomness, randCount, views, countY);
	mpc_JJ(ccc, ddd, eee, aaa, bbb, X[10], 14, hJJ, randomness, randCount, views, countY);
	mpc_JJ(bbb, ccc, ddd, eee, aaa, X[3], 12, hJJ, randomness, randCount, views, countY);
	mpc_JJ(aaa, bbb, ccc, ddd, eee, X[12], 6, hJJ, randomness, randCount, views, countY);

	if (debug)
	{
		printf("alt round1 ");
		printf("aaa = %02X, bb = %02X, cc = %02X, dd = %02X, ee = %02X\n ",aaa[0]^aaa[1]^aaa[2],bbb[0]^bbb[1]^bbb[2],ccc[0]^ccc[1]^ccc[2],ddd[0]^ddd[1]^ddd[2],eee[0]^eee[1]^eee[2]);
	}

	// round 2
	mpc_II(eee, aaa, bbb, ccc, ddd, X[6], 9, hII, randomness, randCount, views, countY);
	mpc_II(ddd, eee, aaa, bbb, ccc, X[11], 13, hII, randomness, randCount, views, countY);
	mpc_II(ccc, ddd, eee, aaa, bbb, X[3], 15, hII, randomness, randCount, views, countY);
	mpc_II(bbb, ccc, ddd, eee, aaa, X[7], 7, hII, randomness, randCount, views, countY);
	mpc_II(aaa, bbb, ccc, ddd, eee, X[0], 12, hII, randomness, randCount, views, countY);
	mpc_II(eee, aaa, bbb, ccc, ddd, X[13], 8, hII, randomness, randCount, views, countY);
	mpc_II(ddd, eee, aaa, bbb, ccc, X[5], 9, hII, randomness, randCount, views, countY);
	mpc_II(ccc, ddd, eee, aaa, bbb, X[10], 11, hII, randomness, randCount, views, countY);
	mpc_II(bbb, ccc, ddd, eee, aaa, X[14], 7, hII, randomness, randCount, views, countY);
	mpc_II(aaa, bbb, ccc, ddd, eee, X[15], 7, hII, randomness, randCount, views, countY);
	mpc_II(eee, aaa, bbb, ccc, ddd, X[8], 12, hII, randomness, randCount, views, countY);
	mpc_II(ddd, eee, aaa, bbb, ccc, X[12], 7, hII, randomness, randCount, views, countY);
	mpc_II(ccc, ddd, eee, aaa, bbb, X[4], 6, hII, randomness, randCount, views, countY);
	mpc_II(bbb, ccc, ddd, eee, aaa, X[9], 15, hII, randomness, randCount, views, countY);
	mpc_II(aaa, bbb, ccc, ddd, eee, X[1], 13, hII, randomness, randCount, views, countY);
	mpc_II(eee, aaa, bbb, ccc, ddd, X[2], 11, hII, randomness, randCount, views, countY);

	// round 3
	mpc_HH(ddd, eee, aaa, bbb, ccc, X[15], 9, hHH, randomness, randCount, views, countY);
	mpc_HH(ccc, ddd, eee, aaa, bbb, X[5], 7, hHH, randomness, randCount, views, countY);
	mpc_HH(bbb, ccc, ddd, eee, aaa, X[1], 15, hHH, randomness, randCount, views, countY);
	mpc_HH(aaa, bbb, ccc, ddd, eee, X[3], 11, hHH, randomness, randCount, views, countY);
	mpc_HH(eee, aaa, bbb, ccc, ddd, X[7], 8, hHH, randomness, randCount, views, countY);
	mpc_HH(ddd, eee, aaa, bbb, ccc, X[14], 6, hHH, randomness, randCount, views, countY);
	mpc_HH(ccc, ddd, eee, aaa, bbb, X[6], 6, hHH, randomness, randCount, views, countY);
	mpc_HH(bbb, ccc, ddd, eee, aaa, X[9], 14, hHH, randomness, randCount, views, countY);
	mpc_HH(aaa, bbb, ccc, ddd, eee, X[11], 12, hHH, randomness, randCount, views, countY);
	mpc_HH(eee, aaa, bbb, ccc, ddd, X[8], 13, hHH, randomness, randCount, views, countY);
	mpc_HH(ddd, eee, aaa, bbb, ccc, X[12], 5, hHH, randomness, randCount, views, countY);
	mpc_HH(ccc, ddd, eee, aaa, bbb, X[2], 14, hHH, randomness, randCount, views, countY);
	mpc_HH(bbb, ccc, ddd, eee, aaa, X[10], 13, hHH, randomness, randCount, views, countY);
	mpc_HH(aaa, bbb, ccc, ddd, eee, X[0], 13, hHH, randomness, randCount, views, countY);
	mpc_HH(eee, aaa, bbb, ccc, ddd, X[4], 7, hHH, randomness, randCount, views, countY);
	mpc_HH(ddd, eee, aaa, bbb, ccc, X[13], 5, hHH, randomness, randCount, views, countY);

	// round 4
	mpc_GG(ccc, ddd, eee, aaa, bbb, X[8], 15, hGG, randomness, randCount, views, countY);
	mpc_GG(bbb, ccc, ddd, eee, aaa, X[6], 5, hGG, randomness, randCount, views, countY);
	mpc_GG(aaa, bbb, ccc, ddd, eee, X[4], 8, hGG, randomness, randCount, views, countY);
	mpc_GG(eee, aaa, bbb, ccc, ddd, X[1], 11, hGG, randomness, randCount, views, countY);
	mpc_GG(ddd, eee, aaa, bbb, ccc, X[3], 14, hGG, randomness, randCount, views, countY);
	mpc_GG(ccc, ddd, eee, aaa, bbb, X[11], 14, hGG, randomness, randCount, views, countY);
	mpc_GG(bbb, ccc, ddd, eee, aaa, X[15], 6, hGG, randomness, randCount, views, countY);
	mpc_GG(aaa, bbb, ccc, ddd, eee, X[0], 14, hGG, randomness, randCount, views, countY);
	mpc_GG(eee, aaa, bbb, ccc, ddd, X[5], 6, hGG, randomness, randCount, views, countY);
	mpc_GG(ddd, eee, aaa, bbb, ccc, X[12], 9, hGG, randomness, randCount, views, countY);
	mpc_GG(ccc, ddd, eee, aaa, bbb, X[2], 12, hGG, randomness, randCount, views, countY);
	mpc_GG(bbb, ccc, ddd, eee, aaa, X[13], 9, hGG, randomness, randCount, views, countY);
	mpc_GG(aaa, bbb, ccc, ddd, eee, X[9], 12, hGG, randomness, randCount, views, countY);
	mpc_GG(eee, aaa, bbb, ccc, ddd, X[7], 5, hGG, randomness, randCount, views, countY);
	mpc_GG(ddd, eee, aaa, bbb, ccc, X[10], 15, hGG, randomness, randCount, views, countY);
	mpc_GG(ccc, ddd, eee, aaa, bbb, X[14], 8, hGG, randomness, randCount, views, countY);

	// round 5
	mpc_FF(bbb, ccc, ddd, eee, aaa, X[12], 8, randomness, randCount, views, countY);
	mpc_FF(aaa, bbb, ccc, ddd, eee, X[15], 5, randomness, randCount, views, countY);
	mpc_FF(eee, aaa, bbb, ccc, ddd, X[10], 12, randomness, randCount, views, countY);
	mpc_FF(ddd, eee, aaa, bbb, ccc, X[4], 9, randomness, randCount, views, countY);
	mpc_FF(ccc, ddd, eee, aaa, bbb, X[1], 12, randomness, randCount, views, countY);
	mpc_FF(bbb, ccc, ddd, eee, aaa, X[5], 5, randomness, randCount, views, countY);
	mpc_FF(aaa, bbb, ccc, ddd, eee, X[8], 14, randomness, randCount, views, countY);
	mpc_FF(eee, aaa, bbb, ccc, ddd, X[7], 6, randomness, randCount, views, countY);
	mpc_FF(ddd, eee, aaa, bbb, ccc, X[6], 8, randomness, randCount, views, countY);
	mpc_FF(ccc, ddd, eee, aaa, bbb, X[2], 13, randomness, randCount, views, countY);
	mpc_FF(bbb, ccc, ddd, eee, aaa, X[13], 6, randomness, randCount, views, countY);
	mpc_FF(aaa, bbb, ccc, ddd, eee, X[14], 5, randomness, randCount, views, countY);
	mpc_FF(eee, aaa, bbb, ccc, ddd, X[0], 15, randomness, randCount, views, countY);
	mpc_FF(ddd, eee, aaa, bbb, ccc, X[3], 13, randomness, randCount, views, countY);
	mpc_FF(ccc, ddd, eee, aaa, bbb, X[9], 11, randomness, randCount, views, countY);
	mpc_FF(bbb, ccc, ddd, eee, aaa, X[11], 11, randomness, randCount, views, countY);

	if (debug)
	{
		printf("alt round5 ");
		printf("aaa = %02X, bb = %02X, cc = %02X, dd = %02X, ee = %02X\n ",aaa[0]^aaa[1]^aaa[2],bbb[0]^bbb[1]^bbb[2],ccc[0]^ccc[1]^ccc[2],ddd[0]^ddd[1]^ddd[2],eee[0]^eee[1]^eee[2]);
	}

	mpc_ADD(cc,buf[1],t0,randomness,randCount,views,countY);
	mpc_ADD(t0,ddd,t1,randomness,randCount,views,countY);
	mpc_ADD(dd,buf[2],t0,randomness,randCount,views,countY);
	mpc_ADD(t0,eee,buf[1],randomness,randCount,views,countY);
	mpc_ADD(ee,buf[3],t0,randomness,randCount,views,countY);
	mpc_ADD(t0,aaa,buf[2],randomness,randCount,views,countY);
	mpc_ADD(aa,buf[4],t0,randomness,randCount,views,countY);
	mpc_ADD(t0,bbb,buf[3],randomness,randCount,views,countY);
	mpc_ADD(bb,buf[0],t0,randomness,randCount,views,countY);
	mpc_ADD(t0,ccc,buf[4],randomness,randCount,views,countY);
	buf[0][0] = t1[0];
	buf[0][1] = t1[1];
	buf[0][2] = t1[2];

	if (debug)
	{
		printf("end ");
		for (int j=0;j<5;j++)
			printf("buf[%d] = %02X,",j,buf[j][0]^buf[j][1]^buf[j][2]);
		printf("\n");
	}

	for (int i = 0; i < 5; i++) {
		results[0][i * 4] = buf[i][0];
		results[1][i * 4] = buf[i][1];
		results[2][i * 4] = buf[i][2];
		mpc_RIGHTSHIFT(buf[i], 8, t0);
		results[0][i * 4 + 1] = t0[0];
		results[1][i * 4 + 1] = t0[1];
		results[2][i * 4 + 1] = t0[2];
		mpc_RIGHTSHIFT(buf[i], 16, t0);
		results[0][i * 4 + 2] = t0[0];
		results[1][i * 4 + 2] = t0[1];
		results[2][i * 4 + 2] = t0[2];
		mpc_RIGHTSHIFT(buf[i], 24, t0);
		results[0][i * 4 + 3] = t0[0];
		results[1][i * 4 + 3] = t0[1];
		results[2][i * 4 + 3] = t0[2];
	}

	return 0;
}

static int mpc_sha256(unsigned char* results[3], unsigned char* inputs[3], int numBits, unsigned char *randomness[3], int * randCount, View views [3], int* countY) {

	if (numBits > 447) {
		printf("Input too long, aborting!");
		return -1;
	}

	int chars = numBits >> 3;
	unsigned char* chunks[3];
	uint32_t w[64][3];

	for (int i = 0; i < 3; i++) {
		chunks[i] = calloc(64, 1); //512 bits
		memcpy(chunks[i], inputs[i], chars);
		chunks[i][chars] = 0x80;
														                //Last 8 chars used for storing length of input without padding, in big-endian.
		//chunk[60] = numBits >> 24;
		//chunk[61] = numBits >> 16;
                chunks[i][62] = numBits >> 8;
		chunks[i][63] = numBits;
		memcpy(views[i].x, chunks[i], 64);

		for (int j = 0; j < 16; j++) {
			w[j][i] = (chunks[i][j * 4] << 24) | (chunks[i][j * 4 + 1] << 16)
				| (chunks[i][j * 4 + 2] << 8) | chunks[i][j * 4 + 3];
		}
		free(chunks[i]);
	}

	uint32_t s0[3], s1[3];
	uint32_t t0[3], t1[3];
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

		mpc_ADD(w[j-16], s0, t1, randomness, randCount, views, countY);
		mpc_ADD(w[j-7], t1, t1, randomness, randCount, views, countY);
		mpc_ADD(t1, s1, w[j], randomness, randCount, views, countY);

	}

	uint32_t a[3] = { hA[0],hA[0],hA[0] };
	uint32_t b[3] = { hA[1],hA[1],hA[1] };
	uint32_t c[3] = { hA[2],hA[2],hA[2] };
	uint32_t d[3] = { hA[3],hA[3],hA[3] };
	uint32_t e[3] = { hA[4],hA[4],hA[4] };
	uint32_t f[3] = { hA[5],hA[5],hA[5] };
	uint32_t g[3] = { hA[6],hA[6],hA[6] };
	uint32_t h[3] = { hA[7],hA[7],hA[7] };
	uint32_t temp1[3], temp2[3], maj[3];
	for (int i = 0; i < 64; i++) {

		mpc_RIGHTROTATE(e, 6, t0);
		mpc_RIGHTROTATE(e, 11, t1);
		mpc_XOR(t0, t1, t0);

		mpc_RIGHTROTATE(e, 25, t1);
		mpc_XOR(t0, t1, s1);

		mpc_ADD(h, s1, t0, randomness, randCount, views, countY);
		mpc_CH(e, f, g, t1, randomness, randCount, views, countY);

		mpc_ADD(t0, t1, t1, randomness, randCount, views, countY);
		mpc_ADDK(t1, k[i], t1, randomness, randCount, views, countY);
		mpc_ADD(t1, w[i], temp1, randomness, randCount, views, countY);

		mpc_RIGHTROTATE(a, 2, t0);
		mpc_RIGHTROTATE(a, 13, t1);
		mpc_XOR(t0, t1, t0);
		mpc_RIGHTROTATE(a, 22, t1);
		mpc_XOR(t0, t1, s0);

		mpc_MAJ(a, b, c, maj, randomness, randCount, views, countY);

		mpc_ADD(s0, maj, temp2, randomness, randCount, views, countY);

		memcpy(h, g, sizeof(uint32_t) * 3);
		memcpy(g, f, sizeof(uint32_t) * 3);
		memcpy(f, e, sizeof(uint32_t) * 3);
		mpc_ADD(d, temp1, e, randomness, randCount, views, countY);
		memcpy(d, c, sizeof(uint32_t) * 3);
		memcpy(c, b, sizeof(uint32_t) * 3);
		memcpy(b, a, sizeof(uint32_t) * 3);
		mpc_ADD(temp1, temp2, a, randomness, randCount, views, countY);
	}
	uint32_t hHa[8][3] = { { hA[0],hA[0],hA[0]  }, { hA[1],hA[1],hA[1] }, { hA[2],hA[2],hA[2] }, { hA[3],hA[3],hA[3]
	},
			{ hA[4],hA[4],hA[4] }, { hA[5],hA[5],hA[5] }, { hA[6],hA[6],hA[6] }, { hA[7],hA[7],hA[7] } };

	mpc_ADD(hHa[0], a, hHa[0], randomness, randCount, views, countY);
	mpc_ADD(hHa[1], b, hHa[1], randomness, randCount, views, countY);
	mpc_ADD(hHa[2], c, hHa[2], randomness, randCount, views, countY);
	mpc_ADD(hHa[3], d, hHa[3], randomness, randCount, views, countY);
	mpc_ADD(hHa[4], e, hHa[4], randomness, randCount, views, countY);
	mpc_ADD(hHa[5], f, hHa[5], randomness, randCount, views, countY);
	mpc_ADD(hHa[6], g, hHa[6], randomness, randCount, views, countY);
	mpc_ADD(hHa[7], h, hHa[7], randomness, randCount, views, countY);

	for (int i = 0; i < 8; i++) {
		mpc_RIGHTSHIFT(hHa[i], 24, t0);
		results[0][i * 4] = t0[0];
		results[1][i * 4] = t0[1];
		results[2][i * 4] = t0[2];
		mpc_RIGHTSHIFT(hHa[i], 16, t0);
		results[0][i * 4 + 1] = t0[0];
		results[1][i * 4 + 1] = t0[1];
		results[2][i * 4 + 1] = t0[2];
		mpc_RIGHTSHIFT(hHa[i], 8, t0);
		results[0][i * 4 + 2] = t0[0];
		results[1][i * 4 + 2] = t0[1];
		results[2][i * 4 + 2] = t0[2];
		results[0][i * 4 + 3] = hHa[i][0];
		results[1][i * 4 + 3] = hHa[i][1];
		results[2][i * 4 + 3] = hHa[i][2];
	}
	return 0;
}
											
static int writeToFile(char filename[], void* data, int size, int numItems) {
	FILE *file;

	file = fopen(filename, "wb");
	if (!file) {
		printf("Unable to open file!");
		return 1;
	}
	fwrite(data, size, numItems, file);
	fclose(file);
	return 0;
}




static int secretShare(unsigned char* input, int numBytes, unsigned char output[3][numBytes]) {
	if(RAND_bytes(output[0], numBytes) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
	}
	if(RAND_bytes(output[1], numBytes) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
	}
	for (int j = 0; j < numBytes; j++) {
		output[2][j] = input[j] ^ output[0][j] ^ output[1][j];
	}
	return 0;
}

static a commit(int numBytes,unsigned char shares[3][numBytes], unsigned char *randomness[3], unsigned char rs[3][4], View views[3], unsigned char hashresult[RIPEMD160_DIGEST_LENGTH]) {
static int printonce=0;

	unsigned char* inputs[3];
	inputs[0] = shares[0];
	inputs[1] = shares[1];
	inputs[2] = shares[2];
	unsigned char* shahashes[3];
	shahashes[0] = malloc(32);
	shahashes[1] = malloc(32);
	shahashes[2] = malloc(32);
	unsigned char* hashes[3];
	hashes[0] = malloc(20);
	hashes[1] = malloc(20);
	hashes[2] = malloc(20);
/*
	unsigned char * pubkey[3];
	unsigned char * pubx[3];
	unsigned char * puby[3];
	pubkey[0] = malloc(65);
	pubkey[1] = malloc(65);
	pubkey[2] = malloc(65);
	int pubkeylen = 33;
	pubx[0] = malloc(32);
	pubx[1] = malloc(32);
	pubx[2] = malloc(32);
	puby[0] = malloc(32);
	puby[1] = malloc(32);
	puby[2] = malloc(32);
*/
	int randCount = 0;

	int* countY = calloc(1, sizeof(int));
	/*
	mpc_MUL_EC(pubx,puby,inputs, randomness, &randCount, views, countY);

	pubkey[0][0] = 0x02;
	pubkey[1][0] = 0x02;
	pubkey[2][0] = 0x02;
	memcpy(&(pubkey[0][1]),pubx[0],32);
	memcpy(&(pubkey[1][1]),pubx[1],32);
	memcpy(&(pubkey[2][1]),pubx[2],32);
	if (!compressed)
	{
		pubkeylen = 65;
		pubkey[0][0] = 0x04;
		pubkey[1][0] = 0x04;
		pubkey[2][0] = 0x04;
		memcpy(&pubkey[0][33],puby[0],32);
		memcpy(&pubkey[1][33],puby[1],32);
		memcpy(&pubkey[2][33],puby[2],32);
	}
	if (debug)
	{
		printf("pubkey: ");
		for (int k = 0; k < pubkeylen; k++)
		{
			printf("%02X",pubkey[0][k]^pubkey[1][k]^pubkey[2][k]);
		}
		printf("\n");
	}
	*/

	if (debug)
	{
		printf("before sha256: ");
		for (int k = 0; k < numBytes; k++)
		{
			printf("%02X",inputs[0][k]^inputs[1][k]^inputs[2][k]);
		}
		printf("\n");
	}

	mpc_sha256(shahashes, inputs, numBytes * 8, randomness, &randCount, views, countY);
	if (debug)
	{
		printf("after sha256: ");
		for (int k = 0; k < SHA256_DIGEST_LENGTH; k++)
		{
			printf("%02X",shahashes[0][k]^shahashes[1][k]^shahashes[2][k]);
		}
		printf("\n");
	}


	mpc_ripemd160(hashes, shahashes, SHA256_DIGEST_LENGTH * 8, randomness, &randCount, views, countY);

	if (!printonce) // just for debug
	{
		printonce=1;
		for (int i = 0; i < 20; i++)
			hashresult[i] = hashes[0][i]^hashes[1][i]^hashes[2][i];
		if (debug)
		{
			printf("hash obtained is: ");
			for (int i = 0; i < 20; i++)
			{
				printf("%02X",hashresult[i]);
			}
			printf("\n");
		}
	}

	//Explicitly add y to view
	for(int i = 0; i<5; i++) {
		views[0].y[*countY] = 	((uint32_t)hashes[0][i * 4 + 0] << 24) | ((uint32_t)hashes[0][i * 4 + 1] << 16)
					| ((uint32_t)hashes[0][i * 4 + 2] << 8) | (uint32_t)hashes[0][i * 4 + 3];
		views[1].y[*countY] = 	((uint32_t)hashes[1][i * 4 + 0] << 24) | ((uint32_t)hashes[1][i * 4 + 1] << 16)
					| ((uint32_t)hashes[1][i * 4 + 2] << 8) | (uint32_t)hashes[1][i * 4 + 3];
		views[2].y[*countY] = 	((uint32_t)hashes[2][i * 4 + 0] << 24) | ((uint32_t)hashes[2][i * 4 + 1] << 16)
					| ((uint32_t)hashes[2][i * 4 + 2] << 8) | (uint32_t)hashes[2][i * 4 + 3];

		*countY += 1;
	}
	if (debug)
		printf("countY %d randcount %d\n",*countY,randCount);
	free(countY);
	free(shahashes[0]);
	free(shahashes[1]);
	free(shahashes[2]);
	free(hashes[0]);
	free(hashes[1]);
	free(hashes[2]);
/*
	free(pubkey[0]);
	free(pubkey[1]);
	free(pubkey[2]);
	free(pubx[0]);
	free(pubx[1]);
	free(pubx[2]);
	free(puby[0]);
	free(puby[1]);
	free(puby[2]);
*/
	uint32_t* result1 = malloc(20);
	output(views[0], result1);
	uint32_t* result2 = malloc(20);
	output(views[1], result2);
	uint32_t* result3 = malloc(20);
	output(views[2], result3);

	a a;
	memcpy(a.yp[0], result1, 20);
	memcpy(a.yp[1], result2, 20);
	memcpy(a.yp[2], result3, 20);

	free(result1);
	free(result2);
	free(result3);

	return a;
}

static void prove(z *zs, int e, unsigned char keys[3][16], unsigned char rs[3][4], View views[3]) {

	memcpy(zs->ke, keys[e], 16);
	memcpy(zs->ke1, keys[(e + 1) % 3], 16);
	memcpy(&(zs->ve),&views[e],sizeof(View));
	memcpy(&(zs->ve1),&views[(e + 1) % 3],sizeof(View));
	memcpy(zs->re, rs[e],4);
	memcpy(zs->re1, rs[(e + 1) % 3],4);

}


/**
 * Copyright (c) 2012-2014 Luke Dashjr
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

const char b58digits_ordered[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const int8_t b58digits_map[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,
    8,  -1, -1, -1, -1, -1, -1, -1, 9,  10, 11, 12, 13, 14, 15, 16, -1, 17, 18,
    19, 20, 21, -1, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1,
    -1, -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
};

static int b58tobin(void *bin, size_t *binszp, const char *b58) {
  size_t binsz = *binszp;
  size_t retsz = 0;
  if (binsz == 0) {
    return 0;
  }
  const unsigned char *b58u = (const unsigned char *)b58;
  unsigned char *binu = bin;
  size_t outisz = (binsz + 3) / 4;
  uint32_t outi[outisz];
  uint64_t t;
  uint32_t c;
  size_t i, j;
  uint8_t bytesleft = binsz % 4;
  uint32_t zeromask = bytesleft ? (0xffffffff << (bytesleft * 8)) : 0;
  unsigned zerocount = 0;
  size_t b58sz;

  b58sz = strlen(b58);
  memset(outi,0, sizeof(outi));

  // Leading zeros, just count
  for (i = 0; i < b58sz && b58u[i] == '1'; ++i) ++zerocount;

  for (; i < b58sz; ++i) {
    if (b58u[i] & 0x80)
      // High-bit set on invalid digit
      return 0;
    if (b58digits_map[b58u[i]] == -1)
      // Invalid base58 digit
      return 0;
    c = (unsigned)b58digits_map[b58u[i]];
    for (j = outisz; j--;) {
     t = ((uint64_t)outi[j]) * 58 + c;
      c = (t & 0x3f00000000) >> 32;
      outi[j] = t & 0xffffffff;
    }
    if (c)
      // Output number too big (carry to the next int32)
      return 0;
    if (outi[0] & zeromask)
      // Output number too big (last int32 filled too far)
      return 0;
  }

  j = 0;
  switch (bytesleft) {
    case 3:
      *(binu++) = (outi[0] & 0xff0000) >> 16;
      //-fallthrough
    case 2:
      *(binu++) = (outi[0] & 0xff00) >> 8;
      //-fallthrough
    case 1:
      *(binu++) = (outi[0] & 0xff);
      ++j;
    default:
      break;
  }
  for (; j < outisz; ++j) {
    *(binu++) = (outi[j] >> 0x18) & 0xff;
    *(binu++) = (outi[j] >> 0x10) & 0xff;
    *(binu++) = (outi[j] >> 8) & 0xff;
    *(binu++) = (outi[j] >> 0) & 0xff;
  }

  // Count canonical base58 byte count
  binu = bin;
  for (i = 0; i < binsz; ++i) {
    if (binu[i]) {
      if (zerocount > i) {
        /* result too large */
        return 0;
      }
      break;
    }
    --*binszp;
  }
  *binszp += zerocount;

  return 1;
}

static int b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz) {
  const uint8_t *bin = data;
  int carry;
  ssize_t i, j, high, zcount = 0;
  size_t size;

  while (zcount < (ssize_t)binsz && !bin[zcount]) ++zcount;

  size = (binsz - zcount) * 138 / 100 + 1;
  uint8_t buf[size];
  memset(buf,0, size);

  for (i = zcount, high = size - 1; i < (ssize_t)binsz; ++i, high = j) {
    for (carry = bin[i], j = size - 1; (j > high) || carry; --j) {
      carry += 256 * buf[j];
      buf[j] = carry % 58;
      carry /= 58;
    }
  }

  for (j = 0; j < (ssize_t)size && !buf[j]; ++j)
    ;

  if (*b58sz <= zcount + size - j) {
    *b58sz = zcount + size - j + 1;
    return 0;
  }
  if (zcount) memset(b58, '1', zcount);
  for (i = zcount; j < (ssize_t)size; ++i, ++j)
    b58[i] = b58digits_ordered[buf[j]];
  b58[i] = '\0';
  *b58sz = i + 1;

  return 1;
}

static void hex2bin(char * hex , int hexsize, unsigned char * bin)
{
	unsigned char tempc;
	int i;

	for (i=0;i<hexsize;i+=2)
	{
		tempc = 0;
		if ((hex[i]>='0') && (hex[i]<='9'))
			tempc = hex[i] - '0';
		else if ((hex[i]>='a') && (hex[i]<='f'))
			tempc = hex[i] - 'a' + 10;
		else if ((hex[i]>='A') && (hex[i]<='F'))
			tempc = hex[i] - 'A' + 10;
		tempc <<= 4;
		if ((hex[i+1]>='0') && (hex[i+1]<='9'))
			tempc += hex[i+1] - '0';
		else if ((hex[i+1]>='a') && (hex[i+1]<='f'))
			tempc += hex[i+1] - 'a' + 10;
		else if ((hex[i+1]>='A') && (hex[i+1]<='F'))
			tempc += hex[i+1] - 'A' + 10;
		bin[(i)/2] = tempc; 
	}
}
static void bin2hex(unsigned char * bin, int binsize, char * hex)
{
	char * hexptr;
	int i;

	hexptr = hex;
	for (i=0;i<binsize;i++)
	{
		sprintf(hexptr,"%02X",bin[i]);
		hexptr+=2;
	}

	*hexptr = 0;
		
}

// generate - create proof from public key
#ifdef WASM
EMSCRIPTEN_KEEPALIVE
#endif
char * generate_poc(char * message, char * secret, char * params)
{
	int KEY_LEN = strlen(secret)/2;
	unsigned char garbage[4];
	unsigned char pubkey[KEY_LEN];
	unsigned char addrbuf[100];
	int i;
	unsigned char rs[NUM_ROUNDS][3][4];
	unsigned char keys[NUM_ROUNDS][3][16];
	a as[NUM_ROUNDS];
	View localViews[NUM_ROUNDS][3];
	unsigned char shares[NUM_ROUNDS][3][KEY_LEN];
	unsigned char *randomness[NUM_ROUNDS][3];
	char * proof;
	SHA256_CTX shactx;
	char  addrstr[200];
	unsigned long int addrstrlen;

	srand((unsigned) time(NULL));
	if(RAND_bytes(garbage, 4) != 1) {
		printf("RAND_bytes failed crypto, aborting");
		return NULL;
	}
	hex2bin(secret,strlen(secret),pubkey);
	
	if (debug)
		printf("secret is [%s]\n",secret);

	//Generating keys
	if(RAND_bytes((unsigned char *)keys, NUM_ROUNDS*3*16) != 1) {
		printf("RAND_bytes failed crypto, aborting");
		return NULL;
	}
	if(RAND_bytes((unsigned char *)rs, NUM_ROUNDS*3*4) != 1) {
		printf("RAND_bytes failed crypto, aborting");
		return NULL;
	}
	

	//Sharing secrets
	if(RAND_bytes((unsigned char *)shares, NUM_ROUNDS*3*KEY_LEN) != 1) {
		printf("RAND_bytes failed crypto, aborting");
		return NULL;
	}
	for(int k=0; k<NUM_ROUNDS; k++) {
		for (int j = 0; j < KEY_LEN ; j++) {
			shares[k][2][j] = pubkey[j] ^ shares[k][0][j] ^ shares[k][1][j];
		}

	}
	//Generating randomness
	for(int k=0; k<NUM_ROUNDS; k++) {
		for(int j = 0; j<3; j++) {
			randomness[k][j] = malloc(rSize*sizeof(unsigned char));
			getAllRandomness(keys[k][j], randomness[k][j]);
		}
	}

	uint8_t ripehash[20];
	for(int k=0; k<NUM_ROUNDS; k++) {
		as[k] = commit(KEY_LEN, shares[k], randomness[k], rs[k], localViews[k],ripehash);
		for(int j=0; j<3; j++) {
			free(randomness[k][j]);
		}
	}

	for(int k=0; k<NUM_ROUNDS; k++) {
		unsigned char hash1[RIPEMD160_DIGEST_LENGTH];
		H(keys[k][0], &localViews[k][0], rs[k][0], hash1);
		memcpy(as[k].h[0], &hash1, 20);
		H(keys[k][1], &localViews[k][1], rs[k][1], hash1);
		memcpy(as[k].h[1], &hash1, 20);
		H(keys[k][2], &localViews[k][2], rs[k][2], hash1);
		memcpy(as[k].h[2], hash1, 20);
	}

	//Generating E
	int es[NUM_ROUNDS];
	uint32_t finalHash[5];
	for (int j = 0; j < 5; j++) {
		finalHash[j] = as[0].yp[0][j]^as[0].yp[1][j]^as[0].yp[2][j];
	}
	H3(message, finalHash, as, NUM_ROUNDS, es);

	if (debug)
	{
		printf("message is [%s], length %ld e0 is %d\n",message,strlen(message),es[0]);
	}

	//Packing Z
	z* zs = malloc(sizeof(z)*NUM_ROUNDS);

	for(int i = 0; i<NUM_ROUNDS; i++) {
		prove(&zs[i],es[i],keys[i],rs[i], localViews[i]);
	}

	uint32_t combined[5];
	unsigned char shahash[32];
	/*
	output(localViews[0][0],(uint32_t*)ripehash[0]);	
	output(localViews[0][1],(uint32_t*)ripehash[1]);	
	output(localViews[0][2],(uint32_t*)ripehash[2]);	
	reconstruct(ripehash[0],ripehash[1],ripehash[2],combined);
	*/

	proof = malloc(P_SIZE);
	memset(proof,0,P_SIZE);
	bin2hex((unsigned char *)as,sizeof(a)*NUM_ROUNDS,proof);
	bin2hex((unsigned char *)zs,sizeof(z)*NUM_ROUNDS,proof+(sizeof(a)*NUM_ROUNDS*2));
	free(zs);

	addrbuf[0] = 0;
	hex2bin(params,2,&(addrbuf[0]));
	memcpy(&addrbuf[1],ripehash,20);
	/*
	for (int i=0;i<5;i++)
	{
		addrbuf[1+i*4] = combined[i]>>24;
		addrbuf[1+i*4+1] = combined[i]>>16;
		addrbuf[1+i*4+2] = combined[i]>>8;
		addrbuf[1+i*4+3] = combined[i]>>0;
	}
	*/
	sha256_init(&shactx);
	sha256_update(&shactx,addrbuf,21);
	sha256_final(&shactx,shahash);
	sha256_init(&shactx);
	sha256_update(&shactx,shahash,sizeof(shahash));
	sha256_final(&shactx,shahash);

	memcpy(&(addrbuf[21]),shahash,4);

	addrstrlen = 200;
	memset(addrstr,0,addrstrlen);
	if (!b58enc(addrstr, &addrstrlen, addrbuf, 25)) 
	{
		printf("b58enc error\n");
		return NULL;
	}

	if (debug)
		printf("address: %s\n",addrstr);
	return proof;

}


// verify - verify proof from public key
#ifdef WASM
EMSCRIPTEN_KEEPALIVE
#endif
char * verify_poc(char * message, char * proof, char * params)
{
	char * ret = malloc(1000);
	a as[NUM_ROUNDS];
	z* zs = malloc(sizeof(z)*NUM_ROUNDS);
	int es[NUM_ROUNDS];
	uint32_t y[5];
	int i;
	unsigned char addrbuf[100];
	char addrstr[200];
	unsigned long int addrstrlen;
	SHA256_CTX shactx;
	unsigned char shahash[SHA256_DIGEST_LENGTH];
	int passed = 1;
	FILE * f;
	char * fileproof = NULL;

	memset(as,0,sizeof(a)*NUM_ROUNDS);
	memset(zs,0,sizeof(z)*NUM_ROUNDS);
	if (debug)
	{
		printf("proof received [%s]\n",proof);
		printf("Length of proof received = %ld, expected %ld\n",strlen(proof),(sizeof(a)+sizeof(z))*NUM_ROUNDS*2);
	}
	if (strlen(proof)<((sizeof(a)+sizeof(z))*NUM_ROUNDS*2))
	{
		f = fopen(proof,"r");
		if (!f)
		{
			printf("unable to open proof file %s\n",proof);
			sprintf(ret,"unable to open proof file %s\n",proof);
			return ret;
		}
		fileproof = malloc((sizeof(a)+sizeof(z))*NUM_ROUNDS*2+1);
		memset(fileproof,0,((sizeof(a)+sizeof(z))*NUM_ROUNDS*2)+1);
		fread(fileproof,1,((sizeof(a)+sizeof(z))*NUM_ROUNDS*2),f);
		proof = fileproof;
		fclose(f);
	}
	if (debug)
	{
		printf("length of proof read [%ld]\n",strlen(proof));
//		printf("proof [%s]\n",proof);
	}
	hex2bin(proof,sizeof(a)*NUM_ROUNDS*2,(unsigned char *)as);
	hex2bin(&(proof[sizeof(a)*NUM_ROUNDS*2]),sizeof(z)*NUM_ROUNDS*2,(unsigned char *)zs);
	reconstruct(as[0].yp[0],as[0].yp[1],as[0].yp[2],y);
	if (fileproof)
		free(fileproof);
	if (debug)
	{
		printf("Proof for hash: ");
		for(int i=0;i<5;i++) {
			printf("%08X", y[i]);
		}
		printf("\n");
	}
	H3(message,y, as, NUM_ROUNDS, es);
	if (debug)
	{
		printf("message is [%s], length %ld e0 is %d\n",message,strlen(message),es[0]);
	}
	
	int verifyResult = 0;
        for(int i = 0; i<NUM_ROUNDS; i++) {
		verifyResult = mpc_verify(&(as[i]), es[i], &(zs[i]));
		if (verifyResult != 0) 
		{
			printf("Not Verified [%d] %d\n", verifyResult, i);
			passed = 0;
		}	
	}
	free(zs);
	if (!passed)
	{
		printf("verification failed\n");
		sprintf(ret,"verification failed!!!!!!!!!!!");
		return ret;
	}
	else
	{
		addrbuf[0] = 0;
		hex2bin(params,2,&(addrbuf[0]));

		for (int i=0;i<5;i++)
		{
			addrbuf[1+i*4] = y[i]>>24;
			addrbuf[1+i*4+1] = y[i]>>16;
			addrbuf[1+i*4+2] = y[i]>>8;
			addrbuf[1+i*4+3] = y[i]>>0;
		}

		sha256_init(&shactx);
		sha256_update(&shactx,addrbuf,21);
		sha256_final(&shactx,shahash);
		sha256_init(&shactx);
		sha256_update(&shactx,shahash,sizeof(shahash));
		sha256_final(&shactx,shahash);

		memcpy(&(addrbuf[21]),shahash,4);

		addrstrlen = sizeof(addrstr);
		memset(addrstr,0,sizeof(addrstr));
		if (!b58enc(addrstr, &addrstrlen, addrbuf, 25)) 
		{
			printf("b58enc error\n");
			free(ret);
			return NULL;
		}
		else
		{
			sprintf(ret,"message [%s] for address [%s] verified ok",message,addrstr);
			return ret;
		}
	}
}

#ifdef WASM
EMSCRIPTEN_KEEPALIVE
#endif
void clearbuf(char * ret)
{
	if (ret)
		free(ret);
}

#ifndef WASM
int main(int argc, char * argv[])
{
	char * rc;

	if (argc != 5)
	{
		printf("Usage: %s <func: 1=generate,2=verify> <message> <key/proof> <params>\n",argv[0]);
		return -1;
	}	       
	if (argv[1][0] == '1')
	{
		rc = generate_poc(argv[2],argv[3],argv[4]);
		printf("%s",rc);
	}
	else if (argv[1][0] == '2')
	{
		rc = verify_poc(argv[2],argv[3],argv[4]);
		printf("%s",rc);
	}
	else
	{
		printf("Usage: %s <func: 1=generate,2=verify> <message> <key/proof> <params>\n",argv[0]);
		return -1;
	}	       
	if (rc)
	{
		clearbuf(rc);
		return 0;
	}
	return -1;

}
#endif
