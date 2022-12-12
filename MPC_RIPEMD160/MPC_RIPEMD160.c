/*
 * Author: Tan Teik Guan
 * Description : ZKBoo for RIPEMD160 
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
 Name        : MPC_SHA256.c
 Author      : Sobuno
 Version     : 0.1
 Description : MPC SHA256 for one block only
 ============================================================================
 */


#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "sharedripe.h"
#include "omp.h"



int totalRandom = 0;
int totalSha = 0;
int totalSS = 0;
int totalHash = 0;
int NUM_ROUNDS = 32;


int debug = 0;

uint32_t rand32() {
	uint32_t x;
	x = rand() & 0xff;
	x |= (rand() & 0xff) << 8;
	x |= (rand() & 0xff) << 16;
	x |= (rand() & 0xff) << 24;

	return x;
}

uint64_t rand64() {
	uint64_t x;
	x = (uint64_t) rand32();
	x |= (uint64_t)(rand() & 0xff) << 32;
	x |= (uint64_t)(rand() & 0xff) << 40;
	x |= (uint64_t)(rand() & 0xff) << 48;
	x |= (uint64_t)(rand() & 0xff) << 56;

	return x;
}

void printbits(uint32_t n) {
	if (n) {
		printbits(n >> 1);
		printf("%d", n & 1);
	}

}



void mpc_XOR(uint32_t x[3], uint32_t y[3], uint32_t z[3]) {
	z[0] = x[0] ^ y[0];
	z[1] = x[1] ^ y[1];
	z[2] = x[2] ^ y[2];
}

void mpc_AND(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
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

void mpc_NEGATE(uint32_t x[3], uint32_t z[3]) {
	z[0] = ~x[0];
	z[1] = ~x[1];
	z[2] = ~x[2];
}



void mpc_OR(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char * randomness[3], int * randCount, View views[3], int* countY) {
	uint32_t t0[3] = { 0 };
	uint32_t t1[3] = { 0 };
	uint32_t t2[3] = { 0 };

	mpc_NEGATE(x,t0);
	mpc_NEGATE(y,t1);
	mpc_AND(t0,t1,t2,randomness,randCount,views,countY);
	mpc_NEGATE(t2,z);

}

void mpc_ADD(uint32_t x[3], uint32_t y[3], uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
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


void mpc_ADDK(uint32_t x[3], uint32_t y, uint32_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
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

void mpc_RIGHTSHIFT(uint32_t x[3], int i, uint32_t z[3]) {
	z[0] = x[0] >> i;
	z[1] = x[1] >> i;
	z[2] = x[2] >> i;
}


void mpc_LEFTROTATE(uint32_t x[], int i, uint32_t z[]) {
	z[0] = LEFTROTATE(x[0], i);
	z[1] = LEFTROTATE(x[1], i);
	z[2] = LEFTROTATE(x[2], i);
}

void mpc_F(uint32_t x1[3], uint32_t x2[3], uint32_t x3[3], uint32_t z[3]) 
{
	uint32_t t0[3] = { 0 };

	mpc_XOR(x1,x2,t0);
	mpc_XOR(t0,x3,z);
}

void mpc_G(uint32_t x1[3], uint32_t x2[3], uint32_t x3[3], uint32_t z[3], unsigned char * randomness[3], int * randCount, View views[3], int* countY) {
	uint32_t t0[3] = { 0 };
	uint32_t t1[3] = { 0 };
	uint32_t t2[3] = { 0 };

	mpc_AND(x1,x2,t0,randomness,randCount,views,countY);
	mpc_NEGATE(x1,t1);
	mpc_AND(t1,x3,t2,randomness,randCount,views,countY);
	mpc_OR(t0,t2,z,randomness,randCount,views,countY);
}

void mpc_H(uint32_t x1[3], uint32_t x2[3], uint32_t x3[3], uint32_t z[3], unsigned char * randomness[3], int * randCount, View views[3], int* countY) {
	uint32_t t0[3] = { 0 };
	uint32_t t1[3] = { 0 };

	mpc_NEGATE(x2,t0);
	mpc_OR(x1,t0,t1,randomness,randCount,views,countY);
	mpc_XOR(t1,x3,z);

}


void mpc_IQ(uint32_t x1[3], uint32_t x2[3], uint32_t x3[3], uint32_t z[3], unsigned char * randomness[3], int * randCount, View views[3], int* countY) {
	uint32_t t0[3] = { 0 };
	uint32_t t1[3] = { 0 };
	uint32_t t2[3] = { 0 };

	mpc_AND(x1,x3,t0,randomness,randCount,views,countY);
	mpc_NEGATE(x3,t1);
	mpc_AND(x2,t1,t2,randomness,randCount,views,countY);
	mpc_OR(t0,t2,z,randomness,randCount,views,countY);
	
}


void mpc_J(uint32_t x1[3], uint32_t x2[3], uint32_t x3[3], uint32_t z[3], unsigned char * randomness[3], int * randCount, View views[3], int* countY) {
	uint32_t t0[3] = { 0 };
	uint32_t t1[3] = { 0 };

	mpc_NEGATE(x3,t0);
	mpc_OR(x2,t0,t1,randomness,randCount,views,countY);
	mpc_XOR(t1,x1,z);
}

void mpc_FF(uint32_t a[3], uint32_t b[3], uint32_t c[3], uint32_t d[3], uint32_t e[3], uint32_t x[3], uint32_t s, unsigned char * randomness[3], int * randCount, View views[3], int* countY) 
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

void mpc_GG(uint32_t a[3], uint32_t b[3], uint32_t c[3], uint32_t d[3], uint32_t e[3], uint32_t x[3], uint32_t s, uint32_t C, unsigned char * randomness[3], int * randCount, View views[3], int* countY) 
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

void mpc_HH(uint32_t a[3], uint32_t b[3], uint32_t c[3], uint32_t d[3], uint32_t e[3], uint32_t x[3], uint32_t s, uint32_t C, unsigned char * randomness[3], int * randCount, View views[3], int* countY) 
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

void mpc_II(uint32_t a[3], uint32_t b[3], uint32_t c[3], uint32_t d[3], uint32_t e[3], uint32_t x[3], uint32_t s, uint32_t C, unsigned char * randomness[3], int * randCount, View views[3], int* countY) 
{
	uint32_t t0[3] = { 0 };
	uint32_t t1[3] = { 0 };
	uint32_t t2[3] = { 0 };
	uint32_t t3[3] = { 0 };
	uint32_t t4[3] = { 0 };

	mpc_IQ(b,c,d,t0,randomness,randCount,views,countY);
	mpc_ADD(t0,x,t1,randomness,randCount,views,countY);
	mpc_ADDK(t1,C,t2,randomness,randCount,views,countY);
	mpc_ADD(t2,a,t3,randomness,randCount,views,countY);
	mpc_LEFTROTATE(t3,s,t4);
	mpc_ADD(t4,e,a,randomness,randCount,views,countY);
	mpc_LEFTROTATE(c,10,c);
}

void mpc_JJ(uint32_t a[3], uint32_t b[3], uint32_t c[3], uint32_t d[3], uint32_t e[3], uint32_t x[3], uint32_t s, uint32_t C, unsigned char * randomness[3], int * randCount, View views[3], int* countY) 
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


int mpc_ripemd160(unsigned char* results[3], unsigned char* inputs[3], int numBits, unsigned char *randomness[3], View views[3], int* countY) {

	if (numBits > 448) {
		printf("Input too long, aborting!");
		return -1;
	}

	int* randCount = calloc(1, sizeof(int));
	*randCount = 0;

	int chars = numBits >> 3;
	unsigned char* chunks[3];
	uint32_t X[16][3];
	uint32_t buf[5][3] = {{ hA[0],hA[0],hA[0] },
				{hA[1],hA[1],hA[1]},
				{hA[2],hA[2],hA[2]},
				{hA[3],hA[3],hA[3]},
				{hA[4],hA[4],hA[4]}};

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

		memcpy(views[i].x,chunks[i], 32);

		for (int j = 0; j < 16; j++) {
			X[j][i] = ((uint32_t)chunks[i][j * 4 + 0] << 0) | ((uint32_t)chunks[i][j * 4 + 1] << 8)
				| ((uint32_t)chunks[i][j * 4 + 2] << 16) | ((uint32_t)chunks[i][j * 4 + 3] << 24);
			
		}
		

		free(chunks[i]);

	}

	if (debug)
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

	if (debug)
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
	if (debug)
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
//printf("randCount %d\n",*randCount);
	free(randCount);

	return 0;
}


int writeToFile(char filename[], void* data, int size, int numItems) {
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




int secretShare(unsigned char* input, int numBytes, unsigned char output[3][numBytes]) {
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



a commit(int numBytes,unsigned char shares[3][numBytes], unsigned char *randomness[3], unsigned char rs[3][4], View views[3]) {
static int printonce=0;

	unsigned char* inputs[3];
	inputs[0] = shares[0];
	inputs[1] = shares[1];
	inputs[2] = shares[2];
	unsigned char* hashes[3];
	hashes[0] = malloc(20);
	hashes[1] = malloc(20);
	hashes[2] = malloc(20);

	int* countY = calloc(1, sizeof(int));
	mpc_ripemd160(hashes, inputs, numBytes * 8, randomness, views, countY);

	if (!printonce) // just for debug
	{
		printonce=1;
		printf("hash obtained is: ");
		for (int i = 0; i < 20; i++)
		{
			printf("%02X",hashes[0][i]^hashes[1][i]^hashes[2][i]);
		}
		printf("\n");
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
//printf("countY %d\n",*countY);
	free(countY);
	free(hashes[0]);
	free(hashes[1]);
	free(hashes[2]);

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

z prove(int e, unsigned char keys[3][16], unsigned char rs[3][4], View views[3]) {
	z z;
	memcpy(z.ke, keys[e], 16);
	memcpy(z.ke1, keys[(e + 1) % 3], 16);
	z.ve = views[e];
	z.ve1 = views[(e + 1) % 3];
	memcpy(z.re, rs[e],4);
	memcpy(z.re1, rs[(e + 1) % 3],4);

	return z;
}



int main(void) {
	setbuf(stdout, NULL);
	srand((unsigned) time(NULL));
	init_EVP();
	openmp_thread_setup();
	struct timeval begin, delta;
	//
	unsigned char garbage[4];
	if(RAND_bytes(garbage, 4) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	
	printf("Enter the string to be hashed (Max 55 characters): ");
	char userInput[56]; //56 is max length as we only support 448 bits 
	userInput[55] = 0x0;
	fgets(userInput, sizeof(userInput)-1, stdin);
	
	int i = strlen(userInput)-1; 
	printf("String length: %d\n", i);
	
	printf("Iterations of RIPEMD160: %d\n", NUM_ROUNDS);


	unsigned char input[i];
	for(int j = 0; j<i; j++) {
		input[j] = userInput[j];
	}

	gettimeofday(&begin,NULL);
	unsigned char rs[NUM_ROUNDS][3][4];
	unsigned char keys[NUM_ROUNDS][3][16];
	a as[NUM_ROUNDS];
	View localViews[NUM_ROUNDS][3];
	int totalCrypto = 0;
	
	//Generating keys
	clock_t beginCrypto = clock(), deltaCrypto;
	if(RAND_bytes((unsigned char *)keys, NUM_ROUNDS*3*16) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	if(RAND_bytes((unsigned char *)rs, NUM_ROUNDS*3*4) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	

	//Sharing secrets
	unsigned char shares[NUM_ROUNDS][3][i];
	if(RAND_bytes((unsigned char *)shares, NUM_ROUNDS*3*i) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {

		for (int j = 0; j < i; j++) {
			shares[k][2][j] = input[j] ^ shares[k][0][j] ^ shares[k][1][j];
		}

	}

	//Generating randomness
	unsigned char *randomness[NUM_ROUNDS][3];
	//#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		for(int j = 0; j<3; j++) {
			randomness[k][j] = malloc(rSize*sizeof(unsigned char));
			getAllRandomness(keys[k][j], randomness[k][j]);
		}
	}

	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		as[k] = commit(i, shares[k], randomness[k], rs[k], localViews[k]);
		for(int j=0; j<3; j++) {
			free(randomness[k][j]);
		}
	}
	
	//Committing
	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		unsigned char hash1[RIPEMD160_DIGEST_LENGTH];
		H(keys[k][0], localViews[k][0], rs[k][0], hash1);
		memcpy(as[k].h[0], &hash1, 20);
		H(keys[k][1], localViews[k][1], rs[k][1], hash1);
		memcpy(as[k].h[1], &hash1, 20);
		H(keys[k][2], localViews[k][2], rs[k][2], hash1);
		memcpy(as[k].h[2], hash1, 20);
	}

	//Generating E
	int es[NUM_ROUNDS];
	uint32_t finalHash[5];
	for (int j = 0; j < 5; j++) {
		finalHash[j] = as[0].yp[0][j]^as[0].yp[1][j]^as[0].yp[2][j];
	}
	H3(finalHash, as, NUM_ROUNDS, es);


	//Packing Z
	z* zs = malloc(sizeof(z)*NUM_ROUNDS);

	//#pragma omp parallel for
	for(int i = 0; i<NUM_ROUNDS; i++) {
		zs[i] = prove(es[i],keys[i],rs[i], localViews[i]);
	}
	
	gettimeofday(&delta,NULL);
	unsigned long inMilli = (delta.tv_sec - begin.tv_sec)*1000000 + (delta.tv_usec - begin.tv_usec);
	inMilli /= 1000;

	
	//Writing to file
	FILE *file;

	char outputFile[3*sizeof(int) + 8];
	sprintf(outputFile, "out%i.bin", NUM_ROUNDS);
	file = fopen(outputFile, "wb");
	if (!file) {
		printf("Unable to open file!");
		return 1;
	}
	fwrite(as, sizeof(a), NUM_ROUNDS, file);
	fwrite(zs, sizeof(z), NUM_ROUNDS, file);

	fclose(file);

	free(zs);



	printf("\n");
	printf("Proof output to file %s\n", outputFile);
	printf("time taken: %ld miliseconds\n",inMilli);

	openmp_thread_cleanup();
	cleanup_EVP();
	return EXIT_SUCCESS;
}
