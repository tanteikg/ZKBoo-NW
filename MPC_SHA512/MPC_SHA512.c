/*
 * Author: Tan Teik Guan
 * Description : ZKBoo for SHA512
 *
 * Copyright 2022 pQCee
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
#include <time.h>
#include "shared512.h"
#include "omp.h"


#define CH(e,f,g) ((e & f) | ((~e) & g))
#define W(t) w[(t) & 0x0F]


int totalRandom = 0;
int totalSha = 0;
int totalSS = 0;
int totalHash = 0;
int NUM_ROUNDS = 1;




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

void printbits(uint64_t n) {
	if (n) {
		printbits(n >> 1);
		printf("%ld", n & 1);
	}

}



void mpc_XOR(uint64_t x[3], uint64_t y[3], uint64_t z[3]) {
	z[0] = x[0] ^ y[0];
	z[1] = x[1] ^ y[1];
	z[2] = x[2] ^ y[2];
}

void mpc_AND(uint64_t x[3], uint64_t y[3], uint64_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint64_t r[3] = { getRandom64(randomness[0], *randCount), getRandom64(randomness[1], *randCount), getRandom64(randomness[2], *randCount)};
	*randCount += 8;
	uint64_t t[3] = { 0 };

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

void mpc_NEGATE(uint64_t x[3], uint64_t z[3]) {
	z[0] = ~x[0];
	z[1] = ~x[1];
	z[2] = ~x[2];
}



void mpc_OR(uint64_t x[3], uint64_t y[3], uint64_t z[3], unsigned char * randomness[3], int * randCount, View views[3], int* countY) {
	uint64_t t0[3] = { 0 };
	uint64_t t1[3] = { 0 };
	uint64_t t2[3] = { 0 };

	mpc_NEGATE(x,t0);
	mpc_NEGATE(y,t1);
	mpc_AND(t0,t1,t2,randomness,randCount,views,countY);
	mpc_NEGATE(t2,z);

}

void mpc_ADD(uint64_t x[3], uint64_t y[3], uint64_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint64_t c[3] = { 0 };
	uint64_t r[3] = { getRandom64(randomness[0], *randCount), getRandom64(randomness[1], *randCount), getRandom64(randomness[2], *randCount)};
	*randCount += 8;

	uint8_t a[3], b[3];

	uint8_t t;

	for(int i=0;i<63;i++)
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


void mpc_ADDK(uint64_t x[3], uint64_t y, uint64_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint64_t c[3] = { 0 };
	uint64_t r[3] = { getRandom64(randomness[0], *randCount), getRandom64(randomness[1], *randCount), getRandom64(randomness[2], *randCount)};
	*randCount += 8;

	uint8_t a[3], b[3];

	uint8_t t;

	for(int i=0;i<63;i++)
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

/*
int sha512(unsigned char* result, unsigned char* input, int numBits) {
	uint64_t hA[8] = { 0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
			0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179};


	if (numBits > 1000) {
		printf("Input too long, aborting!");
		return -1;
	}
	int chars = numBits >> 3;
	unsigned char* chunk = calloc(128, 1); //1024 bits
	memcpy(chunk, input, chars);
	chunk[chars] = 0x80;
	//Last 8 chars used for storing length of input without padding, in big-endian.
	//Since we only care for one block, we are safe with just using last 9 bits and 0'ing the rest

	chunk[124] = numBits >> 24;
	chunk[125] = numBits >> 16;
	chunk[126] = numBits >> 8;
	chunk[127] = numBits;

	uint64_t w[16];
	int i, t;
	for (i = 0; i < 16; i++) {
		w[i] = ((uint64_t)chunk[i * 8] << 56) | ((uint64_t)chunk[i * 8 + 1] << 48)
			| ((uint64_t)chunk[i * 8 + 2] << 40) | ((uint64_t)chunk[i * 8 + 3] << 32)
			| ((uint64_t)chunk[i * 8 + 4] << 24) | ((uint64_t)chunk[i * 8 + 5] << 16)
			| ((uint64_t)chunk[i * 8 + 6] << 8) | (uint64_t)chunk[i * 8 + 7];
	}

	uint64_t s0, s1;

	for (i = 16; i < 80; i++) {
		s0 = RIGHTROTATE(W(i + 14), 19) ^ RIGHTROTATE(W(i + 14), 61)
						^ (W(i + 14) >> 6);
		s1 = RIGHTROTATE(W(i + 1), 1) ^ RIGHTROTATE(W(i + 1), 8)
						^ (W(i + 1) >> 7);
		W(i) += W(i + 9) + s0 + s1;
	}

	uint64_t a, b, c, d, e, f, g, h, temp1, temp2, maj;
	a = hA[0];
	b = hA[1];
	c = hA[2];
	d = hA[3];
	e = hA[4];
	f = hA[5];
	g = hA[6];
	h = hA[7];

	for (i = 0; i < 80; i++) {
		s1 = RIGHTROTATE(e,14) ^ RIGHTROTATE(e, 18) ^ RIGHTROTATE(e, 41);

		temp1 = h + s1 + CH(e, f, g) + k[i] + W(i);
		s0 = RIGHTROTATE(a,28) ^ RIGHTROTATE(a, 34) ^ RIGHTROTATE(a, 39);


		maj = ((a & b) | (b & c)) | (a & c);
		temp2 = s0 + maj;


		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;

	}

	hA[0] += a;
	hA[1] += b;
	hA[2] += c;
	hA[3] += d;
	hA[4] += e;
	hA[5] += f;
	hA[6] += g;
	hA[7] += h;

	for (i = 0; i < 8; i++) {
		result[i * 8] = (hA[i] >> 56);
		result[i * 8 + 1] = (hA[i] >> 48);
		result[i * 8 + 2] = (hA[i] >> 40);
		result[i * 8 + 3] = (hA[i] >> 32);
		result[i * 8 + 4] = (hA[i] >> 24);
		result[i * 8 + 5] = (hA[i] >> 16);
		result[i * 8 + 6] = (hA[i] >> 8);
		result[i * 8 + 7] = hA[i];
	}
	return 0;
}
*/
void mpc_RIGHTROTATE(uint64_t x[], int i, uint64_t z[]) {
	z[0] = RIGHTROTATE(x[0], i);
	z[1] = RIGHTROTATE(x[1], i);
	z[2] = RIGHTROTATE(x[2], i);
}




void mpc_RIGHTSHIFT(uint64_t x[3], int i, uint64_t z[3]) {
	z[0] = x[0] >> i;
	z[1] = x[1] >> i;
	z[2] = x[2] >> i;
}





void mpc_MAJ(uint64_t a[], uint64_t b[3], uint64_t c[3], uint64_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint64_t t0[3];
	uint64_t t1[3];
	uint64_t t2[3];

	mpc_AND(a, b, t0, randomness, randCount, views, countY);
	mpc_AND(b, c, t1, randomness, randCount, views, countY);
	mpc_AND(c, a, t2, randomness, randCount, views, countY);
	mpc_OR(t0, t1, z, randomness, randCount, views, countY);
	mpc_OR(t2, z, z, randomness, randCount, views, countY);
}


void mpc_CH(uint64_t e[], uint64_t f[3], uint64_t g[3], uint64_t z[3], unsigned char *randomness[3], int* randCount, View views[3], int* countY) {
	uint64_t t0[3];
	uint64_t t1[3];
	uint64_t t2[3];

	mpc_AND(e,f,t0, randomness, randCount, views, countY);
	mpc_NEGATE(e,t1);
	mpc_AND(t1,g,t2, randomness, randCount, views, countY);
	mpc_OR(t0,t2,z, randomness, randCount, views, countY);

}



int mpc_sha512(unsigned char* results[3], unsigned char* inputs[3], int numBits, unsigned char *randomness[3], View views[3], int* countY) {



	if (numBits > 1000) {
		printf("Input too long, aborting!");
		return -1;
	}

	int* randCount = calloc(1, sizeof(int));
	*randCount = 0;

	int chars = numBits >> 3;
	unsigned char* chunks[3];
	uint64_t w[16][3];

	for (int i = 0; i < 3; i++) {
		chunks[i] = calloc(128, 1); //1024 bits
		memset(chunks[i],0,128);
		memcpy(chunks[i], inputs[i], chars);
		chunks[i][chars] = 0x80;
		//Last 8 chars used for storing length of input without padding, in big-endian.
		//Since we only care for one block, we are safe with just using last 9 bits and 0'ing the rest

		chunks[i][124] = numBits >> 24;
		chunks[i][125] = numBits >> 16;
		chunks[i][126] = numBits >> 8;
		chunks[i][127] = numBits;
		memcpy(views[i].x, chunks[i], 128);

		for (int j = 0; j < 16; j++) {
			w[j][i] = ((uint64_t)chunks[i][j * 8] << 56) | ((uint64_t)chunks[i][j * 8 + 1] << 48)
				| ((uint64_t)chunks[i][j * 8 + 2] << 40) | ((uint64_t)chunks[i][j * 8 + 3] << 32)
				| ((uint64_t)chunks[i][j * 8 + 4] << 24) | ((uint64_t)chunks[i][j * 8 + 5] << 16)
				| ((uint64_t)chunks[i][j * 8 + 6] << 8) | (uint64_t)chunks[i][j * 8 + 7];
		}
		free(chunks[i]);
	}

	uint64_t s0[3], s1[3];
	uint64_t t0[3], t1[3];
	uint64_t a[3] = { hA[0],hA[0],hA[0] };
	uint64_t b[3] = { hA[1],hA[1],hA[1] };
	uint64_t c[3] = { hA[2],hA[2],hA[2] };
	uint64_t d[3] = { hA[3],hA[3],hA[3] };
	uint64_t e[3] = { hA[4],hA[4],hA[4] };
	uint64_t f[3] = { hA[5],hA[5],hA[5] };
	uint64_t g[3] = { hA[6],hA[6],hA[6] };
	uint64_t h[3] = { hA[7],hA[7],hA[7] };
	uint64_t temp1[3], temp2[3], maj[3];
	for (int i = 0; i < 80; i++) {
		if (i >= 16)
		{
			mpc_RIGHTROTATE(W(i+14), 19, t0);
			mpc_RIGHTROTATE(W(i+14), 61, t1);
			mpc_XOR(t0, t1, t0);
			mpc_RIGHTSHIFT(W(i+14), 6, t1);
			mpc_XOR(t0, t1, s0);

			mpc_RIGHTROTATE(W(i+1), 1, t0);
			mpc_RIGHTROTATE(W(i+1), 8, t1);
			mpc_XOR(t0, t1, t0);
			mpc_RIGHTSHIFT(W(i+1), 7, t1);
			mpc_XOR(t0, t1, s1);

		//w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];

			mpc_ADD(W(i+9), s0, t1, randomness, randCount, views, countY);
			mpc_ADD(s1, t1, t1, randomness, randCount, views, countY);
			mpc_ADD(W(i), t1, W(i), randomness, randCount, views, countY);

		}

		//s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
		mpc_RIGHTROTATE(e, 14, t0);
		mpc_RIGHTROTATE(e, 18, t1);
		mpc_XOR(t0, t1, t0);

		mpc_RIGHTROTATE(e, 41, t1);
		mpc_XOR(t0, t1, s1);


		//ch = (e & f) ^ ((~e) & g);
		//temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

		//t0 = h + s1

		mpc_ADD(h, s1, t0, randomness, randCount, views, countY);


		mpc_CH(e, f, g, t1, randomness, randCount, views, countY);

		//t1 = t0 + t1 (h+s1+ch)
		mpc_ADD(t0, t1, t1, randomness, randCount, views, countY);

		mpc_ADDK(t1, k[i], t1, randomness, randCount, views, countY);

		mpc_ADD(t1, W(i), temp1, randomness, randCount, views, countY);

		//s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
		mpc_RIGHTROTATE(a, 28, t0);
		mpc_RIGHTROTATE(a, 34, t1);
		mpc_XOR(t0, t1, t0);
		mpc_RIGHTROTATE(a, 39, t1);
		mpc_XOR(t0, t1, s0);


		mpc_MAJ(a, b, c, maj, randomness, randCount, views, countY);

		//temp2 = s0+maj;
		mpc_ADD(s0, maj, temp2, randomness, randCount, views, countY);

		memcpy(h, g, sizeof(uint64_t) * 3);
		memcpy(g, f, sizeof(uint64_t) * 3);
		memcpy(f, e, sizeof(uint64_t) * 3);
		//e = d+temp1;
		mpc_ADD(d, temp1, e, randomness, randCount, views, countY);
		memcpy(d, c, sizeof(uint64_t) * 3);
		memcpy(c, b, sizeof(uint64_t) * 3);
		memcpy(b, a, sizeof(uint64_t) * 3);
		//a = temp1+temp2;

		mpc_ADD(temp1, temp2, a, randomness, randCount, views, countY);
	}

	uint64_t hHa[8][3] = { { hA[0],hA[0],hA[0]  }, { hA[1],hA[1],hA[1] }, { hA[2],hA[2],hA[2] }, { hA[3],hA[3],hA[3] },
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
		mpc_RIGHTSHIFT(hHa[i], 56, t0);
		results[0][i * 8] = t0[0];
		results[1][i * 8] = t0[1];
		results[2][i * 8] = t0[2];
		mpc_RIGHTSHIFT(hHa[i], 48, t0);
		results[0][i * 8 + 1] = t0[0];
		results[1][i * 8 + 1] = t0[1];
		results[2][i * 8 + 1] = t0[2];
		mpc_RIGHTSHIFT(hHa[i], 40, t0);
		results[0][i * 8 + 2] = t0[0];
		results[1][i * 8 + 2] = t0[1];
		results[2][i * 8 + 2] = t0[2];
		mpc_RIGHTSHIFT(hHa[i], 32, t0);
		results[0][i * 8 + 3] = t0[0];
		results[1][i * 8 + 3] = t0[1];
		results[2][i * 8 + 3] = t0[2];
		mpc_RIGHTSHIFT(hHa[i], 24, t0);
		results[0][i * 8 + 4] = t0[0];
		results[1][i * 8 + 4] = t0[1];
		results[2][i * 8 + 4] = t0[2];
		mpc_RIGHTSHIFT(hHa[i], 16, t0);
		results[0][i * 8 + 5] = t0[0];
		results[1][i * 8 + 5] = t0[1];
		results[2][i * 8 + 5] = t0[2];
		mpc_RIGHTSHIFT(hHa[i], 8, t0);
		results[0][i * 8 + 6] = t0[0];
		results[1][i * 8 + 6] = t0[1];
		results[2][i * 8 + 6] = t0[2];

		results[0][i * 8 + 7] = hHa[i][0];
		results[1][i * 8 + 7] = hHa[i][1];
		results[2][i * 8 + 7] = hHa[i][2];
	}
printf("randCount %d\n",*randCount);
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


	unsigned char* inputs[3];
	inputs[0] = shares[0];
	inputs[1] = shares[1];
	inputs[2] = shares[2];
	unsigned char* hashes[3];
	hashes[0] = malloc(64);
	hashes[1] = malloc(64);
	hashes[2] = malloc(64);

	int* countY = calloc(1, sizeof(int));
	mpc_sha512(hashes, inputs, numBytes * 8, randomness, views, countY);

	{
		printf("hash obtained is: ");
		for (int i = 0; i < 64; i++)
		{
			printf("%02X",hashes[0][i]^hashes[1][i]^hashes[2][i]);
		}
		printf("\n");
	}

	//Explicitly add y to view
	for(int i = 0; i<8; i++) {
		views[0].y[*countY] = 	((uint64_t)hashes[0][i * 8] << 56) | ((uint64_t)hashes[0][i * 8 + 1] << 48)
					| ((uint64_t)hashes[0][i * 8 + 2] << 40) | ((uint64_t)hashes[0][i * 8 + 3] << 32)
					| ((uint64_t)hashes[0][i * 8 + 4] << 24) | ((uint64_t)hashes[0][i * 8 + 5] << 16)
					| ((uint64_t)hashes[0][i * 8 + 6] << 8) | (uint64_t)hashes[0][i * 8 + 7];
		views[1].y[*countY] = 	((uint64_t)hashes[1][i * 8] << 56) | ((uint64_t)hashes[1][i * 8 + 1] << 48)
					| ((uint64_t)hashes[1][i * 8 + 2] << 40) | ((uint64_t)hashes[1][i * 8 + 3] << 32)
					| ((uint64_t)hashes[1][i * 8 + 4] << 24) | ((uint64_t)hashes[1][i * 8 + 5] << 16)
					| ((uint64_t)hashes[1][i * 8 + 6] << 8) | (uint64_t)hashes[1][i * 8 + 7];
		views[2].y[*countY] = 	((uint64_t)hashes[2][i * 8] << 56) | ((uint64_t)hashes[2][i * 8 + 1] << 48)
					| ((uint64_t)hashes[2][i * 8 + 2] << 40) | ((uint64_t)hashes[2][i * 8 + 3] << 32)
					| ((uint64_t)hashes[2][i * 8 + 4] << 24) | ((uint64_t)hashes[2][i * 8 + 5] << 16)
					| ((uint64_t)hashes[2][i * 8 + 6] << 8) | (uint64_t)hashes[2][i * 8 + 7];

		*countY += 1;
	}
printf("countY %d\n",*countY);
	free(countY);
	free(hashes[0]);
	free(hashes[1]);
	free(hashes[2]);

	uint64_t* result1 = malloc(64);
	output(views[0], result1);
	uint64_t* result2 = malloc(64);
	output(views[1], result2);
	uint64_t* result3 = malloc(64);
	output(views[2], result3);

	a a;
	memcpy(a.yp[0], result1, 64);
	memcpy(a.yp[1], result2, 64);
	memcpy(a.yp[2], result3, 64);

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

	//
	unsigned char garbage[4];
	if(RAND_bytes(garbage, 4) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	
	printf("Enter the string to be hashed (Max 124 characters): ");
	char userInput[125]; //125 is max length as we only support 1000 bits = 125 bytes
	userInput[124] = 0x0;
	fgets(userInput, sizeof(userInput)-1, stdin);
	
	int i = strlen(userInput)-1; 
	printf("String length: %d\n", i);
	
	printf("Iterations of SHA: %d\n", NUM_ROUNDS);


	unsigned char input[i];
	for(int j = 0; j<i; j++) {
		input[j] = userInput[j];
	}

	clock_t begin = clock(), delta, deltaA;
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
	deltaCrypto = clock() - beginCrypto;
	int inMilliCrypto = deltaCrypto * 1000 / CLOCKS_PER_SEC;
	totalCrypto = inMilliCrypto;
	

	//Sharing secrets
	clock_t beginSS = clock(), deltaSS;
	unsigned char shares[NUM_ROUNDS][3][i];
	if(RAND_bytes((unsigned char *)shares, NUM_ROUNDS*3*i) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
		return 0;
	}
	//#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {

		for (int j = 0; j < i; j++) {
			shares[k][2][j] = input[j] ^ shares[k][0][j] ^ shares[k][1][j];
		}

	}
	deltaSS = clock() - beginSS;
	int inMilli = deltaSS * 1000 / CLOCKS_PER_SEC;
	totalSS = inMilli;

	//Generating randomness
	clock_t beginRandom = clock(), deltaRandom;
	unsigned char *randomness[NUM_ROUNDS][3];
	//#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		for(int j = 0; j<3; j++) {
			randomness[k][j] = malloc(rSize*sizeof(unsigned char));
			getAllRandomness(keys[k][j], randomness[k][j]);
		}
	}

	deltaRandom = clock() - beginRandom;
	inMilli = deltaRandom * 1000 / CLOCKS_PER_SEC;
	totalRandom = inMilli;

	//Running MPC-SHA2
	clock_t beginSha = clock(), deltaSha;
	//#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		as[k] = commit(i, shares[k], randomness[k], rs[k], localViews[k]);
		for(int j=0; j<3; j++) {
			free(randomness[k][j]);
		}
	}
	deltaSha = clock() - beginSha;
	inMilli = deltaSha * 1000 / CLOCKS_PER_SEC;
	totalSha = inMilli;
	
	//Committing
	clock_t beginHash = clock(), deltaHash;
	//#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		unsigned char hash1[SHA512_DIGEST_LENGTH];
		H(keys[k][0], localViews[k][0], rs[k][0], hash1);
		memcpy(as[k].h[0], &hash1, 64);
		H(keys[k][1], localViews[k][1], rs[k][1], hash1);
		memcpy(as[k].h[1], &hash1, 64);
		H(keys[k][2], localViews[k][2], rs[k][2], hash1);
		memcpy(as[k].h[2], hash1, 64);
	}
	deltaHash = clock() - beginHash;
				inMilli = deltaHash * 1000 / CLOCKS_PER_SEC;
				totalHash += inMilli;
				
	deltaA = clock() - begin;
	int inMilliA = deltaA * 1000 / CLOCKS_PER_SEC;

	//Generating E
	clock_t beginE = clock(), deltaE;
	int es[NUM_ROUNDS];
	uint64_t finalHash[8];
	for (int j = 0; j < 8; j++) {
		finalHash[j] = as[0].yp[0][j]^as[0].yp[1][j]^as[0].yp[2][j];
	}
	H3(finalHash, as, NUM_ROUNDS, es);
	deltaE = clock() - beginE;
	int inMilliE = deltaE * 1000 / CLOCKS_PER_SEC;


	//Packing Z
	clock_t beginZ = clock(), deltaZ;
	z* zs = malloc(sizeof(z)*NUM_ROUNDS);

	//#pragma omp parallel for
	for(int i = 0; i<NUM_ROUNDS; i++) {
		zs[i] = prove(es[i],keys[i],rs[i], localViews[i]);
	}
	deltaZ = clock() - beginZ;
	int inMilliZ = deltaZ * 1000 / CLOCKS_PER_SEC;
	
	
	//Writing to file
	clock_t beginWrite = clock();
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

	clock_t deltaWrite = clock()-beginWrite;
	free(zs);
	int inMilliWrite = deltaWrite * 1000 / CLOCKS_PER_SEC;


	delta = clock() - begin;
	inMilli = delta * 1000 / CLOCKS_PER_SEC;

	int sumOfParts = 0;

	printf("Generating A: %ju\n", (uintmax_t)inMilliA);
	printf("	Generating keys: %ju\n", (uintmax_t)totalCrypto);
	sumOfParts += totalCrypto;
	printf("	Generating randomness: %ju\n", (uintmax_t)totalRandom);
	sumOfParts += totalRandom;
	printf("	Sharing secrets: %ju\n", (uintmax_t)totalSS);
	sumOfParts += totalSS;
	printf("	Running MPC-SHA2: %ju\n", (uintmax_t)totalSha);
	sumOfParts += totalSha;
	printf("	Committing: %ju\n", (uintmax_t)totalHash);
	sumOfParts += totalHash;
	printf("	*Accounted for*: %ju\n", (uintmax_t)sumOfParts);
	printf("Generating E: %ju\n", (uintmax_t)inMilliE);
	printf("Packing Z: %ju\n", (uintmax_t)inMilliZ);
	printf("Writing file: %ju\n", (uintmax_t)inMilliWrite);
	printf("Total: %d\n",inMilli);
	printf("\n");
	printf("Proof output to file %s", outputFile);



	openmp_thread_cleanup();
	cleanup_EVP();
	return EXIT_SUCCESS;
}
