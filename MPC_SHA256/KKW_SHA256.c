/*
 ============================================================================
 Name        : MPC_SHA256.c
 Author      : Sobuno
 Version     : 0.1
 Description : MPC SHA256 for one block only
 ============================================================================
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "KKW_shared.h"
#include "omp.h"


#define CH(e,f,g) ((e & f) ^ ((~e) & g))


int totalRandom = 0;
int totalSha = 0;
int totalSS = 0;
int totalHash = 0;

uint32_t rand32() {
	uint32_t x;
	x = rand() & 0xff;
	x |= (rand() & 0xff) << 8;
	x |= (rand() & 0xff) << 16;
	x |= (rand() & 0xff) << 24;

	return x;
}

void printbits(uint32_t n) {
	if (n) {
		printbits(n >> 1);
		printf("%d", n & 1);
	}

}

/*

void mpc_XOR(uint32_t x[3], uint32_t y[3], uint32_t z[3]) {
	z[0] = x[0] ^ y[0];
	z[1] = x[1] ^ y[1];
	z[2] = x[2] ^ y[2];
}

*/


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
			setBit((uint8_t *)&views[j].y[*countY],i,s_shares & 0x01);
			s_shares >>=1;
		}
	}

	*countY+=1;
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
				setBit((uint8_t *)&views[j].y[*countY],i,s_shares & 0x01);
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



int mpc_sha256(unsigned char masked_result[SHA256_DIGEST_LENGTH], unsigned char shares[NUM_PARTIES][SHA256_INPUTS], unsigned char * inputs, int numBytes, unsigned char randomness[NUM_PARTIES][rSize], View views[NUM_PARTIES], int* countY) 
{

	if (numBytes > 55)
	{	
		printf("Input too long, aborting!");
		return -1;
	}

	int randCount=0;;

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

	inputs[numBytes] = 0x80;
	inputs[62] = (numBytes *8) >> 8;
	inputs[63] = (numBytes * 8);
	for (int j = 0; j < 16; j++) {
		w_state[j] ^= (inputs[j * 4] << 24) | (inputs[j * 4 + 1] << 16)
							| (inputs[j * 4 + 2] << 8) | inputs[j * 4 + 3];
	}

//	memcpy(views[i].x, w[i], 64);

//	printf("w_state[0] = %x\n",w_state[0]); // just to check that values are scampled

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
		mpc_ADD(w_state[j-16],s0_state,&t1_state,w[j-16], s0, t1, randomness, &randCount, views, countY);
		mpc_ADD(w_state[j-7],t1_state,&t1_state, w[j-7], t1, t1, randomness, &randCount, views, countY);
		mpc_ADD(t1_state, s1_state, &(w_state[j]), t1, s1, w[j], randomness, &randCount, views, countY);

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

		mpc_ADD(h_state, s1_state, &t0_state, h, s1, t0, randomness, &randCount, views,countY);

		mpc_CH(e_state, f_state, g_state, &t1_state, e, f, g, t1, randomness, &randCount, views, countY);

		//t1 = t0 + t1 (h+s1+ch)
		mpc_ADD(t0_state, t1_state, &t1_state, t0, t1, t1, randomness, &randCount, views, countY);

		for (int j = 0; j < NUM_PARTIES;j++)
			temp3[j] = k[i];
		temp3_state = k[i];
		mpc_ADD(t1_state, temp3_state, &t1_state, t1,temp3, t1, randomness, &randCount, views, countY);

		mpc_ADD(t1_state, w_state[i], &temp1_state, t1, w[i], temp1, randomness, &randCount, views, countY);

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

		mpc_MAJ(a_state, b_state, c_state, &maj_state, a, b, c, maj, randomness, &randCount, views, countY);

		//temp2 = s0+maj;
		mpc_ADD(s0_state, maj_state, &temp2_state, s0, maj, temp2, randomness, &randCount, views, countY);

		memcpy(h,g,sizeof(uint32_t) * NUM_PARTIES);
		memcpy(g,f,sizeof(uint32_t) * NUM_PARTIES);
		memcpy(f,e,sizeof(uint32_t) * NUM_PARTIES);
		h_state = g_state;
		g_state = f_state;
		f_state = e_state;
		//e = d+temp1;
		mpc_ADD(d_state, temp1_state, &e_state, d, temp1, e, randomness, &randCount, views, countY);
		memcpy(d,c,sizeof(uint32_t) * NUM_PARTIES);
		memcpy(c,b,sizeof(uint32_t) * NUM_PARTIES);
		memcpy(b,a,sizeof(uint32_t) * NUM_PARTIES);
		d_state = c_state;
		c_state = b_state;
		b_state = a_state;
		//a = temp1+temp2;

		mpc_ADD(temp1_state, temp2_state, &a_state, temp1, temp2, a, randomness, &randCount, views, countY);
	}
	uint32_t hHa[8][NUM_PARTIES];
	uint32_t hHa_state[8];
	for (int i = 0;i < 8;i++)
	{
		hHa_state[i] = hA[i];
		for (int j = 0; j < NUM_PARTIES;j++)
			hHa[i][j] = hA[i];
	}
	mpc_ADD(hHa_state[0], a_state, &hHa_state[0], hHa[0], a, hHa[0], randomness, &randCount, views, countY);
	mpc_ADD(hHa_state[1], b_state, &hHa_state[1], hHa[1], b, hHa[1], randomness, &randCount, views, countY);
	mpc_ADD(hHa_state[2], c_state, &hHa_state[2], hHa[2], c, hHa[2], randomness, &randCount, views, countY);
	mpc_ADD(hHa_state[3], d_state, &hHa_state[3], hHa[3], d, hHa[3], randomness, &randCount, views, countY);
	mpc_ADD(hHa_state[4], e_state, &hHa_state[4], hHa[4], e, hHa[4], randomness, &randCount, views, countY);
	mpc_ADD(hHa_state[5], f_state, &hHa_state[5], hHa[5], f, hHa[5], randomness, &randCount, views, countY);
	mpc_ADD(hHa_state[6], g_state, &hHa_state[6], hHa[6], g, hHa[6], randomness, &randCount, views, countY);
	mpc_ADD(hHa_state[7], h_state, &hHa_state[7], hHa[7], h, hHa[7], randomness, &randCount, views, countY);

	for (int i = 0; i < 8; i++) {
		mpc_RIGHTSHIFT(hHa[i], 24, t0);
		t0_state = hHa_state[i] >> 24;

		for (int j = 0;j< NUM_PARTIES;j++)
			views[j].results[i * 4] = t0[j];
		masked_result[i*4] = t0_state;

		mpc_RIGHTSHIFT(hHa[i], 16, t0);
		t0_state = hHa_state[i] >> 16;
		for (int j = 0;j< NUM_PARTIES;j++)
			views[j].results[i * 4 + 1] = t0[j];
		masked_result[i*4+1] = t0_state;

		mpc_RIGHTSHIFT(hHa[i], 8, t0);
		t0_state = hHa_state[i] >> 8;
		for (int j = 0;j< NUM_PARTIES;j++)
			views[j].results[i * 4 + 2] = t0[j];
		masked_result[i*4+2] = t0_state;

		for (int j = 0;j< NUM_PARTIES;j++)
			views[j].results[i * 4 + 3] = hHa[i][j];
		masked_result[i*4+3] = hHa_state[i];
	}
//	printf("mpc_sha256: randCount %d\n",randCount);

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



int main(int argc, char * argv[]) 
{
//	setbuf(stdout, NULL);
	srand((unsigned) time(NULL));
	init_EVP();
	openmp_thread_setup();

	printf("Enter the string to be hashed (Max 55 characters): ");
	char userInput[56]; //55 is max length as we only support 447 bits = 55.875 bytes
	memset(userInput,0,sizeof(userInput));
	fgets(userInput, sizeof(userInput)-1, stdin);
	
	int i = strlen(userInput)-1; 
	printf("String length: %d\n", i);
	
	//printf("Iterations of SHA: %d\n", NUM_ROUNDS);

	unsigned char input[SHA256_INPUTS] = {0}; // 512 bits
	memset(input,0,sizeof(input));
	for(int j = 0; j<i; j++) {
		input[j] = userInput[j];
	}
	unsigned char masterkeys[NUM_ROUNDS][16];
	unsigned char keys[NUM_ROUNDS][NUM_PARTIES][16];
	unsigned char rsseed[20];
	unsigned char rs[NUM_ROUNDS][NUM_PARTIES][4];

        //Generating keys
	Compute_RAND((unsigned char *)masterkeys, NUM_ROUNDS*16,input,strlen(userInput));  
	RAND_bytes((unsigned char *)&rsseed[4],16);
	for (int j = 0; j < NUM_ROUNDS; j++)
	{
		Compute_RAND((unsigned char *)keys[j], NUM_PARTIES*16,masterkeys[j],16);  
		memcpy((unsigned char *)rsseed,&j,sizeof(int));
		Compute_RAND((unsigned char *)rs[j],NUM_PARTIES*4,rsseed,20);
	}
        //Sharing secrets
	unsigned char shares[NUM_ROUNDS][NUM_PARTIES][SHA256_INPUTS];
	for (int j=0;j<NUM_ROUNDS;j++)
	{
		for (int k=0;k<NUM_PARTIES;k++)
			Compute_RAND((unsigned char *)&(shares[j][k]),SHA256_INPUTS,(unsigned char *)keys[j][k],16);
	}

        //Generating randomness
	unsigned char randomness[NUM_ROUNDS][NUM_PARTIES][rSize];

//	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		for(int j = 0; j<NUM_PARTIES; j++) {
			getAllRandomness(keys[k][j], randomness[k][j]);
		}
	}
	//compute AUX Tape
	SHA256_CTX ctx,hctx,H1ctx,H2ctx;
	unsigned char temphash1[SHA256_DIGEST_LENGTH];
	unsigned char temphash2[SHA256_DIGEST_LENGTH];
	unsigned char temphash3[SHA256_DIGEST_LENGTH];
	unsigned char auxBits[NUM_ROUNDS][rSize/8+1];

	SHA256_Init(&H1ctx);
	for (int k = 0; k<NUM_ROUNDS;k++)
	{
		computeAuxTape(randomness[k],shares[k]);
		SHA256_Init(&hctx);
		for (int j = 0; j < NUM_PARTIES; j++)
		{
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, keys[k][j], 16);
			if (j == (NUM_PARTIES-1))
			{
				size_t pos = 0;
				memset(auxBits,0,rSize/8+1);
				// need to include aux tape
				for (int i = 1; i < rSize; i+=2)
				{
					uint8_t auxBit = getBit(randomness[k][j],i);
					setBit(auxBits[k],pos,auxBit);
					pos++;
				}
				SHA256_Update(&ctx, auxBits[k], rSize/8+1);
			}
			SHA256_Update(&ctx, rs[k][j], 4);
			SHA256_Final(temphash1,&ctx);
			SHA256_Update(&hctx, temphash1, SHA256_DIGEST_LENGTH);
		}
		SHA256_Final(temphash1,&hctx);
		SHA256_Update(&H1ctx, temphash1, SHA256_DIGEST_LENGTH);
	}
	SHA256_Final(temphash1,&H1ctx);


	//Running MPC-SHA2 online
	unsigned char masked_result[NUM_ROUNDS][SHA256_DIGEST_LENGTH];
	View localViews[NUM_ROUNDS][NUM_PARTIES];
	unsigned char H2[NUM_ROUNDS][SHA256_DIGEST_LENGTH];
	SHA256_Init(&H2ctx);
//	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		int countY = 0;
	/*
		printf("shares:");
		for (int l=0;l<NUM_PARTIES;l++)
		{
			printf("party %d:",l);
		for (int j=0;j<10;j++)
		{
			printf("%02X",shares[k][l][j]);
		}
		printf("\n");
		}
	*/	
		mpc_sha256(masked_result[k],shares[k],input, i, randomness[k], localViews[k],&countY);
		
		SHA256_Init(&hctx);
		SHA256_Update(&hctx,masked_result[k],SHA256_DIGEST_LENGTH);
		for (int j=0;j<NUM_PARTIES;j++)
			SHA256_Update(&hctx, localViews[k][j].y,ySize*4);
		SHA256_Update(&hctx, rs[k], NUM_PARTIES*4);
		SHA256_Final(H2[k],&hctx);

		SHA256_Update(&H2ctx, H2[k], SHA256_DIGEST_LENGTH);
		if (k == 0)
		{
			printf("countY %d result of hash:",countY);
			for (int j=0;j<SHA256_DIGEST_LENGTH;j++)
			{
				unsigned char temp = masked_result[k][j];
				for (int i=0;i<NUM_PARTIES;i++)
				{
					temp ^= localViews[k][i].results[j];
				}
				printf("%02X",temp);
			}
			printf("\n");
		}
	}
	SHA256_Final(temphash2,&H2ctx);

	SHA256_Init(&hctx);
	SHA256_Update(&hctx, temphash1, SHA256_DIGEST_LENGTH);
	SHA256_Update(&hctx, temphash2, SHA256_DIGEST_LENGTH);
	SHA256_Final(temphash3,&hctx);

	//Committing
	z kkwProof;
	int es[NUM_ROUNDS];
	memcpy(kkwProof.H,temphash3,SHA256_DIGEST_LENGTH);
	memcpy(kkwProof.rsseed,&rsseed[4],16);
	H3(temphash3, NUM_ONLINE, es);

	int masterkeycount = 0;
	int onlinecount = 0;

	for (int i = 0; i < NUM_ROUNDS;i++)
	{
		if (!es[i])
		{
			memcpy(kkwProof.masterkeys[masterkeycount],masterkeys[i],16);
			memcpy(kkwProof.H2[masterkeycount++],H2[i],SHA256_DIGEST_LENGTH);
		}
		else
		{
			memcpy(kkwProof.auxBits[onlinecount],auxBits[i],rSize/8+1);
			int partycount = 0;
			for (int j = 0; j < NUM_PARTIES; j++)
			{
				if ((j+1) != es[i])
				{
					memcpy(kkwProof.keys[onlinecount][partycount++],keys[i][j],16);
					memcpy(&kkwProof.views[onlinecount],localViews[i],sizeof(View));
				}
				else
				{
					SHA256_Init(&ctx);
					SHA256_Update(&hctx,keys[i][j],SHA256_DIGEST_LENGTH);
					if (j == (NUM_PARTIES-1))
					{
						SHA256_Update(&ctx, auxBits[i], rSize/8+1);
					}
					SHA256_Update(&ctx, rs[i][j], 4);
					SHA256_Final(kkwProof.com[onlinecount],&ctx);
				}
			}
			onlinecount++;
		}
	}
		
	//Writing to file
	FILE *file;
	char outputFile[100];

	sprintf(outputFile, "out%i-%i.bin", NUM_ROUNDS,NUM_ONLINE);
	file = fopen(outputFile, "wb");
	if (!file) {
		printf("Unable to open file!");
		return 1;
	}
	fwrite(&kkwProof, sizeof(z), 1, file);

	fclose(file);

	printf("Proof output to file %s\n", outputFile);

	openmp_thread_cleanup();
	cleanup_EVP();
	return EXIT_SUCCESS;
}
