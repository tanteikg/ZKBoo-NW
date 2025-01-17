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
 * Software: KKW_ECC 
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


int main(int argc, char * argv[]) 
{
//	setbuf(stdout, NULL);
	SHA256_CTX ctx;
	MP_INT mod;
	srand((unsigned) time(NULL));
	init_EVP();

	if (argc != 2)
	{
		printf("Usage: %s <seed>\n",argv[0]);
		return -1;
	}

	unsigned char input[SHA256_DIGEST_LENGTH] = {0}; // 512 bits
	SHA256_Init(&ctx);
	SHA256_Update(&ctx,argv[1],strlen(argv[1]));
	SHA256_Final(input,&ctx);
		
	mpz_init_set_str(&mod,CURVE_P,16);

	unsigned char masterkeys[NUM_ROUNDS][16];
	unsigned char keys[NUM_ROUNDS][NUM_PARTIES][16];
	unsigned char rsseed[20];
	unsigned char rs[NUM_ROUNDS][NUM_PARTIES][4];

        //Generating keys
	Compute_RAND((unsigned char *)masterkeys, NUM_ROUNDS*16,input,SHA256_DIGEST_LENGTH);  
	memset(rsseed,0,20);
	RAND_bytes((unsigned char *)&rsseed[4],16);
	for (int j = 0; j < NUM_ROUNDS; j++)
	{
		Compute_RAND((unsigned char *)keys[j], NUM_PARTIES*16,masterkeys[j],16);  
		memcpy((unsigned char *)rsseed,&j,sizeof(int));
		Compute_RAND((unsigned char *)rs[j],NUM_PARTIES*4,rsseed,20);
	}
        //Sharing secrets
	unsigned char shares[NUM_ROUNDS][NUM_PARTIES][ECC_INPUTS];
	for (int j=0;j<NUM_ROUNDS;j++)
	{
		for (int k=0;k<NUM_PARTIES;k++)
			Compute_RAND((unsigned char *)&(shares[j][k]),ECC_INPUTS,(unsigned char *)keys[j][k],16);
	}

        //Generating randomness
	unsigned char *randomness[NUM_ROUNDS][NUM_PARTIES];

//	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		for(int j = 0; j<NUM_PARTIES; j++) {
			randomness[k][j]= (unsigned char *)malloc(rSize);
			memset(randomness[k][j],0,rSize);
			getAllRandomness(keys[k][j], randomness[k][j]);
		}
	}
	//compute AUX Tape
	SHA256_CTX hctx,H1ctx,H2ctx;
	unsigned char temphash1[SHA256_DIGEST_LENGTH];
	unsigned char temphash2[SHA256_DIGEST_LENGTH];
	unsigned char temphash3[SHA256_DIGEST_LENGTH];
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
				SHA256_Update(&ctx, randomness[k][j], rSize);
			SHA256_Update(&ctx, rs[k][j], 4);
			SHA256_Final(temphash1,&ctx);
			SHA256_Update(&hctx, temphash1, SHA256_DIGEST_LENGTH);
		}
		SHA256_Final(temphash1,&hctx);
		SHA256_Update(&H1ctx, temphash1, SHA256_DIGEST_LENGTH);
	}
	SHA256_Final(temphash1,&H1ctx);

	//Running MPC-SHA2 online
	unsigned char masked_result[NUM_ROUNDS][2][ECC_PUBKEY_LENGTH];
	unsigned char party_result[2][NUM_PARTIES][ECC_PUBKEY_LENGTH];
	unsigned char maskedInputs[NUM_ROUNDS][ECC_INPUTS];
	View localViews[NUM_ROUNDS][NUM_PARTIES];
	unsigned char H2[NUM_ROUNDS][SHA256_DIGEST_LENGTH];
	SHA256_Init(&H2ctx);
//	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		int countY = 0;

		mpc_compute(masked_result[k],maskedInputs[k],shares[k],input, ECC_INPUTS, randomness[k], localViews[k],party_result,&countY);
		SHA256_Init(&hctx);
		SHA256_Update(&hctx,maskedInputs[k],ECC_INPUTS);
		SHA256_Update(&hctx,masked_result[k],ECC_PUBKEY_LENGTH);
		for (int j=0;j<NUM_PARTIES;j++)
			SHA256_Update(&hctx, localViews[k][j].y,ySize*4);
		SHA256_Update(&hctx, rs[k], NUM_PARTIES*4);
		SHA256_Final(H2[k],&hctx);
		SHA256_Update(&H2ctx, H2[k], SHA256_DIGEST_LENGTH);
		if (k == 0)
		{
			MP_INT pubx, puby, tempx, tempy;
			mpz_init(&pubx);
			mpz_init(&puby);
			mpz_init(&tempx);
			mpz_init(&tempy);
			printf("Result of ECC\nGx: ");
			mpz_import(&pubx,ECC_PUBKEY_LENGTH,1,1,0,0,masked_result[k][0]);
			mpz_import(&puby,ECC_PUBKEY_LENGTH,1,1,0,0,masked_result[k][1]);
			for (int i=0;i<NUM_PARTIES;i++)
			{
				mpz_import(&tempx,ECC_PUBKEY_LENGTH,1,1,0,0,party_result[0][i]);
				mpz_import(&tempy,ECC_PUBKEY_LENGTH,1,1,0,0,party_result[1][i]);
				ecAddPoint(&pubx,&puby,&tempx,&tempy);
			}
			mpz_out_str(stdout, 16, &pubx);
			printf("\nGy: ");
			mpz_out_str(stdout, 16, &puby);
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
			memcpy(kkwProof.auxBits[onlinecount],randomness[i][NUM_PARTIES-1],rSize);
			memcpy(kkwProof.maskedInput[onlinecount],maskedInputs[i],ECC_INPUTS);
			int partycount = 0;
			for (int j = 0; j < NUM_PARTIES; j++)
			{
				if ((j+1) != es[i])
				{
					memcpy(kkwProof.keys[onlinecount][partycount++],keys[i][j],16);
				}
				else
				{
					SHA256_Init(&ctx);
					SHA256_Update(&ctx,keys[i][j],16);
					if (j == (NUM_PARTIES-1))
					{
						SHA256_Update(&ctx, randomness[i][NUM_PARTIES-1], rSize);
					}
					SHA256_Update(&ctx, rs[i][j], 4);
					SHA256_Final(kkwProof.com[onlinecount],&ctx);
					memcpy(&kkwProof.views[onlinecount],&localViews[i][j],sizeof(View));
				}
				free(randomness[i][j]);
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
	mpz_clear(&mod);

	printf("Proof output to file %s\n", outputFile);

	cleanup_EVP();
	return EXIT_SUCCESS;
}
