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
	memset(rsseed,0,20);
//	RAND_bytes((unsigned char *)&rsseed[4],16);
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
	memset(randomness,0,NUM_ROUNDS*NUM_PARTIES*rSize);

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
/*
				size_t pos = 0;
				memset(auxBits,0,rSize/8+1);
				// need to include aux tape
				for (int i = 1; i < rSize; i+=2)
				{
					uint8_t auxBit = getBit(randomness[k][j],i);
					setBit(auxBits[k],pos,auxBit);
					pos++;
				}
*/
				SHA256_Update(&ctx, randomness[k][j], rSize);
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
	unsigned char party_result[NUM_PARTIES][SHA256_DIGEST_LENGTH];
	unsigned char maskedInputs[NUM_ROUNDS][SHA256_INPUTS];
	View localViews[NUM_ROUNDS][NUM_PARTIES];
	unsigned char H2[NUM_ROUNDS][SHA256_DIGEST_LENGTH];
	SHA256_Init(&H2ctx);
//	#pragma omp parallel for
	for(int k=0; k<NUM_ROUNDS; k++) {
		int countY = 0;

		mpc_sha256(masked_result[k],maskedInputs[k],shares[k],input, i, randomness[k], localViews[k],party_result,&countY);
		SHA256_Init(&hctx);
		SHA256_Update(&hctx,maskedInputs[k],SHA256_INPUTS);
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
					temp ^= party_result[i][j];
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
			memcpy(kkwProof.auxBits[onlinecount],randomness[i][NUM_PARTIES-1],rSize);
			memcpy(kkwProof.maskedInput[onlinecount],maskedInputs[i],SHA256_INPUTS);
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
