/*
 * name: MPC_RIPEMD160_VERIFIER.c
 * Author: Tan Teik Guan
 * Description: ZKBoo for RIPEMD160 
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
 * Software:  
 *
 * License: MIT 1.0 
 *
 * Licensor: pQCee Pte Ltd 
 *
 */
/*
 ============================================================================
 Name        : MPC_SHA256_VERIFIER.c
 Author      : Sobuno
 Version     : 0.1
 Description : Verifies a proof for SHA-256 generated by MPC_SHA256.c
 ============================================================================
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "sharedripe.h"

int NUM_ROUNDS = 32;

void printbits(uint32_t n) {
	if (n) {
		printbits(n >> 1);
		printf("%d", n & 1);
	}

}



int main(void) {
	setbuf(stdout, NULL);
	init_EVP();
	openmp_thread_setup();
	struct timeval begin, delta;
	
	int passed = 1;

	printf("Iterations of RIPEMD: %d\n", NUM_ROUNDS);

	
	a as[NUM_ROUNDS];
	z zs[NUM_ROUNDS];
	FILE *file;

	char outputFile[3*sizeof(int) + 8];
	sprintf(outputFile, "out%i.bin", NUM_ROUNDS);
	file = fopen(outputFile, "rb");
	if (!file) {
		printf("Unable to open file!");
	}
	fread(&as, sizeof(a), NUM_ROUNDS, file);
	fread(&zs, sizeof(z), NUM_ROUNDS, file);
	fclose(file);

	gettimeofday(&begin,NULL);

	uint32_t y[5];
	reconstruct(as[0].yp[0],as[0].yp[1],as[0].yp[2],y);
	printf("Proof for hash: ");
	for(int i=0;i<5;i++) {
		printf("%08X", y[i]);
	}
	printf("\n");



	int es[NUM_ROUNDS];
	H3(y, as, NUM_ROUNDS, es);


	#pragma omp parallel for
	for(int i = 0; i<NUM_ROUNDS; i++) {
		int verifyResult = verify(as[i], es[i], zs[i]);
		if (verifyResult != 0) {
			printf("Not Verified %d\n", i);
			passed = 0;
		}
	}
	if (passed)
		printf("Verified ok\n");
	
	gettimeofday(&delta,NULL);
        unsigned long inMilli = (delta.tv_sec - begin.tv_sec)*1000000 + (delta.tv_usec - begin.tv_usec);
        inMilli /= 1000;	

	printf("Total time: %ld miliseconds\n", inMilli);
	


	openmp_thread_cleanup();
	cleanup_EVP();
	return EXIT_SUCCESS;
}