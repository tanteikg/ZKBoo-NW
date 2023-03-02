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

#define ySize 736

typedef struct {
	unsigned char x[64];
	uint32_t y[ySize];
} View;

typedef struct {
	uint32_t yp[3][8];
	unsigned char h[3][32];
} a;

typedef struct {
	unsigned char ke[16];
	unsigned char ke1[16];
	View ve;
	View ve1;
	unsigned char re[4];
	unsigned char re1[4];
} z;

// KKW structures

typedef struct tree_t {
    size_t depth;       /* The depth of the tree */
    uint8_t** nodes;    /* The data for each node */
    size_t dataSize;    /* The size data at each node, in bytes */
    uint8_t* haveNode;  /* If we have the data (seed or hash) for node i, haveSeed[i] is 1 */
    uint8_t* exists;    /* Since the tree is not always complete, nodes marked 0 don't exist */
    size_t numNodes;    /* The total number of nodes in the tree */
    size_t numLeaves;   /* The total number of leaves in the tree */
} tree_t;

/* The largest seed size is 256 bits, for the Picnic3-L5-FS parameter set. */
#define MAX_SEED_SIZE_BYTES (32)

typedef struct randomTape_t {
    uint8_t** tape;
    uint32_t pos;
    size_t nTapes;
} randomTape_t;

typedef struct view_t {
    uint32_t* inputShare;
    uint8_t* communicatedBits;
    uint32_t* outputShare;
} view_t;

typedef struct commitments_t {
    uint8_t** hashes;
    size_t nCommitments;
} commitments_t;

typedef uint8_t** inputs_t;

typedef struct msgs_t {
    uint8_t** msgs;         // One for each player
    size_t pos;
    int unopened;           // Index of the unopened party, or -1 if all parties opened (when signing)
} msgs_t;

typedef struct g_commitments_t {
    uint8_t* G[3];
}g_commitments_t;

typedef struct seeds_t {
    uint8_t** seed;
    uint8_t* iSeed;
} seeds_t;

typedef struct shares_t {
    uint16_t* shares;
    size_t numWords;
} shares_t;

typedef struct paramset_t {
    uint32_t numRounds;
    uint32_t numSboxes;
    uint32_t stateSizeBits;
    uint32_t stateSizeBytes;
    uint32_t stateSizeWords;
    uint32_t andSizeBytes;
    uint32_t UnruhGWithoutInputBytes;
    uint32_t UnruhGWithInputBytes;
    uint32_t numMPCRounds;          // T
    uint32_t numOpenedRounds;       // u
    uint32_t numMPCParties;         // N
    uint32_t seedSizeBytes;
    uint32_t saltSizeBytes;
    uint32_t digestSizeBytes;
//    transform_t transform;  // we hardcode to FS
} paramset_t;

typedef struct proof2_t {
    uint8_t* seedInfo;          // Information required to compute the tree with seeds of of all opened parties
    size_t seedInfoLen;         // Length of seedInfo buffer
    uint8_t* aux;               // Last party's correction bits; NULL if P[t] == N-1
    uint8_t* C;                 // Commitment to preprocessing step of unopened party
    uint8_t* input;             // Masked input used in online execution
    uint8_t* msgs;              // Broadcast messages of unopened party P[t]
} proof2_t;

typedef struct signature2_t {
    uint8_t* salt;
    uint8_t* iSeedInfo;         // Info required to recompute the tree of all initial seeds
    size_t iSeedInfoLen;
    uint8_t* cvInfo;            // Info required to check commitments to views (reconstruct Merkle tree)
    size_t cvInfoLen;
    uint8_t* challengeHash;
    uint16_t* challengeC;
    uint16_t* challengeP;
    proof2_t* proofs;           // One proof for each online execution the verifier checks
} signature2_t;



#define RIGHTROTATE(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b)   x= (b)&1 ? (x)|(1 << (i)) : (x)&(~(1 << (i)))
// from picnic_type.c


shares_t* allocateShares(size_t count)
{
    shares_t* shares = malloc(sizeof(shares_t));

    shares->shares = calloc(count, sizeof(uint16_t));
    shares->numWords = count;
    return shares;
}
void freeShares(shares_t* shares)
{
    free(shares->shares);
    free(shares);
}

/* Allocate/free functions for dynamically sized types */
void allocateView(view_t* view, paramset_t* params)
{
    view->inputShare = calloc(params->stateSizeBytes, 1);
    view->communicatedBits = calloc(params->andSizeBytes, 1);
    view->outputShare = calloc(params->stateSizeBytes, 1);
}

void freeView(view_t* view)
{
    free(view->inputShare);
    free(view->communicatedBits);
    free(view->outputShare);
}

size_t getTapeSizeBytes(const paramset_t* params)
{
    return 2*params->andSizeBytes;
}

void allocateRandomTape(randomTape_t* tape, paramset_t* params)
{
    tape->nTapes = params->numMPCParties;
    tape->tape = malloc(tape->nTapes * sizeof(uint8_t*));
    size_t tapeSizeBytes = getTapeSizeBytes(params);
    uint8_t* slab = calloc(1, tape->nTapes * tapeSizeBytes);
    for (uint8_t i = 0; i < tape->nTapes; i++) {
        tape->tape[i] = slab;
        slab += tapeSizeBytes;
    }
    tape->pos = 0;
}

void freeRandomTape(randomTape_t* tape)
{
    if (tape != NULL) {
        free(tape->tape[0]);
        free(tape->tape);
    }
}

void allocateProof2(proof2_t* proof, paramset_t* params)
{
    memset(proof, 0, sizeof(proof2_t));

    proof->seedInfo = NULL;     // Sign/verify code sets it
    proof->seedInfoLen = 0;
    proof->C = malloc(params->digestSizeBytes);
    proof->input = calloc(1, params->stateSizeBytes);
    proof->aux = calloc(1, params->andSizeBytes);
    proof->msgs = calloc(1, params->andSizeBytes);

}
void freeProof2(proof2_t* proof)
{
    free(proof->seedInfo);
    free(proof->C);
    free(proof->input);
    free(proof->aux);
    free(proof->msgs);
}

void allocateProof(proof_t* proof, paramset_t* params)
{
    proof->seed1 = malloc(params->seedSizeBytes);
    proof->seed2 = malloc(params->seedSizeBytes);
    proof->inputShare = malloc(params->stateSizeBytes);
    proof->communicatedBits = malloc(params->andSizeBytes);
    proof->view3Commitment = malloc(params->digestSizeBytes);
    if (params->UnruhGWithInputBytes > 0) {
        proof->view3UnruhG = malloc(params->UnruhGWithInputBytes);
    }
    else {
        proof->view3UnruhG = NULL;
    }
}

void freeProof(proof_t* proof)
{
    free(proof->seed1);
    free(proof->seed2);
    free(proof->inputShare);
    free(proof->communicatedBits);
    free(proof->view3Commitment);
    free(proof->view3UnruhG);
}

void allocateSignature(signature_t* sig, paramset_t* params)
{
    sig->proofs = (proof_t*)malloc(params->numMPCRounds * sizeof(proof_t));

    for (size_t i = 0; i < params->numMPCRounds; i++) {
        allocateProof(&(sig->proofs[i]), params);
    }

    sig->challengeBits = (uint8_t*)malloc(numBytes(2 * params->numMPCRounds));
    sig->salt = (uint8_t*)malloc(params->saltSizeBytes);
}

void freeSignature(signature_t* sig, paramset_t* params)
{
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        freeProof(&(sig->proofs[i]));
    }

    free(sig->proofs);
    free(sig->challengeBits);
    free(sig->salt);
}

void allocateSignature2(signature2_t* sig, paramset_t* params)
{
    sig->salt = (uint8_t*)malloc(params->saltSizeBytes);
    sig->iSeedInfo = NULL;
    sig->iSeedInfoLen = 0;
    sig->cvInfo = NULL;       // Sign/verify code sets it
    sig->cvInfoLen = 0;
    sig->challengeC = (uint16_t*)malloc(params->numOpenedRounds * sizeof(uint16_t));
    sig->challengeP = (uint16_t*)malloc(params->numOpenedRounds * sizeof(uint16_t));
    sig->challengeHash = (uint8_t*)malloc(params->digestSizeBytes);
    sig->proofs = calloc(params->numMPCRounds, sizeof(proof2_t));
    // Individual proofs are allocated during signature generation, only for rounds when neeeded
}

void freeSignature2(signature2_t* sig, paramset_t* params)
{
    free(sig->salt);
    free(sig->iSeedInfo);
    free(sig->cvInfo);
    free(sig->challengeC);
    free(sig->challengeP);
    free(sig->challengeHash);
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        freeProof2(&sig->proofs[i]);
    }
    free(sig->proofs);
}

seeds_t* allocateSeeds(paramset_t* params)
{
    seeds_t* seeds = malloc((params->numMPCRounds + 1) * sizeof(seeds_t));
    size_t nSeeds = params->numMPCParties;
    uint8_t* slab1 = malloc((params->numMPCRounds * nSeeds) * params->seedSizeBytes + params->saltSizeBytes);                                   // Seeds
    uint8_t* slab2 = malloc(params->numMPCRounds * nSeeds * sizeof(uint8_t*) + sizeof(uint8_t*) + params->numMPCRounds * sizeof(uint8_t*) );    // pointers to seeds
    uint8_t* slab3 = malloc((params->numMPCRounds) * params->seedSizeBytes + params->saltSizeBytes);                                            // iSeeds, used to derive seeds

    // We need multiple slabs here, because the seeds are generated with one call to the KDF;
    // they must be stored contiguously

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        seeds[i].seed = (uint8_t**)slab2;
        slab2 += nSeeds * sizeof(uint8_t*);
        seeds[i].iSeed = slab3;
        slab3 += params->seedSizeBytes;

        for (uint32_t j = 0; j < nSeeds; j++) {
            seeds[i].seed[j] = slab1;
            slab1 += params->seedSizeBytes;
        }
    }

    // The salt is the last seed value
    // Accessed by seeds[params->numMPCRounds].iSeed
    seeds[params->numMPCRounds].seed = NULL;
    if (params->numMPCParties == 3) {
        seeds[params->numMPCRounds].iSeed = slab1;      // For ZKB parameter sets, the salt must be derived with the seeds
    }
    else {
        seeds[params->numMPCRounds].iSeed = slab3;      // For Pincic2 paramter sets, the salt is dervied with the initial seeds
    }

    return seeds;
}

void freeSeeds(seeds_t* seeds)
{
    free(seeds[0].seed[0]); // Frees slab1
    free(seeds[0].iSeed);   // Frees slab3
    free(seeds[0].seed);    // frees slab2
    free(seeds);
}

commitments_t* allocateCommitments(paramset_t* params, size_t numCommitments)
{
    commitments_t* commitments = malloc(params->numMPCRounds * sizeof(commitments_t));

    commitments->nCommitments = (numCommitments) ? numCommitments : params->numMPCParties;

    uint8_t* slab = malloc(params->numMPCRounds * (commitments->nCommitments * params->digestSizeBytes +
                                                   commitments->nCommitments * sizeof(uint8_t*)) );

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        commitments[i].hashes = (uint8_t**)slab;
        slab += commitments->nCommitments * sizeof(uint8_t*);

        for (uint32_t j = 0; j < commitments->nCommitments; j++) {
            commitments[i].hashes[j] = slab;
            slab += params->digestSizeBytes;
        }
    }

    return commitments;
}

void freeCommitments(commitments_t* commitments)
{
    free(commitments[0].hashes);
    free(commitments);
}


/* Allocate one commitments_t object with capacity for numCommitments values */
void allocateCommitments2(commitments_t* commitments, paramset_t* params, size_t numCommitments)
{
    commitments->nCommitments = numCommitments;

    uint8_t* slab = malloc(numCommitments * params->digestSizeBytes + numCommitments * sizeof(uint8_t*));

    commitments->hashes = (uint8_t**)slab;
    slab += numCommitments * sizeof(uint8_t*);

    for (size_t i = 0; i < numCommitments; i++) {
        commitments->hashes[i] = slab;
        slab += params->digestSizeBytes;
    }
}

void freeCommitments2(commitments_t* commitments)
{
    if (commitments != NULL) {
        if(commitments->hashes != NULL) {
            free(commitments->hashes);
        }
    }
}

inputs_t allocateInputs(paramset_t* params)
{
    uint8_t* slab = calloc(1, params->numMPCRounds * (params->stateSizeWords*sizeof(uint32_t) + sizeof(uint8_t*)));

    inputs_t inputs = (uint8_t**)slab;

    slab += params->numMPCRounds * sizeof(uint8_t*);

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        inputs[i] = (uint8_t*)slab;
        slab += params->stateSizeWords * sizeof(uint32_t);
    }

    return inputs;
}

void freeInputs(inputs_t inputs)
{
    free(inputs);
}

msgs_t* allocateMsgs(paramset_t* params)
{
    msgs_t* msgs = malloc(params->numMPCRounds * sizeof(msgs_t));
    size_t msgsSize = params->andSizeBytes;
    uint8_t* slab = calloc(1, params->numMPCRounds * (params->numMPCParties * msgsSize +
                                                      params->numMPCParties * sizeof(uint8_t*)));

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        msgs[i].pos = 0;
        msgs[i].unopened = -1;
        msgs[i].msgs = (uint8_t**)slab;
        slab += params->numMPCParties * sizeof(uint8_t*);

        for (uint32_t j = 0; j < params->numMPCParties; j++) {
            msgs[i].msgs[j] = slab;
            slab += msgsSize;
        }
    }

    return msgs;
}

void freeMsgs(msgs_t* msgs)
{
    free(msgs[0].msgs);
    free(msgs);
}

view_t** allocateViews(paramset_t* params)
{
    // 3 views per round
    view_t** views = malloc(params->numMPCRounds * sizeof(view_t *));

    for (size_t i = 0; i < params->numMPCRounds; i++) {
        views[i] = calloc(3, sizeof(view_t));
        for (size_t j = 0; j < 3; j++) {
            allocateView(&views[i][j], params);
        }
    }

    return views;
}

void freeViews(view_t** views, paramset_t* params)
{
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        for (size_t j = 0; j < 3; j++) {
            freeView(&views[i][j]);
        }
        free(views[i]);
    }

    free(views);
}

g_commitments_t* allocateGCommitments(paramset_t* params)
{
    g_commitments_t* gs = NULL;

    if (params->transform == TRANSFORM_UR) {
        gs = malloc(params->numMPCRounds * sizeof(g_commitments_t));
        uint8_t* slab = malloc(params->UnruhGWithInputBytes * params->numMPCRounds * 3);
        for (uint32_t i = 0; i < params->numMPCRounds; i++) {
            for (uint8_t j = 0; j < 3; j++) {
                gs[i].G[j] = slab;
                slab += params->UnruhGWithInputBytes;
            }
        }
    }

    return gs;
}

void freeGCommitments(g_commitments_t* gs)
{
    if (gs != NULL) {
        free(gs[0].G[0]);
        free(gs);
    }
}


// prototype from hash.c
// to implement using sha256 instead of sha3

#define MAX_DIGEST_SIZE 64
#define SHA256_DIGEST_SIZE 32

/* Prefix values for domain separation. */
static const uint8_t HASH_PREFIX_NONE = -1;
static const uint8_t HASH_PREFIX_0 = 0;
static const uint8_t HASH_PREFIX_1 = 1;
static const uint8_t HASH_PREFIX_2 = 2;
static const uint8_t HASH_PREFIX_3 = 3;
static const uint8_t HASH_PREFIX_4 = 4;
static const uint8_t HASH_PREFIX_5 = 5;

typedef HashInstance SHA256_CTX;

void HashUpdate(HashInstance* ctx, const uint8_t* data, size_t byteLen)
{
	SHA256_Update(ctx,data,byteLen);
}

void HashInit(HashInstance* ctx, paramset_t* params, uint8_t hashPrefix)
{
	SHA256_Init(ctx);
	if (hashPrefix != HASH_PREFIX_NONE)
		HashUpdate(ctx,&hashPrefix,1);
}

void HashFinal(HashInstance* ctx)
{
	// do nothing
}

void HashSqueeze(HashInstance* ctx, uint8_t* digest, size_t byteLen)
{
	unsigned char outhash[SHA256_DIGEST_SIZE];
	uint8_t * tempptr = digest;
	int Loop = 0;

	while (byteLen > 0)
	{
		Loop++;
		SHA256_Final(outhash,ctx);
		if (byteLen < SHA256_DIGEST_SIZE)
		{
			memcpy(tempptr,outhash,byteLen);
			byteLen = 0;
		}
		else
		{
			memcpy(tempptr,outhash,SHA256_DIGEST_SIZE);
			tempptr += SHA256_DIGEST_SIZE;
			byteLen -= SHA256_DIGEST_SIZE;
			SHA256_Init(ctx);
			SHA256_Update(ctx,outhash,SHA256_DIGEST_SIZE);
			SHA256_Update(ctx,&Loop,sizeof(Loop));
		}
	}
}


uint16_t toLittleEndian(uint16_t x)
{
#if (PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN)
    return (x << 8) | (x >> 8);
#else
    return x;
#endif
}
void HashUpdateIntLE(HashInstance* ctx, uint16_t x)
{
    uint16_t outputBytesLE = toLittleEndian(x);

    HashUpdate(ctx, (uint8_t*)&outputBytesLE, sizeof(uint16_t));
}

uint16_t fromLittleEndian(uint16_t x)
{
#if (PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN)
    return (x << 8) | (x >> 8);
#else
    return x;
#endif
}


// from tree.c

static int contains(size_t* list, size_t len, size_t value)
{
    for (size_t i = 0; i < len; i++) {
        if (list[i] == value) {
            return 1;
        }
    }
    return 0;
}

int exists(tree_t* tree, size_t i)
{
    if (i >= tree->numNodes) {
        return 0;
    }
    if (tree->exists[i]) {
        return 1;
    }
    return 0;
}

tree_t* createTree(size_t numLeaves, size_t dataSize)
{
    tree_t* tree = malloc(sizeof(tree_t));

    tree->depth = ceil_log2(numLeaves) + 1;
    tree->numNodes = ((1 << (tree->depth)) - 1) - ((1 << (tree->depth - 1)) - numLeaves);  /* Num nodes in complete - number of missing leaves */
    tree->numLeaves = numLeaves;
    tree->dataSize = dataSize;
    tree->nodes = malloc(tree->numNodes * sizeof(uint8_t*));

    uint8_t* slab = calloc(tree->numNodes, dataSize);

    for (size_t i = 0; i < tree->numNodes; i++) {
        tree->nodes[i] = slab;
        slab += dataSize;
    }

    tree->haveNode = calloc(tree->numNodes, 1);

    /* Depending on the number of leaves, the tree may not be complete */
    tree->exists = calloc(tree->numNodes, 1);
    memset(tree->exists + tree->numNodes - tree->numLeaves, 1, tree->numLeaves);    /* Set leaves */
    for (int i = tree->numNodes - tree->numLeaves; i > 0; i--) {
        if (exists(tree, 2 * i + 1) || exists(tree, 2 * i + 2) ) {
            tree->exists[i] = 1;
        }
    }
    tree->exists[0] = 1;

    return tree;
}

void freeTree(tree_t* tree)
{
    if (tree != NULL) {
        free(tree->nodes[0]);
        free(tree->nodes);
        free(tree->haveNode);
        free(tree->exists);
        free(tree);
    }
}
int isLeftChild(size_t node)
{
    if (node == 0)
      return 0;
    return(node % 2 == 1);
}

int hasRightChild(tree_t* tree, size_t node)
{
    return(2 * node + 2 < tree->numNodes && exists(tree, node));
}

int hasLeftChild(tree_t* tree, size_t node)
{
    return(2 * node + 1 < tree->numNodes);
}

size_t getParent(size_t node)
{
    if (node == 0)
      return 0;

    if (isLeftChild(node)) {
        return (node - 1) / 2;
    }
    return (node - 2) / 2;
}

uint8_t** getLeaves(tree_t* tree)
{
    return &tree->nodes[tree->numNodes - tree->numLeaves];
}

uint8_t* getLeaf(tree_t* tree, size_t leafIndex)
{
//    assert(leafIndex < tree->numLeaves);
    size_t firstLeaf = tree->numNodes - tree->numLeaves;
    return tree->nodes[firstLeaf + leafIndex];
}

void hashSeed(uint8_t* digest, const uint8_t* inputSeed, uint8_t* salt, uint8_t hashPrefix, size_t repIndex, size_t nodeIndex, paramset_t* params)
{
    HashInstance ctx;

    HashInit(&ctx, params, hashPrefix);
    HashUpdate(&ctx, inputSeed, params->seedSizeBytes);
    HashUpdate(&ctx, salt, params->saltSizeBytes);
    HashUpdateIntLE(&ctx, (uint16_t)repIndex);
    HashUpdateIntLE(&ctx, (uint16_t)nodeIndex);
    HashFinal(&ctx);
    HashSqueeze(&ctx, digest, 2 * params->seedSizeBytes);
}

void expandSeeds(tree_t* tree, uint8_t* salt, size_t repIndex, paramset_t* params)
{
    uint8_t tmp[2*MAX_SEED_SIZE_BYTES];

    /* Walk the tree, expanding seeds where possible. Compute children of
     * non-leaf nodes. */
    size_t lastNonLeaf = getParent(tree->numNodes - 1);

    for (size_t i = 0; i <= lastNonLeaf; i++) {
        if (!tree->haveNode[i]) {
            continue;
        }

        hashSeed(tmp, tree->nodes[i], salt, HASH_PREFIX_1, repIndex, i, params);

        if (!tree->haveNode[2 * i + 1]) {
            /* left child = H_left(seed_i || salt || t || i) */
            memcpy(tree->nodes[2 * i + 1], tmp, params->seedSizeBytes);
            tree->haveNode[2 * i + 1] = 1;
        }

        /* The last non-leaf node will only have a left child when there are an odd number of leaves */
        if (exists(tree, 2 * i + 2) && !tree->haveNode[2 * i + 2]) {
            /* right child = H_right(seed_i || salt || t || i)  */
            memcpy(tree->nodes[2 * i + 2], tmp + params->seedSizeBytes, params->seedSizeBytes);
            tree->haveNode[2 * i + 2] = 1;
        }

    }

}

tree_t* generateSeeds(size_t nSeeds, uint8_t* rootSeed, uint8_t* salt, size_t repIndex, paramset_t* params)
{
    tree_t* tree = createTree(nSeeds, params->seedSizeBytes);

    memcpy(tree->nodes[0], rootSeed, params->seedSizeBytes);
    tree->haveNode[0] = 1;
    expandSeeds(tree, salt, repIndex, params);

    return tree;
}

int isLeafNode(tree_t* tree, size_t node)
{
    return (2 * node + 1 >= tree->numNodes);
}

int hasSibling(tree_t* tree, size_t node)
{
    if (!exists(tree, node)) {
        return 0;
    }

    if (isLeftChild(node) && !exists(tree, node + 1)) {
        return 0;
    }

    return 1;
}

size_t getSibling(tree_t* tree, size_t node)
{
/*
    assert(node < tree->numNodes);
    assert(node != 0);
    assert(hasSibling(tree, node));
*/

    if (isLeftChild(node)) {
        if (node + 1 < tree->numNodes) {
            return node + 1;
        }
        else {
 //           assert(!"getSibling: request for node with not sibling");
            return 0;
        }
    }
    else {
        return node - 1;
    }
}

void printSeeds(uint8_t* seedsBuf, size_t seedLen, size_t numSeeds)
{
    for (size_t i = 0; i < numSeeds; i++) {
        printf("seed %lu", i);
        printHex("", seedsBuf, seedLen);
        seedsBuf += seedLen;
    }
}

void printLeaves(tree_t* tree)
{
    size_t firstLeaf = tree->numNodes - tree->numLeaves;

    printSeeds(tree->nodes[firstLeaf], tree->dataSize, tree->numLeaves);

}

/* Returns the number of bytes written to output */
static size_t* getRevealedNodes(tree_t* tree, uint16_t* hideList, size_t hideListSize, size_t* outputSize)
{
    /* Compute paths up from hideList to root, store as sets of nodes */
    size_t pathLen = tree->depth - 1;

    /* pathSets[i][0...hideListSize] stores the nodes in the path at depth i
     * for each of the leaf nodes in hideListSize */
    size_t** pathSets = malloc(pathLen * sizeof(size_t*));
    size_t* slab = malloc(hideListSize * pathLen * sizeof(size_t));

    for (size_t i = 0; i < pathLen; i++) {
        pathSets[i] = slab;
        slab += hideListSize;
    }

    /* Compute the paths back to the root */
    for (size_t i = 0; i < hideListSize; i++) {
        size_t pos = 0;
        size_t node = hideList[i] + (tree->numNodes - tree->numLeaves); /* input lists leaf indexes, translate to nodes */
        pathSets[pos][i] = node;
        pos++;
        while ( (node = getParent(node)) != 0 ) {
            pathSets[pos][i] = node;
            pos++;
        }
    }

    /* Determine seeds to reveal */
    size_t* revealed = malloc(tree->numLeaves * sizeof(size_t));
    size_t revealedPos = 0;
    for (size_t d = 0; d < pathLen; d++) {
        for (size_t i = 0; i < hideListSize; i++) {
            if (!hasSibling(tree, pathSets[d][i])) {
                continue;
            }
            size_t sibling = getSibling(tree, pathSets[d][i]);
            if (!contains(pathSets[d], hideListSize, sibling )) {
                // Determine the seed to reveal 
                while(!hasRightChild(tree, sibling) && !isLeafNode(tree, sibling)) {
                    sibling = 2 * sibling + 1; // sibling = leftChild(sibling)
                }

                // Only reveal if we haven't already 
                if (!contains(revealed, revealedPos, sibling)) {
                    revealed[revealedPos] = sibling;
                    revealedPos++;
                }
            }
        }
    }

    free(pathSets[0]);
    free(pathSets);

    *outputSize = revealedPos;
    return revealed;
}

size_t revealSeedsSize(size_t numNodes, uint16_t* hideList, size_t hideListSize, paramset_t* params)
{
    tree_t* tree = createTree(numNodes, params->seedSizeBytes);
    size_t numNodesRevealed = 0;
    size_t* revealed = getRevealedNodes(tree, hideList, hideListSize, &numNodesRevealed);

    freeTree(tree);
    free(revealed);
    return numNodesRevealed * params->seedSizeBytes;
}

size_t revealSeeds(tree_t* tree, uint16_t* hideList, size_t hideListSize, uint8_t* output, size_t outputSize, paramset_t* params)
{
    uint8_t* outputBase = output;
    size_t revealedSize = 0;

    if (outputSize > INT_MAX) {
        return -1;
    }
    int outLen = (int)outputSize;


    size_t* revealed = getRevealedNodes(tree, hideList, hideListSize, &revealedSize);
    for (size_t i = 0; i < revealedSize; i++) {
        outLen -= params->seedSizeBytes;
        if (outLen < 0) {
            assert(!"Insufficient sized buffer provided to revealSeeds");
            free(revealed);
            return 0;
        }
        memcpy(output, tree->nodes[revealed[i]], params->seedSizeBytes);
        output += params->seedSizeBytes;
    }


    free(revealed);
    return output - outputBase;
}

int reconstructSeeds(tree_t* tree, uint16_t* hideList, size_t hideListSize,
                     uint8_t* input, size_t inputLen, uint8_t* salt, size_t repIndex, paramset_t* params)
{
    int ret =  0;

    if (inputLen > INT_MAX) {
        return -1;
    }
    int inLen = (int)inputLen;

    size_t revealedSize = 0;
    size_t* revealed = getRevealedNodes(tree, hideList, hideListSize, &revealedSize);
    for (size_t i = 0; i < revealedSize; i++) {
        inLen -= params->seedSizeBytes;
        if (inLen < 0) {
            ret = -1;
            goto Exit;
        }
        memcpy(tree->nodes[revealed[i]], input, params->seedSizeBytes);
        tree->haveNode[revealed[i]] = 1;
        input += params->seedSizeBytes;
    }

    expandSeeds(tree, salt, repIndex, params);

Exit:
    free(revealed);
    return ret;
}

static void computeParentHash(tree_t* tree, size_t child, uint8_t* salt, paramset_t* params)
{
    if (!exists(tree, child)) {
        return;
    }

    size_t parent = getParent(child);

    if (tree->haveNode[parent]) {
        return;
    }

    /* Compute the hash for parent, if we have everything */
    if (!tree->haveNode[2 * parent + 1]) {
        return;
    }

    if (exists(tree, 2 * parent + 2) && !tree->haveNode[2 * parent + 2]) {
        return;
    }

    /* Compute parent data = H(left child data || [right child data] || salt || parent idx) */
    HashInstance ctx;

    HashInit(&ctx, params, HASH_PREFIX_3);
    HashUpdate(&ctx, tree->nodes[2 * parent + 1], params->digestSizeBytes);
    if (hasRightChild(tree, parent)) {
        /* One node may not have a right child when there's an odd number of leaves */
        HashUpdate(&ctx, tree->nodes[2 * parent + 2], params->digestSizeBytes);
    }

    HashUpdate(&ctx, salt, params->saltSizeBytes);
    HashUpdateIntLE(&ctx, (uint16_t)parent);
    HashFinal(&ctx);
    HashSqueeze(&ctx, tree->nodes[parent], params->digestSizeBytes);
    tree->haveNode[parent] = 1;
}

/* Create a Merkle tree by hashing up all nodes.
 * leafData must have length tree->numNodes, but some may be NULL. */
void buildMerkleTree(tree_t* tree, uint8_t** leafData, uint8_t* salt, paramset_t* params)
{
    size_t firstLeaf = tree->numNodes - tree->numLeaves;

    /* Copy data to the leaves. The actual data being committed to has already been
     * hashed, according to the spec. */
    for (size_t i = 0; i < tree->numLeaves; i++) {
        if (leafData[i] != NULL) {
            memcpy(tree->nodes[firstLeaf + i], leafData[i], tree->dataSize);
            tree->haveNode[firstLeaf + i] = 1;
        }
    }
    /* Starting at the leaves, work up the tree, computing the hashes for intermediate nodes */
    for (int i = (int)tree->numNodes; i > 0; i--) {
        computeParentHash(tree, i, salt, params);
    }
}


/* Note that we never output the root node */
static size_t* getRevealedMerkleNodes(tree_t* tree, uint16_t* missingLeaves,
                                      size_t missingLeavesSize, size_t* outputSize)
{
    size_t firstLeaf = tree->numNodes - tree->numLeaves;
    uint8_t* missingNodes = calloc(tree->numNodes, 1);

    /* Mark leaves that are missing */
    for (size_t i = 0; i < missingLeavesSize; i++) {
        missingNodes[firstLeaf + missingLeaves[i]] = 1;
    }

    /* For the nonleaf nodes, if both leaves are missing, mark it as missing too */
    int lastNonLeaf = getParent(tree->numNodes - 1);
    for (int i = lastNonLeaf; i > 0; i--) {
        if (!exists(tree, i)) {
            continue;
        }
        if (exists(tree, 2 * i + 2)) {
            if (missingNodes[2 * i + 1] && missingNodes[2 * i + 2]) {
                missingNodes[i] = 1;
            }
        }
        else {
            if (missingNodes[2 * i + 1]) {
                missingNodes[i] = 1;
            }
        }
    }

    /* For each missing leaf node, add the highest missing node on the path
     * back to the root to the set to be revealed */
    size_t* revealed = malloc(tree->numLeaves * sizeof(size_t));
    size_t pos = 0;
    for (size_t i = 0; i < missingLeavesSize; i++) {
        size_t node = missingLeaves[i] + firstLeaf;  /* input is leaf indexes, translate to nodes */
        do {
            if (!missingNodes[getParent(node)]) {
                if (!contains(revealed, pos, node)) {
                    revealed[pos] = node;
                    pos++;
                }
                break;
            }
        } while ((node = getParent(node)) != 0);
    }

    free(missingNodes);
    *outputSize = pos;
    return revealed;
}

size_t openMerkleTreeSize(size_t numNodes, uint16_t* missingLeaves, size_t missingLeavesSize, paramset_t* params)
{

    tree_t* tree = createTree(numNodes, params->digestSizeBytes);
    size_t revealedSize = 0;
    size_t* revealed = getRevealedMerkleNodes(tree, missingLeaves, missingLeavesSize, &revealedSize);

    freeTree(tree);
    free(revealed);

    return revealedSize * params->digestSizeBytes;
}


/* Serialze the missing nodes that the verifier will require to check commitments for non-missing leaves */
uint8_t* openMerkleTree(tree_t* tree, uint16_t* missingLeaves, size_t missingLeavesSize, size_t* outputSizeBytes)
{
    size_t revealedSize = 0;
    size_t* revealed = getRevealedMerkleNodes(tree, missingLeaves, missingLeavesSize, &revealedSize);

    /* Serialize output */
    *outputSizeBytes = revealedSize * tree->dataSize;
    uint8_t* output = malloc(*outputSizeBytes);
    uint8_t* outputBase = output;

    for (size_t i = 0; i < revealedSize; i++) {
        memcpy(output, tree->nodes[revealed[i]], tree->dataSize);
        output += tree->dataSize;
    }

    free(revealed);

    return outputBase;
}

/* addMerkleNodes: deserialize and add the data for nodes provided by the committer */
int addMerkleNodes(tree_t* tree, uint16_t* missingLeaves, size_t missingLeavesSize, uint8_t* input, size_t inputSize)
{
    int ret = 0;

    assert(missingLeavesSize < tree->numLeaves);

    if (inputSize > INT_MAX) {
        return -1;
    }
    int intLen = (int)inputSize;

    size_t revealedSize = 0;
    size_t* revealed = getRevealedMerkleNodes(tree, missingLeaves, missingLeavesSize, &revealedSize);
    assert(!contains(revealed, revealedSize, 0));

    /* Deserialize input */
    for (size_t i = 0; i < revealedSize; i++) {
        intLen -= tree->dataSize;
        if (intLen < 0) {
            ret = -1;
            goto Exit;
        }
        memcpy(tree->nodes[revealed[i]], input, tree->dataSize);
        input += tree->dataSize;
        tree->haveNode[revealed[i]] = 1;
    }

    if (intLen != 0) {
        ret = -1;
        goto Exit;
    }

Exit:

    free(revealed);

    return ret;
}

/* verifyMerkleTree: verify for each leaf that is set */
int verifyMerkleTree(tree_t* tree, /* uint16_t* missingLeaves, size_t missingLeavesSize, */
                     uint8_t** leafData, uint8_t* salt, paramset_t* params)
{
    size_t firstLeaf = tree->numNodes - tree->numLeaves;

    /* Copy the leaf data, where we have it. The actual data being committed to has already been
     * hashed, according to the spec. */
    for (size_t i = 0; i < tree->numLeaves; i++) {
        if (leafData[i] != NULL) {
            if (tree->haveNode[firstLeaf + i] == 1) {
                return -1;  /* A leaf was assigned from the prover for a node we've recomputed */
            }

            if (leafData[i] != NULL) {
                memcpy(tree->nodes[firstLeaf + i], leafData[i], tree->dataSize);
                tree->haveNode[firstLeaf + i] = 1;
            }
        }
    }

    /* At this point the tree has some of the leaves, and some intermediate nodes
     * Work up the tree, computing all nodes we don't have that are missing. */
    for (int i = (int)tree->numNodes; i > 0; i--) {
        computeParentHash(tree, i, salt, params);
    }

    /* Fail if the root was not computed. */
    if (!tree->haveNode[0]) {
        return -1;
    }

    return 0;
}

// 

/* Input is the tapes for one parallel repitition; i.e., tapes[t]
 * Updates the random tapes of all players with the mask values for the output of
 * AND gates, and computes the N-th party's share such that the AND gate invariant
 * holds on the mask values.
 */
static void computeAuxTape(randomTape_t* tapes, uint8_t* inputs, paramset_t* params)
{
    uint32_t roundKey[LOWMC_MAX_WORDS];
    uint32_t x[LOWMC_MAX_WORDS] = {0};
    uint32_t y[LOWMC_MAX_WORDS];
    uint32_t key[LOWMC_MAX_WORDS];
    uint32_t key0[LOWMC_MAX_WORDS];

    key0[params->stateSizeWords - 1] = 0;
    tapesToParityBits(key0, params->stateSizeBits, tapes);

    // key = key0 x KMatrix[0]^(-1)
    matrix_mul(key, key0, KMatrixInv(0, params), params);

    if(inputs != NULL) {
        memcpy(inputs, key, params->stateSizeBytes);
    }


    for (uint32_t r = params->numRounds; r > 0; r--) {
        matrix_mul(roundKey, key, KMatrix(r, params), params);    // roundKey = key * KMatrix(r)
        xor_array(x, x, roundKey, params->stateSizeWords);
        matrix_mul(y, x, LMatrixInv(r-1, params), params);

        if(r == 1) {
            // Use key as input
            memcpy(x, key0, params->stateSizeBytes);
        }
        else {
            tapes->pos = params->stateSizeBits * 2 * (r - 1);
            // Read input mask shares from tapes
            tapesToParityBits(x, params->stateSizeBits, tapes);
        }
	tapes->pos = params->stateSizeBits * 2 * (r - 1) + params->stateSizeBits;
        aux_mpc_sbox(x, y, tapes, params);
    }

    // Reset the random tape counter so that the online execution uses the
    // same random bits as when computing the aux shares
    tapes->pos = 0;
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
void getAllRandomness(unsigned char key[16], unsigned char randomness[2912]) {
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

	for(int j=0;j<182;j++) {
		if(1 != EVP_EncryptUpdate(ctx, &randomness[j*16], &len, plaintext, strlen ((char *)plaintext)))
			handleErrors();

	}
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);
}

uint32_t getRandom32(unsigned char randomness[2912], int randCount) {
	uint32_t ret;
	memcpy(&ret, &randomness[randCount], 4);
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

void H(unsigned char k[16], View v, unsigned char r[4], unsigned char hash[SHA256_DIGEST_LENGTH]) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, k, 16);
	SHA256_Update(&ctx, &v, sizeof(v));
	SHA256_Update(&ctx, r, 4);
	SHA256_Final(hash, &ctx);
}


void H3(uint32_t y[8], a* as, int s, int* es) {

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, y, 32);
	SHA256_Update(&ctx, as, sizeof(a)*s);
	SHA256_Final(hash, &ctx);

	//Pick bits from hash
	int i = 0;
	int bitTracker = 0;
	while(i < s) {
		if(bitTracker >= SHA256_DIGEST_LENGTH*8) { //Generate new hash as we have run out of bits in the previous hash
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, hash, sizeof(hash));
			SHA256_Final(hash, &ctx);
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
	memcpy(result, &v.y[ySize - 8], 32);
}

void reconstruct(uint32_t* y0, uint32_t* y1, uint32_t* y2, uint32_t* result) {
	for (int i = 0; i < 8; i++) {
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


int mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][2912], int* randCount, int* countY) {
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


int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][2912], int* randCount, int* countY) {
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

void mpc_RIGHTROTATE2(uint32_t x[], int i, uint32_t z[]) {
	z[0] = RIGHTROTATE(x[0], i);
	z[1] = RIGHTROTATE(x[1], i);
}

void mpc_RIGHTSHIFT2(uint32_t x[2], int i, uint32_t z[2]) {
	z[0] = x[0] >> i;
	z[1] = x[1] >> i;
}


int mpc_MAJ_verify(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t z[3], View ve, View ve1, unsigned char randomness[2][2912], int* randCount, int* countY) {
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

int mpc_CH_verify(uint32_t e[2], uint32_t f[2], uint32_t g[2], uint32_t z[2], View ve, View ve1, unsigned char randomness[2][2912], int* randCount, int* countY) {

	uint32_t t0[3];
	mpc_XOR2(f,g,t0);
	if(mpc_AND_verify(e, t0, t0, ve, ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	mpc_XOR2(t0,g,z);


	return 0;
}


int verify(a a, int e, z z) {
	unsigned char* hash = malloc(SHA256_DIGEST_LENGTH);
	H(z.ke, z.ve, z.re, hash);

	if (memcmp(a.h[e], hash, 32) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	H(z.ke1, z.ve1, z.re1, hash);
	if (memcmp(a.h[(e + 1) % 3], hash, 32) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	free(hash);

	uint32_t* result = malloc(32);
	output(z.ve, result);
	if (memcmp(a.yp[e], result, 32) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}

	output(z.ve1, result);
	if (memcmp(a.yp[(e + 1) % 3], result, 32) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}

	free(result);

	unsigned char randomness[2][2912];
	getAllRandomness(z.ke, randomness[0]);
	getAllRandomness(z.ke1, randomness[1]);

	int* randCount = calloc(1, sizeof(int));
	int* countY = calloc(1, sizeof(int));

	uint32_t w[64][2];
	for (int j = 0; j < 16; j++) {
		w[j][0] = (z.ve.x[j * 4] << 24) | (z.ve.x[j * 4 + 1] << 16)
								| (z.ve.x[j * 4 + 2] << 8) | z.ve.x[j * 4 + 3];
		w[j][1] = (z.ve1.x[j * 4] << 24) | (z.ve1.x[j * 4 + 1] << 16)
								| (z.ve1.x[j * 4 + 2] << 8) | z.ve1.x[j * 4 + 3];
	}

	uint32_t s0[2], s1[2];
	uint32_t t0[2], t1[2];
	for (int j = 16; j < 64; j++) {
		//s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^ (w[i][j-15] >> 3);
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

		if(mpc_ADD_verify(w[j-16], s0, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, j);
#endif
			return 1;
		}


		if(mpc_ADD_verify(w[j-7], t1, t1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, j);
#endif
			return 1;
		}
		if(mpc_ADD_verify(t1, s1, w[j], z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, j);
#endif
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



		if(mpc_ADD_verify(t1, w[i], temp1, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
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



		memcpy(vh, vg, sizeof(uint32_t) * 2);
		memcpy(vg, vf, sizeof(uint32_t) * 2);
		memcpy(vf, ve, sizeof(uint32_t) * 2);
		//e = d+temp1;
		if(mpc_ADD_verify(vd, temp1, ve, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}

		memcpy(vd, vc, sizeof(uint32_t) * 2);
		memcpy(vc, vb, sizeof(uint32_t) * 2);
		memcpy(vb, va, sizeof(uint32_t) * 2);
		//a = temp1+temp2;

		if(mpc_ADD_verify(temp1, temp2, va, z.ve, z.ve1, randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}
	}

	uint32_t hHa[8][3] = { { hA[0],hA[0],hA[0]  }, { hA[1],hA[1],hA[1] }, { hA[2],hA[2],hA[2] }, { hA[3],hA[3],hA[3] },
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

	free(randCount);
	free(countY);

	return 0;
}


#endif /* SHARED_H_ */
