TARGETS: PoAO.exe  PoAO.js

SHELL := /bin/bash

PoAO.exe: PoAO.c PoAO.h sha256.c sha256.h ripemd160.c
	gcc -g -Warray-bounds sha256.c ripemd160.c PoAO.c -o PoAO.exe 

PoAO.js: PoAO.c PoAO.h sha256.c sha256.h ripemd160.c
	source ~/dev/emsdk/emsdk_env.sh && emcc -s ALLOW_MEMORY_GROWTH -s MAXIMUM_MEMORY=4GB -DWASM sha256.c ripemd160.c PoAO.c -o PoAO.js -sEXPORTED_RUNTIME_METHODS=ccall -s FORCE_FILESYSTEM=1 

MPC_ADDRESS.exe: MPC_ADDRESS.c shared_address.h
	gcc -g -fopenmp MPC_ADDRESS.c -o MPC_ADDRESS.exe -lssl -lcrypto -lgmp

MPC_ADDRESS_VERIFIER.exe: MPC_ADDRESS_VERIFIER.c shared_address.h
	gcc -fopenmp MPC_ADDRESS_VERIFIER.c -o MPC_ADDRESS_VERIFIER.exe -lssl -lcrypto -lgmp

clean:
	rm MPC_ADDRESS.exe MPC_ADDRESS_VERIFIER.exe PoAO.exe
