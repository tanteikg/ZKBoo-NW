TARGETS: MPC_SHA512.exe MPC_SHA512_VERIFIER.exe 

MPC_SHA512.exe: MPC_SHA512.c shared512.h
	gcc -g -fopenmp MPC_SHA512.c -o MPC_SHA512.exe -lssl -lcrypto

MPC_SHA512_VERIFIER.exe: MPC_SHA512_VERIFIER.c shared512.h
	gcc -fopenmp MPC_SHA512_VERIFIER.c -o MPC_SHA512_VERIFIER.exe -lssl -lcrypto

clean:
	rm MPC_SHA512.exe MPC_SHA512_VERIFIER.exe
