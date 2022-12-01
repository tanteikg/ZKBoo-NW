TARGETS: MPC_SHA256.exe MPC_SHA256_VERIFIER.exe 

MPC_SHA256.exe: MPC_SHA256.c shared.h
	gcc -fopenmp MPC_SHA256.c -o MPC_SHA256.exe -lssl -lcrypto

MPC_SHA256_VERIFIER.exe: MPC_SHA256_VERIFIER.c shared.h
	gcc -fopenmp MPC_SHA256_VERIFIER.c -o MPC_SHA256_VERIFIER.exe -lssl -lcrypto

clean:
	rm MPC_SHA256.exe MPC_SHA256_VERIFIER.exe
