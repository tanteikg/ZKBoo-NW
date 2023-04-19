TARGETS: KKW_ECC KKW_ECC_VERIFIER

KKW_ECC: KKW_ECC.c KKW_shared.h
	gcc -g KKW_ECC.c -o KKW_ECC -lssl -lcrypto -lgmp

KKW_ECC_VERIFIER: KKW_ECC_VERIFIER.c KKW_shared.h
	gcc -g KKW_ECC_VERIFIER.c -o KKW_ECC_VERIFIER -lssl -lcrypto -lgmp

clean:
	rm KKW_ECC KKW_ECC_VERIFIER
