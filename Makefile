all:
	gcc -o lookup_bep_034 main.c lookup_bep_034.c -lresolv -pthread
