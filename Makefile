CC = gcc
CFLAGS = -Wall -std=c99 -g

all: encrypt decrypt

encrypt: encrypt.o io.o DES.o DESMagic.o
	$(CC) $(CFLAGS) -o encrypt encrypt.o io.o DES.o DESMagic.o
	
decrypt: decrypt.o io.o DES.o DESMagic.o
	$(CC) $(CFLAGS) -o decrypt decrypt.o io.o DES.o DESMagic.o

encrypt.o: encrypt.c io.h DES.h
	$(CC) $(CFLAGS) -c encrypt.c

decrypt.o: decrypt.c io.h DES.h
	$(CC) $(CFLAGS) -c decrypt.c

io.o: io.c io.h DES.h
	$(CC) $(CFLAGS) -c io.c

DES.o: DES.c DES.h DESMagic.h
	$(CC) $(CFLAGS) -c DES.c

DESMagic.o: DESMagic.c DESMagic.h
	$(CC) $(CFLAGS) -c DESMagic.c