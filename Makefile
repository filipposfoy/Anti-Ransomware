CC = gcc
CFLAGS = -g
LIBS = -lcrypto -lcurl

all: antivirus

antivirus: antivirus.o list.o
	$(CC) antivirus.o list.o $(LIBS) -o antivirus $(CFLAGS)

antivirus.o: antivirus.c
	$(CC) -c antivirus.c $(CFLAGS)

list.o: utilities/list.c
	$(CC) -c utilities/list.c $(CFLAGS)

clean:
	rm -f *.o antivirus
