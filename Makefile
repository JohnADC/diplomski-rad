CC=gcc
CFLAGS=-Wall -Wextra -g -O0 -I/usr/local/include
LDFLAGS=-L/usr/local/lib -lssl -lcrypto -ltls

all: client

#server: server.c
#	${CC} -c ${CFLAGS} $@.c
#	${CC} -o $@ $@.o ${LDFLAGS}

client: client.c
	${CC} -c ${CFLAGS} $@.c
	${CC} -o $@ $@.o ${LDFLAGS}

#server-1: server-1.c
#	${CC} -c ${CFLAGS} $@.c
#	${CC} -o $@ $@.o ${LDFLAGS}

#client-1: client-1.c
#	${CC} -c ${CFLAGS} $@.c
#	${CC} -o $@ $@.o ${LDFLAGS}

clean:
	@-rm -f client
	@-rm -f *.o *.BAK a.out core *.core
	@-rm -fr client.dSYM
	

