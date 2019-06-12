CC=gcc
CFLAGS=-Wall -Wextra -g -O0 -I/usr/local/include
LDFLAGS=-L/usr/local/lib -lssl -lcrypto -ltls

all: client server server-browser

server: server.c
	${CC} -c ${CFLAGS} $@.c
	${CC} -o $@ $@.o ${LDFLAGS}

server-browser: server-browser.c
	${CC} -c ${CFLAGS} $@.c
	${CC} -o $@ $@.o ${LDFLAGS}

client: client.c
	${CC} -c ${CFLAGS} $@.c
	${CC} -o $@ $@.o ${LDFLAGS}


clean:
	@-rm -f client
	@-rm -f server
	@-rm -f server-browser
	@-rm -f *.o *.BAK a.out core *.core
	@-rm -fr client.dSYM
	@-rm -fr server.dSYM
	@-rm -fr server-browser.dSYM
	
