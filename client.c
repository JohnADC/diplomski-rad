#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include <tls.h>

#define BUFSIZE 1000

static void usage()
{
	fprintf(stderr, "usage: ./client\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	struct tls *tls = NULL;
    struct tls_config *config = NULL;
	struct sockaddr_in server_sa;
	char buffer[BUFSIZE];
	u_short port = 9999;
	ssize_t len;
	//char *hostname = "revoked-demo.pca.dfn.de";
	int sd;

	if (argc != 1)
		usage();
	
	printf("Configuring and initializing tls connection\n");
	
	tls_init();

    tls = tls_client();

    config = tls_config_new();

  
    tls_config_set_ca_file(config, "CA/root.pem");
    
    tls_config_set_cert_file(config, "CA/client.crt");
    
    tls_config_set_key_file(config, "CA/client.key");

    //tls_config_insecure_noverifycert(config);

    tls_configure(tls, config);
	 
	//tls_config_ocsp_require_stapling(config);
	 
	memset(&server_sa, 0, sizeof(server_sa));
	server_sa.sin_family = AF_INET;
	server_sa.sin_port = htons(port);
	server_sa.sin_addr.s_addr = inet_addr("localhost");


	if ((sd=socket(AF_INET,SOCK_STREAM,0)) == -1)
		err(1, "socket failed\n");

	printf("Starting TLS connect\n");
	
	if(tls_connect(tls, "localhost", "9999") < 0) {
        errx(1, "tls_connect error %s\n", tls_error(tls));
    }

	len = tls_read(tls, buffer, BUFSIZE);
	printf("Primljeno (%zd): %s\n", len, buffer);

    while(1) {
		fgets(buffer, BUFSIZE, stdin);
		
		if ((len = tls_write(tls, buffer, BUFSIZE) == -1)) break;

        
    }

	//PISANJE I CITANJE OVDJE

	tls_close(tls);
    tls_free(tls);
    tls_config_free(config);
	close(sd);
	return(0);
}
