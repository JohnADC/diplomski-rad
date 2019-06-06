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

#define BUFSIZE 1024

static void usage()
{
	fprintf(stderr, "usage: ./server\n");
	exit(1);
}


int main(int argc, char *argv[])
{
	struct tls *tls = NULL;
	struct tls *ctls = NULL;
    struct tls_config *config = NULL;
	struct sockaddr_in server_sa, client;
	char buffer[BUFSIZE];
	u_short port = 9999;
	int sd, clientsd;
	int revoked = 1, ocsp = 1;
	char *msg = "HELLO TLS CLIENT\n";
	ssize_t len;


	if (argc != 1)
		usage();
	
	printf("Configuring and initializing tls connection\n");	
	
	config = tls_config_new();
	
	tls_config_verify_client_optional(config);
	
	tls_config_set_ca_file(config, "CA/root.pem");
	
	if(!revoked){
		tls_config_set_cert_file(config, "CA/server.crt");
		
		tls_config_set_key_file(config, "CA/server.key");
		
		if(ocsp){
			tls_config_set_ocsp_staple_file(config, "CA/server.crt-ocsp.der.new");
		}
	} else {
		tls_config_set_cert_file(config, "CA/revoked.crt");
		
		tls_config_set_key_file(config, "CA/revoked.key");
		
		if(ocsp){
			tls_config_set_ocsp_staple_file(config, "CA/revoked.crt-ocsp.der.new");
		}
	}

	tls = tls_server(); 
	
	tls_configure(tls, config);
	 
	memset(&server_sa, 0, sizeof(server_sa));
	server_sa.sin_family = AF_INET;
	server_sa.sin_port = htons(port);
	server_sa.sin_addr.s_addr = htonl(INADDR_ANY);



	if ((sd=socket(AF_INET,SOCK_STREAM,0)) == -1)
		err(1, "socket failed\n");
		
	bind(sd, (struct sockaddr *) &server_sa, sizeof(server_sa)); 

	listen(sd, 10);

	socklen_t clientlen = sizeof(client);
	
    clientsd = accept(sd, (struct sockaddr *) &client, &clientlen);
	

    if(tls_accept_socket(tls, &ctls, clientsd) < 0) {
        errx(1, "tls_accept_socket error\n");
    }

    len = tls_write(ctls, msg, strlen(msg));

	printf("sent %s, size %d\n", msg, (int)len);


    while(1) {
		printf("Cekam da se klijent javi\n");
		
		if ((len = tls_read(ctls, buffer, BUFSIZE)) == -1) {
			errx(1, "tls_read: %s\n", tls_error(ctls));
		}
		
		buffer[len] = '\0';
		if (len == 0) { 
			break;
		}
		printf("Primljeno (%zd): %s\n", len, buffer);
        
    }

	tls_close(ctls);
    tls_free(ctls);
	tls_close(tls);
    tls_free(tls);
    tls_config_free(config);
	close(sd);
	return(0);
}
