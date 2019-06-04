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
#include <poll.h>


#include <tls.h>

#DEFINE BUFSIZE 1024

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
	struct sockaddr_in server_sa;
	char buffer[BUFSIZE];
	pid_t pid;
	u_short port = 9999;
	int sd;
	int revoked = 0, ocsp = 0;
	char *msg = "HELLO TLS CLIENT\n";
	ssize_t len;


	if (argc != 1)
		usage();
	
	printf("Configuring and initializing tls connection\n")	
	
	tls_config = tls_config_new();
	
	tls_config_verify_client_optional(tls_config);
	
	tls_config_set_ca_file(tls_config, "CA/root.pem");
	
	if(!revoked){
		tls_config_set_cert_file(tls_config, "CA/server.crt");
		
		tls_config_set_key_file(tls_config, "CA/server.key");
		
		if(ocsp){
			tls_config_set_ocsp_staple_file(tls_config, "CA/server.crt-ocsp.der");
		}
	} else {
		tls_config_set_cert_file(tls_config, "CA/revoked.crt");
		
		tls_config_set_key_file(tls_config, "CA/revoked.key");
		
		if(ocsp){
			tls_config_set_ocsp_staple_file(tls_config, "CA/revoked.crt-ocsp.der");
		}
	}

	tls = tls_server(); 
	
	tls_configure(tls, tls_config);
	 
	memset(&server_sa, 0, sizeof(server_sa));
	server_sa.sin_family = AF_INET;
	server_sa.sin_port = htons(port);
	server_sa.sin_addr.s_addr = inet_addr(INADDR_ANY);



	if ((sd=socket(AF_INET,SOCK_STREAM,0)) == -1)
		err(1, "socket failed\n");

	listen(sd, 10);

    sd = accept(sock, (struct sockaddr *) &client, sizeof(client));

    if(tls_accept_socket(tls, &ctls, sd) < 0) {
        errx(1, "tls_accept_socket error\n");
    }

    len = tls_write(ctls, msg, strlen(msg));



    while(1) {

		if ((len = tls_read(ctls, buffer, BUFSIZE) == -1) break;
		bufs[len] = '\0';
		if (len == 0) { 
			break;
		}
		printf("Primljeno (%zd): %s\n", len, buffer);
        
    }
    tls_close(ctls);
    tls_close(tls);
    tls_free(ctls);
    tls_free(tls);
    tls_config_free(config);

	



	//PISANJE I CITANJE OVDJE

	tls_close(tls);
    tls_free(tls);
    tls_config_free(config);
	close(sd);
	return(0);
}
