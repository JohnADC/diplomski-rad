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

void commandInfo()
{
	fprintf(stderr, "usage: ./server-browser [-p port] [-r] [-v] [-o]\n\n"
					"Use -p to set port number, 9999 is used as default\n"
					"Use -r to use revoked server certificate\n"
					"Use -o to provide ocsp stappling response\n");
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
	int p, ch;
	int sock, clientsock;
	int revoked = 0, ocsp = 0;
	ssize_t len;
	int opt = 1;

    while((ch = getopt(argc, argv, "p:ro")) != -1){
			switch(ch){
					case 'p':	p = atoi(optarg);
								if(p <= 0 || p > 65535) commandInfo();
								port = (unsigned short)p;
								break;
					case 'r':	revoked = 1;
								break;
					case 'o':	ocsp = 1;
								break;			
					case '?':   commandInfo();
								break;
					default:	commandInfo();
			}
	}
	
    if(optind < argc){
    	commandInfo();
    }

	if(tls_init() == -1)
		errx(1, "tls_init failed");
		
	if((tls = tls_server()) == NULL)
		err(1, "tls_server failed");
	
	if((config = tls_config_new()) == NULL)
		errx(1, "tls_config_new failed");
	
	tls_config_set_ca_file(config, "CA/root.pem");
	
	if(!revoked){
		tls_config_set_cert_file(config, "CA/server.crt");
		
		tls_config_set_key_file(config, "CA/server.key");
		
		if(ocsp){
			tls_config_set_ocsp_staple_file(config, "CA/server.crt-ocsp.der");
		}
	} else {
		tls_config_set_cert_file(config, "CA/revoked.crt");
		
		tls_config_set_key_file(config, "CA/revoked.key");
		
		if(ocsp){
			tls_config_set_ocsp_staple_file(config, "CA/revoked.crt-ocsp.der");
		}
	}
	
	if(tls_configure(tls, config) == -1)
		err(1, "tls_configure failed");
	 
	memset(&server_sa, 0, sizeof(server_sa));
	server_sa.sin_family = AF_INET;
	server_sa.sin_port = htons(port);
	server_sa.sin_addr.s_addr = htonl(INADDR_ANY);



	if ((sock=socket(AF_INET,SOCK_STREAM,0)) == -1)
		err(1, "socket failed\n");
		
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, 4);	
		
	if (bind(sock, (struct sockaddr *) &server_sa, sizeof(server_sa)) == -1)
		err(1, "bind failed\n");

	if(listen(sock, 10) == -1)
		err(1, "listen failed\n");

	socklen_t clientlen = sizeof(client);
	
    if ((clientsock = accept(sock, (struct sockaddr *) &client, &clientlen)) == -1)
		err(1, "accept failed");
	

    if(tls_accept_socket(tls, &ctls, clientsock) < 0) {
        errx(1, "tls_accept_socket error\n");
    }

    if((len = tls_read(ctls, buffer, BUFSIZE)) == -1) {
		errx(1, "tls_write: %s\n", tls_error(ctls));	
	}

	char body[1024]={0};
	sprintf(body, "<HTML> <TITLE>Ovo je do 500 znakova dobivene poruke</TITLE> <BODY BGCOLOR=\"lightblue\">\r\n<p>\r\n%s\r\n<p>\r\n</BODY>\r\n</HTML>\r\n", buffer);
	int bodysize=strlen(body);
	
	char header[1024]={0};
	sprintf(header, "HTTP/1.0 200 OK\r\nContent-Length: %d\r\nContent-Type: text/html\r\n\r\n", bodysize);
	
	strncat(header, body, 500);
		
	if ((len = tls_write(ctls, header, strlen(header))) == -1) {
		errx(1, "tls_read: %s\n", tls_error(ctls));
	}
	
    
	tls_close(ctls);
    tls_free(ctls);
	tls_close(tls);
    tls_free(tls);
    tls_config_free(config);
	close(sock);
	return(0);
}
