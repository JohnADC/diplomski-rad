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
#include <time.h>
#include <stdarg.h>

#include <tls.h>

#define BUFSIZE 1000

void report_tls(struct tls * tls_ctx, char * host);

void commandInfo()
{
	fprintf(stderr, "usage: ./client [-p port] [-r] [-v] [-o]\n\n"
					"Use -p to set port number, 9999 is used as default\n"
					"Use -r to use revoked client certificate\n"
					"Use -v to verify server certificate\n"
					"Use -o to require ocsp stappling\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	struct tls *tls = NULL;
    struct tls_config *config = NULL;
	struct sockaddr_in server_sa;
	char buffer[BUFSIZE];
	u_short port = 9999;
	int p, ch;
	ssize_t len;
	int sock;
	int revoked = 0, ocsp = 0, verify = 0;

    while((ch = getopt(argc, argv, "p:rov")) != -1){
			switch(ch){
					case 'p':	p = atoi(optarg);
								if(p <= 0 || p > 65535) commandInfo();
								port = (unsigned short)p;
								break;
					case 'r':	revoked = 1;
								break;
					case 'o':	ocsp = 1;
								break;			
					case 'v':	verify = 1;
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
		
	if((tls = tls_client()) == NULL)
		err(1, "tls_client failed");
	
	if((config = tls_config_new()) == NULL)
		errx(1, "tls_config_new failed");

	if(!verify){
		tls_config_insecure_noverifycert(config);	
    } else {
		if (tls_config_set_crl_file(config, "CA/intermediate/crl/intermediate.crl.pem") == -1)
			errx(1, "unable to set crl file");
	}
    
    tls_config_set_ca_file(config, "CA/root.pem");
    
    if(!revoked){			
		tls_config_set_cert_file(config, "CA/client.crt");
		
		tls_config_set_key_file(config, "CA/client.key");
		
	}else{
		tls_config_set_cert_file(config, "CA/revoked.crt");
    
		tls_config_set_key_file(config, "CA/revoked.key");
	}
		
	if(ocsp){ 
		tls_config_ocsp_require_stapling(config);
	 }

    if (tls_config_set_crl_file(config, "CA/intermediate/crl/intermediate.crl.pem") == -1)
		errx(1, "unable to set crl file");

	if(tls_configure(tls, config) == -1)
		err(1, "tls_configure failed");
    
	 
	memset(&server_sa, 0, sizeof(server_sa));
	server_sa.sin_family = AF_INET;
	server_sa.sin_port = htons(port);
	server_sa.sin_addr.s_addr = inet_addr("127.0.0.1");


	if ((sock=socket(AF_INET,SOCK_STREAM,0)) == -1)
		err(1, "socket failed\n");

	printf("Starting TLS connect\n");
	
	if (connect(sock, (struct sockaddr *)&server_sa, sizeof(server_sa)) < 0) {
        err(1, "Connect");
    }
	
	if(tls_connect_socket(tls, sock,"localhost") < 0) {
        errx(1, "tls_connect error %s\n", tls_error(tls));
    }

	if ((len = tls_handshake(tls)) == -1) {
		errx(1, "tls_handshake: %s\n", tls_error(tls));
	}
	
	report_tls(tls, "localhost");

	if ((len = tls_read(tls, buffer, BUFSIZE)) == -1) {
		errx(1, "tls_read: %s\n", tls_error(tls));
	}
	
	buffer[len]='\0';
	printf("Server message: %s\n", buffer);
	
    while(1) {
		memset(buffer, 0, BUFSIZE);
		fgets(buffer, BUFSIZE, stdin);

		if ((len = tls_write(tls, buffer, BUFSIZE) == -1)) {
				errx(1, "tls_write: %s\n", tls_error(tls));
		}
        
    }

	

	tls_close(tls);
    tls_free(tls);
    tls_config_free(config);
	close(sock);
	return(0);
}



//This function has been created by Bob Beck and taken from https://github.com/bob-beck/
void report_tls(struct tls * tls_ctx, char * host)
{
	time_t t;
	const char *ocsp_url;

	fprintf(stderr, "TLS handshake negotiated %s/%s with host %s\n",
	    tls_conn_version(tls_ctx), tls_conn_cipher(tls_ctx), host);
	fprintf(stderr, "Peer name: %s\n", host);
	if (tls_peer_cert_subject(tls_ctx))
		fprintf(stderr, "Subject: %s\n",
		    tls_peer_cert_subject(tls_ctx));
	if (tls_peer_cert_issuer(tls_ctx))
		fprintf(stderr, "Issuer: %s\n",
		    tls_peer_cert_issuer(tls_ctx));
	if ((t = tls_peer_cert_notbefore(tls_ctx)) != -1)
		fprintf(stderr, "Valid From: %s", ctime(&t));
	if ((t = tls_peer_cert_notafter(tls_ctx)) != -1)
		fprintf(stderr, "Valid Until: %s", ctime(&t));
	if (tls_peer_cert_hash(tls_ctx))
		fprintf(stderr, "Cert Hash: %s\n",
		    tls_peer_cert_hash(tls_ctx));
	ocsp_url = tls_peer_ocsp_url(tls_ctx);
	if (ocsp_url != NULL)
		fprintf(stderr, "OCSP URL: %s\n", ocsp_url);
	switch (tls_peer_ocsp_response_status(tls_ctx)) {
	case TLS_OCSP_RESPONSE_SUCCESSFUL:
		fprintf(stderr, "OCSP Stapling: %s\n",
		    tls_peer_ocsp_result(tls_ctx) == NULL ?  "" :
		    tls_peer_ocsp_result(tls_ctx));
		fprintf(stderr,
		    "  response_status=%d cert_status=%d crl_reason=%d\n",
		    tls_peer_ocsp_response_status(tls_ctx),
		    tls_peer_ocsp_cert_status(tls_ctx),
		    tls_peer_ocsp_crl_reason(tls_ctx));
		t = tls_peer_ocsp_this_update(tls_ctx);
		fprintf(stderr, "  this update: %s",
		    t != -1 ? ctime(&t) : "\n");
		t =  tls_peer_ocsp_next_update(tls_ctx);
		fprintf(stderr, "  next update: %s",
		    t != -1 ? ctime(&t) : "\n");
		t =  tls_peer_ocsp_revocation_time(tls_ctx);
		fprintf(stderr, "  revocation: %s",
		    t != -1 ? ctime(&t) : "\n");
		break;
	case -1:
		break;
	default:
		fprintf(stderr, "OCSP Stapling:  failure - response_status %d (%s)\n",
		    tls_peer_ocsp_response_status(tls_ctx),
		    tls_peer_ocsp_result(tls_ctx) == NULL ?  "" :
		    tls_peer_ocsp_result(tls_ctx));
		break;

	}
}
