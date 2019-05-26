//revoked-demo.pca.dfn.de

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
	char buffer[80];
	size_t maxread;
	ssize_t r, rc;
	u_short port = 80;
	char *hostname = "revoked-demo.pca.dfn.de";
	int sd;
	printf("2\n");
	if (argc != 1)
		usage();
	printf("3\n");
	tls_init();

    tls = tls_client();

    config = tls_config_new();

    // Ako imam CA certifikat:
    //tls_config_set_ca_path(config, "../../../etc/ssl/certs");
    // a ako nemam:
    tls_config_insecure_noverifycert(config);

    // Ako provjeravam hostname, tj. CN u certifikatu:
    // u tls_connect_socket se upise CN: "MM server"
    // a ako ne zelim provjeru:
    // tls_config_insecure_noverifyname(config);

    tls_configure(tls, config);

	/*
	 * first set up "server_sa" to be the location of the server
	 */
	 
	tls_config_ocsp_require_stapling(config);
	 
	memset(&server_sa, 0, sizeof(server_sa));
	server_sa.sin_family = AF_INET;
	server_sa.sin_port = htons(port);
	server_sa.sin_addr.s_addr = inet_addr("193.174.13.82");
	if (server_sa.sin_addr.s_addr == INADDR_NONE) {
		fprintf(stderr, "Invalid IP address %s\n", argv[1]);
		usage();
	}
	printf("4\n");
	/* ok now get a socket. we don't care where... */
	if ((sd=socket(AF_INET,SOCK_STREAM,0)) == -1)
		err(1, "socket failed\n");
	printf("4.1\n");
	/* connect the socket to the server described in "server_sa" */
	//if (connect(sd, (struct sockaddr *)&server_sa, sizeof(server_sa))== -1){
		//printf("4.1.1\n");
		//err(1, "connect failed\n");
	//}
	printf("4.2\n");
	if(tls_connect(tls, hostname, "443") < 0) {
        errx(1, "tls_connect error %s\n", tls_error(tls));
    }
	printf("5\n");



	r = -1;
	rc = 0;
	maxread = sizeof(buffer) - 1; /* leave room for a 0 byte */
	while ((r != 0) && rc < maxread) {
		r = tls_read(tls, buffer + rc, maxread - rc);
		if (r == -1) {
			if (errno != EINTR)
				err(1, "read failed");
		} else
			rc += r;
	}
	/*
	 * we must make absolutely sure buffer has a terminating 0 byte
	 * if we are to use it as a C string
	 */
	buffer[rc] = '\0';

	printf("Server sent:  %s\n",buffer);
	tls_close(tls);
    tls_free(tls);
    tls_config_free(config);
	close(sd);
	return(0);
}
