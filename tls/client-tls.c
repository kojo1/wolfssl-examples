/* client-tls.c
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */
 
 
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "cyassl/ctaocrypt/settings.h"

#include    <stdio.h>
#include    <stdlib.h>
#include    <string.h>

#if defined(CYASSL_LWIP)
     #include "lwip/sockets.h"
     #define inet_pton(af, src, dst) ( *(unsigned long *)dst = inet_addr(src))
#else
     #include    <unistd.h>
     #include    <errno.h>
     #include    <arpa/inet.h>
#endif

#include    <cyassl/ssl.h>          /* CyaSSL security library */

#define MAXDATASIZE  4096   /* maximum acceptable amount of data */
#define SERV_PORT    11111    /* define default port number */

#if !defined(NO_SERVER_CERT)
const char* cert = "../certs/ca-cert.pem";
#endif

/* 
 * resolving secape sequence
 */
static void esc_seq(char *buff) 
{
    int i, j ;

    for(i=0, j=0; i<strlen(buff); i++, j++) {
        if(buff[i]=='\\') {
            switch (buff[i+1]) {
            case 'n':
                buff[j] = '\n' ;
                break ;
            case 'r':
                buff[j] = '\r' ; 
                break ;
            default:  /* unknow cahr */
                buff[j] = buff[i+1] ;
                break ;
            }
            i++ ;
        } else	buff[j] = buff[i] ;
    }
    buff[j+1] = '\0' ;
}

/* 
 * clients initial contact with server. (socket to connect, security layer)
 */
static int ClientGreet(int sock, CYASSL* ssl)
{
    /* data to send to the server, data recieved from the server */
    char   sendBuff[MAXDATASIZE], rcvBuff[MAXDATASIZE] = {0};
    int     ret = 0;                /* variable for error checking */

    printf("Message for server:\t");
    fgets(sendBuff, MAXDATASIZE, stdin) ;
    esc_seq(sendBuff) ;

    if (CyaSSL_write(ssl, sendBuff, strlen(sendBuff)) != strlen(sendBuff)) {
        /* the message is not able to send, or error trying */
        ret = CyaSSL_get_error(ssl, 0);
        printf("Write error: Error: %i\n", ret);
        return EXIT_FAILURE;
    }

    printf("Recieved: \t" ) ;
    do {
        ret = CyaSSL_read(ssl, rcvBuff, MAXDATASIZE-1) ;
        if (ret < 0) {
            /* the server failed to send data, or error trying */
            ret = CyaSSL_get_error(ssl, 0);
            printf("Read error. Error: %i\n", ret);
            return EXIT_FAILURE;
        }
        rcvBuff[ret] = '\0' ;
        printf("%s", rcvBuff);
    }while(ret > 0) ;

    return 0;
}

/* 
 * applies TLS 1.2 security layer to data being sent.
 */
static int Security(int sock)
{
    CYASSL_CTX* ctx;
    CYASSL*     ssl;    /* create CYASSL object */
    int         ret = 0;

    CyaSSL_Init();      /* initialize CyaSSL */
    /* CyaSSL_Debugging_ON() ;  */
    
    /* create and initiLize CYASSL_CTX structure */
    if ((ctx = CyaSSL_CTX_new(CyaTLSv1_2_client_method())) == NULL) {
        printf("SSL_CTX_new error.\n");
        return EXIT_FAILURE;
    }

#if !defined(NO_SERVER_CERT)
    /* load CA certificates into CyaSSL_CTX. which will verify the server */
    if (CyaSSL_CTX_load_verify_locations(ctx, cert, 0) != SSL_SUCCESS) {
        printf("Error loading %s. Please check the file.\n", cert);
        return EXIT_FAILURE;
    }
#else
    CyaSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
#endif
    if ((ssl = CyaSSL_new(ctx)) == NULL) {
        printf("CyaSSL_new error.\n");
        return EXIT_FAILURE;
    }
    CyaSSL_set_fd(ssl, sock);

    ret = CyaSSL_connect(ssl);
    if (ret == SSL_SUCCESS) {
        ret = ClientGreet(sock, ssl);
    } else {
        printf("CyaSSL connection error.\n");
        return EXIT_FAILURE;
    }

    /* frees all data before client termination */
    CyaSSL_free(ssl);
    CyaSSL_CTX_free(ctx);
    CyaSSL_Cleanup();

    return ret;
}

/* 
 * Command line argumentCount and argumentValues 
 */
#if defined(NO_MAIN_DRIVER)
int client_tls_main(int argc, char** argv) 
#else
int main(int argc, char** argv) 
#endif
{
    int     sockfd;                         /* socket file descriptor */
    struct  sockaddr_in servAddr;           /* struct for server address */
    int     ret = 0;                        /* variable for error checking */
	
    if ((argc != 2) && (argc != 3)) {
        /* if the number of arguments is not two, error */
        printf("usage: ./client-tls  <IP address> [<Port number>]\n");
        return EXIT_FAILURE;
    }

    /* internet address family, stream based tcp, default protocol */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        printf("Failed to create socket. Error: %i\n", errno);
        return EXIT_FAILURE;
    }
  
    memset(&servAddr, 0, sizeof(servAddr)); /* clears memory block for use */  
    servAddr.sin_family = AF_INET;          /* sets addressfamily to internet*/
    servAddr.sin_port = (argc == 3) ? htons(atoi(argv[2])) : htons(SERV_PORT);   
                                            /* sets port to defined port */

    /* looks for the server at the entered address (ip in the command line) */
    if (inet_pton(AF_INET, argv[1], &servAddr.sin_addr) < 1) {
        /* checks validity of address */
        ret = errno;
        printf("Invalid Address. Error: %i\n", ret);
        return EXIT_FAILURE;
    }

    if (connect(sockfd, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
        /* if socket fails to connect to the server*/
        ret = errno;
        printf("Connect error. Error: %i\n", ret);
        return EXIT_FAILURE;
    }
    Security(sockfd);

#if defined(CYASSL_CLOSESOCKET)
    closesocket(sockfd) ;
#else
    close(sockfd) ;
#endif
    return ret;
}
