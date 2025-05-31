#include "consts.h"
#include "security.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <sys/fcntl.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: server <port>\n");
        exit(1);
    }

    /* Create sockets */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    // use IPv4  use UDP

    /* Construct our address */
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET; // use IPv4
    server_addr.sin_addr.s_addr =
        INADDR_ANY; // accept all connections
                    // same as inet_addr("0.0.0.0")
                    // "Address string to network bytes"
    // Set receiving port
    int PORT = atoi(argv[1]);
    server_addr.sin_port = htons(PORT); // Big endian

    // Let operating system know about our config */
    bind(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr));

    // Listen for new clients
    listen(sockfd, 5);

    struct sockaddr_in client_addr; // Same information, but about client
    socklen_t client_size = sizeof(client_addr);

    // Accept client connection
    int clientfd = accept(sockfd, (struct sockaddr*) &client_addr, &client_size);
    if (clientfd < 0) {
        perror("accept");
        exit(1);
    }

    // Set the socket nonblocking
    int flags = fcntl(clientfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(clientfd, F_SETFL, flags);
    setsockopt(clientfd, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));
    setsockopt(clientfd, SOL_SOCKET, SO_REUSEPORT, &(int) {1}, sizeof(int));

    // Initialize 'state_sec' for server
    init_sec(SERVER_CLIENT_HELLO_AWAIT, NULL, argc > 2);
    uint8_t buffer[2048];
    ssize_t len;
    while (clientfd) {
        // receive data
        len = recv(clientfd, buffer, sizeof(buffer), 0);
        if (len > 0) {
            output_sec(buffer, len);
        }

        memset(buffer, 0, sizeof(buffer)); // clear the buffer before reuse

        // send data
        len = input_sec(buffer, sizeof(buffer));
        if (len > 0) {
            send(clientfd, buffer, len, 0);
        }
    }
    close(clientfd);
    close(sockfd);
    return 0;
}
