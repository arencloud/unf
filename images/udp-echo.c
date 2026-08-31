#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum {
    DEFAULT_PORT = 5353,
    MAX_DATAGRAM_BYTES = 65535,
};

static int parse_port(const char *value)
{
    char *end = NULL;
    errno = 0;
    long port = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || port < 1 || port > 65535) {
        return -1;
    }
    return (int)port;
}

static int socket_family(const char *value)
{
    if (strcmp(value, "4") == 0) {
        return AF_INET;
    }
    if (strcmp(value, "6") == 0) {
        return AF_INET6;
    }
    return -1;
}

int main(int argc, char **argv)
{
    int family = argc > 1 ? socket_family(argv[1]) : AF_INET;
    int port = argc > 2 ? parse_port(argv[2]) : DEFAULT_PORT;
    if (family < 0 || port < 0 || argc > 3) {
        fprintf(stderr, "usage: %s [4|6] [port]\n", argv[0]);
        return 2;
    }

    int socket_fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) {
        perror("socket");
        return 1;
    }
    int enabled = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
        perror("setsockopt(SO_REUSEADDR)");
        close(socket_fd);
        return 1;
    }
    if (family == AF_INET6
        && setsockopt(socket_fd, IPPROTO_IPV6, IPV6_V6ONLY, &enabled, sizeof(enabled)) != 0) {
        perror("setsockopt(IPV6_V6ONLY)");
        close(socket_fd);
        return 1;
    }

    struct sockaddr_storage bind_address;
    memset(&bind_address, 0, sizeof(bind_address));
    socklen_t bind_length;
    if (family == AF_INET) {
        struct sockaddr_in *address = (struct sockaddr_in *)&bind_address;
        address->sin_family = AF_INET;
        address->sin_port = htons((uint16_t)port);
        address->sin_addr.s_addr = htonl(INADDR_ANY);
        bind_length = sizeof(*address);
    } else {
        struct sockaddr_in6 *address = (struct sockaddr_in6 *)&bind_address;
        address->sin6_family = AF_INET6;
        address->sin6_port = htons((uint16_t)port);
        address->sin6_addr = in6addr_any;
        bind_length = sizeof(*address);
    }
    if (bind(socket_fd, (struct sockaddr *)&bind_address, bind_length) != 0) {
        perror("bind");
        close(socket_fd);
        return 1;
    }

    unsigned char *payload = malloc(MAX_DATAGRAM_BYTES);
    if (payload == NULL) {
        perror("malloc");
        close(socket_fd);
        return 1;
    }
    for (;;) {
        struct sockaddr_storage peer;
        socklen_t peer_length = sizeof(peer);
        ssize_t received = recvfrom(socket_fd, payload, MAX_DATAGRAM_BYTES, 0,
                                    (struct sockaddr *)&peer, &peer_length);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recvfrom");
            break;
        }
        ssize_t sent;
        do {
            sent = sendto(socket_fd, payload, (size_t)received, 0,
                          (struct sockaddr *)&peer, peer_length);
        } while (sent < 0 && errno == EINTR);
        if (sent != received) {
            if (sent < 0) {
                perror("sendto");
            } else {
                fprintf(stderr, "short UDP send: %zd of %zd bytes\n", sent, received);
            }
            break;
        }
    }
    free(payload);
    close(socket_fd);
    return 1;
}
