#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void usage(const char *program) {
    fprintf(stderr, "usage: %s ADDRESS PORT hop|destination|both\n", program);
}

static struct cmsghdr *append_options(struct msghdr *message, struct cmsghdr *previous,
                                      int type) {
    struct cmsghdr *control = previous == NULL ? CMSG_FIRSTHDR(message) : CMSG_NXTHDR(message, previous);
    if (control == NULL) {
        return NULL;
    }
    control->cmsg_level = IPPROTO_IPV6;
    control->cmsg_type = type;
    control->cmsg_len = CMSG_LEN(8);
    uint8_t options[8] = {IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0};
    memcpy(CMSG_DATA(control), options, sizeof(options));
    return control;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        usage(argv[0]);
        return 2;
    }
    char *end = NULL;
    long parsed_port = strtol(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0' || parsed_port < 1 || parsed_port > 65535) {
        usage(argv[0]);
        return 2;
    }

    struct sockaddr_in6 destination = {
        .sin6_family = AF_INET6,
        .sin6_port = htons((uint16_t)parsed_port),
    };
    if (inet_pton(AF_INET6, argv[1], &destination.sin6_addr) != 1) {
        fprintf(stderr, "invalid IPv6 address: %s\n", argv[1]);
        return 2;
    }

    int socket_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        perror("socket");
        return 1;
    }
    struct sockaddr_in6 source = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(40000),
        .sin6_addr = IN6ADDR_ANY_INIT,
    };
    if (bind(socket_fd, (struct sockaddr *)&source, sizeof(source)) != 0) {
        perror("bind");
        close(socket_fd);
        return 1;
    }

    uint8_t payload[] = "unf-ipv6-extension-probe";
    struct iovec vector = {.iov_base = payload, .iov_len = sizeof(payload)};
    char control_buffer[2 * CMSG_SPACE(8)] = {0};
    struct msghdr message = {
        .msg_name = &destination,
        .msg_namelen = sizeof(destination),
        .msg_iov = &vector,
        .msg_iovlen = 1,
        .msg_control = control_buffer,
        .msg_controllen = sizeof(control_buffer),
    };

    struct cmsghdr *last = NULL;
    if (strcmp(argv[3], "hop") == 0 || strcmp(argv[3], "both") == 0) {
        last = append_options(&message, last, IPV6_HOPOPTS);
    }
    if (strcmp(argv[3], "destination") == 0 || strcmp(argv[3], "both") == 0) {
        last = append_options(&message, last, IPV6_DSTOPTS);
    }
    if (last == NULL) {
        usage(argv[0]);
        close(socket_fd);
        return 2;
    }
    message.msg_controllen = (size_t)((char *)last - control_buffer) + CMSG_SPACE(8);

    if (sendmsg(socket_fd, &message, 0) < 0) {
        fprintf(stderr, "sendmsg: %s\n", strerror(errno));
        close(socket_fd);
        return 1;
    }
    close(socket_fd);
    return 0;
}
