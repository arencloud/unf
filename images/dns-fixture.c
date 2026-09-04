#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

enum { DNS_PORT = 53, DNS_MAX_MESSAGE = 512 };

static uint16_t read_u16(const uint8_t *value) {
    return (uint16_t)(((uint16_t)value[0] << 8) | value[1]);
}

static void write_u16(uint8_t *value, uint16_t number) {
    value[0] = (uint8_t)(number >> 8);
    value[1] = (uint8_t)number;
}

static void write_u32(uint8_t *value, uint32_t number) {
    value[0] = (uint8_t)(number >> 24);
    value[1] = (uint8_t)(number >> 16);
    value[2] = (uint8_t)(number >> 8);
    value[3] = (uint8_t)number;
}

static int parse_question(const uint8_t *message, size_t length, char *name,
                          size_t name_capacity, size_t *question_end,
                          uint16_t *query_type) {
    if (length < 17 || read_u16(message + 4) != 1) return -1;
    size_t offset = 12;
    size_t written = 0;
    while (offset < length) {
        uint8_t label_length = message[offset++];
        if (label_length == 0) break;
        if ((label_length & 0xc0U) != 0 || label_length > 63 ||
            offset + label_length > length) return -1;
        if (written != 0) {
            if (written + 1 >= name_capacity) return -1;
            name[written++] = '.';
        }
        if (written + label_length >= name_capacity) return -1;
        memcpy(name + written, message + offset, label_length);
        written += label_length;
        offset += label_length;
    }
    if (offset + 4 > length || written == 0) return -1;
    name[written] = '\0';
    *query_type = read_u16(message + offset);
    if (read_u16(message + offset + 2) != 1) return -1;
    *question_end = offset + 4;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: %s NAME IPV4 IPV6 TTL EMPTY_FILE\n", argv[0]);
        return 2;
    }
    struct in_addr answer_v4;
    struct in6_addr answer_v6;
    if (inet_pton(AF_INET, argv[2], &answer_v4) != 1 ||
        inet_pton(AF_INET6, argv[3], &answer_v6) != 1) {
        fputs("invalid fixture address\n", stderr);
        return 2;
    }
    char *end = NULL;
    unsigned long parsed_ttl = strtoul(argv[4], &end, 10);
    if (end == argv[4] || *end != '\0' || parsed_ttl == 0 || parsed_ttl > UINT32_MAX) {
        fputs("invalid fixture TTL\n", stderr);
        return 2;
    }
    uint32_t ttl = (uint32_t)parsed_ttl;
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        perror("socket");
        return 1;
    }
    int reuse = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
        perror("setsockopt");
        return 1;
    }
    struct sockaddr_in listen_address = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr = {.s_addr = htonl(INADDR_ANY)},
    };
    if (bind(socket_fd, (struct sockaddr *)&listen_address, sizeof(listen_address)) != 0) {
        perror("bind");
        return 1;
    }
    for (;;) {
        uint8_t request[DNS_MAX_MESSAGE];
        struct sockaddr_storage peer;
        socklen_t peer_length = sizeof(peer);
        ssize_t received = recvfrom(socket_fd, request, sizeof(request), 0,
                                    (struct sockaddr *)&peer, &peer_length);
        if (received < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            return 1;
        }
        char query_name[254];
        size_t question_end = 0;
        uint16_t query_type = 0;
        if (parse_question(request, (size_t)received, query_name, sizeof(query_name),
                           &question_end, &query_type) != 0 ||
            strcasecmp(query_name, argv[1]) != 0) continue;
        uint8_t response[DNS_MAX_MESSAGE];
        memcpy(response, request, question_end);
        int authoritative_empty = access(argv[5], F_OK) == 0;
        int has_answer = !authoritative_empty && (query_type == 1 || query_type == 28);
        write_u16(response + 2, authoritative_empty ? 0x8183U : 0x8180U);
        write_u16(response + 6, has_answer ? 1 : 0);
        write_u16(response + 8, 0);
        write_u16(response + 10, 0);
        size_t response_length = question_end;
        if (has_answer) {
            response[response_length++] = 0xc0;
            response[response_length++] = 0x0c;
            write_u16(response + response_length, query_type);
            response_length += 2;
            write_u16(response + response_length, 1);
            response_length += 2;
            write_u32(response + response_length, ttl);
            response_length += 4;
            uint16_t data_length = query_type == 1 ? 4 : 16;
            write_u16(response + response_length, data_length);
            response_length += 2;
            memcpy(response + response_length,
                   query_type == 1 ? (const void *)&answer_v4 : (const void *)&answer_v6,
                   data_length);
            response_length += data_length;
        }
        if (sendto(socket_fd, response, response_length, 0,
                   (struct sockaddr *)&peer, peer_length) < 0) {
            perror("sendto");
            return 1;
        }
    }
}
