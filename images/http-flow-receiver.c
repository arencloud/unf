#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum {
    DEFAULT_PORT = 8080,
    MAX_HEADER_BYTES = 65536,
    MAX_BODY_BYTES = 2 * 1024 * 1024,
};

struct receiver_state {
    const char *expected_token;
    uint64_t fail_first;
    uint64_t attempts;
    uint64_t accepted;
    uint64_t delay_millis;
    uint64_t last_sequence;
    uint64_t sequence_duplicates;
    uint64_t sequence_regressions;
    uint64_t max_body_bytes;
    bool has_sequence;
    char *last_body;
    size_t last_body_length;
};

static void delay_response(uint64_t delay_millis)
{
    struct timespec delay = {
        .tv_sec = (time_t)(delay_millis / 1000),
        .tv_nsec = (long)((delay_millis % 1000) * 1000000),
    };
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

static void record_export_sequence(struct receiver_state *state, const char *body)
{
    const char marker[] = "\"export_sequence\":";
    const char *value = strstr(body, marker);
    if (value == NULL) {
        return;
    }
    value += sizeof(marker) - 1;
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || parsed == 0) {
        return;
    }
    uint64_t sequence = (uint64_t)parsed;
    if (state->has_sequence) {
        if (sequence == state->last_sequence) {
            state->sequence_duplicates++;
        } else if (sequence < state->last_sequence) {
            state->sequence_regressions++;
        }
    }
    state->last_sequence = sequence;
    state->has_sequence = true;
}

static int send_all(int socket_fd, const char *data, size_t length)
{
    while (length > 0) {
        ssize_t sent = send(socket_fd, data, length, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        data += sent;
        length -= (size_t)sent;
    }
    return 0;
}

static int respond(int socket_fd, int status, const char *reason,
                   const char *content_type, const char *body, size_t body_length)
{
    char header[512];
    int header_length = snprintf(header, sizeof(header),
                                 "HTTP/1.1 %d %s\r\n"
                                 "Content-Type: %s\r\n"
                                 "Content-Length: %zu\r\n"
                                 "Connection: close\r\n\r\n",
                                 status, reason, content_type, body_length);
    if (header_length < 0 || (size_t)header_length >= sizeof(header)) {
        return -1;
    }
    if (send_all(socket_fd, header, (size_t)header_length) != 0) {
        return -1;
    }
    return body_length == 0 || send_all(socket_fd, body, body_length) == 0 ? 0 : -1;
}

static int parse_unsigned(const char *value, uint64_t maximum, uint64_t *parsed)
{
    char *end = NULL;
    errno = 0;
    unsigned long long candidate = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || candidate > maximum) {
        return -1;
    }
    *parsed = (uint64_t)candidate;
    return 0;
}

static bool copy_header_value(const char *headers, const char *name,
                              char *value_out, size_t value_capacity)
{
    size_t name_length = strlen(name);
    const char *line = strstr(headers, "\r\n");
    while (line != NULL && line[2] != '\r' && line[2] != '\0') {
        line += 2;
        const char *line_end = strstr(line, "\r\n");
        if (line_end == NULL) {
            return false;
        }
        if ((size_t)(line_end - line) > name_length
            && strncasecmp(line, name, name_length) == 0
            && line[name_length] == ':') {
            const char *value = line + name_length + 1;
            while (value < line_end && (*value == ' ' || *value == '\t')) {
                value++;
            }
            size_t value_length = (size_t)(line_end - value);
            while (value_length > 0
                   && (value[value_length - 1] == ' ' || value[value_length - 1] == '\t')) {
                value_length--;
            }
            if (value_length + 1 > value_capacity) {
                return false;
            }
            memcpy(value_out, value, value_length);
            value_out[value_length] = '\0';
            return true;
        }
        line = line_end;
    }
    return false;
}

static int read_request(int socket_fd, char **request_out, char **body_out,
                        size_t *body_length_out)
{
    size_t capacity = MAX_HEADER_BYTES + MAX_BODY_BYTES + 1;
    char *request = malloc(capacity);
    if (request == NULL) {
        return -1;
    }
    size_t used = 0;
    char *separator = NULL;
    while (used < MAX_HEADER_BYTES) {
        ssize_t received = recv(socket_fd, request + used, capacity - used - 1, 0);
        if (received <= 0) {
            free(request);
            return -1;
        }
        used += (size_t)received;
        request[used] = '\0';
        separator = strstr(request, "\r\n\r\n");
        if (separator != NULL) {
            break;
        }
    }
    if (separator == NULL) {
        free(request);
        return -1;
    }
    size_t header_length = (size_t)(separator - request) + 4;
    char content_length_value[32];
    bool has_content_length = copy_header_value(request, "Content-Length",
                                                content_length_value,
                                                sizeof(content_length_value));
    uint64_t content_length = 0;
    if (has_content_length
        && parse_unsigned(content_length_value, MAX_BODY_BYTES, &content_length) != 0) {
        free(request);
        return -1;
    }
    while (used - header_length < content_length) {
        ssize_t received = recv(socket_fd, request + used, capacity - used - 1, 0);
        if (received <= 0) {
            free(request);
            return -1;
        }
        used += (size_t)received;
        request[used] = '\0';
    }
    *request_out = request;
    *body_out = request + header_length;
    *body_length_out = (size_t)content_length;
    return 0;
}

static bool authorized(char *request, const struct receiver_state *state)
{
    if (state->expected_token == NULL || state->expected_token[0] == '\0') {
        return true;
    }
    char authorization[MAX_HEADER_BYTES];
    if (!copy_header_value(request, "Authorization", authorization, sizeof(authorization))
        || strncmp(authorization, "Bearer ", 7) != 0) {
        return false;
    }
    return strcmp(authorization + 7, state->expected_token) == 0;
}

static void handle_connection(int socket_fd, struct receiver_state *state)
{
    char *request = NULL;
    char *body = NULL;
    size_t body_length = 0;
    if (read_request(socket_fd, &request, &body, &body_length) != 0) {
        (void)respond(socket_fd, 400, "Bad Request", "text/plain", "bad request\n", 12);
        return;
    }

    char method[16] = {0};
    char path[256] = {0};
    if (sscanf(request, "%15s %255s", method, path) != 2) {
        (void)respond(socket_fd, 400, "Bad Request", "text/plain", "bad request\n", 12);
        free(request);
        return;
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/health") == 0) {
        (void)respond(socket_fd, 200, "OK", "text/plain", "ok\n", 3);
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/last") == 0) {
        if (state->last_body == NULL) {
            (void)respond(socket_fd, 404, "Not Found", "text/plain", "none\n", 5);
        } else {
            (void)respond(socket_fd, 200, "OK", "application/json", state->last_body,
                          state->last_body_length);
        }
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/stats") == 0) {
        char stats[384];
        int length = snprintf(stats, sizeof(stats),
                              "{\"attempts\":%llu,\"accepted\":%llu,"
                              "\"last_sequence\":%llu,\"sequence_duplicates\":%llu,"
                              "\"sequence_regressions\":%llu,\"max_body_bytes\":%llu}\n",
                              (unsigned long long)state->attempts,
                              (unsigned long long)state->accepted,
                              (unsigned long long)state->last_sequence,
                              (unsigned long long)state->sequence_duplicates,
                              (unsigned long long)state->sequence_regressions,
                              (unsigned long long)state->max_body_bytes);
        if (length > 0 && (size_t)length < sizeof(stats)) {
            (void)respond(socket_fd, 200, "OK", "application/json", stats, (size_t)length);
        }
    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/flows") == 0) {
        if (!authorized(request, state)) {
            (void)respond(socket_fd, 401, "Unauthorized", "text/plain", "unauthorized\n", 13);
        } else {
            char *saved = malloc(body_length + 1);
            if (saved == NULL) {
                (void)respond(socket_fd, 500, "Internal Server Error", "text/plain",
                              "allocation failure\n", 19);
            } else {
                memcpy(saved, body, body_length);
                saved[body_length] = '\0';
                free(state->last_body);
                state->last_body = saved;
                state->last_body_length = body_length;
                if (body_length > state->max_body_bytes) {
                    state->max_body_bytes = body_length;
                }
                record_export_sequence(state, saved);
                state->attempts++;
                delay_response(state->delay_millis);
                if (state->attempts <= state->fail_first) {
                    (void)respond(socket_fd, 503, "Service Unavailable", "text/plain",
                                  "retry\n", 6);
                } else {
                    state->accepted++;
                    (void)respond(socket_fd, 204, "No Content", "text/plain", "", 0);
                }
            }
        }
    } else {
        (void)respond(socket_fd, 404, "Not Found", "text/plain", "not found\n", 10);
    }
    free(request);
}

int main(int argc, char **argv)
{
    uint64_t port = DEFAULT_PORT;
    if (argc > 2 || (argc == 2 && parse_unsigned(argv[1], UINT16_MAX, &port) != 0)
        || port == 0) {
        fprintf(stderr, "usage: %s [port]\n", argv[0]);
        return 2;
    }
    struct receiver_state state = {
        .expected_token = getenv("UNF_FLOW_RECEIVER_TOKEN"),
    };
    const char *fail_first = getenv("UNF_FLOW_RECEIVER_FAIL_FIRST");
    if (fail_first != NULL && parse_unsigned(fail_first, UINT32_MAX, &state.fail_first) != 0) {
        fprintf(stderr, "UNF_FLOW_RECEIVER_FAIL_FIRST must be a nonnegative integer\n");
        return 2;
    }
    const char *delay_millis = getenv("UNF_FLOW_RECEIVER_DELAY_MILLIS");
    if (delay_millis != NULL
        && parse_unsigned(delay_millis, 60000, &state.delay_millis) != 0) {
        fprintf(stderr, "UNF_FLOW_RECEIVER_DELAY_MILLIS must be between 0 and 60000\n");
        return 2;
    }

    int server_fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_fd < 0) {
        perror("create receiver socket");
        return 1;
    }
    int enabled = 1;
    int disabled = 0;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0
        || setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, &disabled, sizeof(disabled)) != 0) {
        perror("configure receiver socket");
        close(server_fd);
        return 1;
    }
    struct sockaddr_in6 address = {
        .sin6_family = AF_INET6,
        .sin6_port = htons((uint16_t)port),
        .sin6_addr = IN6ADDR_ANY_INIT,
    };
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) != 0
        || listen(server_fd, 16) != 0) {
        perror("bind/listen receiver socket");
        close(server_fd);
        return 1;
    }
    printf("UNF test flow receiver listening on port %llu\n", (unsigned long long)port);
    fflush(stdout);
    for (;;) {
        int client_fd = accept4(server_fd, NULL, NULL, SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept receiver connection");
            break;
        }
        handle_connection(client_fd, &state);
        close(client_fd);
    }
    free(state.last_body);
    close(server_fd);
    return 1;
}
