#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

enum {
    POLICY_KEY_SIZE = 12,
    POLICY_VALUE_SIZE = 32,
    POLICY_BANK_COUNT = 2,
};

static volatile sig_atomic_t interrupted;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    interrupted = 1;
}

static int bpf_call(enum bpf_cmd command, union bpf_attr *attributes)
{
    return (int)syscall(__NR_bpf, command, attributes, sizeof(*attributes));
}

static int open_pinned_map(const char *path)
{
    union bpf_attr attributes = {0};
    attributes.pathname = (uint64_t)(uintptr_t)path;
    return bpf_call(BPF_OBJ_GET, &attributes);
}

static int map_info(int map_fd, struct bpf_map_info *info)
{
    union bpf_attr attributes = {0};
    uint32_t info_length = sizeof(*info);
    attributes.info.bpf_fd = (uint32_t)map_fd;
    attributes.info.info_len = info_length;
    attributes.info.info = (uint64_t)(uintptr_t)info;
    return bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attributes);
}

static int update_noexist(int map_fd, const uint8_t *key, const uint8_t *value)
{
    union bpf_attr attributes = {0};
    attributes.map_fd = (uint32_t)map_fd;
    attributes.key = (uint64_t)(uintptr_t)key;
    attributes.value = (uint64_t)(uintptr_t)value;
    attributes.flags = BPF_NOEXIST;
    return bpf_call(BPF_MAP_UPDATE_ELEM, &attributes);
}

static int delete_key(int map_fd, const uint8_t *key)
{
    union bpf_attr attributes = {0};
    attributes.map_fd = (uint32_t)map_fd;
    attributes.key = (uint64_t)(uintptr_t)key;
    return bpf_call(BPF_MAP_DELETE_ELEM, &attributes);
}

static void pressure_key(uint8_t *key, uint32_t sequence, uint8_t bank)
{
    memset(key, 0, POLICY_KEY_SIZE);
    memcpy(&key[4], &sequence, sizeof(sequence));
    key[8] = 0xfa;
    key[9] = 0x17;
    key[11] = bank;
}

static int validate_policy_map(int map_fd, struct bpf_map_info *info)
{
    if (map_info(map_fd, info) != 0) {
        perror("inspect pressure map");
        return -1;
    }
    if (info->type != BPF_MAP_TYPE_HASH || info->key_size != POLICY_KEY_SIZE
        || info->value_size != POLICY_VALUE_SIZE || info->max_entries == 0) {
        fprintf(stderr,
                "pressure target must be a nonempty hash map with 12-byte keys and 32-byte values\n");
        return -1;
    }
    return 0;
}

static int fill_to_capacity(int map_fd, uint32_t max_entries, uint8_t bank,
                            const char *stop_path, uint64_t *inserted)
{
    uint8_t key[POLICY_KEY_SIZE];
    uint8_t value[POLICY_VALUE_SIZE] = {0};
    uint64_t limit = (uint64_t)max_entries + 1;

    for (uint64_t sequence = 1; sequence <= limit; sequence++) {
        if (interrupted || (stop_path != NULL && access(stop_path, F_OK) == 0)) {
            return 1;
        }
        pressure_key(key, (uint32_t)sequence, bank);
        if (update_noexist(map_fd, key, value) == 0) {
            (*inserted)++;
            continue;
        }
        if (errno == EEXIST) {
            continue;
        }
        if (errno == ENOSPC || errno == E2BIG) {
            return 0;
        }
        perror("fill pressure map");
        return -1;
    }

    // Concurrent rollback can remove synthetic keys while a hold pass is
    // inserting them, allowing more than max_entries successful insertions over
    // time without the map ever exceeding its physical capacity. Start another
    // pass instead of treating that expected race as a tool failure.
    return 0;
}

static int clear_pressure_keys(int map_fd, const struct bpf_map_info *info, uint8_t bank)
{
    uint8_t key[POLICY_KEY_SIZE];
    uint32_t removed = 0;
    uint64_t limit = (uint64_t)info->max_entries + 1;
    for (uint64_t sequence = 1; sequence <= limit; sequence++) {
        pressure_key(key, (uint32_t)sequence, bank);
        if (delete_key(map_fd, key) == 0) {
            removed++;
        } else if (errno != ENOENT) {
            perror("delete pressure key");
            return -1;
        }
    }
    printf("removed %u synthetic pressure keys\n", removed);
    fflush(stdout);
    return 0;
}

static int create_ready_file(const char *path, uint64_t inserted)
{
    int ready_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (ready_fd < 0) {
        perror("create pressure ready file");
        return -1;
    }
    char message[64];
    int length = snprintf(message, sizeof(message), "%llu\n",
                          (unsigned long long)inserted);
    ssize_t written = write(ready_fd, message, (size_t)length);
    int saved_errno = errno;
    close(ready_fd);
    if (written != length) {
        errno = saved_errno;
        perror("write pressure ready file");
        return -1;
    }
    return 0;
}

static int parse_bank(const char *value, uint8_t *bank)
{
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed >= POLICY_BANK_COUNT) {
        fprintf(stderr, "policy bank must be 0 or 1\n");
        return -1;
    }
    *bank = (uint8_t)parsed;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 4 && argc != 6) {
        fprintf(stderr,
                "usage: %s clear MAP BANK | %s hold MAP BANK READY_FILE STOP_FILE\n",
                argv[0], argv[0]);
        return 2;
    }

    uint8_t bank;
    if (parse_bank(argv[3], &bank) != 0) {
        return 2;
    }
    int map_fd = open_pinned_map(argv[2]);
    if (map_fd < 0) {
        perror("open pinned pressure map");
        return 1;
    }
    struct bpf_map_info info = {0};
    if (validate_policy_map(map_fd, &info) != 0) {
        close(map_fd);
        return 1;
    }

    if (strcmp(argv[1], "clear") == 0 && argc == 4) {
        int result = clear_pressure_keys(map_fd, &info, bank);
        close(map_fd);
        return result == 0 ? 0 : 1;
    }
    if (strcmp(argv[1], "hold") != 0 || argc != 6) {
        fprintf(stderr,
                "usage: %s clear MAP BANK | %s hold MAP BANK READY_FILE STOP_FILE\n",
                argv[0], argv[0]);
        close(map_fd);
        return 2;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    uint64_t inserted = 0;
    int fill_result = fill_to_capacity(map_fd, info.max_entries, bank, argv[5], &inserted);
    int ready_result = fill_result == 0 ? create_ready_file(argv[4], inserted) : 0;
    if (fill_result != 0 || ready_result != 0) {
        clear_pressure_keys(map_fd, &info, bank);
        close(map_fd);
        return fill_result < 0 || ready_result != 0 ? 1 : 0;
    }
    printf("pressure map reached capacity after %llu synthetic insertions\n",
           (unsigned long long)inserted);
    fflush(stdout);

    while (!interrupted && access(argv[5], F_OK) != 0) {
        fill_result = fill_to_capacity(map_fd, info.max_entries, bank, argv[5], &inserted);
        if (fill_result < 0) {
            break;
        }
        usleep(10000);
    }

    int clear_result = clear_pressure_keys(map_fd, &info, bank);
    close(map_fd);
    return fill_result < 0 || clear_result != 0 ? 1 : 0;
}
