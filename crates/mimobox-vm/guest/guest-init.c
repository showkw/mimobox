#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/io.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
extern char **environ;
/* USE_VSOCK 由构建脚本通过 -DUSE_VSOCK 显式启用，默认不定义。
 * vhost-vsock 数据面恢复前，guest-init 默认只走串口协议。 */
#ifdef USE_VSOCK
/* Alpine musl 没有 linux/vm_sockets.h，手动定义 AF_VSOCK 和 sockaddr_vm。
 * 定义与 Linux 内核 include/uapi/linux/vm_sockets.h 一致。 */
#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

struct sockaddr_vm {
    unsigned short svm_family;
    unsigned short svm_reserved1;
    unsigned int svm_port;
    unsigned int svm_cid;
    unsigned char svm_zero[sizeof(struct sockaddr) -
                           sizeof(sa_family_t) -
                           sizeof(unsigned short) -
                           sizeof(unsigned int) -
                           sizeof(unsigned int)];
};
#endif

#define SERIAL_COM1_BASE 0x3f8
#define SERIAL_REG_RBR 0
#define SERIAL_REG_THR 0
#define SERIAL_REG_LSR 5
#define SERIAL_LSR_DATA_READY 0x01
#define SERIAL_LSR_THR_EMPTY 0x20

#define COMMAND_BUFFER_CAP 4096
#define OUTPUT_BUFFER_CAP 1024
#define FS_WRITE_MAX_BYTES (10 * 1024 * 1024)
#define FS_RESULT_STATUS_OK 0
#define FS_RESULT_STATUS_PATH_ERROR 1
#define FS_RESULT_STATUS_IO_ERROR 2
#define FS_RESULT_STATUS_PERMISSION_ERROR 3
#define FS_RESULT_STATUS_NO_SPACE 4
#ifdef USE_VSOCK
#define VSOCK_HOST_CID 2
#define VSOCK_HOST_PORT 1024
#define VSOCK_OUTPUT_CAP 65536
#define VSOCK_COMMAND_POLL_TIMEOUT_MS 5000
#endif

static const char *const SHELL_PATH = "/bin/sh";
static const char *const READY_LINE = "READY\n";
static const char *const INIT_OK_LINE = "mimobox-kvm: init OK\n";
/* BOOT_PROFILE 由构建脚本通过 -DBOOT_PROFILE 显式启用，默认不定义。 */
#ifdef BOOT_PROFILE
/* 仅在显式启用 BOOT_PROFILE 时输出 boot profile，避免 release 冷启动额外串口开销。 */
static const char *const BOOT_TIME_PREFIX = "BOOT_TIME:";
#endif
static const int OUTPUT_STREAM_STDOUT = STDOUT_FILENO;
static const int OUTPUT_STREAM_STDERR = STDERR_FILENO;
static volatile sig_atomic_t current_command_pid = -1;

typedef struct {
    char command_line[COMMAND_BUFFER_CAP];
    const char *json_payload;
    bool structured;
    bool has_timeout;
    uint64_t timeout_secs;
} exec_request_t;

static void close_fd_if_open(int *fd);

static void write_console_line(const char *message) {
    const unsigned char *cursor = (const unsigned char *)message;
    size_t length = strlen(message);

    while (length > 0) {
        unsigned char lsr = inb(SERIAL_COM1_BASE + SERIAL_REG_LSR);
        if ((lsr & SERIAL_LSR_THR_EMPTY) == 0) {
            continue;
        }
        outb(*cursor, SERIAL_COM1_BASE + SERIAL_REG_THR);
        cursor++;
        length--;
    }
}

static void write_console_bytes(const void *buffer, size_t length) {
    const unsigned char *cursor = (const unsigned char *)buffer;
    while (length > 0) {
        unsigned char lsr = inb(SERIAL_COM1_BASE + SERIAL_REG_LSR);
        if ((lsr & SERIAL_LSR_THR_EMPTY) == 0) {
            continue;
        }
        outb(*cursor, SERIAL_COM1_BASE + SERIAL_REG_THR);
        cursor++;
        length--;
    }
}

#ifdef BOOT_PROFILE
static uint64_t monotonic_now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        dprintf(STDERR_FILENO, "guest-init: clock_gettime failed: %s\n", strerror(errno));
        return 0;
    }

    return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

static void write_boot_time(const char *stage, uint64_t timestamp_ns) {
    char buffer[96];
    int written = snprintf(
        buffer,
        sizeof(buffer),
        "%s%s:%" PRIu64 "\n",
        BOOT_TIME_PREFIX,
        stage,
        timestamp_ns
    );
    if (written > 0) {
        write_console_bytes(buffer, (size_t)written);
    }
}
#endif

static void mount_if_needed(
    const char *source,
    const char *target,
    const char *fstype,
    unsigned long flags
) {
    if (mount(source, target, fstype, flags, "") == 0) {
        return;
    }

    if (errno == EBUSY) {
        return;
    }

    dprintf(STDERR_FILENO, "guest-init: mount %s on %s failed: %s\n", source, target, strerror(errno));
}

static int setup_console(void) {
    int console_fd = open("/dev/console", O_RDWR | O_NOCTTY);
    if (console_fd < 0) {
        return -1;
    }

    if (dup2(console_fd, STDIN_FILENO) < 0 ||
        dup2(console_fd, STDOUT_FILENO) < 0 ||
        dup2(console_fd, STDERR_FILENO) < 0) {
        close(console_fd);
        return -1;
    }

    if (console_fd > STDERR_FILENO) {
        close(console_fd);
    }
    return 0;
}

static void update_uart_access(void) {
    if (ioperm(SERIAL_COM1_BASE, 8, 1) < 0) {
        dprintf(STDERR_FILENO, "guest-init: ioperm failed: %s\n", strerror(errno));
        _exit(125);
    }
}

static int read_serial_byte(unsigned char *value) {
    if (value == NULL) {
        return -1;
    }

    for (;;) {
        unsigned char lsr = inb(SERIAL_COM1_BASE + SERIAL_REG_LSR);
        if ((lsr & SERIAL_LSR_DATA_READY) == 0) {
            usleep(1000);
            continue;
        }

        *value = inb(SERIAL_COM1_BASE + SERIAL_REG_RBR);
        return 0;
    }
}

static int discard_serial_bytes(size_t length) {
    unsigned char discarded = 0;
    while (length > 0) {
        if (read_serial_byte(&discarded) < 0) {
            return -1;
        }
        length--;
    }
    return 0;
}

static bool is_supported_command_prefix(const char *prefix) {
    if (prefix == NULL) {
        return false;
    }

    return strcmp(prefix, "EXEC:") == 0 ||
           strcmp(prefix, "EXECS:") == 0 ||
           strcmp(prefix, "SIGNAL:KILL:") == 0 ||
           strcmp(prefix, "HTTP:REQUEST:") == 0 ||
           strcmp(prefix, "FS:READ:") == 0 ||
           strcmp(prefix, "FS:WRITE:") == 0;
}

static int read_command_frame(char *buffer, size_t capacity) {
    char prefix[16];
    char streaming_id[16];
    char http_request_id[16];
    size_t prefix_len = 0;
    size_t payload_len = 0;
    unsigned char value = 0;
    bool saw_digit = false;
    bool is_streaming_exec = false;
    bool is_http_request = false;

    if (capacity == 0) {
        return -1;
    }

    for (;;) {
        if (read_serial_byte(&value) < 0) {
            return -1;
        }
        if (value >= '0' && value <= '9') {
            payload_len = (size_t)(value - '0');
            saw_digit = true;
            break;
        }
        if (value == '\n' || value == '\r') {
            return -3;
        }
        if (prefix_len + 1 >= sizeof(prefix)) {
            return -3;
        }
        prefix[prefix_len++] = (char)value;
        prefix[prefix_len] = '\0';
        if (strcmp(prefix, "SIGNAL:KILL:") == 0) {
            if (prefix_len >= capacity) {
                return -2;
            }
            memcpy(buffer, prefix, prefix_len);
            for (;;) {
                if (read_serial_byte(&value) < 0) {
                    return -1;
                }
                if (value == '\n') {
                    buffer[prefix_len] = '\0';
                    return 0;
                }
                if (prefix_len + 1 >= capacity) {
                    return -2;
                }
                buffer[prefix_len++] = (char)value;
            }
        }
    }

    is_streaming_exec = strcmp(prefix, "EXECS:") == 0;
    is_http_request = strcmp(prefix, "HTTP:REQUEST:") == 0;
    if (is_streaming_exec) {
        size_t id_len = 0;
        streaming_id[id_len++] = (char)value;
        streaming_id[id_len] = '\0';

        for (;;) {
            unsigned char digit = 0;
            if (read_serial_byte(&digit) < 0) {
                return -1;
            }
            if (digit == ':') {
                if (id_len == 0) {
                    return -3;
                }
                break;
            }
            if (digit < '0' || digit > '9') {
                return -3;
            }
            if (id_len + 1 >= sizeof(streaming_id)) {
                return -3;
            }
            streaming_id[id_len++] = (char)digit;
            streaming_id[id_len] = '\0';
        }

        saw_digit = false;
        payload_len = 0;
        if (read_serial_byte(&value) < 0) {
            return -1;
        }
        if (value < '0' || value > '9') {
            return -3;
        }
        payload_len = (size_t)(value - '0');
        saw_digit = true;
    }
    if (is_http_request) {
        size_t id_len = 0;
        http_request_id[id_len++] = (char)value;
        http_request_id[id_len] = '\0';

        for (;;) {
            unsigned char digit = 0;
            if (read_serial_byte(&digit) < 0) {
                return -1;
            }
            if (digit == ':') {
                if (id_len == 0) {
                    return -3;
                }
                break;
            }
            if (digit < '0' || digit > '9') {
                return -3;
            }
            if (id_len + 1 >= sizeof(http_request_id)) {
                return -3;
            }
            http_request_id[id_len++] = (char)digit;
            http_request_id[id_len] = '\0';
        }

        saw_digit = false;
        payload_len = 0;
        if (read_serial_byte(&value) < 0) {
            return -1;
        }
        if (value < '0' || value > '9') {
            return -3;
        }
        payload_len = (size_t)(value - '0');
        saw_digit = true;
    }

    for (;;) {
        unsigned char digit = 0;
        if (read_serial_byte(&digit) < 0) {
            return -1;
        }
        if (digit == ':') {
            if (!saw_digit) {
                return -3;
            }
            break;
        }
        if (digit < '0' || digit > '9') {
            return -3;
        }
        saw_digit = true;
        if (payload_len > (SIZE_MAX - (size_t)(digit - '0')) / 10) {
            return -3;
        }
        payload_len = payload_len * 10 + (size_t)(digit - '0');
    }

    if (!is_supported_command_prefix(prefix)) {
        if (discard_serial_bytes(payload_len) < 0) {
            return -1;
        }
        if (read_serial_byte(&value) < 0) {
            return -1;
        }
        return value == '\n' ? -3 : -3;
    }

    size_t total_prefix_len = prefix_len;
    if (is_streaming_exec) {
        total_prefix_len += strlen(streaming_id) + 1;
    }
    if (is_http_request) {
        total_prefix_len += strlen(http_request_id) + 1;
    }

    if (total_prefix_len + payload_len >= capacity) {
        if (discard_serial_bytes(payload_len) < 0) {
            return -1;
        }
        if (read_serial_byte(&value) < 0) {
            return -1;
        }
        if (value != '\n') {
            return -3;
        }
        return -2;
    }

    memcpy(buffer, prefix, prefix_len);
    if (is_streaming_exec) {
        size_t id_len = strlen(streaming_id);
        memcpy(buffer + prefix_len, streaming_id, id_len);
        buffer[prefix_len + id_len] = ':';
    }
    if (is_http_request) {
        size_t id_len = strlen(http_request_id);
        memcpy(buffer + prefix_len, http_request_id, id_len);
        buffer[prefix_len + id_len] = ':';
    }
    for (size_t index = 0; index < payload_len; index++) {
        if (read_serial_byte(&value) < 0) {
            return -1;
        }
        buffer[total_prefix_len + index] = (char)value;
    }

    if (read_serial_byte(&value) < 0) {
        return -1;
    }
    if (value != '\n') {
        return -3;
    }

    buffer[total_prefix_len + payload_len] = '\0';
    return 0;
}

static int expect_serial_newline(void) {
    unsigned char value = 0;
    if (read_serial_byte(&value) < 0) {
        return -1;
    }
    return value == '\n' ? 0 : -1;
}

static int read_length_prefix(size_t *length) {
    size_t parsed = 0;
    bool saw_digit = false;

    if (length == NULL) {
        return -1;
    }

    for (;;) {
        unsigned char digit = 0;
        if (read_serial_byte(&digit) < 0) {
            return -1;
        }
        if (digit == ':') {
            if (!saw_digit) {
                return -3;
            }
            *length = parsed;
            return 0;
        }
        if (digit < '0' || digit > '9') {
            return -3;
        }
        saw_digit = true;
        if (parsed > (SIZE_MAX - (size_t)(digit - '0')) / 10) {
            return -3;
        }
        parsed = parsed * 10 + (size_t)(digit - '0');
    }
}

static int write_all_fd(int fd, const unsigned char *data, size_t length) {
    size_t written_total = 0;

    while (written_total < length) {
        ssize_t written = write(fd, data + written_total, length - written_total);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        written_total += (size_t)written;
    }

    return 0;
}

static int fs_status_from_errno(int errnum) {
    switch (errnum) {
    case ENOENT:
    case ENOTDIR:
    case EISDIR:
    case ENAMETOOLONG:
    case EINVAL:
        return FS_RESULT_STATUS_PATH_ERROR;
    case EACCES:
    case EPERM:
    case EROFS:
        return FS_RESULT_STATUS_PERMISSION_ERROR;
    case ENOSPC:
    case EDQUOT:
    case EFBIG:
        return FS_RESULT_STATUS_NO_SPACE;
    default:
        return FS_RESULT_STATUS_IO_ERROR;
    }
}

static bool has_parent_dir_component(const char *path) {
    const char *cursor = path;

    while (cursor != NULL && *cursor != '\0') {
        while (*cursor == '/') {
            cursor++;
        }

        const char *component_start = cursor;
        while (*cursor != '\0' && *cursor != '/') {
            cursor++;
        }

        size_t component_len = (size_t)(cursor - component_start);
        if (component_len == 2 &&
            component_start[0] == '.' &&
            component_start[1] == '.') {
            return true;
        }
    }

    return false;
}

static int validate_sandbox_path(const char *path) {
    if (path == NULL) {
        return FS_RESULT_STATUS_PATH_ERROR;
    }
    if (strncmp(path, "/sandbox/", 9) != 0) {
        return FS_RESULT_STATUS_PATH_ERROR;
    }
    if (has_parent_dir_component(path)) {
        return FS_RESULT_STATUS_PATH_ERROR;
    }

    return FS_RESULT_STATUS_OK;
}

static void write_fs_write_result(int status) {
    char buffer[32];
    int written = snprintf(buffer, sizeof(buffer), "FSRESULT:%d\n", status);
    if (written > 0) {
        write_console_bytes(buffer, (size_t)written);
    }
}

static void write_fs_read_result_prefix(int status, size_t data_len) {
    char buffer[64];
    int written = snprintf(buffer, sizeof(buffer), "FSRESULT:%d:%zu:", status, data_len);
    if (written > 0) {
        write_console_bytes(buffer, (size_t)written);
    }
}

static void write_fs_read_result_status(int status) {
    write_fs_read_result_prefix(status, 0);
    write_console_bytes("\n", 1);
}

static int consume_fs_write_body(int fd, size_t data_len, int initial_status) {
    unsigned char chunk[OUTPUT_BUFFER_CAP];
    int status = initial_status;

    while (data_len > 0) {
        size_t chunk_len = data_len < sizeof(chunk) ? data_len : sizeof(chunk);
        for (size_t index = 0; index < chunk_len; index++) {
            if (read_serial_byte(&chunk[index]) < 0) {
                return FS_RESULT_STATUS_IO_ERROR;
            }
        }

        if (status == FS_RESULT_STATUS_OK && fd >= 0) {
            if (write_all_fd(fd, chunk, chunk_len) < 0) {
                status = fs_status_from_errno(errno);
                close_fd_if_open(&fd);
            }
        }

        data_len -= chunk_len;
    }

    if (expect_serial_newline() < 0) {
        return FS_RESULT_STATUS_IO_ERROR;
    }

    if (fd >= 0 && close(fd) < 0 && status == FS_RESULT_STATUS_OK) {
        status = fs_status_from_errno(errno);
    }

    return status;
}

static void handle_fs_read(const char *path) {
    int status = validate_sandbox_path(path);
    if (status != FS_RESULT_STATUS_OK) {
        write_fs_read_result_status(status);
        return;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        write_fs_read_result_status(fs_status_from_errno(errno));
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        status = fs_status_from_errno(errno);
        close_fd_if_open(&fd);
        write_fs_read_result_status(status);
        return;
    }
    if (!S_ISREG(st.st_mode) || st.st_size < 0) {
        close_fd_if_open(&fd);
        write_fs_read_result_status(FS_RESULT_STATUS_PATH_ERROR);
        return;
    }

    size_t data_len = (size_t)st.st_size;
    write_fs_read_result_prefix(FS_RESULT_STATUS_OK, data_len);

    unsigned char chunk[OUTPUT_BUFFER_CAP];
    size_t remaining = data_len;
    while (remaining > 0) {
        size_t chunk_len = remaining < sizeof(chunk) ? remaining : sizeof(chunk);
        ssize_t read_len = read(fd, chunk, chunk_len);
        if (read_len < 0) {
            if (errno == EINTR) {
                continue;
            }
            close_fd_if_open(&fd);
            return;
        }
        if (read_len == 0) {
            close_fd_if_open(&fd);
            return;
        }
        write_console_bytes(chunk, (size_t)read_len);
        remaining -= (size_t)read_len;
    }

    close_fd_if_open(&fd);
    write_console_bytes("\n", 1);
}

static void handle_fs_write(const char *path) {
    size_t data_len = 0;
    int status = read_length_prefix(&data_len);
    if (status < 0) {
        write_fs_write_result(FS_RESULT_STATUS_IO_ERROR);
        return;
    }

    int path_status = validate_sandbox_path(path);
    if (path_status != FS_RESULT_STATUS_OK) {
        status = consume_fs_write_body(-1, data_len, path_status);
        write_fs_write_result(status);
        return;
    }
    if (data_len > FS_WRITE_MAX_BYTES) {
        status = consume_fs_write_body(-1, data_len, FS_RESULT_STATUS_NO_SPACE);
        write_fs_write_result(status);
        return;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    int open_status = FS_RESULT_STATUS_OK;
    if (fd < 0) {
        open_status = fs_status_from_errno(errno);
    }

    status = consume_fs_write_body(fd, data_len, open_status);
    write_fs_write_result(status);
}

static void write_escaped_output(int stream_fd, const unsigned char *data, size_t length) {
    char escaped[5];
    char prefix[16];
    int prefix_written = snprintf(prefix, sizeof(prefix), "OUTPUT:%d:", stream_fd);

    if (prefix_written > 0) {
        write_console_bytes(prefix, (size_t)prefix_written);
    }
    for (size_t index = 0; index < length; index++) {
        unsigned char byte = data[index];
        switch (byte) {
        case '\\':
            write_console_bytes("\\\\", 2);
            break;
        case '\n':
            write_console_bytes("\\n", 2);
            break;
        case '\r':
            write_console_bytes("\\r", 2);
            break;
        case '\t':
            write_console_bytes("\\t", 2);
            break;
        default:
            if (byte >= 0x20 && byte <= 0x7e) {
                write_console_bytes(&byte, 1);
            } else {
                int written = snprintf(escaped, sizeof(escaped), "\\x%02x", byte);
                if (written > 0) {
                    write_console_bytes(escaped, (size_t)written);
                }
            }
            break;
        }
    }
    write_console_bytes("\n", 1);
}

static void write_exit_code(int exit_code) {
    char buffer[32];
    int written = snprintf(buffer, sizeof(buffer), "EXIT:%d\n", exit_code);
    if (written > 0) {
        write_console_bytes(buffer, (size_t)written);
    }
}

static void write_stream_start(uint32_t stream_id) {
    char buffer[64];
    int written = snprintf(buffer, sizeof(buffer), "STREAM:START:%" PRIu32 "\n", stream_id);
    if (written > 0) {
        write_console_bytes(buffer, (size_t)written);
    }
}

static void write_stream_chunk(const char *kind, uint32_t stream_id,
                               const unsigned char *data, size_t length) {
    char header[96];
    int header_len = snprintf(
        header,
        sizeof(header),
        "STREAM:%s:%" PRIu32 ":%zu:",
        kind,
        stream_id,
        length
    );
    if (header_len > 0) {
        write_console_bytes(header, (size_t)header_len);
    }
    if (length > 0) {
        write_console_bytes(data, length);
    }
    write_console_bytes("\n", 1);
}

static void write_stream_end(uint32_t stream_id, int exit_code) {
    char buffer[64];
    int written = snprintf(buffer, sizeof(buffer), "STREAM:END:%" PRIu32 ":%d\n", stream_id, exit_code);
    if (written > 0) {
        write_console_bytes(buffer, (size_t)written);
    }
}

static void write_exit_timeout(void) {
    write_console_line("EXIT:TIMEOUT\n");
}

static void write_stream_timeout(uint32_t stream_id) {
    char buffer[64];
    int written = snprintf(buffer, sizeof(buffer), "STREAM:TIMEOUT:%" PRIu32 "\n", stream_id);
    if (written > 0) {
        write_console_bytes(buffer, (size_t)written);
    }
}

static void write_http_request_passthrough(const char *request_frame) {
    const char *id_start = request_frame + strlen("HTTP:REQUEST:");
    const char *payload_start = strchr(id_start, ':');
    if (payload_start == NULL) {
        static const unsigned char invalid_http_frame[] = "invalid HTTP:REQUEST frame";
        write_escaped_output(OUTPUT_STREAM_STDOUT, invalid_http_frame, sizeof(invalid_http_frame) - 1);
        write_exit_code(125);
        return;
    }

    size_t request_id_len = (size_t)(payload_start - id_start);
    payload_start++;
    size_t payload_len = strlen(payload_start);

    write_console_bytes("HTTP:REQUEST:", sizeof("HTTP:REQUEST:") - 1);
    write_console_bytes(id_start, request_id_len);

    char len_buffer[32];
    int len_written = snprintf(len_buffer, sizeof(len_buffer), ":%zu:", payload_len);
    if (len_written > 0) {
        write_console_bytes(len_buffer, (size_t)len_written);
    }
    if (payload_len > 0) {
        write_console_bytes(payload_start, payload_len);
    }
    write_console_bytes("\n", 1);
}

static int child_exit_code_from_status(int status) {
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 125;
}

static void set_current_command_pid(pid_t pid) {
    current_command_pid = (sig_atomic_t)pid;
}

static void clear_current_command_pid(void) {
    current_command_pid = -1;
}

static void kill_running_command(void) {
    pid_t pid = (pid_t)current_command_pid;
    if (pid <= 0) {
        return;
    }
    kill(-pid, SIGKILL);
}

static int monotonic_now_ms(uint64_t *now_ms) {
    struct timespec ts;

    if (now_ms == NULL) {
        return -1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        return -1;
    }

    *now_ms = ((uint64_t)ts.tv_sec * 1000ull) + ((uint64_t)ts.tv_nsec / 1000000ull);
    return 0;
}

static int remaining_timeout_ms(uint64_t deadline_ms) {
    uint64_t now_ms = 0;

    if (monotonic_now_ms(&now_ms) < 0) {
        return 0;
    }
    if (now_ms >= deadline_ms) {
        return 0;
    }

    uint64_t remaining = deadline_ms - now_ms;
    if (remaining > (uint64_t)INT_MAX) {
        return INT_MAX;
    }
    return (int)remaining;
}

static void skip_json_ws(const char **cursor) {
    while (cursor != NULL && *cursor != NULL) {
        char ch = **cursor;
        if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t') {
            return;
        }
        (*cursor)++;
    }
}

static int parse_json_string(const char **cursor, char *buffer, size_t capacity) {
    size_t written = 0;

    if (cursor == NULL || *cursor == NULL || buffer == NULL || capacity == 0) {
        return -1;
    }
    if (**cursor != '"') {
        return -1;
    }
    (*cursor)++;

    while (**cursor != '\0') {
        char ch = **cursor;
        (*cursor)++;

        if (ch == '"') {
            if (written >= capacity) {
                return -1;
            }
            buffer[written] = '\0';
            return 0;
        }

        if (ch == '\\') {
            char escaped = **cursor;
            if (escaped == '\0') {
                return -1;
            }
            (*cursor)++;
            switch (escaped) {
            case '"':
            case '\\':
            case '/':
                ch = escaped;
                break;
            case 'b':
                ch = '\b';
                break;
            case 'f':
                ch = '\f';
                break;
            case 'n':
                ch = '\n';
                break;
            case 'r':
                ch = '\r';
                break;
            case 't':
                ch = '\t';
                break;
            default:
                return -1;
            }
        }

        if (written + 1 >= capacity) {
            return -1;
        }
        buffer[written++] = ch;
    }

    return -1;
}

static int skip_json_string(const char **cursor) {
    if (cursor == NULL || *cursor == NULL || **cursor != '"') {
        return -1;
    }
    (*cursor)++;

    while (**cursor != '\0') {
        char ch = **cursor;
        (*cursor)++;
        if (ch == '"') {
            return 0;
        }
        if (ch == '\\') {
            if (**cursor == '\0') {
                return -1;
            }
            (*cursor)++;
        }
    }

    return -1;
}

static int parse_json_u64(const char **cursor, uint64_t *value) {
    uint64_t parsed = 0;
    bool saw_digit = false;

    if (cursor == NULL || *cursor == NULL || value == NULL) {
        return -1;
    }

    while (**cursor >= '0' && **cursor <= '9') {
        saw_digit = true;
        if (parsed > (UINT64_MAX - (uint64_t)(**cursor - '0')) / 10ull) {
            return -1;
        }
        parsed = parsed * 10ull + (uint64_t)(**cursor - '0');
        (*cursor)++;
    }

    if (!saw_digit) {
        return -1;
    }

    *value = parsed;
    return 0;
}

static int parse_exec_request(const char *payload, exec_request_t *request) {
    const char *cursor = payload;
    bool saw_cmd = false;

    if (payload == NULL || request == NULL) {
        return -1;
    }

    memset(request, 0, sizeof(*request));
    skip_json_ws(&cursor);
    if (*cursor != '{') {
        size_t length = strnlen(payload, sizeof(request->command_line));
        if (length >= sizeof(request->command_line)) {
            return -1;
        }
        memcpy(request->command_line, payload, length);
        request->command_line[length] = '\0';
        return 0;
    }

    request->structured = true;
    request->json_payload = payload;
    cursor++;

    for (;;) {
        char key[32];

        skip_json_ws(&cursor);
        if (*cursor == '}') {
            cursor++;
            break;
        }
        if (parse_json_string(&cursor, key, sizeof(key)) < 0) {
            return -1;
        }
        skip_json_ws(&cursor);
        if (*cursor != ':') {
            return -1;
        }
        cursor++;
        skip_json_ws(&cursor);

        if (strcmp(key, "cmd") == 0) {
            if (parse_json_string(&cursor, request->command_line, sizeof(request->command_line)) < 0) {
                return -1;
            }
            saw_cmd = true;
        } else if (strcmp(key, "timeout") == 0) {
            if (parse_json_u64(&cursor, &request->timeout_secs) < 0 || request->timeout_secs == 0) {
                return -1;
            }
            request->has_timeout = true;
        } else if (strcmp(key, "env") == 0) {
            if (*cursor != '{') {
                return -1;
            }
            int depth = 1;
            cursor++;
            while (*cursor != '\0' && depth > 0) {
                if (*cursor == '"') {
                    if (skip_json_string(&cursor) < 0) {
                        return -1;
                    }
                    continue;
                }
                if (*cursor == '{') {
                    depth++;
                } else if (*cursor == '}') {
                    depth--;
                }
                cursor++;
            }
            if (depth != 0) {
                return -1;
            }
        } else {
            return -1;
        }

        skip_json_ws(&cursor);
        if (*cursor == ',') {
            cursor++;
            continue;
        }
        if (*cursor == '}') {
            cursor++;
            break;
        }
        return -1;
    }

    skip_json_ws(&cursor);
    if (*cursor != '\0' || !saw_cmd || request->command_line[0] == '\0') {
        return -1;
    }

    return 0;
}

static int apply_exec_env_from_json(const exec_request_t *request, int stderr_fd) {
    const char *cursor = request != NULL ? request->json_payload : NULL;

    if (request == NULL || !request->structured || cursor == NULL) {
        return 0;
    }

    skip_json_ws(&cursor);
    if (*cursor != '{') {
        return -1;
    }
    cursor++;

    for (;;) {
        char key[32];

        skip_json_ws(&cursor);
        if (*cursor == '}') {
            return 0;
        }
        if (parse_json_string(&cursor, key, sizeof(key)) < 0) {
            return -1;
        }
        skip_json_ws(&cursor);
        if (*cursor != ':') {
            return -1;
        }
        cursor++;
        skip_json_ws(&cursor);

        if (strcmp(key, "cmd") == 0) {
            char discarded[COMMAND_BUFFER_CAP];
            if (parse_json_string(&cursor, discarded, sizeof(discarded)) < 0) {
                return -1;
            }
        } else if (strcmp(key, "timeout") == 0) {
            uint64_t discarded_timeout = 0;
            if (parse_json_u64(&cursor, &discarded_timeout) < 0) {
                return -1;
            }
        } else if (strcmp(key, "env") == 0) {
            skip_json_ws(&cursor);
            if (*cursor != '{') {
                return -1;
            }
            cursor++;
            for (;;) {
                char env_key[256];
                char env_value[1024];

                skip_json_ws(&cursor);
                if (*cursor == '}') {
                    cursor++;
                    break;
                }
                if (parse_json_string(&cursor, env_key, sizeof(env_key)) < 0) {
                    return -1;
                }
                skip_json_ws(&cursor);
                if (*cursor != ':') {
                    return -1;
                }
                cursor++;
                skip_json_ws(&cursor);
                if (parse_json_string(&cursor, env_value, sizeof(env_value)) < 0) {
                    return -1;
                }
                if (setenv(env_key, env_value, 1) < 0) {
                    dprintf(stderr_fd, "guest-init: setenv failed for %s: %s\n", env_key, strerror(errno));
                    return -1;
                }
                skip_json_ws(&cursor);
                if (*cursor == ',') {
                    cursor++;
                    continue;
                }
                if (*cursor == '}') {
                    cursor++;
                    break;
                }
                return -1;
            }
        } else {
            return -1;
        }

        skip_json_ws(&cursor);
        if (*cursor == ',') {
            cursor++;
            continue;
        }
        if (*cursor == '}') {
            return 0;
        }
        return -1;
    }
}

static void close_fd_if_open(int *fd) {
    if (fd == NULL || *fd < 0) {
        return;
    }

    close(*fd);
    *fd = -1;
}

/* ===== vsock 数据面辅助函数 ===== */
#ifdef USE_VSOCK

/* 从 fd 读取精确 n 字节 */
static int read_exact(int fd, void *buf, size_t n) {
    unsigned char *p = (unsigned char *)buf;
    size_t remaining = n;
    while (remaining > 0) {
        ssize_t r = read(fd, p, remaining);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (r == 0) {
            return -1; /* 对端关闭 */
        }
        p += r;
        remaining -= (size_t)r;
    }
    return 0;
}

/* 向 fd 写入精确 n 字节 */
static int write_exact(int fd, const void *buf, size_t n) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t remaining = n;
    while (remaining > 0) {
        ssize_t w = write(fd, p, remaining);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (w == 0) {
            return -1;
        }
        p += w;
        remaining -= (size_t)w;
    }
    return 0;
}

/* 尝试通过 AF_VSOCK 连接 host，成功返回 fd，失败返回 -1 */
static int connect_to_host_vsock(void) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = VSOCK_HOST_CID;
    addr.svm_port = VSOCK_HOST_PORT;

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* vsock 命令帧读取：4 字节大端长度前缀 + payload，返回 payload 长度，失败返回负数 */
static int read_vsock_command(int fd, char *buffer, size_t capacity) {
    unsigned char len_buf[4];
    uint32_t payload_len = 0;

    if (read_exact(fd, len_buf, 4) < 0) {
        return -1;
    }
    payload_len = ((uint32_t)len_buf[0] << 24) |
                  ((uint32_t)len_buf[1] << 16) |
                  ((uint32_t)len_buf[2] << 8)  |
                  ((uint32_t)len_buf[3]);
    if (payload_len == 0) {
        return -1;
    }
    if (payload_len >= capacity) {
        return -2; /* 命令过长 */
    }
    if (read_exact(fd, buffer, payload_len) < 0) {
        return -1;
    }
    buffer[payload_len] = '\0';
    return (int)payload_len;
}

/* vsock 输出收集缓冲区 */
typedef struct {
    unsigned char data[VSOCK_OUTPUT_CAP];
    size_t len;
} output_buffer_t;

static void output_buffer_init(output_buffer_t *buf) {
    buf->len = 0;
}

static void output_buffer_append(output_buffer_t *buf, const unsigned char *data, size_t len) {
    size_t available = sizeof(buf->data) - buf->len;
    if (len > available) {
        len = available;
    }
    if (len > 0) {
        memcpy(buf->data + buf->len, data, len);
        buf->len += len;
    }
}

/* 将命令执行结果通过 vsock 二进制帧发送：
 * 4字节 stdout_len (大端) + stdout_data +
 * 4字节 stderr_len (大端) + stderr_data +
 * 1字节 exit_code */
static void send_vsock_result(int fd, const unsigned char *stdout_data, size_t stdout_len,
                              const unsigned char *stderr_data, size_t stderr_len,
                              int exit_code) {
    unsigned char len_buf[4];

    /* stdout 长度（大端） */
    len_buf[0] = (unsigned char)((stdout_len >> 24) & 0xff);
    len_buf[1] = (unsigned char)((stdout_len >> 16) & 0xff);
    len_buf[2] = (unsigned char)((stdout_len >> 8) & 0xff);
    len_buf[3] = (unsigned char)(stdout_len & 0xff);
    write_exact(fd, len_buf, 4);
    if (stdout_len > 0) {
        write_exact(fd, stdout_data, stdout_len);
    }

    /* stderr 长度（大端） */
    len_buf[0] = (unsigned char)((stderr_len >> 24) & 0xff);
    len_buf[1] = (unsigned char)((stderr_len >> 16) & 0xff);
    len_buf[2] = (unsigned char)((stderr_len >> 8) & 0xff);
    len_buf[3] = (unsigned char)(stderr_len & 0xff);
    write_exact(fd, len_buf, 4);
    if (stderr_len > 0) {
        write_exact(fd, stderr_data, stderr_len);
    }

    /* exit code（1 字节） */
    unsigned char ec = (unsigned char)(exit_code & 0xff);
    write_exact(fd, &ec, 1);
}

/* 从子进程管道收集输出到缓冲区（由 poll 驱动，非阻塞式单次读取） */
static int collect_child_output(int source_fd, output_buffer_t *out) {
    unsigned char tmp[OUTPUT_BUFFER_CAP];

    for (;;) {
        ssize_t r = read(source_fd, tmp, sizeof(tmp));
        if (r == 0) {
            return 1; /* EOF */
        }
        if (r > 0) {
            output_buffer_append(out, tmp, (size_t)r);
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }
}

/* vsock 路径的命令执行：收集原始 stdout/stderr 到缓冲区 */
static int execute_command_vsock(const char *command_line,
                                 output_buffer_t *stdout_buf,
                                 output_buffer_t *stderr_buf) {
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};

    output_buffer_init(stdout_buf);
    output_buffer_init(stderr_buf);

    if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) {
        close_fd_if_open(&stdout_pipe[0]);
        close_fd_if_open(&stdout_pipe[1]);
        close_fd_if_open(&stderr_pipe[0]);
        close_fd_if_open(&stderr_pipe[1]);
        return 125;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close_fd_if_open(&stdout_pipe[0]);
        close_fd_if_open(&stdout_pipe[1]);
        close_fd_if_open(&stderr_pipe[0]);
        close_fd_if_open(&stderr_pipe[1]);
        return 125;
    }

    if (pid == 0) {
        /* 子进程：与 execute_command 相同的 execve 逻辑 */
        static char *const envp[] = {
            "HOME=/root",
            "PATH=/bin:/sbin:/usr/bin:/usr/sbin",
            "SHELL=/bin/sh",
            "TERM=dumb",
            NULL,
        };
        char *const argv[] = {
            (char *)SHELL_PATH,
            "-lc",
            (char *)command_line,
            NULL,
        };
        int stdin_fd = -1;

        close_fd_if_open(&stdout_pipe[0]);
        close_fd_if_open(&stderr_pipe[0]);
        if (dup2(stdout_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(stderr_pipe[1], STDERR_FILENO) < 0) {
            _exit(125);
        }
        stdin_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (stdin_fd < 0 || dup2(stdin_fd, STDIN_FILENO) < 0) {
            _exit(125);
        }
        if (stdin_fd > STDERR_FILENO) {
            close(stdin_fd);
        }
        close_fd_if_open(&stdout_pipe[1]);
        close_fd_if_open(&stderr_pipe[1]);

        execve(SHELL_PATH, argv, envp);
        _exit(127);
    }

    close_fd_if_open(&stdout_pipe[1]);
    close_fd_if_open(&stderr_pipe[1]);

    struct pollfd poll_fds[2] = {
        { .fd = stdout_pipe[0], .events = POLLIN | POLLHUP, .revents = 0 },
        { .fd = stderr_pipe[0], .events = POLLIN | POLLHUP, .revents = 0 },
    };

    while (poll_fds[0].fd >= 0 || poll_fds[1].fd >= 0) {
        int poll_status = poll(poll_fds, 2, -1);
        if (poll_status < 0) {
            if (errno == EINTR) {
                continue;
            }
            close_fd_if_open(&poll_fds[0].fd);
            close_fd_if_open(&poll_fds[1].fd);
            return 125;
        }

        for (size_t index = 0; index < 2; index++) {
            if (poll_fds[index].fd < 0 || poll_fds[index].revents == 0) {
                continue;
            }
            if ((poll_fds[index].revents & (POLLIN | POLLHUP)) == 0) {
                close_fd_if_open(&poll_fds[0].fd);
                close_fd_if_open(&poll_fds[1].fd);
                return 125;
            }

            output_buffer_t *target = (index == 0) ? stdout_buf : stderr_buf;
            int collect_status = collect_child_output(poll_fds[index].fd, target);
            if (collect_status < 0) {
                close_fd_if_open(&poll_fds[0].fd);
                close_fd_if_open(&poll_fds[1].fd);
                return 125;
            }
            if (collect_status > 0) {
                close_fd_if_open(&poll_fds[index].fd);
            }
        }
    }
    close_fd_if_open(&poll_fds[0].fd);
    close_fd_if_open(&poll_fds[1].fd);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        return 125;
    }

    return child_exit_code_from_status(status);
}

/* 串口命令循环前置声明，供 vsock 超时后直接回退。 */
static void serial_command_loop(void);

/* vsock 命令循环：从 vsock socket 读取命令，执行，返回二进制结果 */
static void vsock_command_loop(int *vsock_fd) {
    char command_buffer[COMMAND_BUFFER_CAP];

    if (vsock_fd == NULL || *vsock_fd < 0) {
        return;
    }

    for (;;) {
        struct pollfd poll_fd = {
            .fd = *vsock_fd,
            .events = POLLIN | POLLHUP,
            .revents = 0,
        };

        int poll_status = 0;
        for (;;) {
            poll_status = poll(&poll_fd, 1, VSOCK_COMMAND_POLL_TIMEOUT_MS);
            if (poll_status < 0 && errno == EINTR) {
                continue;
            }
            break;
        }

        if (poll_status == 0) {
            /* host 已建立连接但 5 秒内未下发命令，主动关闭并切回串口协议。 */
            close_fd_if_open(vsock_fd);
            serial_command_loop();
            return;
        }
        if (poll_status < 0) {
            break;
        }
        if ((poll_fd.revents & (POLLERR | POLLNVAL)) != 0) {
            break;
        }
        if ((poll_fd.revents & POLLIN) == 0) {
            /* 仅收到 HUP 等非可读事件时，认为 host 已放弃当前 vsock 会话。 */
            break;
        }

        int read_status = read_vsock_command(*vsock_fd, command_buffer, sizeof(command_buffer));
        if (read_status < 0) {
            /* vsock 连接断开或读取失败，退出循环 */
            break;
        }

        output_buffer_t stdout_buf;
        output_buffer_t stderr_buf;
        int exit_code = execute_command_vsock(command_buffer, &stdout_buf, &stderr_buf);
        send_vsock_result(*vsock_fd,
                          stdout_buf.data, stdout_buf.len,
                          stderr_buf.data, stderr_buf.len,
                          exit_code);
    }
}
#endif

/* ===== 串口数据面函数 ===== */

static pid_t spawn_command_child(const exec_request_t *request, int stdout_pipe[2], int stderr_pipe[2]) {
    pid_t pid = fork();
    if (pid != 0) {
        if (pid > 0) {
            setpgid(pid, pid);
        }
        return pid;
    }

    static char home_env[] = "HOME=/root";
    static char path_env[] = "PATH=/bin:/sbin:/usr/bin:/usr/sbin";
    static char shell_env[] = "SHELL=/bin/sh";
    static char term_env[] = "TERM=dumb";
    char *const argv[] = {
        (char *)SHELL_PATH,
        "-lc",
        (char *)request->command_line,
        NULL,
    };
    int stdin_fd = -1;

    setpgid(0, 0);
    close_fd_if_open(&stdout_pipe[0]);
    close_fd_if_open(&stderr_pipe[0]);
    if (dup2(stdout_pipe[1], STDOUT_FILENO) < 0 || dup2(stderr_pipe[1], STDERR_FILENO) < 0) {
        dprintf(stderr_pipe[1], "guest-init: dup2 failed: %s\n", strerror(errno));
        _exit(125);
    }
    stdin_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (stdin_fd < 0 || dup2(stdin_fd, STDIN_FILENO) < 0) {
        dprintf(stderr_pipe[1], "guest-init: redirect stdin failed: %s\n", strerror(errno));
        _exit(125);
    }
    if (stdin_fd > STDERR_FILENO) {
        close(stdin_fd);
    }
    close_fd_if_open(&stdout_pipe[1]);
    close_fd_if_open(&stderr_pipe[1]);

    clearenv();
    putenv(home_env);
    putenv(path_env);
    putenv(shell_env);
    putenv(term_env);
    if (apply_exec_env_from_json(request, STDERR_FILENO) < 0) {
        dprintf(STDERR_FILENO, "guest-init: invalid EXEC env payload\n");
        _exit(125);
    }

    execve(SHELL_PATH, argv, environ);
    dprintf(STDERR_FILENO, "guest-init: execve failed: %s\n", strerror(errno));
    _exit(127);
}

static int wait_for_child_exit(pid_t pid) {
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        dprintf(STDERR_FILENO, "guest-init: waitpid failed: %s\n", strerror(errno));
        return 125;
    }

    return child_exit_code_from_status(status);
}

static int forward_child_output_blocking(int stream_fd, int source_fd) {
    for (;;) {
        unsigned char buffer[OUTPUT_BUFFER_CAP];
        ssize_t read_bytes = read(source_fd, buffer, sizeof(buffer));
        if (read_bytes == 0) {
            return 1;
        }
        if (read_bytes > 0) {
            write_escaped_output(stream_fd, buffer, (size_t)read_bytes);
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }

        dprintf(STDERR_FILENO, "guest-init: read child output failed: %s\n", strerror(errno));
        return -1;
    }
}

static int forward_child_output_streaming(uint32_t stream_id, const char *kind, int source_fd) {
    for (;;) {
        unsigned char buffer[OUTPUT_BUFFER_CAP];
        ssize_t read_bytes = read(source_fd, buffer, sizeof(buffer));
        if (read_bytes == 0) {
            return 1;
        }
        if (read_bytes > 0) {
            write_stream_chunk(kind, stream_id, buffer, (size_t)read_bytes);
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }

        dprintf(STDERR_FILENO, "guest-init: read child output failed: %s\n", strerror(errno));
        return -1;
    }
}

static int execute_command_blocking(const exec_request_t *request, bool *timed_out) {
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    uint64_t deadline_ms = 0;

    if (timed_out != NULL) {
        *timed_out = false;
    }

    if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) {
        close_fd_if_open(&stdout_pipe[0]);
        close_fd_if_open(&stdout_pipe[1]);
        close_fd_if_open(&stderr_pipe[0]);
        close_fd_if_open(&stderr_pipe[1]);
        dprintf(STDERR_FILENO, "guest-init: pipe failed: %s\n", strerror(errno));
        return 125;
    }

    pid_t pid = spawn_command_child(request, stdout_pipe, stderr_pipe);
    if (pid < 0) {
        close_fd_if_open(&stdout_pipe[0]);
        close_fd_if_open(&stdout_pipe[1]);
        close_fd_if_open(&stderr_pipe[0]);
        close_fd_if_open(&stderr_pipe[1]);
        dprintf(STDERR_FILENO, "guest-init: fork failed: %s\n", strerror(errno));
        return 125;
    }

    close_fd_if_open(&stdout_pipe[1]);
    close_fd_if_open(&stderr_pipe[1]);
    set_current_command_pid(pid);
    if (request->has_timeout && monotonic_now_ms(&deadline_ms) == 0) {
        deadline_ms += request->timeout_secs * 1000ull;
    }

    struct pollfd poll_fds[2] = {
        {
            .fd = stdout_pipe[0],
            .events = POLLIN | POLLHUP,
            .revents = 0,
        },
        {
            .fd = stderr_pipe[0],
            .events = POLLIN | POLLHUP,
            .revents = 0,
        },
    };
    const int stream_fds[2] = {OUTPUT_STREAM_STDOUT, OUTPUT_STREAM_STDERR};

    while (poll_fds[0].fd >= 0 || poll_fds[1].fd >= 0) {
        int poll_timeout_ms = request->has_timeout ? remaining_timeout_ms(deadline_ms) : -1;
        int poll_status = poll(poll_fds, 2, poll_timeout_ms);
        if (poll_status == 0 && request->has_timeout) {
            kill_running_command();
            close_fd_if_open(&poll_fds[0].fd);
            close_fd_if_open(&poll_fds[1].fd);
            wait_for_child_exit(pid);
            clear_current_command_pid();
            if (timed_out != NULL) {
                *timed_out = true;
            }
            return 124;
        }
        if (poll_status < 0) {
            if (errno == EINTR) {
                continue;
            }

            dprintf(STDERR_FILENO, "guest-init: poll child output failed: %s\n", strerror(errno));
            close_fd_if_open(&poll_fds[0].fd);
            close_fd_if_open(&poll_fds[1].fd);
            kill_running_command();
            wait_for_child_exit(pid);
            clear_current_command_pid();
            return 125;
        }

        for (size_t index = 0; index < 2; index++) {
            if (poll_fds[index].fd < 0 || poll_fds[index].revents == 0) {
                continue;
            }
            if ((poll_fds[index].revents & (POLLIN | POLLHUP)) == 0) {
                dprintf(STDERR_FILENO, "guest-init: child output poll failed: revents=%d\n", poll_fds[index].revents);
                close_fd_if_open(&poll_fds[0].fd);
                close_fd_if_open(&poll_fds[1].fd);
                kill_running_command();
                wait_for_child_exit(pid);
                clear_current_command_pid();
                return 125;
            }

            int forward_status = forward_child_output_blocking(stream_fds[index], poll_fds[index].fd);
            if (forward_status < 0) {
                close_fd_if_open(&poll_fds[0].fd);
                close_fd_if_open(&poll_fds[1].fd);
                kill_running_command();
                wait_for_child_exit(pid);
                clear_current_command_pid();
                return 125;
            }

            if (forward_status > 0) {
                close_fd_if_open(&poll_fds[index].fd);
            }
        }
    }
    close_fd_if_open(&poll_fds[0].fd);
    close_fd_if_open(&poll_fds[1].fd);

    clear_current_command_pid();
    return wait_for_child_exit(pid);
}

static int execute_command_streaming(uint32_t stream_id, const exec_request_t *request, bool *timed_out) {
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    uint64_t deadline_ms = 0;

    if (timed_out != NULL) {
        *timed_out = false;
    }

    if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) {
        close_fd_if_open(&stdout_pipe[0]);
        close_fd_if_open(&stdout_pipe[1]);
        close_fd_if_open(&stderr_pipe[0]);
        close_fd_if_open(&stderr_pipe[1]);
        dprintf(STDERR_FILENO, "guest-init: pipe failed: %s\n", strerror(errno));
        return 125;
    }

    pid_t pid = spawn_command_child(request, stdout_pipe, stderr_pipe);
    if (pid < 0) {
        close_fd_if_open(&stdout_pipe[0]);
        close_fd_if_open(&stdout_pipe[1]);
        close_fd_if_open(&stderr_pipe[0]);
        close_fd_if_open(&stderr_pipe[1]);
        dprintf(STDERR_FILENO, "guest-init: fork failed: %s\n", strerror(errno));
        return 125;
    }

    close_fd_if_open(&stdout_pipe[1]);
    close_fd_if_open(&stderr_pipe[1]);
    set_current_command_pid(pid);
    if (request->has_timeout && monotonic_now_ms(&deadline_ms) == 0) {
        deadline_ms += request->timeout_secs * 1000ull;
    }

    write_stream_start(stream_id);

    struct pollfd poll_fds[2] = {
        {
            .fd = stdout_pipe[0],
            .events = POLLIN | POLLHUP,
            .revents = 0,
        },
        {
            .fd = stderr_pipe[0],
            .events = POLLIN | POLLHUP,
            .revents = 0,
        },
    };
    const char *const stream_kinds[2] = {"STDOUT", "STDERR"};

    while (poll_fds[0].fd >= 0 || poll_fds[1].fd >= 0) {
        int poll_timeout_ms = request->has_timeout ? remaining_timeout_ms(deadline_ms) : -1;
        int poll_status = poll(poll_fds, 2, poll_timeout_ms);
        if (poll_status == 0 && request->has_timeout) {
            kill_running_command();
            close_fd_if_open(&poll_fds[0].fd);
            close_fd_if_open(&poll_fds[1].fd);
            wait_for_child_exit(pid);
            clear_current_command_pid();
            if (timed_out != NULL) {
                *timed_out = true;
            }
            return 124;
        }
        if (poll_status < 0) {
            if (errno == EINTR) {
                continue;
            }

            dprintf(STDERR_FILENO, "guest-init: poll child output failed: %s\n", strerror(errno));
            close_fd_if_open(&poll_fds[0].fd);
            close_fd_if_open(&poll_fds[1].fd);
            kill_running_command();
            wait_for_child_exit(pid);
            clear_current_command_pid();
            return 125;
        }

        for (size_t index = 0; index < 2; index++) {
            if (poll_fds[index].fd < 0 || poll_fds[index].revents == 0) {
                continue;
            }
            if ((poll_fds[index].revents & (POLLIN | POLLHUP)) == 0) {
                dprintf(STDERR_FILENO, "guest-init: child output poll failed: revents=%d\n", poll_fds[index].revents);
                close_fd_if_open(&poll_fds[0].fd);
                close_fd_if_open(&poll_fds[1].fd);
                kill_running_command();
                wait_for_child_exit(pid);
                clear_current_command_pid();
                return 125;
            }

            int forward_status = forward_child_output_streaming(stream_id, stream_kinds[index], poll_fds[index].fd);
            if (forward_status < 0) {
                close_fd_if_open(&poll_fds[0].fd);
                close_fd_if_open(&poll_fds[1].fd);
                kill_running_command();
                wait_for_child_exit(pid);
                clear_current_command_pid();
                return 125;
            }

            if (forward_status > 0) {
                close_fd_if_open(&poll_fds[index].fd);
            }
        }
    }

    close_fd_if_open(&poll_fds[0].fd);
    close_fd_if_open(&poll_fds[1].fd);
    clear_current_command_pid();
    return wait_for_child_exit(pid);
}

static void serial_command_loop(void) {
    char command_buffer[COMMAND_BUFFER_CAP];

    for (;;) {
        int line_status = read_command_frame(command_buffer, sizeof(command_buffer));
        if (line_status == -2) {
            static const unsigned char too_long[] = "command frame too long";
            write_escaped_output(OUTPUT_STREAM_STDOUT, too_long, sizeof(too_long) - 1);
            write_exit_code(126);
            continue;
        }
        if (line_status < 0) {
            static const unsigned char read_failed[] = "serial command frame read failed";
            static const unsigned char invalid_frame[] = "invalid command frame";
            if (line_status == -3) {
                write_escaped_output(OUTPUT_STREAM_STDOUT, invalid_frame, sizeof(invalid_frame) - 1);
            } else {
                write_escaped_output(OUTPUT_STREAM_STDOUT, read_failed, sizeof(read_failed) - 1);
            }
            write_exit_code(125);
            continue;
        }

        if (strncmp(command_buffer, "FS:READ:", 8) == 0) {
            handle_fs_read(command_buffer + 8);
            continue;
        }
        if (strncmp(command_buffer, "FS:WRITE:", 9) == 0) {
            handle_fs_write(command_buffer + 9);
            continue;
        }
        if (strncmp(command_buffer, "SIGNAL:KILL:", 12) == 0) {
            kill_running_command();
            continue;
        }
        if (strncmp(command_buffer, "EXEC:", 5) == 0) {
            exec_request_t request;
            bool timed_out = false;

            if (parse_exec_request(command_buffer + 5, &request) < 0) {
                static const unsigned char invalid_exec_payload[] = "invalid EXEC payload";
                write_escaped_output(OUTPUT_STREAM_STDOUT, invalid_exec_payload, sizeof(invalid_exec_payload) - 1);
                write_exit_code(125);
                continue;
            }

            int exit_code = execute_command_blocking(&request, &timed_out);
            if (timed_out) {
                write_exit_timeout();
            } else {
                write_exit_code(exit_code);
            }
            continue;
        }
        if (strncmp(command_buffer, "EXECS:", 6) == 0) {
            char *id_end = strchr(command_buffer + 6, ':');
            if (id_end == NULL) {
                static const unsigned char invalid_streaming_frame[] = "invalid EXECS frame";
                write_escaped_output(OUTPUT_STREAM_STDOUT, invalid_streaming_frame, sizeof(invalid_streaming_frame) - 1);
                write_exit_code(125);
                continue;
            }

            errno = 0;
            char *parse_end = NULL;
            unsigned long parsed_id = strtoul(command_buffer + 6, &parse_end, 10);
            if (errno != 0 || parse_end != id_end || parsed_id > UINT32_MAX) {
                static const unsigned char invalid_streaming_id[] = "invalid EXECS id";
                write_escaped_output(OUTPUT_STREAM_STDOUT, invalid_streaming_id, sizeof(invalid_streaming_id) - 1);
                write_exit_code(125);
                continue;
            }

            exec_request_t request;
            bool timed_out = false;
            if (parse_exec_request(id_end + 1, &request) < 0) {
                static const unsigned char invalid_streaming_payload[] = "invalid EXECS payload";
                write_escaped_output(OUTPUT_STREAM_STDOUT, invalid_streaming_payload, sizeof(invalid_streaming_payload) - 1);
                write_stream_end((uint32_t)parsed_id, 125);
                continue;
            }

            int exit_code = execute_command_streaming((uint32_t)parsed_id, &request, &timed_out);
            if (timed_out) {
                write_stream_timeout((uint32_t)parsed_id);
            } else {
                write_stream_end((uint32_t)parsed_id, exit_code);
            }
            continue;
        }
        if (strncmp(command_buffer, "HTTP:REQUEST:", 13) == 0) {
            write_http_request_passthrough(command_buffer);
            continue;
        }
        {
            static const unsigned char invalid_prefix[] = "unsupported command prefix";
            write_escaped_output(OUTPUT_STREAM_STDOUT, invalid_prefix, sizeof(invalid_prefix) - 1);
            write_exit_code(125);
        }
    }
}

int main(void) {
#ifdef BOOT_PROFILE
    uint64_t init_entry_ns = monotonic_now_ns();
    uint64_t mounts_done_ns = 0;
    uint64_t uart_access_done_ns = 0;
    uint64_t init_ok_ns = 0;
    uint64_t ready_ns = 0;
    uint64_t command_loop_ns = 0;
#endif

    if (setup_console() < 0) {
        _exit(125);
    }

    signal(SIGPIPE, SIG_IGN);
    mount_if_needed("proc", "/proc", "proc", 0);
    mount_if_needed("devtmpfs", "/dev", "devtmpfs", 0);
    mkdir("/sandbox", 0755);
#ifdef BOOT_PROFILE
    mounts_done_ns = monotonic_now_ns();
#endif
    update_uart_access();
#ifdef BOOT_PROFILE
    uart_access_done_ns = monotonic_now_ns();

    write_boot_time("init_entry", init_entry_ns);
    write_boot_time("mounts_done", mounts_done_ns);
    write_boot_time("uart_access_done", uart_access_done_ns);
#endif

    write_console_line(INIT_OK_LINE);
#ifdef BOOT_PROFILE
    init_ok_ns = monotonic_now_ns();
    write_boot_time("init_ok", init_ok_ns);

    ready_ns = monotonic_now_ns();
    write_boot_time("ready", ready_ns);
#endif
    write_console_line(READY_LINE);
#ifdef BOOT_PROFILE
    command_loop_ns = monotonic_now_ns();
    write_boot_time("command_loop", command_loop_ns);
#endif

    /* 默认禁用 vsock，直接走串口。vhost-vsock 数据面恢复后可通过 -DUSE_VSOCK 重新启用。 */
#ifdef USE_VSOCK
    int vsock_fd = connect_to_host_vsock();
    if (vsock_fd >= 0) {
        vsock_command_loop(&vsock_fd);
        close_fd_if_open(&vsock_fd);
        /* vsock 循环退出（连接断开），回退到串口命令循环 */
    }
#endif

    serial_command_loop();
}
