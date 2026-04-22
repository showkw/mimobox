#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SERIAL_COM1_BASE 0x3f8
#define SERIAL_REG_RBR 0
#define SERIAL_REG_THR 0
#define SERIAL_REG_LSR 5
#define SERIAL_LSR_DATA_READY 0x01
#define SERIAL_LSR_THR_EMPTY 0x20

#define COMMAND_BUFFER_CAP 4096
#define OUTPUT_BUFFER_CAP 1024

static const char *const SHELL_PATH = "/bin/sh";
static const char *const READY_LINE = "READY\n";
static const char *const INIT_OK_LINE = "mimobox-kvm: init OK\n";
static const char *const BOOT_TIME_PREFIX = "BOOT_TIME:";
static const int OUTPUT_STREAM_STDOUT = STDOUT_FILENO;
static const int OUTPUT_STREAM_STDERR = STDERR_FILENO;

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

static int read_command_frame(char *buffer, size_t capacity) {
    static const char prefix[] = "EXEC:";
    size_t payload_len = 0;
    unsigned char value = 0;
    bool saw_digit = false;

    if (capacity == 0) {
        return -1;
    }

    for (size_t index = 0; index < sizeof(prefix) - 1; index++) {
        if (read_serial_byte(&value) < 0) {
            return -1;
        }
        if (value != (unsigned char)prefix[index]) {
            return -3;
        }
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

    if (payload_len >= capacity) {
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

    for (size_t index = 0; index < payload_len; index++) {
        if (read_serial_byte(&value) < 0) {
            return -1;
        }
        buffer[index] = (char)value;
    }

    if (read_serial_byte(&value) < 0) {
        return -1;
    }
    if (value != '\n') {
        return -3;
    }

    buffer[payload_len] = '\0';
    return 0;
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

static int child_exit_code_from_status(int status) {
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 125;
}

static void close_fd_if_open(int *fd) {
    if (fd == NULL || *fd < 0) {
        return;
    }

    close(*fd);
    *fd = -1;
}

static int forward_child_output(int stream_fd, int source_fd) {
    unsigned char buffer[OUTPUT_BUFFER_CAP];

    for (;;) {
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

static int execute_command(const char *command_line) {
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};

    if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0) {
        close_fd_if_open(&stdout_pipe[0]);
        close_fd_if_open(&stdout_pipe[1]);
        close_fd_if_open(&stderr_pipe[0]);
        close_fd_if_open(&stderr_pipe[1]);
        dprintf(STDERR_FILENO, "guest-init: pipe failed: %s\n", strerror(errno));
        return 125;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close_fd_if_open(&stdout_pipe[0]);
        close_fd_if_open(&stdout_pipe[1]);
        close_fd_if_open(&stderr_pipe[0]);
        close_fd_if_open(&stderr_pipe[1]);
        dprintf(STDERR_FILENO, "guest-init: fork failed: %s\n", strerror(errno));
        return 125;
    }

    if (pid == 0) {
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

        execve(SHELL_PATH, argv, envp);
        dprintf(STDERR_FILENO, "guest-init: execve failed: %s\n", strerror(errno));
        _exit(127);
    }

    close_fd_if_open(&stdout_pipe[1]);
    close_fd_if_open(&stderr_pipe[1]);

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
        int poll_status = poll(poll_fds, 2, -1);
        if (poll_status < 0) {
            if (errno == EINTR) {
                continue;
            }

            dprintf(STDERR_FILENO, "guest-init: poll child output failed: %s\n", strerror(errno));
            close_fd_if_open(&poll_fds[0].fd);
            close_fd_if_open(&poll_fds[1].fd);
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
                return 125;
            }

            int forward_status = forward_child_output(stream_fds[index], poll_fds[index].fd);
            if (forward_status < 0) {
                close_fd_if_open(&poll_fds[0].fd);
                close_fd_if_open(&poll_fds[1].fd);
                return 125;
            }

            if (forward_status > 0) {
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
        dprintf(STDERR_FILENO, "guest-init: waitpid failed: %s\n", strerror(errno));
        return 125;
    }

    return child_exit_code_from_status(status);
}

int main(void) {
    uint64_t init_entry_ns = monotonic_now_ns();
    uint64_t mounts_done_ns = 0;
    uint64_t uart_access_done_ns = 0;
    uint64_t init_ok_ns = 0;
    uint64_t ready_ns = 0;
    uint64_t command_loop_ns = 0;

    if (setup_console() < 0) {
        _exit(125);
    }

    signal(SIGPIPE, SIG_IGN);
    mount_if_needed("proc", "/proc", "proc", 0);
    mount_if_needed("sysfs", "/sys", "sysfs", 0);
    mount_if_needed("devtmpfs", "/dev", "devtmpfs", 0);
    mounts_done_ns = monotonic_now_ns();
    update_uart_access();
    uart_access_done_ns = monotonic_now_ns();

    write_boot_time("init_entry", init_entry_ns);
    write_boot_time("mounts_done", mounts_done_ns);
    write_boot_time("uart_access_done", uart_access_done_ns);

    write_console_line(INIT_OK_LINE);
    init_ok_ns = monotonic_now_ns();
    write_boot_time("init_ok", init_ok_ns);

    ready_ns = monotonic_now_ns();
    write_boot_time("ready", ready_ns);
    write_console_line(READY_LINE);
    command_loop_ns = monotonic_now_ns();
    write_boot_time("command_loop", command_loop_ns);

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

        int exit_code = execute_command(command_buffer);
        write_exit_code(exit_code);
    }
}
