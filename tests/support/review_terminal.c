/* Disposable QEMU fixtures only. Script a generated fixture's choices on a
 * real PTY. The deployer binary has no test-mode exception to terminal review.
 * The command keeps its PID so the harness can test real manager signals. */
#define _XOPEN_SOURCE 700
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static void die(const char *what) {
    perror(what);
    exit(125);
}

static void full_write(int fd, const char *data, size_t size) {
    while (size) {
        ssize_t written = write(fd, data, size);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) die("write review terminal");
        data += written;
        size -= (size_t)written;
    }
}

int main(int argc, char **argv) {
    int cancel = argc > 1 && strcmp(argv[1], "--fixture-cancel") == 0;
    if (cancel) { ++argv; --argc; }
    if (argc < 4 ||
        (strcmp(argv[2], "run") != 0 && strcmp(argv[2], "authorize") != 0)) {
        fputs("usage: review-terminal [--fixture-cancel] DEPLOYER run|authorize FIXTURE.xml ...\n", stderr);
        return 125;
    }
    FILE *xml = fopen(argv[3], "rb");
    if (!xml) die("open test deployment");
    char input[262145];
    size_t size = fread(input, 1, sizeof(input), xml);
    if (ferror(xml) || size == sizeof(input) || fclose(xml) != 0) die("read test deployment");
    input[size] = 0;
    const char *tag = "<deployment id=\"";
    char *identity = strstr(input, tag);
    if (!identity) die("find fixture ID");
    identity += strlen(tag);
    char *last = strchr(identity, '"');
    if (!last || last == identity || last - identity > 128) die("bound fixture ID");
    for (char *i = identity; i < last; ++i) {
        if (!(isalnum((unsigned char)*i) || *i == '-' || *i == '_')) die("validate fixture ID");
    }
    int one_click = 0;
    for (int i = 4; i < argc; ++i) {
        if (strcmp(argv[i], "--accept-recommendations") == 0) one_click = 1;
    }
    if (!one_click) {
        fputs("review-terminal requires the fixture's one-click recommendation option\n", stderr);
        return 125;
    }
    char final[160];
    int length = snprintf(final, sizeof(final), "%s %.*s\n",
                          strcmp(argv[2], "run") == 0 ? "deploy" : "authorize", (int)(last - identity), identity);
    if (length <= 0 || (size_t)length >= sizeof(final)) die("create fixture answer");
    int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0) die("prepare PTY");
    const char *slave_name = ptsname(master);
    if (!slave_name) die("name PTY");
    int slave = open(slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0) die("open PTY slave");
    struct termios mode;
    if (tcgetattr(slave, &mode) < 0) die("read PTY mode");
    mode.c_lflag &= (tcflag_t)~ECHO;
    mode.c_oflag &= (tcflag_t)~OPOST;
    if (tcsetattr(slave, TCSANOW, &mode) < 0) die("configure PTY");
    pid_t relay = fork();
    if (relay < 0) die("fork PTY relay");
    if (relay == 0) {
        close(slave);
        if (cancel) {
            full_write(master, "cancel\n", 7);
        } else {
            full_write(master, final, (size_t)length);
        }
        char data[4096];
        for (;;) {
            ssize_t n = read(master, data, sizeof(data));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) _exit(0);
            full_write(STDOUT_FILENO, data, (size_t)n);
        }
    }
    close(master);
    for (int fd = 0; fd <= 2; ++fd) {
        if (dup2(slave, fd) < 0) die("connect PTY to test command");
    }
    close(slave);
    execv(argv[1], argv + 1);
    die("exec test deployer");
}
