#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <crypt.h>
#include <ctype.h>
#include <stdarg.h>

#define PORT 50936
#define SID "1009"
#define REGNO "IT24100936"
#define LOG_FILE "server_IT24100936.log"
#define BASE_DIR "/srv/ie2102/IT24100936"

#define MAX_PAYLOAD 4096
#define MAX_LINE 8192
#define MAX_USERNAME 32
#define MAX_PASSWORD 64
#define TOKEN_LEN 64
#define SESSION_TIMEOUT 300
#define RATE_WINDOW 10
#define RATE_LIMIT 20
#define LOGIN_FAIL_LIMIT 3
#define LOGIN_LOCK_SECS 60

typedef struct {
    int authed;
    char username[MAX_USERNAME + 1];
    char token[TOKEN_LEN + 1];
    time_t last_activity;
    int window_count;
    time_t window_start;
} Session;

typedef struct {
    char ip[64];
    int count;
    time_t first_time;
    time_t lock_until;
} FailRecord;

static FailRecord fail_records[256];
static int fail_record_count = 0;

static void reap_children(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
}

static void trim_newline(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[n - 1] = '\0';
        n--;
    }
}

static void now_string(char *out, size_t size) {
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(out, size, "%Y-%m-%d %H:%M:%S", &tmv);
}

static void ensure_dir(const char *path) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

static void log_event(const char *ip_port, const char *username, const char *command, const char *result) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) return;

    char ts[64];
    now_string(ts, sizeof(ts));
    fprintf(fp, "%s | %s | PID:%d | USER:%s | CMD:%s | RESULT:%s\n",
            ts,
            ip_port ? ip_port : "-",
            getpid(),
            (username && username[0]) ? username : "-",
            command ? command : "-",
            result ? result : "-");
    fclose(fp);
}

static void send_response(int fd, const char *fmt, ...) {
    char body[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);

    char frame[4096];
    int len = (int)strlen(body);
    int n = snprintf(frame, sizeof(frame), "LEN:%d\n%s", len, body);
    if (n > 0) {
        send(fd, frame, (size_t)n, 0);
    }
}

static int valid_username(const char *u) {
    size_t n = strlen(u);
    if (n < 3 || n > MAX_USERNAME) return 0;
    for (size_t i = 0; i < n; i++) {
        if (!(isalnum((unsigned char)u[i]) || u[i] == '_')) return 0;
    }
    return 1;
}

static int get_fail_record_index(const char *ip) {
    for (int i = 0; i < fail_record_count; i++) {
        if (strcmp(fail_records[i].ip, ip) == 0) return i;
    }
    if (fail_record_count >= 256) return -1;
    snprintf(fail_records[fail_record_count].ip, sizeof(fail_records[fail_record_count].ip), "%s", ip);
    fail_records[fail_record_count].count = 0;
    fail_records[fail_record_count].first_time = 0;
    fail_records[fail_record_count].lock_until = 0;
    return fail_record_count++;
}

static int ip_locked(const char *ip) {
    int idx = get_fail_record_index(ip);
    if (idx < 0) return 0;
    return fail_records[idx].lock_until > time(NULL);
}

static void record_login_failure(const char *ip) {
    int idx = get_fail_record_index(ip);
    if (idx < 0) return;
    time_t now = time(NULL);
    if (now - fail_records[idx].first_time > LOGIN_LOCK_SECS) {
        fail_records[idx].count = 0;
        fail_records[idx].first_time = now;
    }
    if (fail_records[idx].first_time == 0) fail_records[idx].first_time = now;
    fail_records[idx].count++;
    if (fail_records[idx].count >= LOGIN_FAIL_LIMIT) {
        fail_records[idx].lock_until = now + LOGIN_LOCK_SECS;
        fail_records[idx].count = 0;
        fail_records[idx].first_time = now;
    }
}

static void clear_login_failures(const char *ip) {
    int idx = get_fail_record_index(ip);
    if (idx < 0) return;
    fail_records[idx].count = 0;
    fail_records[idx].first_time = 0;
    fail_records[idx].lock_until = 0;
}

static int session_expired(Session *s) {
    if (!s->authed) return 0;
    return (time(NULL) - s->last_activity) > SESSION_TIMEOUT;
}

static void generate_token(char *out, size_t size, const char *username) {
    unsigned int r1 = (unsigned int)rand();
    unsigned int r2 = (unsigned int)rand();
    snprintf(out, size, "%s_%ld_%u_%u", username, (long)time(NULL), r1, r2);
}

static int save_user(const char *username, const char *salt_hash) {
    ensure_dir(BASE_DIR);
    char dir[256], file[512];
    snprintf(dir, sizeof(dir), "%s/%s", BASE_DIR, username);
    ensure_dir(dir);
    snprintf(file, sizeof(file), "%s/user.txt", dir);

    if (access(file, F_OK) == 0) return 0;

    FILE *fp = fopen(file, "w");
    if (!fp) return -1;
    fprintf(fp, "username=%s\npassword=%s\n", username, salt_hash);
    fclose(fp);
    return 1;
}

static int load_user_hash(const char *username, char *out, size_t size) {
    char file[512], line[512];
    snprintf(file, sizeof(file), "%s/%s/user.txt", BASE_DIR, username);
    FILE *fp = fopen(file, "r");
    if (!fp) return 0;

    while (fgets(line, sizeof(line), fp)) {
        trim_newline(line);
        if (strncmp(line, "password=", 9) == 0) {
            snprintf(out, size, "%s", line + 9);
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

static int verify_password(const char *password, const char *stored_hash) {
    char *hashed = crypt(password, stored_hash);
    if (!hashed) return 0;
    return strcmp(hashed, stored_hash) == 0;
}

static int rate_limit_hit(Session *s) {
    time_t now = time(NULL);
    if (s->window_start == 0 || (now - s->window_start) > RATE_WINDOW) {
        s->window_start = now;
        s->window_count = 0;
    }
    s->window_count++;
    return s->window_count > RATE_LIMIT;
}

static int parse_three_tokens(const char *cmd, char *a, char *b, char *c) {
    return sscanf(cmd, "%31s %63s %63s", a, b, c);
}

static void handle_command(int fd, Session *sess, const char *client_ip, const char *ip_port, const char *cmdline) {
    char cmd[32] = {0}, arg1[64] = {0}, arg2[64] = {0};
    char logcmd[256];
    snprintf(logcmd, sizeof(logcmd), "%s", cmdline);

    if (rate_limit_hit(sess)) {
        send_response(fd, "ERR 429 SID:%s Too many requests", SID);
        log_event(ip_port, sess->username, logcmd, "ERR 429 rate-limit");
        return;
    }

    if (session_expired(sess)) {
        sess->authed = 0;
        sess->username[0] = '\0';
        sess->token[0] = '\0';
        send_response(fd, "ERR 440 SID:%s Session expired", SID);
        log_event(ip_port, "-", logcmd, "ERR 440 session-expired");
        return;
    }

    int parts = parse_three_tokens(cmdline, cmd, arg1, arg2);
    for (size_t i = 0; i < strlen(cmd); i++) cmd[i] = (char)toupper((unsigned char)cmd[i]);

    if (strcmp(cmd, "REGISTER") == 0) {
        if (parts != 3) {
            send_response(fd, "ERR 400 SID:%s Usage: REGISTER <user> <pass>", SID);
            log_event(ip_port, sess->username, logcmd, "ERR 400 bad-register-format");
            return;
        }
        if (!valid_username(arg1)) {
            send_response(fd, "ERR 422 SID:%s Invalid username", SID);
            log_event(ip_port, sess->username, logcmd, "ERR 422 invalid-username");
            return;
        }
        char salt[64];
        snprintf(salt, sizeof(salt), "$6$%ld$", (long)time(NULL) ^ (long)getpid());
        char *hash = crypt(arg2, salt);
        if (!hash) {
            send_response(fd, "ERR 500 SID:%s Hashing failed", SID);
            log_event(ip_port, sess->username, logcmd, "ERR 500 hash-failed");
            return;
        }
        int sv = save_user(arg1, hash);
        if (sv == 0) {
            send_response(fd, "ERR 409 SID:%s User already exists", SID);
            log_event(ip_port, sess->username, logcmd, "ERR 409 user-exists");
            return;
        }
        if (sv < 0) {
            send_response(fd, "ERR 500 SID:%s Could not store user", SID);
            log_event(ip_port, sess->username, logcmd, "ERR 500 save-failed");
            return;
        }
        send_response(fd, "OK 201 SID:%s User registered", SID);
        log_event(ip_port, arg1, logcmd, "OK 201 registered");
        return;
    }

    if (strcmp(cmd, "LOGIN") == 0) {
        if (parts != 3) {
            send_response(fd, "ERR 400 SID:%s Usage: LOGIN <user> <pass>", SID);
            log_event(ip_port, sess->username, logcmd, "ERR 400 bad-login-format");
            return;
        }
        if (ip_locked(client_ip)) {
            send_response(fd, "ERR 423 SID:%s Login temporarily locked", SID);
            log_event(ip_port, sess->username, logcmd, "ERR 423 lockout");
            return;
        }
        char stored[256];
        if (!load_user_hash(arg1, stored, sizeof(stored)) || !verify_password(arg2, stored)) {
            record_login_failure(client_ip);
            send_response(fd, "ERR 401 SID:%s Invalid credentials", SID);
            log_event(ip_port, arg1, logcmd, "ERR 401 invalid-credentials");
            return;
        }
        clear_login_failures(client_ip);
        sess->authed = 1;
        strncpy(sess->username, arg1, MAX_USERNAME);
        sess->username[MAX_USERNAME] = '\0';
        generate_token(sess->token, sizeof(sess->token), arg1);
        sess->last_activity = time(NULL);
        send_response(fd, "OK 200 SID:%s TOKEN %s", SID, sess->token);
        log_event(ip_port, sess->username, logcmd, "OK 200 login-success");
        return;
    }

    if (strcmp(cmd, "LOGOUT") == 0) {
        if (!sess->authed) {
            send_response(fd, "ERR 401 SID:%s Not logged in", SID);
            log_event(ip_port, sess->username, logcmd, "ERR 401 not-logged-in");
            return;
        }
        sess->authed = 0;
        sess->username[0] = '\0';
        sess->token[0] = '\0';
        send_response(fd, "OK 200 SID:%s Logged out", SID);
        log_event(ip_port, "-", logcmd, "OK 200 logout");
        return;
    }

    if (strcmp(cmd, "PING") == 0) {
        send_response(fd, "OK 200 SID:%s PONG", SID);
        log_event(ip_port, sess->username, logcmd, "OK 200 pong");
        return;
    }

    if (strcmp(cmd, "WHOAMI") == 0) {
        char tok[128] = {0};
        if (sscanf(cmdline, "%*s %127s", tok) != 1) {
            send_response(fd, "ERR 400 SID:%s Usage: WHOAMI <token>", SID);
            log_event(ip_port, sess->username, logcmd, "ERR 400 bad-whoami-format");
            return;
        }
        if (!sess->authed || strcmp(tok, sess->token) != 0) {
            send_response(fd, "ERR 403 SID:%s Invalid token", SID);
            log_event(ip_port, sess->username, logcmd, "ERR 403 invalid-token");
            return;
        }
        sess->last_activity = time(NULL);
        send_response(fd, "OK 200 SID:%s USER %s", SID, sess->username);
        log_event(ip_port, sess->username, logcmd, "OK 200 whoami");
        return;
    }

    send_response(fd, "ERR 400 SID:%s Unknown command", SID);
    log_event(ip_port, sess->username, logcmd, "ERR 400 unknown-command");
}

static void process_client(int client_fd, struct sockaddr_in *client_addr) {
    Session sess;
    memset(&sess, 0, sizeof(sess));

    char client_ip[64];
    char ip_port[128];
    inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, sizeof(client_ip));
    snprintf(ip_port, sizeof(ip_port), "%s:%d", client_ip, ntohs(client_addr->sin_port));

    char buffer[16384];
    int used = 0;

    while (1) {
        ssize_t n = recv(client_fd, buffer + used, sizeof(buffer) - used, 0);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        used += (int)n;

        int offset = 0;
        while (1) {
            char *nl = memchr(buffer + offset, '\n', (size_t)(used - offset));
            if (!nl) break;

            int header_len = (int)(nl - (buffer + offset));
            if (header_len <= 0 || header_len >= 64) {
                send_response(client_fd, "ERR 400 SID:%s Invalid frame header", SID);
                log_event(ip_port, sess.username, "FRAME", "ERR 400 invalid-header");
                close(client_fd);
                return;
            }

            char header[64];
            memcpy(header, buffer + offset, (size_t)header_len);
            header[header_len] = '\0';

            int payload_len = -1;
            if (sscanf(header, "LEN:%d", &payload_len) != 1) {
                send_response(client_fd, "ERR 400 SID:%s Invalid length", SID);
                log_event(ip_port, sess.username, "FRAME", "ERR 400 invalid-length");
                close(client_fd);
                return;
            }
            if (payload_len < 0) {
                send_response(client_fd, "ERR 400 SID:%s Negative length", SID);
                log_event(ip_port, sess.username, "FRAME", "ERR 400 negative-length");
                close(client_fd);
                return;
            }
            if (payload_len > MAX_PAYLOAD) {
                send_response(client_fd, "ERR 413 SID:%s Payload too large", SID);
                log_event(ip_port, sess.username, "FRAME", "ERR 413 oversized-payload");
                close(client_fd);
                return;
            }

            int frame_size = header_len + 1 + payload_len;
            if ((used - offset) < frame_size) break;

            char payload[MAX_PAYLOAD + 1];
            memcpy(payload, nl + 1, (size_t)payload_len);
            payload[payload_len] = '\0';
            handle_command(client_fd, &sess, client_ip, ip_port, payload);

            offset += frame_size;
        }

        if (offset > 0) {
            memmove(buffer, buffer + offset, (size_t)(used - offset));
            used -= offset;
        }

        if (used == (int)sizeof(buffer)) {
            send_response(client_fd, "ERR 413 SID:%s Buffer overflow rejected", SID);
            log_event(ip_port, sess.username, "FRAME", "ERR 413 buffer-overflow");
            break;
        }
    }

    close(client_fd);
}

int main(void) {
    srand((unsigned int)(time(NULL) ^ getpid()));
    ensure_dir(BASE_DIR);

    signal(SIGCHLD, reap_children);
    signal(SIGPIPE, SIG_IGN);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 20) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("Server running on port %d with SID:%s\n", PORT, SID);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(client_fd);
            continue;
        }

        if (pid == 0) {
            close(server_fd);
            process_client(client_fd, &client_addr);
            exit(0);
        }

        close(client_fd);
    }

    close(server_fd);
    return 0;
}
