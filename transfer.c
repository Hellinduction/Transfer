/*
 * transfer.c — file-transfer client with streaming gzip compression + resume support
 *
 * Compile (plain TCP):
 *   docker run --rm -v ${PWD}:/src alpine sh -c \
 *     "apk add --no-cache gcc musl-dev zlib-dev zlib-static && \
 *      gcc -static -o /src/transfer /src/transfer.c -lz && chmod +x /src/transfer"
 *
 * Compile (with TLS via OpenSSL):
 *   docker run --rm -v ${PWD}:/src alpine sh -c \
 *     "apk add --no-cache gcc musl-dev zlib-dev zlib-static openssl-dev openssl-libs-static && \
 *      gcc -static -o /src/transfer /src/transfer.c -lz -lssl -lcrypto && chmod +x /src/transfer"
 *
 * Usage:
 *   transfer <server_ip> <server_port> [flags] <code> <file/folder>
 *
 * Flags:
 *   --tls              connect with TLS (required for nginx TLS termination)
 *   --nr               non-recursive (top-level files only)
 *   --nj               skip .jar files
 *   --ignore <word>    skip files/folders whose name contains <word> (repeatable)
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <zlib.h>
#ifdef HAVE_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifndef TCP_USER_TIMEOUT
#define TCP_USER_TIMEOUT 18
#endif

#define CHUNK_RAW  65536
#define CHUNK_COMP 66000

static const char       *g_server_ip;
static int               g_server_port;
static const char       *g_code;
static struct sockaddr_in g_addr;
static int               g_addr_resolved = 0;
static int               g_sock    = -1;
static int               g_sent    = 0;
static int               g_skipped = 0;
static int               g_errors  = 0;
static int               g_tty     = 0;
static int               g_aborted = 0;

static int          g_use_tls = 0;
static const char **g_ignores  = NULL;
static int          g_nignores = 0;

#ifdef HAVE_TLS
static SSL_CTX *g_ssl_ctx = NULL;
static SSL     *g_ssl     = NULL;
#endif

/* ── manifest (files already on server) ──────────────────────────────────── */

typedef struct { char path[1024]; uint64_t size; uint32_t crc32; } ManifestEntry;
static ManifestEntry *g_manifest   = NULL;
static uint32_t       g_manifest_n = 0;

/* ── helpers ──────────────────────────────────────────────────────────────── */

static int is_ignored(const char *name) {
    for (int i = 0; i < g_nignores; i++)
        if (strcasestr(name, g_ignores[i])) return 1;
    return 0;
}

static int send_all(int fd, const void *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t r;
#ifdef HAVE_TLS
        if (g_ssl) r = SSL_write(g_ssl, (const char*)buf + sent, (int)(n - sent));
        else
#endif
        r = send(fd, (const char*)buf + sent, n - sent, 0);
        if (r <= 0) return -1;
        sent += (size_t)r;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r;
#ifdef HAVE_TLS
        if (g_ssl) r = SSL_read(g_ssl, (char*)buf + got, (int)(n - got));
        else
#endif
        r = recv(fd, (char*)buf + got, n - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static void write_be32(uint8_t *b, uint32_t v) {
    b[0]=(uint8_t)(v>>24); b[1]=(uint8_t)(v>>16); b[2]=(uint8_t)(v>>8); b[3]=(uint8_t)v;
}
static void write_be64(uint8_t *b, uint64_t v) {
    for (int i = 7; i >= 0; i--) { b[i]=(uint8_t)(v&0xFF); v>>=8; }
}
static uint32_t read_be32(int fd) {
    uint8_t b[4]; if (recv_all(fd,b,4)<0) return 0;
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
}
static uint64_t read_be64(int fd) {
    uint8_t b[8]; if (recv_all(fd,b,8)<0) return 0;
    uint64_t v=0; for(int i=0;i<8;i++) v=(v<<8)|b[i]; return v;
}

/* ── CRC32 of a local file ───────────────────────────────────────────────── */

static uint32_t file_crc32(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    uint32_t crc = crc32(0L, Z_NULL, 0);
    uint8_t buf[CHUNK_RAW];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        crc = crc32(crc, buf, (uInt)n);
    close(fd);
    return crc;
}

/* ── manifest: read from server, build skip-set ──────────────────────────── */

static void read_manifest(void) {
    uint32_t count = read_be32(g_sock);
    if (count == 0) return;
    g_manifest = malloc(count * sizeof(ManifestEntry));
    if (!g_manifest) {
        /* drain to keep protocol in sync */
        for (uint32_t i = 0; i < count; i++) {
            uint32_t nl = read_be32(g_sock);
            char tmp[1024]; if (nl > 1023) break;
            recv_all(g_sock, tmp, nl);
            uint8_t skip[12]; recv_all(g_sock, skip, 12);
        }
        return;
    }
    for (uint32_t i = 0; i < count; i++) {
        uint32_t nl = read_be32(g_sock);
        if (nl == 0 || nl > 1023) break;
        if (recv_all(g_sock, g_manifest[g_manifest_n].path, nl) < 0) break;
        g_manifest[g_manifest_n].path[nl] = '\0';
        g_manifest[g_manifest_n].size  = read_be64(g_sock);
        g_manifest[g_manifest_n].crc32 = read_be32(g_sock);
        g_manifest_n++;
    }
    if (g_manifest_n > 0)
        printf("Server has %u file(s) — will skip unchanged files.\n", g_manifest_n);
}

static int manifest_has(const char *path, uint64_t size, uint32_t crc) {
    for (uint32_t i = 0; i < g_manifest_n; i++) {
        if (g_manifest[i].size  == size &&
            g_manifest[i].crc32 == crc  &&
            strcmp(g_manifest[i].path, path) == 0)
            return 1;
    }
    return 0;
}

/* ── connect + handshake + read manifest ─────────────────────────────────── */

static int connect_to_server(void) {
    if (!g_addr_resolved) {
        char port_str[16]; snprintf(port_str, sizeof(port_str), "%d", g_server_port);
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        int gai = getaddrinfo(g_server_ip, port_str, &hints, &res);
        if (gai) { fprintf(stderr, "Cannot resolve %s: %s\n", g_server_ip, gai_strerror(gai)); return -1; }
        memcpy(&g_addr, res->ai_addr, sizeof(g_addr));
        freeaddrinfo(res);
        g_addr_resolved = 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return -1; }

    /* non-blocking connect with 10s timeout */
    fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
    int cr = connect(sock, (struct sockaddr*)&g_addr, sizeof(g_addr));
    if (cr < 0 && errno != EINPROGRESS) {
        fprintf(stderr, "Cannot connect to %s:%d: %s\n", g_server_ip, g_server_port, strerror(errno));
        close(sock); return -1;
    }
    if (cr != 0) {
        fd_set wfds; FD_ZERO(&wfds); FD_SET(sock, &wfds);
        struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
        int sel = select(sock + 1, NULL, &wfds, NULL, &tv);
        if (sel <= 0) {
            fprintf(stderr, "Cannot connect to %s:%d: %s\n", g_server_ip, g_server_port,
                    sel == 0 ? "timed out" : strerror(errno));
            close(sock); return -1;
        }
        int err = 0; socklen_t elen = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err) {
            fprintf(stderr, "Cannot connect to %s:%d: %s\n", g_server_ip, g_server_port, strerror(err));
            close(sock); return -1;
        }
    }
    /* restore blocking mode */
    fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) & ~O_NONBLOCK);

    struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int tcp_timeout_ms = 30000;
    setsockopt(sock, IPPROTO_TCP, TCP_USER_TIMEOUT, &tcp_timeout_ms, sizeof(tcp_timeout_ms));

#ifdef HAVE_TLS
    if (g_use_tls) {
        g_ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!g_ssl_ctx) { fprintf(stderr, "SSL_CTX_new failed\n"); close(sock); return -1; }
        SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
        g_ssl = SSL_new(g_ssl_ctx);
        SSL_set_fd(g_ssl, sock);
        SSL_set_tlsext_host_name(g_ssl, g_server_ip); /* SNI */
        if (SSL_connect(g_ssl) <= 0) {
            fprintf(stderr, "TLS handshake failed\n");
            SSL_free(g_ssl); g_ssl = NULL;
            SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL;
            close(sock); return -1;
        }
    }
#endif

    uint8_t magic[4] = {0x54, 0x52, 0x46, 0x53};
    send_all(sock, magic, 4);
    char code_buf[256]; snprintf(code_buf, sizeof(code_buf), "%s\n", g_code);
    send_all(sock, code_buf, strlen(code_buf));
    char confirm = 0; recv_all(sock, &confirm, 1);
    if (confirm != 'l') {
        fprintf(stderr, "Bad confirmation: 0x%02x\n", (unsigned char)confirm);
        close(sock); return -1;
    }
    /* server is alive — extend timeout for manifest (server hashes all files) */
    struct timeval tv_long = { .tv_sec = 300, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv_long, sizeof(tv_long));
    return sock;
}

/* ── send one file (skips if server manifest matches) ────────────────────── */

static int send_file_data(const char *abs_path, const char *rel_path) {
    struct stat st;
    if (stat(abs_path, &st) < 0) {
        fprintf(stderr, "\nCannot stat %s: %s\n", abs_path, strerror(errno));
        return 0; /* non-fatal: skip this file */
    }

    if (g_manifest_n > 0) {
        uint32_t crc = file_crc32(abs_path);
        if (manifest_has(rel_path, (uint64_t)st.st_size, crc)) {
            g_skipped++;
            if (g_tty) {
                printf("\r\033[K  [skip] %s", rel_path);
                fflush(stdout);
            }
            return 0;
        }
    }

    int ffd = open(abs_path, O_RDONLY);
    if (ffd < 0) {
        fprintf(stderr, "\nCannot open %s: %s\n", abs_path, strerror(errno));
        return 0;
    }

    uint32_t nlen = (uint32_t)strlen(rel_path);
    uint8_t flags = 0x01, hdr[4], sz[8];
    write_be32(hdr, nlen);
    write_be64(sz, (uint64_t)st.st_size);

    if (send_all(g_sock, &flags, 1)      < 0 ||
        send_all(g_sock, hdr, 4)         < 0 ||
        send_all(g_sock, rel_path, nlen) < 0 ||
        send_all(g_sock, sz, 8)          < 0) {
        close(ffd); return -1;
    }

    z_stream s; memset(&s, 0, sizeof(s));
    deflateInit(&s, Z_BEST_SPEED);
    uint8_t in_buf[CHUNK_RAW], out_buf[CHUNK_COMP];
    int eof = 0, ok = 1;
    while (!eof && ok) {
        size_t got = 0;
        while (got < CHUNK_RAW) {
            ssize_t r = read(ffd, in_buf + got, CHUNK_RAW - got);
            if (r < 0) { ok = 0; break; }
            if (r == 0) { eof = 1; break; }
            got += (size_t)r;
        }
        if (!ok) break;
        s.avail_in = (uInt)got; s.next_in = in_buf;
        int flush = eof ? Z_FINISH : Z_NO_FLUSH;
        do {
            s.avail_out = CHUNK_COMP; s.next_out = out_buf;
            deflate(&s, flush);
            uint32_t have = CHUNK_COMP - s.avail_out;
            if (have > 0) {
                uint8_t chdr[4]; write_be32(chdr, have);
                if (send_all(g_sock, chdr, 4) < 0 ||
                    send_all(g_sock, out_buf, have) < 0) { ok = 0; break; }
            }
        } while (s.avail_out == 0);
    }
    deflateEnd(&s);

    uint8_t zero[4] = {0,0,0,0};
    if (ok) send_all(g_sock, zero, 4);
    close(ffd);
    if (!ok) return -1;

    g_sent++;
    if (g_tty) { printf("\r\033[K  [%d] %s", g_sent, rel_path); fflush(stdout); }
    return 0;
}

/* ── count files in directory (quick pass, no network I/O) ──────────────── */

static uint32_t count_dir(const char *dir, int nr, int nj) {
    DIR *d = opendir(dir); if (!d) return 0;
    struct dirent *de; uint32_t n = 0;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name,".") || !strcmp(de->d_name,"..")) continue;
        if (is_ignored(de->d_name)) continue;
        if (nj) { size_t nl=strlen(de->d_name); if (nl>=4 && !strcmp(de->d_name+nl-4,".jar")) continue; }
        char full[4096]; snprintf(full, sizeof(full), "%s/%s", dir, de->d_name);
        struct stat st; if (stat(full, &st) < 0) continue;
        if (S_ISDIR(st.st_mode) && !nr) n += count_dir(full, 0, nj);
        else if (S_ISREG(st.st_mode)) n++;
    }
    closedir(d); return n;
}

/* ── walk directory ───────────────────────────────────────────────────────── */

static void walk_dir(const char *dir, size_t root_len, int nr, int nj) {
    DIR *d = opendir(dir);
    if (!d) { fprintf(stderr, "\nCannot open dir %s: %s\n", dir, strerror(errno)); return; }
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name,".") || !strcmp(de->d_name,"..")) continue;
        if (is_ignored(de->d_name)) continue;
        if (nj) { size_t nl=strlen(de->d_name); if (nl>=4 && !strcmp(de->d_name+nl-4,".jar")) continue; }

        char full[4096]; snprintf(full, sizeof(full), "%s/%s", dir, de->d_name);
        struct stat st; if (stat(full, &st) < 0) continue;

        if (g_aborted) break;
        if (S_ISDIR(st.st_mode) && !nr) {
            walk_dir(full, root_len, 0, nj);
        } else if (S_ISREG(st.st_mode)) {
            const char *rel = full + root_len;
            while (*rel == '/') rel++;
            if (send_file_data(full, rel) < 0) {
                g_errors++;
                g_aborted = 1;
                printf("\nConnection lost.\n");
                break;
            }
        }
    }
    closedir(d);
}

/* ── usage ────────────────────────────────────────────────────────────────── */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <server_ip> <server_port> [flags] <code> <file/folder>\n"
        "\n"
        "  --nr               non-recursive\n"
        "  --nj               skip .jar files\n"
        "  --ignore <word>    skip files/dirs whose name contains <word> (repeatable)\n"
        "\n"
        "Example:\n"
        "  %s 1.2.3.4 5812 --ignore backup abc123 ./world\n",
        prog, prog);
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    if (argc < 5) { usage(argv[0]); return 1; }

    signal(SIGPIPE, SIG_IGN);

    g_server_ip   = argv[1];
    g_server_port = atoi(argv[2]);
    if (g_server_port <= 0 || g_server_port > 65535) {
        fprintf(stderr, "Invalid port: %s\n", argv[2]); return 1;
    }
    if (g_server_port == 443) g_use_tls = 1;

    int nr = 0, nj = 0;
    char **clean = malloc((size_t)argc * sizeof(char*)); int nc = 0;
    g_ignores = malloc((size_t)argc * sizeof(const char*)); g_nignores = 0;

    for (int i = 3; i < argc; i++) {
        if      (!strcmp(argv[i],"--nr") || !strcmp(argv[i],"-nr"))   nr = 1;
        else if (!strcmp(argv[i],"--nj") || !strcmp(argv[i],"-nj"))   nj = 1;
        else if (!strcmp(argv[i],"--tls")|| !strcmp(argv[i],"-tls"))  g_use_tls = 1;
        else if ((!strcmp(argv[i],"--ignore")||!strcmp(argv[i],"-ignore")) && i+1<argc)
            g_ignores[g_nignores++] = argv[++i];
        else if (!strcmp(argv[i],"--zip") || !strcmp(argv[i],"-zip")) ;
        else clean[nc++] = argv[i];
    }
    if (nc < 2) { usage(argv[0]); free(clean); return 1; }
    g_code = clean[0]; const char *path = clean[1]; free(clean);

    g_tty = isatty(STDOUT_FILENO);

    struct stat st;
    if (stat(path, &st) < 0) { fprintf(stderr, "Not found: %s\n", path); return 1; }

    g_sock = connect_to_server();
    if (g_sock < 0) return 1;

    read_manifest(); /* read skip-list from server before sending anything */
    /* restore 30s timeout for file transfers */
    { struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
      setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); }

    /* send 0x02 metadata packet with total file count */
    {
        uint32_t total = S_ISDIR(st.st_mode) ? count_dir(path, nr, nj) : 1;
        uint8_t meta[5]; meta[0] = 0x02; write_be32(meta+1, total);
        send_all(g_sock, meta, 5);
    }

    printf("Connected (code: %s)\n", g_code);

    if (S_ISREG(st.st_mode)) {
        const char *fname = strrchr(path, '/');
        fname = fname ? fname+1 : path;
        if (send_file_data(path, fname) < 0) { close(g_sock); return 1; }
    } else if (S_ISDIR(st.st_mode)) {
        char root[4096]; strncpy(root, path, sizeof(root)-1);
        size_t rlen = strlen(root);
        while (rlen > 0 && root[rlen-1] == '/') root[--rlen] = '\0';
        const char *last_sep = strrchr(root, '/');
        size_t prefix_len = last_sep ? (size_t)(last_sep - root + 1) : 0;
        walk_dir(root, prefix_len, nr, nj);
    }

    uint8_t term = 0xFF;
    send_all(g_sock, &term, 1);
#ifdef HAVE_TLS
    if (g_ssl) { SSL_shutdown(g_ssl); SSL_free(g_ssl); }
    if (g_ssl_ctx) SSL_CTX_free(g_ssl_ctx);
#endif
    close(g_sock);
    printf("%sDone: %d sent, %d skipped, %d failed.\n",
           g_tty ? "\n" : "", g_sent, g_skipped, g_errors);
    return g_errors ? 1 : 0;
}
