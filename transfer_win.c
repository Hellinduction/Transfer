/*
 * transfer_win.c — Windows file-transfer client
 *
 * Compile (no TLS, from WSL):
 *   x86_64-w64-mingw32-gcc transfer_win.c -o transfer.exe -lws2_32 -lz -static
 *
 * Compile (with TLS, from WSL):
 *   x86_64-w64-mingw32-gcc transfer_win.c -o transfer.exe -DHAVE_TLS -lws2_32 -lz -lssl -lcrypto -static
 *
 * Usage:
 *   transfer.exe <server_ip> <server_port> [flags] <code> <file/folder>
 *
 * Flags:
 *   --nr               non-recursive (top-level files only)
 *   --nj               skip .jar files
 *   --tls              force TLS (auto-enabled on port 443)
 *   --ignore <word>    skip files/folders whose name contains <word> (repeatable)
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <zlib.h>
#ifdef HAVE_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#pragma comment(lib, "ws2_32.lib")

#define CHUNK_RAW  65536
#define CHUNK_COMP 66000

static const char       *g_server_ip;
static int               g_server_port;
static const char       *g_code;
static struct sockaddr_in g_addr;
static int               g_addr_resolved = 0;
static SOCKET            g_sock    = INVALID_SOCKET;
static int               g_sent    = 0;
static int               g_skipped = 0;
static int               g_errors  = 0;
static int               g_tty     = 0;
static int               g_aborted = 0;
static int               g_use_tls = 0;

static const char **g_ignores  = NULL;
static int          g_nignores = 0;

#ifdef HAVE_TLS
static SSL_CTX *g_ssl_ctx = NULL;
static SSL     *g_ssl     = NULL;
#endif

/* ── manifest ─────────────────────────────────────────────────────────── */

typedef struct { char path[1024]; uint64_t size; uint32_t crc32; } ManifestEntry;
static ManifestEntry *g_manifest   = NULL;
static uint32_t       g_manifest_n = 0;

/* ── helpers ──────────────────────────────────────────────────────────── */

static int is_ignored(const char *name) {
    for (int i = 0; i < g_nignores; i++) {
        char hay[512], ndl[512];
        strncpy(hay, name,          sizeof(hay)-1); hay[sizeof(hay)-1] = '\0';
        strncpy(ndl, g_ignores[i],  sizeof(ndl)-1); ndl[sizeof(ndl)-1] = '\0';
        CharLowerA(hay); CharLowerA(ndl);
        if (strstr(hay, ndl)) return 1;
    }
    return 0;
}

static int send_all(SOCKET s, const void *buf, int n) {
    int sent = 0;
    while (sent < n) {
        int r;
#ifdef HAVE_TLS
        if (g_ssl) r = SSL_write(g_ssl, (const char*)buf + sent, n - sent);
        else
#endif
        r = send(s, (const char*)buf + sent, n - sent, 0);
        if (r <= 0) return -1;
        sent += r;
    }
    return 0;
}

static int recv_all(SOCKET s, void *buf, int n) {
    int got = 0;
    while (got < n) {
        int r;
#ifdef HAVE_TLS
        if (g_ssl) r = SSL_read(g_ssl, (char*)buf + got, n - got);
        else
#endif
        r = recv(s, (char*)buf + got, n - got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    return 0;
}

static void write_be32(uint8_t *b, uint32_t v) {
    b[0]=(uint8_t)(v>>24); b[1]=(uint8_t)(v>>16); b[2]=(uint8_t)(v>>8); b[3]=(uint8_t)v;
}
static void write_be64(uint8_t *b, uint64_t v) {
    for (int i = 7; i >= 0; i--) { b[i]=(uint8_t)(v&0xFF); v>>=8; }
}
static uint32_t read_be32s(SOCKET s) {
    uint8_t b[4]; if (recv_all(s,b,4)<0) return 0;
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
}
static uint64_t read_be64s(SOCKET s) {
    uint8_t b[8]; if (recv_all(s,b,8)<0) return 0;
    uint64_t v=0; for(int i=0;i<8;i++) v=(v<<8)|b[i]; return v;
}

static uint32_t file_crc32_win(const char *path) {
    FILE *f = fopen(path, "rb"); if (!f) return 0;
    uint32_t crc = crc32(0L, Z_NULL, 0);
    uint8_t buf[CHUNK_RAW]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        crc = crc32(crc, buf, (uInt)n);
    fclose(f);
    return crc;
}

/* ── manifest ─────────────────────────────────────────────────────────── */

static void read_manifest(void) {
    uint32_t count = read_be32s(g_sock);
    if (count == 0) return;
    g_manifest = malloc(count * sizeof(ManifestEntry));
    if (!g_manifest) {
        for (uint32_t i = 0; i < count; i++) {
            uint32_t nl = read_be32s(g_sock);
            char tmp[1024]; if (nl > 1023) break;
            recv_all(g_sock, tmp, (int)nl);
            uint8_t skip[12]; recv_all(g_sock, skip, 12);
        }
        return;
    }
    for (uint32_t i = 0; i < count; i++) {
        uint32_t nl = read_be32s(g_sock);
        if (nl == 0 || nl > 1023) break;
        if (recv_all(g_sock, g_manifest[g_manifest_n].path, (int)nl) < 0) break;
        g_manifest[g_manifest_n].path[nl] = '\0';
        g_manifest[g_manifest_n].size  = read_be64s(g_sock);
        g_manifest[g_manifest_n].crc32 = read_be32s(g_sock);
        g_manifest_n++;
    }
    if (g_manifest_n > 0)
        printf("Server has %u file(s) — will skip CRC32 matches.\n", g_manifest_n);
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

/* ── connect + handshake ─────────────────────────────────────────────── */

static SOCKET connect_to_server(void) {
    if (!g_addr_resolved) {
        char port_str[16]; snprintf(port_str, sizeof(port_str), "%d", g_server_port);
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        int gai = getaddrinfo(g_server_ip, port_str, &hints, &res);
        if (gai) { fprintf(stderr, "Cannot resolve %s: %s\n", g_server_ip, gai_strerror(gai)); return INVALID_SOCKET; }
        memcpy(&g_addr, res->ai_addr, sizeof(g_addr));
        freeaddrinfo(res);
        g_addr_resolved = 1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) { fprintf(stderr, "socket() failed\n"); return INVALID_SOCKET; }

    /* non-blocking connect with 10s timeout */
    u_long nb = 1; ioctlsocket(sock, FIONBIO, &nb);
    connect(sock, (struct sockaddr*)&g_addr, sizeof(g_addr));
    fd_set wfds; FD_ZERO(&wfds); FD_SET(sock, &wfds);
    struct timeval ctv = { 10, 0 };
    int sel = select(0, NULL, &wfds, NULL, &ctv);
    if (sel <= 0) {
        fprintf(stderr, "Cannot connect to %s:%d: %s\n", g_server_ip, g_server_port,
                sel == 0 ? "timed out" : "failed");
        closesocket(sock); return INVALID_SOCKET;
    }
    int err = 0; int elen = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &elen);
    if (err) {
        fprintf(stderr, "Cannot connect to %s:%d: error %d\n", g_server_ip, g_server_port, err);
        closesocket(sock); return INVALID_SOCKET;
    }
    nb = 0; ioctlsocket(sock, FIONBIO, &nb);

    DWORD tms = 30000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tms, sizeof(tms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&tms, sizeof(tms));

#ifdef HAVE_TLS
    if (g_use_tls) {
        g_ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!g_ssl_ctx) { fprintf(stderr, "SSL_CTX_new failed\n"); closesocket(sock); return INVALID_SOCKET; }
        SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
        g_ssl = SSL_new(g_ssl_ctx);
        SSL_set_fd(g_ssl, (int)sock);
        SSL_set_tlsext_host_name(g_ssl, g_server_ip);
        if (SSL_connect(g_ssl) <= 0) {
            fprintf(stderr, "TLS handshake failed\n");
            SSL_free(g_ssl); g_ssl = NULL;
            SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL;
            closesocket(sock); return INVALID_SOCKET;
        }
    }
#endif

    uint8_t magic[4] = {0x54, 0x52, 0x46, 0x53};
    send_all(sock, magic, 4);
    char code_buf[256]; snprintf(code_buf, sizeof(code_buf), "%s\n", g_code);
    send_all(sock, code_buf, (int)strlen(code_buf));
    char confirm = 0; recv_all(sock, &confirm, 1);
    if (confirm != 'l') {
        fprintf(stderr, "Bad confirmation: 0x%02x\n", (unsigned char)confirm);
        closesocket(sock); return INVALID_SOCKET;
    }
    return sock;
}

/* ── count files (quick pass before transfer) ────────────────────────── */

static uint32_t count_dir_win(const char *dir, int nr, int nj) {
    char pattern[4096]; snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    WIN32_FIND_DATAA fd; HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    uint32_t n = 0;
    do {
        if (!strcmp(fd.cFileName,".") || !strcmp(fd.cFileName,"..")) continue;
        if (is_ignored(fd.cFileName)) continue;
        if (nj) { size_t nl=strlen(fd.cFileName); if (nl>=4 && !_stricmp(fd.cFileName+nl-4,".jar")) continue; }
        char full[4096]; snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!nr) n += count_dir_win(full, 0, nj);
        } else {
            n++;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return n;
}

/* ── send one file ───────────────────────────────────────────────────── */

static int send_file_data(const char *abs_path, const char *rel_path) {
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!GetFileAttributesExA(abs_path, GetFileExInfoStandard, &fa)) {
        fprintf(stderr, "\nCannot stat: %s\n", abs_path);
        return 0;
    }
    uint64_t file_size = ((uint64_t)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;

    if (g_manifest_n > 0) {
        uint32_t crc = file_crc32_win(abs_path);
        if (manifest_has(rel_path, file_size, crc)) {
            g_skipped++;
            if (g_tty) { printf("\r\033[K  [skip] %s", rel_path); fflush(stdout); }
            return 0;
        }
    }

    FILE *ffd = fopen(abs_path, "rb");
    if (!ffd) {
        fprintf(stderr, "\nCannot open: %s\n", abs_path);
        return 0;
    }

    uint32_t nlen = (uint32_t)strlen(rel_path);
    uint8_t flags = 0x01, hdr[4], sz[8];
    write_be32(hdr, nlen);
    write_be64(sz, file_size);

    if (send_all(g_sock, &flags, 1)           < 0 ||
        send_all(g_sock, hdr, 4)              < 0 ||
        send_all(g_sock, rel_path, (int)nlen) < 0 ||
        send_all(g_sock, sz, 8)               < 0) {
        fclose(ffd); return -1;
    }

    z_stream s; memset(&s, 0, sizeof(s));
    deflateInit(&s, Z_BEST_SPEED);
    uint8_t in_buf[CHUNK_RAW], out_buf[CHUNK_COMP];
    int eof = 0, ok = 1;
    while (!eof && ok) {
        size_t got = fread(in_buf, 1, CHUNK_RAW, ffd);
        if (ferror(ffd)) { ok = 0; break; }
        if (got == 0) { eof = 1; }
        s.avail_in = (uInt)got; s.next_in = in_buf;
        int flush = eof ? Z_FINISH : Z_NO_FLUSH;
        do {
            s.avail_out = CHUNK_COMP; s.next_out = out_buf;
            deflate(&s, flush);
            uint32_t have = CHUNK_COMP - s.avail_out;
            if (have > 0) {
                uint8_t chdr[4]; write_be32(chdr, have);
                if (send_all(g_sock, chdr, 4) < 0 ||
                    send_all(g_sock, out_buf, (int)have) < 0) { ok = 0; break; }
            }
        } while (s.avail_out == 0);
    }
    deflateEnd(&s);
    fclose(ffd);

    uint8_t zero[4] = {0,0,0,0};
    if (ok) send_all(g_sock, zero, 4);
    if (!ok) return -1;

    g_sent++;
    if (g_tty) { printf("\r\033[K  [%d] %s", g_sent, rel_path); fflush(stdout); }
    return 0;
}

/* ── walk directory ───────────────────────────────────────────────────── */

static void walk_dir(const char *dir, size_t root_len, int nr, int nj) {
    char pattern[4096]; snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    WIN32_FIND_DATAA fd; HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
        if (is_ignored(fd.cFileName)) continue;
        if (nj) {
            size_t nl = strlen(fd.cFileName);
            if (nl >= 4 && !_stricmp(fd.cFileName + nl - 4, ".jar")) continue;
        }

        char full[4096]; snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName);

        if (g_aborted) break;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!nr) walk_dir(full, root_len, 0, nj);
        } else {
            const char *rel = full + root_len;
            while (*rel == '\\' || *rel == '/') rel++;
            char rel_fwd[4096]; strncpy(rel_fwd, rel, sizeof(rel_fwd)-1); rel_fwd[sizeof(rel_fwd)-1] = '\0';
            for (char *p = rel_fwd; *p; p++) if (*p == '\\') *p = '/';

            if (send_file_data(full, rel_fwd) < 0) {
                g_errors++;
                g_aborted = 1;
                printf("\nConnection lost.\n");
                break;
            }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

/* ── usage ────────────────────────────────────────────────────────────── */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <server_ip> <server_port> [flags] <code> <file/folder>\n"
        "\n"
        "  --nr               non-recursive\n"
        "  --nj               skip .jar files\n"
        "  --tls              force TLS (auto on port 443)\n"
        "  --ignore <word>    skip files/dirs whose name contains <word> (repeatable)\n"
        "\n"
        "Example:\n"
        "  %s 1.2.3.4 5812 --ignore backup abc123 .\\world\n",
        prog, prog);
}

/* ── main ─────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD conMode = 0;
    if (GetConsoleMode(hOut, &conMode))
        SetConsoleMode(hOut, conMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    if (argc < 5) { usage(argv[0]); return 1; }

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

#ifndef HAVE_TLS
    if (g_use_tls) {
        fprintf(stderr, "TLS not compiled in — rebuild with -DHAVE_TLS\n");
        return 1;
    }
#endif

    g_tty = _isatty(_fileno(stdout));

    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "Not found: %s\n", path); return 1;
    }

    g_sock = connect_to_server();
    if (g_sock == INVALID_SOCKET) { WSACleanup(); return 1; }

    read_manifest();

    /* send 0x02 metadata packet with total file count */
    {
        uint32_t total = (attr & FILE_ATTRIBUTE_DIRECTORY) ? count_dir_win(path, nr, nj) : 1;
        uint8_t meta[5]; meta[0] = 0x02; write_be32(meta+1, total);
        send_all(g_sock, meta, 5);
    }

    printf("Connected (code: %s)\n", g_code);

    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        const char *fname = strrchr(path, '\\');
        if (!fname) fname = strrchr(path, '/');
        fname = fname ? fname + 1 : path;
        if (send_file_data(path, fname) < 0) { closesocket(g_sock); WSACleanup(); return 1; }
    } else {
        char root[4096]; strncpy(root, path, sizeof(root)-1); root[sizeof(root)-1] = '\0';
        size_t rlen = strlen(root);
        while (rlen > 0 && (root[rlen-1] == '\\' || root[rlen-1] == '/')) root[--rlen] = '\0';
        const char *sep  = strrchr(root, '\\');
        const char *sep2 = strrchr(root, '/');
        if (sep2 > sep) sep = sep2;
        size_t prefix_len = sep ? (size_t)(sep - root + 1) : 0;
        walk_dir(root, prefix_len, nr, nj);
    }

    uint8_t term = 0xFF;
    send_all(g_sock, &term, 1);
#ifdef HAVE_TLS
    if (g_ssl) { SSL_shutdown(g_ssl); SSL_free(g_ssl); }
    if (g_ssl_ctx) SSL_CTX_free(g_ssl_ctx);
#endif
    closesocket(g_sock);
    printf("%sDone: %d sent, %d skipped, %d failed.\n",
           g_tty ? "\n" : "", g_sent, g_skipped, g_errors);
    WSACleanup();
    return g_errors ? 1 : 0;
}
