/*
 * transfer_server_win.c  —  Windows file-transfer receiver (WinSock2)
 *
 * Cross-compile from WSL:
 *   x86_64-w64-mingw32-gcc transfer_server_win.c -o transfer_server.exe -lws2_32 -lz -static
 *
 * Run:
 *   transfer_server.exe [port]   (default 5812)
 *
 * Received files land in .\received\<code>\<relative_path>
 * Port-forward your router TCP 5812 → this machine's LAN IP on 5812.
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <io.h>      /* _isatty, _fileno */
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <zlib.h>

#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_PORT 5812
#define OUTPUT_DIR   "received"
#define BUF_SIZE     8192
#define CHUNK_COMP   66000   /* max compressed chunk size from client */
#define CHUNK_RAW    65536   /* inflate output buffer */

static CRITICAL_SECTION g_log_cs;
static int g_progress_line = 0; /* 1 = a \r line is pending (no \n yet) */

/* ── helpers ──────────────────────────────────────────────────────────── */

static void log_msg(const char *msg) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    EnterCriticalSection(&g_log_cs);
    if (g_progress_line) { printf("\n"); g_progress_line = 0; }
    printf("[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, msg);
    fflush(stdout);
    LeaveCriticalSection(&g_log_cs);
}

#define LOG(fmt, ...) \
    do { char _m[2048]; snprintf(_m, sizeof(_m), fmt, ##__VA_ARGS__); log_msg(_m); } while(0)

static int recv_all(SOCKET s, void *buf, int n) {
    int got = 0;
    while (got < n) {
        int r = recv(s, (char*)buf + got, n - got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    return 0;
}

static uint32_t read_be32(SOCKET s) {
    uint8_t b[4];
    if (recv_all(s, b, 4) < 0) return 0;
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|(uint32_t)b[3];
}

static uint64_t read_be64(SOCKET s) {
    uint8_t b[8];
    if (recv_all(s, b, 8) < 0) return 0;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

/* Sanitize a single-component identifier (code). */
static void sanitize(const char *in, char *out, size_t max) {
    const char *base = in;
    for (const char *p = in; *p; p++)
        if (*p == '/' || *p == '\\') base = p + 1;
    size_t i = 0;
    for (const char *p = base; *p && i < max - 1; p++, i++) {
        char c = *p;
        out[i] = ((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')
                  ||c=='.'||c=='-'||c=='_') ? c : '_';
    }
    out[i] = '\0';
}

/* Sanitize a relative file path — splits on separators, rejects '..' traversal. */
static int sanitize_path(const char *in, char *out, size_t max) {
    out[0] = '\0';
    size_t out_len = 0;
    const char *p = in;
    while (*p) {
        const char *end = p;
        while (*end && *end != '/' && *end != '\\') end++;
        size_t comp_len = (size_t)(end - p);
        if (comp_len == 0)                                { p = *end ? end+1 : end; continue; }
        if (comp_len == 1 && p[0] == '.')                { p = *end ? end+1 : end; continue; }
        if (comp_len == 2 && p[0] == '.' && p[1] == '.') { out[0] = '\0'; return 0; }
        char comp[256]; size_t ci = 0;
        for (size_t i = 0; i < comp_len && ci < sizeof(comp)-1; i++) {
            char c = p[i];
            comp[ci++] = ((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')
                          || c=='.' || c=='-' || c=='_') ? c : '_';
        }
        comp[ci] = '\0';
        if (ci == 0)                           { p = *end ? end+1 : end; continue; }
        if (out_len > 0 && out_len < max-1)    out[out_len++] = '\\';
        size_t to_copy = ci;
        if (out_len + to_copy >= max) to_copy = max - out_len - 1;
        memcpy(out + out_len, comp, to_copy); out_len += to_copy; out[out_len] = '\0';
        p = *end ? end+1 : end;
    }
    return out_len > 0 ? 1 : 0;
}

/* Create all directories in path, including intermediate ones. */
static void mkdir_p_win(const char *path) {
    char tmp[2048]; strncpy(tmp, path, sizeof(tmp)-1); tmp[sizeof(tmp)-1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '\\') { *p = '\0'; CreateDirectoryA(tmp, NULL); *p = '\\'; }
    }
    CreateDirectoryA(tmp, NULL);
}

/* ── manifest: walk received\code\, send CRC32 list to client ────────────── */

typedef struct {
    char     path[1024];
    uint64_t size;
    uint32_t crc32;
} MEntry;

static uint32_t file_crc32_win(const char *path) {
    FILE *f = fopen(path, "rb"); if (!f) return 0;
    uint32_t crc = crc32(0L, Z_NULL, 0);
    uint8_t buf[65536]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        crc = crc32(crc, buf, (uInt)n);
    fclose(f);
    return crc;
}

typedef struct { MEntry *entries; int count; int cap; } ManifestBuf;

static void me_add(ManifestBuf *m, const char *rel, uint64_t sz, uint32_t crc) {
    if (m->count >= m->cap) {
        int new_cap = m->cap ? m->cap*2 : 64;
        MEntry *tmp = realloc(m->entries, (size_t)new_cap * sizeof(MEntry));
        if (!tmp) return;
        m->entries = tmp; m->cap = new_cap;
    }
    strncpy(m->entries[m->count].path, rel, 1023); m->entries[m->count].path[1023] = '\0';
    m->entries[m->count].size  = sz;
    m->entries[m->count].crc32 = crc;
    m->count++;
}

static void manifest_walk_win(const char *dir, size_t root_len, ManifestBuf *m) {
    char pattern[4096]; snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    WIN32_FIND_DATAA fd2; HANDLE h = FindFirstFileA(pattern, &fd2);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!strcmp(fd2.cFileName,".") || !strcmp(fd2.cFileName,"..")) continue;
        char full[4096]; snprintf(full, sizeof(full), "%s\\%s", dir, fd2.cFileName);
        if (fd2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            manifest_walk_win(full, root_len, m);
        } else {
            const char *rel = full + root_len; while (*rel=='\\' || *rel=='/') rel++;
            uint64_t sz = ((uint64_t)fd2.nFileSizeHigh<<32)|fd2.nFileSizeLow;
            /* normalize to forward slashes so client strcmp works */
            char norm[1024]; strncpy(norm, rel, 1023); norm[1023] = '\0';
            for (char *p = norm; *p; p++) if (*p == '\\') *p = '/';
            me_add(m, norm, sz, file_crc32_win(full));
        }
    } while (FindNextFileA(h, &fd2));
    FindClose(h);
}

static void send_manifest_win(SOCKET s, const char *code_dir) {
    ManifestBuf m = {NULL, 0, 0};
    DWORD attr = GetFileAttributesA(code_dir);
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        manifest_walk_win(code_dir, strlen(code_dir), &m);
        if (_isatty(_fileno(stdout))) {
            EnterCriticalSection(&g_log_cs);
            if (g_progress_line) { printf("\n"); g_progress_line = 0; }
            printf("  Built manifest: %d files\n", m.count);
            fflush(stdout);
            LeaveCriticalSection(&g_log_cs);
        }
    }
    uint8_t cb[4];
    cb[0]=(uint8_t)(m.count>>24); cb[1]=(uint8_t)(m.count>>16); cb[2]=(uint8_t)(m.count>>8); cb[3]=(uint8_t)m.count;
    send(s, (char*)cb, 4, 0);
    for (int i = 0; i < m.count; i++) {
        uint32_t nl = (uint32_t)strlen(m.entries[i].path);
        uint8_t hdr[4];
        hdr[0]=(uint8_t)(nl>>24); hdr[1]=(uint8_t)(nl>>16); hdr[2]=(uint8_t)(nl>>8); hdr[3]=(uint8_t)nl;
        send(s, (char*)hdr, 4, 0);
        send(s, m.entries[i].path, (int)nl, 0);
        uint8_t tail[12];
        uint64_t sz = m.entries[i].size;
        for (int j=7;j>=0;j--) { tail[j]=(uint8_t)(sz&0xFF); sz>>=8; }
        uint32_t crc = m.entries[i].crc32;
        tail[8]=(uint8_t)(crc>>24); tail[9]=(uint8_t)(crc>>16); tail[10]=(uint8_t)(crc>>8); tail[11]=(uint8_t)crc;
        send(s, (char*)tail, 12, 0);
    }
    free(m.entries);
}

static void human_size(uint64_t b, char *out) {
    if      (b < 1024ULL)       sprintf(out, "%llu B",  (unsigned long long)b);
    else if (b < 1048576ULL)    sprintf(out, "%.1f KB", b/1024.0);
    else if (b < 1073741824ULL) sprintf(out, "%.1f MB", b/1048576.0);
    else                        sprintf(out, "%.1f GB", b/1073741824.0);
}

/* ── per-connection handler (Windows thread) ──────────────────────────── */

typedef struct { SOCKET sock; struct sockaddr_in addr; } Client;

static DWORD WINAPI handle_client(LPVOID param) {
    Client *c = (Client*)param;
    SOCKET s  = c->sock;
    char remote[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &c->addr.sin_addr, remote, sizeof(remote));
    free(c);

    /* Magic header check — drop crawlers silently */
    {
        uint8_t magic[4], expected[4] = {0x54, 0x52, 0x46, 0x53};
        if (recv_all(s, magic, 4) < 0 || memcmp(magic, expected, 4) != 0) {
            closesocket(s); return 0;
        }
    }

    LOG("Connection from %s", remote);

    /* 1. Read code until '\n' */
    char code_raw[256]; int ci = 0; char ch;
    while (ci < (int)sizeof(code_raw)-1 && recv(s, &ch, 1, 0) == 1 && ch != '\n')
        code_raw[ci++] = ch;
    code_raw[ci] = '\0';

    char code[256];
    sanitize(code_raw, code, sizeof(code));

    /* If the first line looks like a version prefix (e.g. "1.1_"), read the real code next */
    if (code[0] >= '0' && code[0] <= '9') {
        ci = 0;
        while (ci < (int)sizeof(code_raw)-1 && recv(s, &ch, 1, 0) == 1 && ch != '\n')
            code_raw[ci++] = ch;
        code_raw[ci] = '\0';
        sanitize(code_raw, code, sizeof(code));
    }

    if (code[0] == '\0') {
        LOG("Empty or invalid code — closing");
        closesocket(s); return 0;
    }
    LOG("Code: %s  waiting for files...", code);

    /* 2. Send confirmation 'l' */
    send(s, "l", 1, 0);

    /* 3. Send manifest of already-received files so client can skip matches */
    char code_dir[512];
    snprintf(code_dir, sizeof(code_dir), "%s\\%s", OUTPUT_DIR, code);
    send_manifest_win(s, code_dir);

    /* 4. Receive files in a loop until terminator (flags == 0xFF) */
    uint8_t *in_buf  = (uint8_t*)malloc(CHUNK_COMP);
    uint8_t *out_buf = (uint8_t*)malloc(CHUNK_RAW);
#define MAX_FILE_BYTES (50ULL * 1024 * 1024 * 1024)

    int files_ok = 0, files_err = 0;
    uint32_t total_expected = 0;

    for (;;) {
        uint8_t flags = 0;
        if (recv_all(s, &flags, 1) < 0) break;
        if (flags == 0xFF) break; /* clean end-of-transfer */

        /* metadata packet: total file count from client */
        if (flags == 0x02) {
            total_expected = read_be32(s);
            continue;
        }

        /* 3a. Read filename */
        uint32_t name_len = read_be32(s);
        if (name_len == 0 || name_len > 1023) {
            LOG("Bad name_len: %u — aborting connection", name_len);
            break;
        }
        char name_raw[1024] = {0};
        if (recv_all(s, name_raw, (int)name_len) < 0) break;
        name_raw[name_len] = '\0';

        char relpath[1024];
        if (!sanitize_path(name_raw, relpath, sizeof(relpath)) || relpath[0] == '\0') {
            LOG("Invalid path — aborting connection");
            break;
        }

        /* 3b. Read original size */
        uint64_t orig_len = read_be64(s);
        if (orig_len > MAX_FILE_BYTES) {
            LOG("Claimed size too large for %s — aborting", relpath);
            break;
        }

        if (_isatty(_fileno(stdout))) {
            EnterCriticalSection(&g_log_cs);
            if (total_expected)
                printf("\r\033[K  [%d/%u] %s", files_ok + files_err + 1, total_expected, relpath);
            else
                printf("\r\033[K  [%d] %s", files_ok + files_err + 1, relpath);
            fflush(stdout);
            g_progress_line = 1;
            LeaveCriticalSection(&g_log_cs);
        }

        /* 3c. Build destination path */

        char dest[2048];
        snprintf(dest, sizeof(dest), "%s\\%s", code_dir, relpath);

        char dest_dir[2048]; strncpy(dest_dir, dest, sizeof(dest_dir)-1);
        char *last_sep = strrchr(dest_dir, '\\');
        if (last_sep) { *last_sep = '\0'; mkdir_p_win(dest_dir); }

        /* collision avoidance */
        if (GetFileAttributesA(dest) != INVALID_FILE_ATTRIBUTES) {
            SYSTEMTIME st2; GetLocalTime(&st2);
            char stamp[32];
            sprintf(stamp, "%04d%02d%02d_%02d%02d%02d",
                    st2.wYear, st2.wMonth, st2.wDay, st2.wHour, st2.wMinute, st2.wSecond);
            char *dot   = strrchr(dest, '.');
            char *slash = strrchr(dest, '\\');
            char new_dest[2048];
            if (dot && (!slash || dot > slash)) {
                char tmp[2048]; strncpy(tmp, dest, sizeof(tmp)-1);
                tmp[dot - dest] = '\0';
                snprintf(new_dest, sizeof(new_dest), "%s_%s.%s", tmp, stamp, dot+1);
            } else {
                snprintf(new_dest, sizeof(new_dest), "%s_%s", dest, stamp);
            }
            strncpy(dest, new_dest, sizeof(dest)-1); dest[sizeof(dest)-1] = '\0';
        }

        /* 3d. Open output file */
        FILE *f = fopen(dest, "wb");
        if (!f) {
            LOG("Cannot create: %s — skipping", dest);
            files_err++;
            /* drain data to keep connection usable */
            if (flags & 0x01) {
                uint32_t cl;
                while ((cl = read_be32(s)) > 0) {
                    uint8_t tmp2[CHUNK_COMP];
                    if (cl > CHUNK_COMP || recv_all(s, tmp2, (int)cl) < 0) goto done;
                }
            } else {
                uint8_t tmp2[BUF_SIZE]; uint64_t rem = orig_len;
                while (rem > 0) {
                    int want = (int)(rem > BUF_SIZE ? BUF_SIZE : rem);
                    int r = recv(s, (char*)tmp2, want, 0);
                    if (r <= 0) goto done;
                    rem -= (uint64_t)r;
                }
            }
            continue;
        }

        /* 3e. Receive and write file data */
        int ok = 1;
        if (flags & 0x01) {
            z_stream zs; memset(&zs, 0, sizeof(zs));
            inflateInit(&zs);
            uint32_t chunk_len;
            while (ok && (chunk_len = read_be32(s)) > 0) {
                if (chunk_len > CHUNK_COMP || recv_all(s, in_buf, (int)chunk_len) < 0) { ok = 0; break; }
                zs.next_in  = in_buf;
                zs.avail_in = chunk_len;
                do {
                    zs.next_out  = out_buf;
                    zs.avail_out = CHUNK_RAW;
                    inflate(&zs, Z_NO_FLUSH);
                    uint32_t have = CHUNK_RAW - zs.avail_out;
                    if (have) fwrite(out_buf, 1, have, f);
                } while (zs.avail_out == 0);
            }
            inflateEnd(&zs);
        } else {
            uint64_t remaining = orig_len;
            while (remaining > 0) {
                int want = (int)(remaining > BUF_SIZE ? BUF_SIZE : remaining);
                int r = recv(s, (char*)in_buf, want, 0);
                if (r <= 0) { ok = 0; break; }
                fwrite(in_buf, 1, (size_t)r, f);
                remaining -= (uint64_t)r;
            }
        }
        fclose(f);

        if (ok) files_ok++;
        else { files_err++; goto done; }
    }

done:
    free(in_buf); free(out_buf);
    closesocket(s);
    if (_isatty(_fileno(stdout))) {
        EnterCriticalSection(&g_log_cs);
        if (g_progress_line) { printf("\n"); g_progress_line = 0; }
        LeaveCriticalSection(&g_log_cs);
    }
    LOG("Done: %d saved, %d failed  (code: %s)", files_ok, files_err, code);
    return 0;
}

/* ── main ─────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    int port = argc > 1 ? atoi(argv[1]) : DEFAULT_PORT;

    InitializeCriticalSection(&g_log_cs);
    CreateDirectoryA(OUTPUT_DIR, NULL);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n"); return 1;
    }

    SOCKET srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCKET) {
        fprintf(stderr, "socket() failed: %d\n", WSAGetLastError()); return 1;
    }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((u_short)port);

    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e == WSAEADDRINUSE)
            fprintf(stderr, "Port %d is already in use.\n", port);
        else
            fprintf(stderr, "bind() failed: %d\n", e);
        return 1;
    }
    if (listen(srv, SOMAXCONN) == SOCKET_ERROR) {
        fprintf(stderr, "listen() failed: %d\n", WSAGetLastError()); return 1;
    }

    /* Enable ANSI escape codes (works on Win10 v1511+ / Windows Terminal) */
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD conMode = 0;
    if (GetConsoleMode(hOut, &conMode))
        SetConsoleMode(hOut, conMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    LOG("TransferServer listening on port %d", port);
    LOG("Saving files to: %s\\", OUTPUT_DIR);

    for (;;) {
        Client *c = malloc(sizeof(Client));
        int len = sizeof(c->addr);
        c->sock = accept(srv, (struct sockaddr*)&c->addr, &len);
        if (c->sock == INVALID_SOCKET) { free(c); continue; }

        HANDLE th = CreateThread(NULL, 0, handle_client, c, 0, NULL);
        if (th) CloseHandle(th);
        else { closesocket(c->sock); free(c); }
    }

    WSACleanup();
    return 0;
}
