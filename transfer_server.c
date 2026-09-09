/*
 * transfer_server.c  —  POSIX file-transfer receiver
 *
 * Compile (WSL/Ubuntu):  gcc transfer_server.c -o transfer_server -lpthread -lz
 * Run:                   ./transfer_server_linux [port]   (default 5812)
 *
 * Received files land in ./received/<code>/<relative_path>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <signal.h>

#define DEFAULT_PORT 5812
#define OUTPUT_DIR   "received"
#define BUF_SIZE     8192
#define CHUNK_COMP   66000
#define CHUNK_RAW    65536

static pthread_mutex_t g_log_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_progress_line = 0; /* 1 = a \r line is pending (no \n yet) */

/* ── helpers ──────────────────────────────────────────────────────────── */

static void log_ts(const char *msg) {
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char buf[16];
    strftime(buf, sizeof(buf), "%H:%M:%S", tm);
    pthread_mutex_lock(&g_log_mu);
    if (g_progress_line) { printf("\n"); g_progress_line = 0; }
    printf("[%s] %s\n", buf, msg);
    fflush(stdout);
    pthread_mutex_unlock(&g_log_mu);
}

#define LOG(fmt, ...) \
    do { char _m[4096]; snprintf(_m, sizeof(_m), fmt, ##__VA_ARGS__); log_ts(_m); } while(0)

static int recv_all(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, (char*)buf + got, n - got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    return 0;
}

static uint32_t read_be32(int fd) {
    uint8_t b[4];
    if (recv_all(fd, b, 4) < 0) return 0;
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|(uint32_t)b[3];
}

static uint64_t read_be64(int fd) {
    uint8_t b[8];
    if (recv_all(fd, b, 8) < 0) return 0;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

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
        if (out_len > 0 && out_len < max-1)    out[out_len++] = '/';
        size_t to_copy = ci;
        if (out_len + to_copy >= max) to_copy = max - out_len - 1;
        memcpy(out + out_len, comp, to_copy); out_len += to_copy; out[out_len] = '\0';
        p = *end ? end+1 : end;
    }
    return out_len > 0 ? 1 : 0;
}

static void mkdir_p(const char *path) {
    char tmp[2048]; strncpy(tmp, path, sizeof(tmp)-1); tmp[sizeof(tmp)-1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
    }
    mkdir(tmp, 0755);
}

/* ── manifest: walk received/code/, send CRC32 list to client ────────────── */

typedef struct {
    char     path[1024];
    uint64_t size;
    uint32_t crc32;
} MEntry;

static uint32_t file_crc32(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    uint32_t crc = crc32(0L, Z_NULL, 0);
    uint8_t buf[65536]; ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        crc = crc32(crc, buf, (uInt)n);
    close(fd);
    return crc;
}

/* Pass 1: count files only (no CRC32 — fast, just stat) */
static uint32_t count_manifest(const char *dir) {
    DIR *d = opendir(dir); if (!d) return 0;
    struct dirent *de; uint32_t n = 0;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name,".") || !strcmp(de->d_name,"..")) continue;
        char full[4096]; snprintf(full, sizeof(full), "%s/%s", dir, de->d_name);
        struct stat st; if (stat(full, &st) < 0) continue;
        if (S_ISDIR(st.st_mode)) n += count_manifest(full);
        else if (S_ISREG(st.st_mode)) n++;
    }
    closedir(d);
    return n;
}

/* Pass 2: walk + CRC32 + send each entry immediately so data flows continuously */
static void stream_manifest(int fd, const char *dir, size_t root_len) {
    DIR *d = opendir(dir); if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name,".") || !strcmp(de->d_name,"..")) continue;
        char full[4096]; snprintf(full, sizeof(full), "%s/%s", dir, de->d_name);
        struct stat st; if (stat(full, &st) < 0) continue;
        if (S_ISDIR(st.st_mode)) {
            stream_manifest(fd, full, root_len);
        } else if (S_ISREG(st.st_mode)) {
            const char *rel = full + root_len; while (*rel == '/') rel++;
            uint32_t nl = (uint32_t)strlen(rel);
            uint32_t crc = file_crc32(full);
            uint8_t hdr[4];
            hdr[0]=(uint8_t)(nl>>24); hdr[1]=(uint8_t)(nl>>16); hdr[2]=(uint8_t)(nl>>8); hdr[3]=(uint8_t)nl;
            send(fd, hdr, 4, 0);
            send(fd, rel, nl, 0);
            uint8_t tail[12];
            uint64_t sz = (uint64_t)st.st_size;
            for (int j=7;j>=0;j--) { tail[j]=(uint8_t)(sz&0xFF); sz>>=8; }
            tail[8]=(uint8_t)(crc>>24); tail[9]=(uint8_t)(crc>>16); tail[10]=(uint8_t)(crc>>8); tail[11]=(uint8_t)crc;
            send(fd, tail, 12, 0);
        }
    }
    closedir(d);
}

static void send_manifest(int fd, const char *code_dir) {
    struct stat st;
    if (stat(code_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        uint8_t cb[4] = {0,0,0,0}; send(fd, cb, 4, 0);
        return;
    }
    uint32_t count = count_manifest(code_dir);
    uint8_t cb[4];
    cb[0]=(uint8_t)(count>>24); cb[1]=(uint8_t)(count>>16); cb[2]=(uint8_t)(count>>8); cb[3]=(uint8_t)count;
    send(fd, cb, 4, 0);
    if (count > 0) {
        size_t root_len = strlen(code_dir);
        stream_manifest(fd, code_dir, root_len);
        if (isatty(STDOUT_FILENO)) {
            pthread_mutex_lock(&g_log_mu);
            if (g_progress_line) { printf("\n"); g_progress_line = 0; }
            printf("  Sent manifest: %u files\n", count);
            fflush(stdout);
            pthread_mutex_unlock(&g_log_mu);
        }
    }
}

static void human_size(uint64_t b, char *out) {
    if      (b < 1024ULL)             sprintf(out, "%llu B",  (unsigned long long)b);
    else if (b < 1048576ULL)          sprintf(out, "%.1f KB", b/1024.0);
    else if (b < 1073741824ULL)       sprintf(out, "%.1f MB", b/1048576.0);
    else                              sprintf(out, "%.1f GB", b/1073741824.0);
}

/* ── per-connection handler ───────────────────────────────────────────── */

typedef struct { int fd; struct sockaddr_in addr; } Client;

static void *handle_client(void *arg) {
    Client *c = (Client*)arg;
    int fd    = c->fd;
    char remote[64];
    inet_ntop(AF_INET, &c->addr.sin_addr, remote, sizeof(remote));
    free(c);

    /* Detect PROXY protocol header (nginx) or direct TRFS magic.
     * PROXY header starts with "PROX"; TRFS magic starts with 0x54.
     * Both paths end with the 4-byte TRFS magic having been consumed. */
    {
        uint8_t first4[4];
        if (recv_all(fd, first4, 4) < 0) { close(fd); return NULL; }
        uint8_t expected[4] = {0x54, 0x52, 0x46, 0x53};
        if (memcmp(first4, "PROX", 4) == 0) {
            /* Read rest of PROXY protocol line to extract real client IP */
            char line[256]; int li = 4;
            memcpy(line, first4, 4);
            char ch;
            while (li < (int)sizeof(line)-1 && recv(fd, &ch, 1, 0) == 1) {
                line[li++] = ch;
                if (ch == '\n') break;
            }
            line[li] = '\0';
            char proto[16], src_ip[64], dst_ip[64]; int sp, dp;
            if (sscanf(line, "PROXY %15s %63s %63s %d %d",
                       proto, src_ip, dst_ip, &sp, &dp) >= 3
                    && strcmp(proto, "UNKNOWN") != 0)
                strncpy(remote, src_ip, sizeof(remote)-1);
            if (recv_all(fd, first4, 4) < 0 || memcmp(first4, expected, 4) != 0) {
                close(fd); return NULL;
            }
        } else if (memcmp(first4, expected, 4) != 0) {
            close(fd); return NULL;
        }
    }

    LOG("Connection from %s", remote);

    /* 1. Read code */
    char code_raw[256]; int ci = 0; char ch;
    while (ci < (int)sizeof(code_raw)-1 && recv(fd, &ch, 1, 0) == 1 && ch != '\n')
        code_raw[ci++] = ch;
    code_raw[ci] = '\0';

    char code[256];
    sanitize(code_raw, code, sizeof(code));

    /* If the first line looks like a version prefix (e.g. "1.1_"), read the real code next */
    if (code[0] >= '0' && code[0] <= '9') {
        ci = 0;
        while (ci < (int)sizeof(code_raw)-1 && recv(fd, &ch, 1, 0) == 1 && ch != '\n')
            code_raw[ci++] = ch;
        code_raw[ci] = '\0';
        sanitize(code_raw, code, sizeof(code));
    }

    if (code[0] == '\0') {
        LOG("Empty or invalid code — closing");
        close(fd); return NULL;
    }
    LOG("Code: %s  waiting for files...", code);

    /* 2. Send confirmation 'l' */
    send(fd, "l", 1, 0);

    /* 3. Send manifest of already-received files so client can skip matches */
    char code_dir[768];
    snprintf(code_dir, sizeof(code_dir), "%s/%s", OUTPUT_DIR, code);
    send_manifest(fd, code_dir);

    /* 4. Receive files in a loop until terminator (flags == 0xFF) */
    uint8_t *in_buf  = (uint8_t*)malloc(CHUNK_COMP);
    uint8_t *out_buf = (uint8_t*)malloc(CHUNK_RAW);
    if (!in_buf || !out_buf) { free(in_buf); free(out_buf); close(fd); return NULL; }
#define MAX_FILE_BYTES (50ULL * 1024 * 1024 * 1024)

    int files_ok = 0, files_err = 0;
    uint32_t total_expected = 0;

    for (;;) {
        uint8_t flags = 0;
        if (recv_all(fd, &flags, 1) < 0) break;
        if (flags == 0xFF) break; /* terminator — clean end of transfer */

        /* metadata packet: total file count from client */
        if (flags == 0x02) {
            total_expected = read_be32(fd);
            continue;
        }

        /* 3a. Read filename */
        uint32_t name_len = read_be32(fd);
        if (name_len == 0 || name_len > 1023) {
            LOG("Bad name_len: %u — aborting connection", name_len);
            break;
        }
        char name_raw[1024] = {0};
        if (recv_all(fd, name_raw, name_len) < 0) break;

        char relpath[1024];
        if (!sanitize_path(name_raw, relpath, sizeof(relpath)) || relpath[0] == '\0') {
            LOG("Invalid path — aborting connection");
            break;
        }

        /* 3b. Read original size */
        uint64_t orig_len = read_be64(fd);
        if (orig_len > MAX_FILE_BYTES) {
            LOG("Claimed size too large for %s — aborting", relpath);
            break;
        }

        if (isatty(STDOUT_FILENO)) {
            pthread_mutex_lock(&g_log_mu);
            if (total_expected)
                printf("\r\033[K  [%d/%u] %.70s", files_ok + files_err + 1, total_expected, relpath);
            else
                printf("\r\033[K  [%d] %.70s", files_ok + files_err + 1, relpath);
            fflush(stdout);
            g_progress_line = 1;
            pthread_mutex_unlock(&g_log_mu);
        }

        /* 3c. Build destination path */

        char dest[2048];
        snprintf(dest, sizeof(dest), "%s/%s", code_dir, relpath);

        char dest_dir[2048]; strncpy(dest_dir, dest, sizeof(dest_dir)-1);
        char *last_sep = strrchr(dest_dir, '/');
        if (last_sep) { *last_sep = '\0'; mkdir_p(dest_dir); }

        /* collision avoidance */
        if (access(dest, F_OK) == 0) {
            time_t t = time(NULL); struct tm *tm = localtime(&t);
            char stamp[32]; strftime(stamp, sizeof(stamp), "%Y%m%d_%H%M%S", tm);
            char *dot   = strrchr(dest, '.');
            char *slash = strrchr(dest, '/');
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
        int out = open(dest, O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (out < 0) {
            LOG("Cannot create %s: %s — skipping", dest, strerror(errno));
            files_err++;
            /* drain incoming data so connection stays usable */
            if (flags & 0x01) {
                uint32_t cl;
                while ((cl = read_be32(fd)) > 0) {
                    if (cl > CHUNK_COMP || recv_all(fd, in_buf, cl) < 0) goto done;
                }
            } else {
                uint64_t rem = orig_len;
                while (rem > 0) {
                    size_t want = rem > BUF_SIZE ? BUF_SIZE : (size_t)rem;
                    ssize_t r = recv(fd, in_buf, want, 0);
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
            while ((chunk_len = read_be32(fd)) > 0) {
                if (chunk_len > CHUNK_COMP || recv_all(fd, in_buf, chunk_len) < 0) { ok = 0; break; }
                zs.next_in  = in_buf;
                zs.avail_in = chunk_len;
                do {
                    zs.next_out  = out_buf;
                    zs.avail_out = CHUNK_RAW;
                    inflate(&zs, Z_NO_FLUSH);
                    uint32_t have = CHUNK_RAW - zs.avail_out;
                    if (have) write(out, out_buf, have);
                } while (zs.avail_out == 0);
            }
            inflateEnd(&zs);
        } else {
            uint64_t remaining = orig_len;
            while (remaining > 0) {
                size_t want = remaining > BUF_SIZE ? BUF_SIZE : (size_t)remaining;
                ssize_t r = recv(fd, in_buf, want, 0);
                if (r <= 0) { ok = 0; break; }
                write(out, in_buf, (size_t)r);
                remaining -= (uint64_t)r;
            }
        }
        close(out);

        if (ok) files_ok++;
        else { files_err++; goto done; }
    }

done:
    free(in_buf); free(out_buf);
    close(fd);
    if (isatty(STDOUT_FILENO)) {
        pthread_mutex_lock(&g_log_mu);
        if (g_progress_line) { printf("\n"); g_progress_line = 0; }
        pthread_mutex_unlock(&g_log_mu);
    }
    LOG("Done: %d saved, %d failed  (code: %s)", files_ok, files_err, code);
    return NULL;
}

/* ── main ─────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN); /* prevent server death when client disconnects mid-send */
    int port = argc > 1 ? atoi(argv[1]) : DEFAULT_PORT;

    mkdir(OUTPUT_DIR, 0755);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }

    /* SO_REUSEADDR intentionally omitted — we want bind to fail if port is taken */

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)port);

    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        if (errno == EADDRINUSE)
            fprintf(stderr, "Port %d is already in use.\n", port);
        else
            perror("bind");
        return 1;
    }
    if (listen(srv, 16) < 0)                                  { perror("listen"); return 1; }

    LOG("TransferServer listening on port %d", port);
    LOG("Saving files to: %s/", OUTPUT_DIR);

    for (;;) {
        Client *c = malloc(sizeof(Client));
        socklen_t len = sizeof(c->addr);
        c->fd = accept(srv, (struct sockaddr*)&c->addr, &len);
        if (c->fd < 0) { free(c); continue; }

        pthread_t th;
        if (pthread_create(&th, NULL, handle_client, c) == 0) {
            pthread_detach(th);
        } else {
            close(c->fd);
            free(c);
        }
    }
}
