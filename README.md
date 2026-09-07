# transfer

Streaming file transfer over TCP. Compresses in flight, skips files already on the server (CRC32 match), supports TLS for nginx termination.

## Quick start

**Server:**
```bash
chmod +x transfer_server
chown root:root transfer_server
./transfer_server [port]   # default 5812
```
Files land in `./received/<code>/`.

**Client:**
```bash
./transfer <ip> <port> <code> <file_or_folder>
./transfer <ip> <port> --nr --nj --ignore <word> <code> <file_or_folder>
# port 443 enables TLS automatically; use --tls to force it on other ports
```

## nginx TLS setup

If you can't port-forward, expose the server through a domain with TLS termination.

**`/etc/nginx/nginx.conf`** — add after the `http {}` block:
```nginx
stream {
    map $ssl_preread_server_name $upstream {
        transfer.example.com    127.0.0.1:1443;
        default                 127.0.0.1:4443;
    }
    server {
        listen 443; listen [::]:443;
        ssl_preread on;
        proxy_pass $upstream;
    }
    server {
        listen 127.0.0.1:1443 ssl;
        ssl_certificate     /etc/letsencrypt/live/transfer.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/transfer.example.com/privkey.pem;
        ssl_protocols       TLSv1.2 TLSv1.3;
        proxy_pass          127.0.0.1:5812;
    }
}
```

Change all existing `listen 443 ssl` in your site configs to `listen 4443 ssl`.

Requires `libnginx-mod-stream` and a cert (`certbot certonly --nginx -d transfer.example.com`).

## Protocol / custom clients

Every connection must open with the 4-byte magic header `0x54 0x52 0x46 0x53` (`TRFS`) before the code line. Connections that don't are dropped silently — this keeps port scanners and crawlers off the console.

## Compile from source

**Linux server:**
```bash
docker run --rm -v "${PWD}:/src" alpine sh -c \
  "apk add gcc musl-dev zlib-dev zlib-static && \
   gcc -static -o /src/transfer_server /src/transfer_server.c -lpthread -lz"
```
**Windows server (from WSL):**
```bash
x86_64-w64-mingw32-gcc transfer_server_win.c -o transfer_server.exe -lws2_32 -lz -static
```
**Windows client (from WSL, no TLS):**
```bash
x86_64-w64-mingw32-gcc transfer_win.c -o transfer.exe -lws2_32 -lz -static
```
**Windows client (with TLS, from WSL — requires OpenSSL built for MinGW):**
```bash
# Build OpenSSL for MinGW once:
wget https://github.com/openssl/openssl/releases/download/openssl-3.3.2/openssl-3.3.2.tar.gz
tar xf openssl-3.3.2.tar.gz && cd openssl-3.3.2
./Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- --prefix=/tmp/ssl no-shared no-tests
make -j4 && make install_sw

# Then compile:
x86_64-w64-mingw32-gcc transfer_win.c -o transfer_tls.exe -DHAVE_TLS \
  -I/tmp/ssl/include -L/tmp/ssl/lib64 \
  -Wl,--start-group -lssl -lcrypto -lz -lgdi32 -lcrypt32 -lws2_32 -Wl,--end-group -static
```
**Linux client (with TLS):**
```bash
docker run --rm -v "${PWD}:/src" alpine sh -c \
  "apk add gcc musl-dev zlib-dev zlib-static openssl-dev openssl-libs-static && \
   gcc -static -DHAVE_TLS -o /src/transfer /src/transfer.c -lz -lssl -lcrypto"
```
