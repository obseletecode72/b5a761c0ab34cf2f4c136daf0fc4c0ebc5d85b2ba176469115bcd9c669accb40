/*
 * rawssh.c - Biblioteca SSH2 propria, thread-safe, alta performance
 * Implementa RFC 4253/4252/4254 sobre TCP com OpenSSL
 * Cada sessao e 100% independente - zero estado global compartilhado
 * Suporte a bind direto na NIC (SO_BINDTODEVICE)
 *
 * Algoritmos suportados:
 *   KEX: curve25519-sha256, ecdh-sha2-nistp256, diffie-hellman-group14/16,
 *        diffie-hellman-group-exchange-sha256
 *   Host key: ssh-ed25519, ecdsa-sha2-nistp*, rsa-sha2-*, ssh-rsa
 *   Cipher: chacha20-poly1305@openssh.com, aes128-ctr, aes256-ctr
 *   MAC: hmac-sha2-256, hmac-sha1 (implicit with chacha20-poly1305)
 *   Compression: none
 */

#define _GNU_SOURCE
#include "rawssh.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>

/* ========== Internal structures ========== */

/* Cipher state for one direction */
typedef struct {
    EVP_CIPHER_CTX *ctx;
    unsigned char key[RAWSSH_KEY_SIZE];
    unsigned char iv[RAWSSH_IV_SIZE];
    unsigned char mac_key[64]; /* up to 64 for sha512 */
    int cipher_block;
    int key_len;
    int mac_len;
    uint32_t seq;
} crypto_dir;

struct rawssh_session {
    int sock;
    int timeout_sec;
    char nic[64];

    /* Version exchange */
    char server_version[256];
    char client_version[256];

    /* KEXINIT payloads (needed for hash) */
    unsigned char *my_kexinit;
    int my_kexinit_len;
    unsigned char *peer_kexinit;
    int peer_kexinit_len;

    /* DH key exchange */
    BIGNUM *dh_p;
    BIGNUM *dh_g;
    BIGNUM *dh_x; /* private */
    BIGNUM *dh_e; /* public */
    BIGNUM *dh_f; /* server public */
    BIGNUM *dh_k; /* shared secret */

    /* Session ID and exchange hash */
    unsigned char session_id[64];
    int session_id_len;
    unsigned char exchange_hash[64];

    /* Crypto state */
    crypto_dir c2s; /* client to server */
    crypto_dir s2c; /* server to client */
    int encrypted;

    /* KEX algorithm selection */
    int kex_type;       /* 0=dh-group14, 1=dh-group16, 2=curve25519, 3=ecdh-p256, 4=dh-gex-sha256 */
    int kex_hash_type;  /* 0=sha1, 1=sha256, 2=sha512 */
    int cipher_key_len; /* 16 or 32 (64 for chacha20-poly1305) */
    int mac_is_sha256;  /* independent from kex hash */
    int is_chacha20;    /* 1 if using chacha20-poly1305@openssh.com */

    /* Authenticated flag */
    int authenticated;

    /* Channel counter */
    uint32_t next_channel_id;
};

struct rawssh_channel {
    rawssh_session *session;
    uint32_t local_id;
    uint32_t remote_id;
    uint32_t remote_window;
    uint32_t remote_maxpkt;
    int eof;
    int closed;

    /* Read buffer for channel data */
    unsigned char data_buf[RAWSSH_MAX_PAYLOAD];
    int data_pos;
    int data_len;
};

/* ========== Byte-packing helpers (big-endian) ========== */

static void put_u32(unsigned char *buf, uint32_t v) {
    buf[0] = (v >> 24) & 0xFF;
    buf[1] = (v >> 16) & 0xFF;
    buf[2] = (v >> 8) & 0xFF;
    buf[3] = v & 0xFF;
}

static uint32_t get_u32(const unsigned char *buf) {
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
}

static void put_string(unsigned char *buf, const void *data, uint32_t len, int *offset) {
    put_u32(buf + *offset, len);
    *offset += 4;
    if (len > 0) {
        memcpy(buf + *offset, data, len);
        *offset += len;
    }
}

static int get_string(const unsigned char *buf, int buflen, int *offset,
                      const unsigned char **out, uint32_t *out_len) {
    if (*offset + 4 > buflen) return -1;
    uint32_t len = get_u32(buf + *offset);
    *offset += 4;
    if (*offset + (int)len > buflen) return -1;
    *out = buf + *offset;
    *out_len = len;
    *offset += len;
    return 0;
}

static void put_cstring(unsigned char *buf, const char *str, int *offset) {
    uint32_t len = (uint32_t)strlen(str);
    put_string(buf, str, len, offset);
}

/* Write BIGNUM as SSH mpint (with leading zero if high bit set) */
static void put_mpint(unsigned char *buf, const BIGNUM *bn, int *offset) {
    int n = BN_num_bytes(bn);
    unsigned char *tmp = malloc(n + 1);
    if (!tmp) { /* fallback: write zero-length mpint */
        put_u32(buf + *offset, 0);
        *offset += 4;
        return;
    }
    BN_bn2bin(bn, tmp);
    /* Check if leading byte has high bit set - need extra zero */
    int pad = (n > 0 && (tmp[0] & 0x80)) ? 1 : 0;
    put_u32(buf + *offset, n + pad);
    *offset += 4;
    if (pad) {
        buf[(*offset)++] = 0;
    }
    memcpy(buf + *offset, tmp, n);
    *offset += n;
    free(tmp);
}

/* ========== Low-level I/O ========== */

static int sock_wait(int fd, int events, int timeout_ms) {
    struct pollfd pf = {fd, events, 0};
    int r = poll(&pf, 1, timeout_ms);
    if (r <= 0) return r; /* 0 = timeout, -1 = error */
    if (pf.revents & POLLNVAL) return -1;
    /* For reads: POLLIN with POLLHUP means data still available - allow it */
    if ((events & POLLIN) && (pf.revents & POLLIN)) return r;
    /* For writes or pure POLLHUP/POLLERR without data: error */
    if (pf.revents & (POLLERR | POLLHUP)) return -1;
    return r;
}

static int raw_send(rawssh_session *s, const void *data, int len) {
    const unsigned char *p = data;
    int sent = 0;
    while (sent < len) {
        int r = sock_wait(s->sock, POLLOUT, s->timeout_sec * 1000);
        if (r <= 0) return (r == 0) ? RAWSSH_TIMEOUT : RAWSSH_TCP_ERROR;
        r = send(s->sock, p + sent, len - sent, MSG_NOSIGNAL);
        if (r < 0) {
            if (errno == EPIPE || errno == ECONNRESET)
                return RAWSSH_CLOSED;
            return RAWSSH_TCP_ERROR;
        }
        if (r == 0) return RAWSSH_CLOSED;
        sent += r;
    }
    return sent;
}

static int raw_recv(rawssh_session *s, void *data, int len) {
    unsigned char *p = data;
    int got = 0;
    while (got < len) {
        int r = sock_wait(s->sock, POLLIN, s->timeout_sec * 1000);
        if (r <= 0) return (r == 0) ? RAWSSH_TIMEOUT : RAWSSH_TCP_ERROR;
        r = recv(s->sock, p + got, len - got, 0);
        if (r < 0) {
            if (errno == ECONNRESET)
                return RAWSSH_CLOSED;
            return RAWSSH_TCP_ERROR;
        }
        if (r == 0) return RAWSSH_CLOSED; /* peer closed connection */
        got += r;
    }
    return got;
}

/* Read a line (for version exchange) */
/* Optimized: use MSG_PEEK to find \n then read in bulk */
static int read_line(rawssh_session *s, char *buf, int maxlen) {
    int pos = 0;
    while (pos < maxlen - 1) {
        int r = sock_wait(s->sock, POLLIN, s->timeout_sec * 1000);
        if (r <= 0) return (r == 0) ? RAWSSH_TIMEOUT : RAWSSH_TCP_ERROR;
        /* Peek available data to find newline */
        int avail = maxlen - 1 - pos;
        r = recv(s->sock, buf + pos, avail, MSG_PEEK);
        if (r < 0) return (errno == ECONNRESET) ? RAWSSH_CLOSED : RAWSSH_TCP_ERROR;
        if (r == 0) return RAWSSH_CLOSED; /* peer closed before sending version */
        /* Scan for \n in peeked data */
        int nl = -1;
        for (int i = 0; i < r; i++) {
            if (buf[pos + i] == '\n') { nl = i; break; }
        }
        if (nl >= 0) {
            /* Consume up to and including \n */
            int consume = nl + 1;
            r = recv(s->sock, buf + pos, consume, 0);
            if (r <= 0) return RAWSSH_CLOSED;
            pos += nl; /* don't include \n */
            if (pos > 0 && buf[pos - 1] == '\r') pos--;
            buf[pos] = 0;
            return pos;
        }
        /* No newline yet - consume all peeked bytes */
        r = recv(s->sock, buf + pos, r, 0);
        if (r <= 0) return RAWSSH_CLOSED;
        pos += r;
    }
    buf[pos] = 0;
    return pos;
}

/* ========== SSH Packet I/O ========== */

/* Send an unencrypted SSH packet */
static int send_packet_plain(rawssh_session *s, const unsigned char *payload, int plen) {
    int block = 8;
    int padlen = block - ((4 + 1 + plen) % block);
    if (padlen < 4) padlen += block;
    int total = 4 + 1 + plen + padlen;

    unsigned char *pkt = malloc(total);
    if (!pkt) return RAWSSH_ALLOC_FAIL;

    put_u32(pkt, 1 + plen + padlen);
    pkt[4] = (unsigned char)padlen;
    memcpy(pkt + 5, payload, plen);
    RAND_bytes(pkt + 5 + plen, padlen);

    int rc = raw_send(s, pkt, total);
    free(pkt);
    if (rc < 0) return rc;
    s->c2s.seq++;
    return RAWSSH_OK;
}

/* Send an encrypted SSH packet - chacha20-poly1305 AEAD mode */
static int send_packet_chacha20(rawssh_session *s, const unsigned char *payload, int plen) {
    /* chacha20-poly1305@openssh.com uses 8-byte block alignment */
    int block = 8;
    int padlen = block - ((4 + 1 + plen) % block);
    if (padlen < 4) padlen += block;
    int pktlen = 1 + plen + padlen;
    int total = 4 + pktlen;

    unsigned char *plain = malloc(total);
    if (!plain) return RAWSSH_ALLOC_FAIL;

    put_u32(plain, pktlen);
    plain[4] = (unsigned char)padlen;
    memcpy(plain + 5, payload, plen);
    RAND_bytes(plain + 5 + plen, padlen);

    /* OpenSSL EVP_chacha20 IV layout: 4 bytes counter (LE) + 12 bytes nonce
     * SSH chacha20-poly1305 nonce = 8-byte big-endian sequence number
     * We place it at the END of the 12-byte nonce field: 4 zero + 8-byte seqno */
    unsigned char chacha_iv[16];
    memset(chacha_iv, 0, 16);
    /* counter = 0 at bytes 0-3 (already zeroed) */
    /* nonce padding at bytes 4-7 (already zeroed) */
    put_u32(chacha_iv + 12, s->c2s.seq); /* seqno at bytes 12-15 (big-endian, but only 32-bit) */
    /* Actually per openssh: nonce is 8 bytes, placed as the full 12-byte nonce:
     * bytes 4-7 = 0, bytes 8-11 = 0, bytes 12-15 = seqno
     * But OpenSSL nonce is 12 bytes at IV[4..15] */
    memset(chacha_iv + 4, 0, 8); /* first 8 bytes of nonce = 0 */
    put_u32(chacha_iv + 12, s->c2s.seq); /* last 4 bytes of nonce = seqno */

    /* Step 1: Encrypt packet length (4 bytes) with header key (K_2, stored at mac_key) */
    unsigned char enc_len[4];
    {
        EVP_CIPHER_CTX *hctx = EVP_CIPHER_CTX_new();
        if (!hctx) { free(plain); return RAWSSH_ALLOC_FAIL; }
        EVP_EncryptInit_ex(hctx, EVP_chacha20(), NULL, s->c2s.mac_key, chacha_iv);
        int outl = 0;
        EVP_EncryptUpdate(hctx, enc_len, &outl, plain, 4);
        EVP_CIPHER_CTX_free(hctx);
    }

    /* Step 2: Derive Poly1305 one-time key from counter=0 block of main key */
    unsigned char poly_key[32];
    {
        EVP_CIPHER_CTX *kctx = EVP_CIPHER_CTX_new();
        if (!kctx) { free(plain); return RAWSSH_ALLOC_FAIL; }
        EVP_EncryptInit_ex(kctx, EVP_chacha20(), NULL, s->c2s.key, chacha_iv);
        unsigned char zeros[32] = {0};
        int outl = 0;
        EVP_EncryptUpdate(kctx, poly_key, &outl, zeros, 32);
        EVP_CIPHER_CTX_free(kctx);
    }

    /* Step 3: Encrypt payload with main key, counter starting at 1
     * Skip first 64 bytes (counter block 0 used for poly1305 key) */
    unsigned char *enc_payload = malloc(pktlen);
    if (!enc_payload) { free(plain); return RAWSSH_ALLOC_FAIL; }
    {
        EVP_CIPHER_CTX *pctx = EVP_CIPHER_CTX_new();
        if (!pctx) { free(enc_payload); free(plain); return RAWSSH_ALLOC_FAIL; }
        EVP_EncryptInit_ex(pctx, EVP_chacha20(), NULL, s->c2s.key, chacha_iv);
        /* Discard first 64 bytes to advance past counter=0 block */
        unsigned char discard[64];
        int outl = 0;
        EVP_EncryptUpdate(pctx, discard, &outl, discard, 64);
        outl = 0;
        EVP_EncryptUpdate(pctx, enc_payload, &outl, plain + 4, pktlen);
        EVP_CIPHER_CTX_free(pctx);
    }
    free(plain);

    /* Step 4: Compute Poly1305 tag over encrypted_length + encrypted_payload */
    unsigned char tag[16];
    {
        EVP_MAC *mac = EVP_MAC_fetch(NULL, "POLY1305", NULL);
        if (!mac) { free(enc_payload); return RAWSSH_ALLOC_FAIL; }
        EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(mac);
        EVP_MAC_free(mac);
        if (!mctx) { free(enc_payload); return RAWSSH_ALLOC_FAIL; }
        EVP_MAC_init(mctx, poly_key, 32, NULL);
        EVP_MAC_update(mctx, enc_len, 4);
        EVP_MAC_update(mctx, enc_payload, pktlen);
        size_t taglen = 16;
        EVP_MAC_final(mctx, tag, &taglen, 16);
        EVP_MAC_CTX_free(mctx);
    }

    /* Send: encrypted_length(4) + encrypted_payload(pktlen) + tag(16) */
    unsigned char *sendbuf = malloc(4 + pktlen + 16);
    if (!sendbuf) { free(enc_payload); return RAWSSH_ALLOC_FAIL; }
    memcpy(sendbuf, enc_len, 4);
    memcpy(sendbuf + 4, enc_payload, pktlen);
    memcpy(sendbuf + 4 + pktlen, tag, 16);
    free(enc_payload);

    int rc = raw_send(s, sendbuf, 4 + pktlen + 16);
    free(sendbuf);
    if (rc < 0) return rc;

    s->c2s.seq++;
    return RAWSSH_OK;
}

/* Send an encrypted SSH packet - AES-CTR + HMAC mode */
static int send_packet_encrypted(rawssh_session *s, const unsigned char *payload, int plen) {
    if (s->is_chacha20)
        return send_packet_chacha20(s, payload, plen);

    int block = s->c2s.cipher_block;
    if (block < 8) block = 8;
    int padlen = block - ((4 + 1 + plen) % block);
    if (padlen < 4) padlen += block;
    int pktlen = 1 + plen + padlen;
    int total = 4 + pktlen;

    unsigned char *plain = malloc(total);
    if (!plain) return RAWSSH_ALLOC_FAIL;

    put_u32(plain, pktlen);
    plain[4] = (unsigned char)padlen;
    memcpy(plain + 5, payload, plen);
    RAND_bytes(plain + 5 + plen, padlen);

    /* Compute MAC over seqno + unencrypted packet */
    unsigned char mac[RAWSSH_MAC_SIZE];
    int mac_len = s->c2s.mac_len;
    if (mac_len > 0) {
        unsigned char seqbuf[4];
        put_u32(seqbuf, s->c2s.seq);

        unsigned int hmac_len = 0;
        HMAC_CTX *hctx = HMAC_CTX_new();
        if (!hctx) { free(plain); return RAWSSH_ALLOC_FAIL; }
        if (s->c2s.mac_len >= 32) {
            HMAC_Init_ex(hctx, s->c2s.mac_key, 32, EVP_sha256(), NULL);
        } else {
            HMAC_Init_ex(hctx, s->c2s.mac_key, 20, EVP_sha1(), NULL);
        }
        HMAC_Update(hctx, seqbuf, 4);
        HMAC_Update(hctx, plain, total);
        HMAC_Final(hctx, mac, &hmac_len);
        HMAC_CTX_free(hctx);
    }

    /* Encrypt in place */
    unsigned char *enc = malloc(total);
    if (!enc) { free(plain); return RAWSSH_ALLOC_FAIL; }
    int outl = 0;
    EVP_EncryptUpdate(s->c2s.ctx, enc, &outl, plain, total);
    free(plain);

    /* Send encrypted data + MAC in single syscall via writev */
    int rc;
    if (mac_len > 0) {
        struct iovec iov[2] = {
            { .iov_base = enc, .iov_len = total },
            { .iov_base = mac, .iov_len = mac_len }
        };
        int want = total + mac_len;
        int sent = 0;
        while (sent < want) {
            int r = sock_wait(s->sock, POLLOUT, s->timeout_sec * 1000);
            if (r <= 0) { free(enc); return (r == 0) ? RAWSSH_TIMEOUT : RAWSSH_TCP_ERROR; }
            /* Adjust iov for partial writes */
            int off = sent;
            int iovcnt = 0;
            struct iovec wv[2];
            for (int i = 0; i < 2; i++) {
                if (off >= (int)iov[i].iov_len) {
                    off -= iov[i].iov_len;
                } else {
                    wv[iovcnt].iov_base = (char*)iov[i].iov_base + off;
                    wv[iovcnt].iov_len = iov[i].iov_len - off;
                    iovcnt++;
                    off = 0;
                }
            }
            ssize_t w = writev(s->sock, wv, iovcnt);
            if (w <= 0) { free(enc); return RAWSSH_TCP_ERROR; }
            sent += w;
        }
        rc = RAWSSH_OK;
    } else {
        rc = raw_send(s, enc, total);
        if (rc < 0) { free(enc); return rc; }
        rc = RAWSSH_OK;
    }
    free(enc);

    s->c2s.seq++;
    return rc;
}

static int send_packet(rawssh_session *s, const unsigned char *payload, int plen) {
    if (s->encrypted)
        return send_packet_encrypted(s, payload, plen);
    else
        return send_packet_plain(s, payload, plen);
}

/* Receive an unencrypted SSH packet */
static int recv_packet_plain(rawssh_session *s, unsigned char *payload, int *plen) {
    unsigned char hdr[4];
    int rc = raw_recv(s, hdr, 4);
    if (rc < 0) return rc;

    uint32_t pktlen = get_u32(hdr);
    if (pktlen > RAWSSH_MAX_PACKET || pktlen < 2) return RAWSSH_PROTO_ERROR;

    unsigned char *pkt = malloc(pktlen);
    if (!pkt) return RAWSSH_ALLOC_FAIL;

    rc = raw_recv(s, pkt, pktlen);
    if (rc < 0) { free(pkt); return rc; }

    int padlen = pkt[0];
    int datalen = pktlen - padlen - 1;
    if (datalen < 0 || datalen > RAWSSH_MAX_PAYLOAD) {
        free(pkt);
        return RAWSSH_PROTO_ERROR;
    }

    memcpy(payload, pkt + 1, datalen);
    *plen = datalen;
    free(pkt);
    s->s2c.seq++;
    return RAWSSH_OK;
}

/* Receive an encrypted SSH packet - chacha20-poly1305 AEAD mode */
static int recv_packet_chacha20(rawssh_session *s, unsigned char *payload, int *plen) {
    /* Step 1: Read encrypted length (4 bytes) */
    unsigned char enc_len[4];
    int rc = raw_recv(s, enc_len, 4);
    if (rc < 0) return rc;

    /* Build IV: 4-byte LE counter (0) + 12-byte nonce (4 zero + 4 zero + 4 seqno BE) */
    unsigned char chacha_iv[16];
    memset(chacha_iv, 0, 16);
    put_u32(chacha_iv + 12, s->s2c.seq);

    /* Decrypt length using header key (K_2, stored in mac_key) */
    unsigned char dec_len_buf[4];
    {
        EVP_CIPHER_CTX *hctx = EVP_CIPHER_CTX_new();
        if (!hctx) return RAWSSH_ALLOC_FAIL;
        EVP_DecryptInit_ex(hctx, EVP_chacha20(), NULL, s->s2c.mac_key, chacha_iv);
        int outl = 0;
        EVP_DecryptUpdate(hctx, dec_len_buf, &outl, enc_len, 4);
        EVP_CIPHER_CTX_free(hctx);
    }

    uint32_t pktlen = get_u32(dec_len_buf);
    if (pktlen > RAWSSH_MAX_PACKET || pktlen < 2) return RAWSSH_PROTO_ERROR;

    /* Step 2: Read encrypted payload + tag */
    unsigned char *enc_payload = malloc(pktlen);
    if (!enc_payload) return RAWSSH_ALLOC_FAIL;
    rc = raw_recv(s, enc_payload, pktlen);
    if (rc < 0) { free(enc_payload); return rc; }

    unsigned char tag_recv[16];
    rc = raw_recv(s, tag_recv, 16);
    if (rc < 0) { free(enc_payload); return rc; }

    /* Step 3: Derive Poly1305 key and verify tag */
    unsigned char poly_key[32];
    {
        EVP_CIPHER_CTX *kctx = EVP_CIPHER_CTX_new();
        if (!kctx) { free(enc_payload); return RAWSSH_ALLOC_FAIL; }
        EVP_EncryptInit_ex(kctx, EVP_chacha20(), NULL, s->s2c.key, chacha_iv);
        unsigned char zeros[32] = {0};
        int outl = 0;
        EVP_EncryptUpdate(kctx, poly_key, &outl, zeros, 32);
        EVP_CIPHER_CTX_free(kctx);
    }

    unsigned char tag_calc[16];
    {
        EVP_MAC *mac = EVP_MAC_fetch(NULL, "POLY1305", NULL);
        if (!mac) { free(enc_payload); return RAWSSH_ALLOC_FAIL; }
        EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(mac);
        EVP_MAC_free(mac);
        if (!mctx) { free(enc_payload); return RAWSSH_ALLOC_FAIL; }
        EVP_MAC_init(mctx, poly_key, 32, NULL);
        EVP_MAC_update(mctx, enc_len, 4);
        EVP_MAC_update(mctx, enc_payload, pktlen);
        size_t taglen = 16;
        EVP_MAC_final(mctx, tag_calc, &taglen, 16);
        EVP_MAC_CTX_free(mctx);
    }

    if (CRYPTO_memcmp(tag_recv, tag_calc, 16) != 0) {
        free(enc_payload);
        return RAWSSH_PROTO_ERROR;
    }

    /* Step 4: Decrypt payload with main key, counter starting at 1 */
    unsigned char *dec_payload = malloc(pktlen);
    if (!dec_payload) { free(enc_payload); return RAWSSH_ALLOC_FAIL; }
    {
        EVP_CIPHER_CTX *pctx = EVP_CIPHER_CTX_new();
        if (!pctx) { free(dec_payload); free(enc_payload); return RAWSSH_ALLOC_FAIL; }
        EVP_DecryptInit_ex(pctx, EVP_chacha20(), NULL, s->s2c.key, chacha_iv);
        /* Skip first 64 bytes (counter block 0 used for poly1305 key) */
        unsigned char discard[64];
        int outl = 0;
        EVP_DecryptUpdate(pctx, discard, &outl, discard, 64);
        outl = 0;
        EVP_DecryptUpdate(pctx, dec_payload, &outl, enc_payload, pktlen);
        EVP_CIPHER_CTX_free(pctx);
    }
    free(enc_payload);

    int padlen = dec_payload[0];
    int datalen = pktlen - padlen - 1;
    if (datalen < 0 || datalen > RAWSSH_MAX_PAYLOAD) {
        free(dec_payload);
        return RAWSSH_PROTO_ERROR;
    }

    memcpy(payload, dec_payload + 1, datalen);
    *plen = datalen;
    free(dec_payload);
    s->s2c.seq++;
    return RAWSSH_OK;
}

/* Receive an encrypted SSH packet - AES-CTR + HMAC mode */
static int recv_packet_encrypted(rawssh_session *s, unsigned char *payload, int *plen) {
    if (s->is_chacha20)
        return recv_packet_chacha20(s, payload, plen);

    int block = s->s2c.cipher_block;
    if (block < 8) block = 8;

    /* Read first block to get packet length */
    unsigned char first_block[32];
    int rc = raw_recv(s, first_block, block);
    if (rc < 0) return rc;

    unsigned char dec_first[32];
    int outl = 0;
    EVP_DecryptUpdate(s->s2c.ctx, dec_first, &outl, first_block, block);

    uint32_t pktlen = get_u32(dec_first);
    if (pktlen > RAWSSH_MAX_PACKET || pktlen < 2) return RAWSSH_PROTO_ERROR;

    int remaining = 4 + pktlen - block;
    unsigned char *full_enc = NULL;
    unsigned char *full_dec = malloc(4 + pktlen);
    if (!full_dec) return RAWSSH_ALLOC_FAIL;

    memcpy(full_dec, dec_first, block);

    if (remaining > 0) {
        full_enc = malloc(remaining);
        if (!full_enc) { free(full_dec); return RAWSSH_ALLOC_FAIL; }
        rc = raw_recv(s, full_enc, remaining);
        if (rc < 0) { free(full_enc); free(full_dec); return rc; }

        outl = 0;
        EVP_DecryptUpdate(s->s2c.ctx, full_dec + block, &outl, full_enc, remaining);
        free(full_enc);
    }

    /* Read and verify MAC */
    int mac_len = s->s2c.mac_len;
    if (mac_len > 0) {
        unsigned char mac_recv[RAWSSH_MAC_SIZE];
        rc = raw_recv(s, mac_recv, mac_len);
        if (rc < 0) { free(full_dec); return rc; }

        /* Compute expected MAC */
        unsigned char mac_calc[RAWSSH_MAC_SIZE];
        unsigned char seqbuf[4];
        put_u32(seqbuf, s->s2c.seq);

        unsigned int hmac_len = 0;
        HMAC_CTX *hctx = HMAC_CTX_new();
        if (!hctx) { free(full_dec); return RAWSSH_ALLOC_FAIL; }
        if (s->s2c.mac_len >= 32) {
            HMAC_Init_ex(hctx, s->s2c.mac_key, 32, EVP_sha256(), NULL);
        } else {
            HMAC_Init_ex(hctx, s->s2c.mac_key, 20, EVP_sha1(), NULL);
        }
        HMAC_Update(hctx, seqbuf, 4);
        HMAC_Update(hctx, full_dec, 4 + pktlen);
        HMAC_Final(hctx, mac_calc, &hmac_len);
        HMAC_CTX_free(hctx);

        if (CRYPTO_memcmp(mac_recv, mac_calc, mac_len) != 0) {
            free(full_dec);
            return RAWSSH_PROTO_ERROR;
        }
    }

    int padlen = full_dec[4];
    int datalen = pktlen - padlen - 1;
    if (datalen < 0 || datalen > RAWSSH_MAX_PAYLOAD) {
        free(full_dec);
        return RAWSSH_PROTO_ERROR;
    }

    memcpy(payload, full_dec + 5, datalen);
    *plen = datalen;
    free(full_dec);
    s->s2c.seq++;
    return RAWSSH_OK;
}

static int recv_packet_raw(rawssh_session *s, unsigned char *payload, int *plen) {
    if (s->encrypted)
        return recv_packet_encrypted(s, payload, plen);
    else
        return recv_packet_plain(s, payload, plen);
}

/* Wrapper: auto-handle DISCONNECT, IGNORE, DEBUG per RFC 4253 §11
 * These messages can arrive at any time and must be handled transparently. */
static int recv_packet(rawssh_session *s, unsigned char *payload, int *plen) {
    for (int i = 0; i < 20; i++) {
        int rc = recv_packet_raw(s, payload, plen);
        if (rc < 0) return rc;
        /* Server is disconnecting us */
        if (payload[0] == SSH_MSG_DISCONNECT) return RAWSSH_CLOSED;
        /* Skip debug/ignore messages - servers send these any time */
        if (payload[0] == SSH_MSG_IGNORE || payload[0] == SSH_MSG_DEBUG)
            continue;
        /* SSH_MSG_UNIMPLEMENTED - skip but note it */
        if (payload[0] == SSH_MSG_UNIMPLEMENTED)
            continue;
        return rc;
    }
    return RAWSSH_PROTO_ERROR; /* too many ignored messages */
}

/* ========== Key Exchange ========== */

/* RFC 3526 - Group 14 (2048-bit MODP) */
static const char *dh_group14_p_hex =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

/* RFC 3526 - Group 16 (4096-bit MODP) */
static const char *dh_group16_p_hex =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
    "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
    "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
    "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
    "FFFFFFFFFFFFFFFF";

/* Helper: get EVP_MD for KEX hash */
static const EVP_MD *get_kex_md(rawssh_session *s) {
    switch (s->kex_hash_type) {
        case 2:  return EVP_sha512();
        case 1:  return EVP_sha256();
        default: return EVP_sha1();
    }
}

#define KEX_LIST "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1"
#define HOSTKEY_LIST "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-256,rsa-sha2-512,ssh-rsa"
#define CIPHER_LIST "aes128-ctr,aes256-ctr,chacha20-poly1305@openssh.com"
#define MAC_LIST "hmac-sha2-256,hmac-sha1"

/* Build KEXINIT packet */
static int build_kexinit(rawssh_session *s) {
    unsigned char payload[2048];
    int off = 0;

    payload[off++] = SSH_MSG_KEXINIT;
    RAND_bytes(payload + off, 16);
    off += 16;

    put_cstring(payload, KEX_LIST, &off);
    put_cstring(payload, HOSTKEY_LIST, &off);
    put_cstring(payload, CIPHER_LIST, &off);
    put_cstring(payload, CIPHER_LIST, &off);
    put_cstring(payload, MAC_LIST, &off);
    put_cstring(payload, MAC_LIST, &off);
    put_cstring(payload, "none", &off);
    put_cstring(payload, "none", &off);
    put_cstring(payload, "", &off);
    put_cstring(payload, "", &off);
    payload[off++] = 0;
    put_u32(payload + off, 0);
    off += 4;

    s->my_kexinit = malloc(off);
    memcpy(s->my_kexinit, payload, off);
    s->my_kexinit_len = off;

    return send_packet(s, payload, off);
}

/* Find first matching algorithm from comma-separated lists */
static int find_match(const char *client, const char *server, char *out, int outlen) {
    char *ccopy = strdup(client);
    char *saveptr = NULL;
    char *tok = strtok_r(ccopy, ",", &saveptr);
    while (tok) {
        /* Check if tok appears in server list */
        const char *p = server;
        while (p) {
            const char *comma = strchr(p, ',');
            int slen = comma ? (int)(comma - p) : (int)strlen(p);
            if (slen == (int)strlen(tok) && strncmp(p, tok, slen) == 0) {
                strncpy(out, tok, outlen - 1);
                out[outlen - 1] = 0;
                free(ccopy);
                return 0;
            }
            p = comma ? comma + 1 : NULL;
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }
    free(ccopy);
    return -1;
}

/* Parse server KEXINIT and negotiate algorithms */
static int parse_kexinit(rawssh_session *s, const unsigned char *payload, int plen) {
    /* Save server kexinit for hash */
    s->peer_kexinit = malloc(plen);
    memcpy(s->peer_kexinit, payload, plen);
    s->peer_kexinit_len = plen;

    int off = 1 + 16; /* skip type + cookie */

    /* Parse name-lists */
    const unsigned char *data;
    uint32_t dlen;
    char server_kex[256] = {0};
    char server_hostkey[256] = {0};
    char server_enc_c2s[256] = {0};
    char server_enc_s2c[256] = {0};
    char server_mac_c2s[256] = {0};
    char server_mac_s2c[256] = {0};

    /* kex_algorithms */
    if (get_string(payload, plen, &off, &data, &dlen) < 0) return RAWSSH_PROTO_ERROR;
    snprintf(server_kex, sizeof(server_kex), "%.*s", (int)dlen, (char *)data);

    /* server_host_key_algorithms */
    if (get_string(payload, plen, &off, &data, &dlen) < 0) return RAWSSH_PROTO_ERROR;
    snprintf(server_hostkey, sizeof(server_hostkey), "%.*s", (int)dlen, (char *)data);

    /* encryption c2s */
    if (get_string(payload, plen, &off, &data, &dlen) < 0) return RAWSSH_PROTO_ERROR;
    snprintf(server_enc_c2s, sizeof(server_enc_c2s), "%.*s", (int)dlen, (char *)data);

    /* encryption s2c */
    if (get_string(payload, plen, &off, &data, &dlen) < 0) return RAWSSH_PROTO_ERROR;
    snprintf(server_enc_s2c, sizeof(server_enc_s2c), "%.*s", (int)dlen, (char *)data);

    /* mac c2s */
    if (get_string(payload, plen, &off, &data, &dlen) < 0) return RAWSSH_PROTO_ERROR;
    snprintf(server_mac_c2s, sizeof(server_mac_c2s), "%.*s", (int)dlen, (char *)data);

    /* mac s2c */
    if (get_string(payload, plen, &off, &data, &dlen) < 0) return RAWSSH_PROTO_ERROR;
    snprintf(server_mac_s2c, sizeof(server_mac_s2c), "%.*s", (int)dlen, (char *)data);

    /* Negotiate */
    char chosen_kex[64], chosen_cipher_c2s[64], chosen_cipher_s2c[64];
    char chosen_mac_c2s[64], chosen_mac_s2c[64], chosen_hostkey[64];

    if (find_match(KEX_LIST, server_kex, chosen_kex, sizeof(chosen_kex)) < 0)
        return RAWSSH_PROTO_ERROR;

    /* Determine KEX type and hash */
    if (strstr(chosen_kex, "curve25519")) {
        s->kex_type = 2; s->kex_hash_type = 1; /* sha256 */
    } else if (strstr(chosen_kex, "ecdh-sha2-nistp256")) {
        s->kex_type = 3; s->kex_hash_type = 1;
    } else if (strstr(chosen_kex, "group-exchange-sha256")) {
        s->kex_type = 4; s->kex_hash_type = 1; /* sha256 */
    } else if (strstr(chosen_kex, "group16")) {
        s->kex_type = 1; s->kex_hash_type = 2; /* sha512 */
    } else if (strstr(chosen_kex, "group14-sha256")) {
        s->kex_type = 0; s->kex_hash_type = 1;
    } else {
        s->kex_type = 0; s->kex_hash_type = 0; /* sha1 */
    }

    if (find_match(HOSTKEY_LIST, server_hostkey, chosen_hostkey, sizeof(chosen_hostkey)) < 0)
        return RAWSSH_PROTO_ERROR;

    if (find_match(CIPHER_LIST, server_enc_c2s, chosen_cipher_c2s, sizeof(chosen_cipher_c2s)) < 0)
        return RAWSSH_PROTO_ERROR;
    if (find_match(CIPHER_LIST, server_enc_s2c, chosen_cipher_s2c, sizeof(chosen_cipher_s2c)) < 0)
        return RAWSSH_PROTO_ERROR;

    /* Check for chacha20-poly1305@openssh.com */
    if (strstr(chosen_cipher_c2s, "chacha20-poly1305")) {
        s->is_chacha20 = 1;
        s->cipher_key_len = 64; /* 2x32 bytes: main key + header key */
    } else if (strstr(chosen_cipher_c2s, "aes256")) {
        s->cipher_key_len = 32;
    } else {
        s->cipher_key_len = 16;
    }

    /* For chacha20-poly1305, MAC is built into the cipher - no separate MAC needed */
    if (s->is_chacha20) {
        /* Try to negotiate MAC but don't fail if server doesn't offer any we support */
        find_match(MAC_LIST, server_mac_c2s, chosen_mac_c2s, sizeof(chosen_mac_c2s));
        find_match(MAC_LIST, server_mac_s2c, chosen_mac_s2c, sizeof(chosen_mac_s2c));
        s->mac_is_sha256 = 0; /* unused with chacha20-poly1305 */
    } else {
        if (find_match(MAC_LIST, server_mac_c2s, chosen_mac_c2s, sizeof(chosen_mac_c2s)) < 0)
            return RAWSSH_PROTO_ERROR;
        if (find_match(MAC_LIST, server_mac_s2c, chosen_mac_s2c, sizeof(chosen_mac_s2c)) < 0)
            return RAWSSH_PROTO_ERROR;
        s->mac_is_sha256 = (strstr(chosen_mac_c2s, "sha2-256") != NULL);
    }

    return RAWSSH_OK;
}

/* Derive a key using the SSH key derivation (RFC 4253 Section 7.2) */
static void derive_key(rawssh_session *s, char id, int need,
                       unsigned char *out) {
    const EVP_MD *md = get_kex_md(s);
    int hash_len = EVP_MD_size(md);

    int klen = BN_num_bytes(s->dh_k);
    unsigned char *kbuf = malloc(klen + 5);
    int koff = 0;
    put_mpint(kbuf, s->dh_k, &koff);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, kbuf, koff);
    EVP_DigestUpdate(ctx, s->exchange_hash, s->session_id_len);
    EVP_DigestUpdate(ctx, &id, 1);
    EVP_DigestUpdate(ctx, s->session_id, s->session_id_len);

    unsigned char hash[64];
    unsigned int hlen;
    EVP_DigestFinal_ex(ctx, hash, &hlen);

    int got = hlen < (unsigned)need ? hlen : need;
    memcpy(out, hash, got);

    while (got < need) {
        EVP_DigestInit_ex(ctx, md, NULL);
        EVP_DigestUpdate(ctx, kbuf, koff);
        EVP_DigestUpdate(ctx, s->exchange_hash, s->session_id_len);
        EVP_DigestUpdate(ctx, out, got);
        EVP_DigestFinal_ex(ctx, hash, &hlen);
        int chunk = (got + (int)hlen > need) ? need - got : (int)hlen;
        memcpy(out + got, hash, chunk);
        got += chunk;
    }

    EVP_MD_CTX_free(ctx);
    free(kbuf);
}

/* Exchange hash for DH (e,f are mpints) */
static int compute_exchange_hash(rawssh_session *s,
                                  const unsigned char *k_s, int k_s_len,
                                  const BIGNUM *e, const BIGNUM *f,
                                  const BIGNUM *k) {
    const EVP_MD *md = get_kex_md(s);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);

    int off = 0;
    unsigned char tmp[8192];
    put_cstring(tmp, s->client_version, &off);
    EVP_DigestUpdate(ctx, tmp, off);
    off = 0;
    put_cstring(tmp, s->server_version, &off);
    EVP_DigestUpdate(ctx, tmp, off);

    put_u32(tmp, s->my_kexinit_len);
    EVP_DigestUpdate(ctx, tmp, 4);
    EVP_DigestUpdate(ctx, s->my_kexinit, s->my_kexinit_len);
    put_u32(tmp, s->peer_kexinit_len);
    EVP_DigestUpdate(ctx, tmp, 4);
    EVP_DigestUpdate(ctx, s->peer_kexinit, s->peer_kexinit_len);

    off = 0;
    put_string(tmp, k_s, k_s_len, &off);
    EVP_DigestUpdate(ctx, tmp, off);
    off = 0; put_mpint(tmp, e, &off); EVP_DigestUpdate(ctx, tmp, off);
    off = 0; put_mpint(tmp, f, &off); EVP_DigestUpdate(ctx, tmp, off);
    off = 0; put_mpint(tmp, k, &off); EVP_DigestUpdate(ctx, tmp, off);

    unsigned int hlen;
    EVP_DigestFinal_ex(ctx, s->exchange_hash, &hlen);
    EVP_MD_CTX_free(ctx);

    s->session_id_len = hlen;
    if (!s->session_id[0] && !s->session_id[1])
        memcpy(s->session_id, s->exchange_hash, hlen);
    return RAWSSH_OK;
}

/* Exchange hash for ECDH/curve25519 (Q_C, Q_S are strings, not mpints) */
static int compute_exchange_hash_ecdh(rawssh_session *s,
                                       const unsigned char *k_s, int k_s_len,
                                       const unsigned char *q_c, int q_c_len,
                                       const unsigned char *q_s, int q_s_len) {
    const EVP_MD *md = get_kex_md(s);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);

    int off = 0;
    unsigned char tmp[8192];
    put_cstring(tmp, s->client_version, &off);
    EVP_DigestUpdate(ctx, tmp, off);
    off = 0;
    put_cstring(tmp, s->server_version, &off);
    EVP_DigestUpdate(ctx, tmp, off);

    put_u32(tmp, s->my_kexinit_len);
    EVP_DigestUpdate(ctx, tmp, 4);
    EVP_DigestUpdate(ctx, s->my_kexinit, s->my_kexinit_len);
    put_u32(tmp, s->peer_kexinit_len);
    EVP_DigestUpdate(ctx, tmp, 4);
    EVP_DigestUpdate(ctx, s->peer_kexinit, s->peer_kexinit_len);

    off = 0;
    put_string(tmp, k_s, k_s_len, &off);
    EVP_DigestUpdate(ctx, tmp, off);
    off = 0; put_string(tmp, q_c, q_c_len, &off); EVP_DigestUpdate(ctx, tmp, off);
    off = 0; put_string(tmp, q_s, q_s_len, &off); EVP_DigestUpdate(ctx, tmp, off);
    off = 0; put_mpint(tmp, s->dh_k, &off); EVP_DigestUpdate(ctx, tmp, off);

    unsigned int hlen;
    EVP_DigestFinal_ex(ctx, s->exchange_hash, &hlen);
    EVP_MD_CTX_free(ctx);

    s->session_id_len = hlen;
    if (!s->session_id[0] && !s->session_id[1])
        memcpy(s->session_id, s->exchange_hash, hlen);
    return RAWSSH_OK;
}

/* Complete KEX: NEWKEYS exchange + key derivation (shared by all KEX types) */
static int complete_kex(rawssh_session *s) {
    unsigned char nk = SSH_MSG_NEWKEYS;
    int rc = send_packet(s, &nk, 1);
    if (rc < 0) return rc;

    unsigned char rpayload[RAWSSH_MAX_PAYLOAD];
    int rplen;
    rc = recv_packet(s, rpayload, &rplen);
    if (rc < 0) return rc;
    if (rpayload[0] != SSH_MSG_NEWKEYS) return RAWSSH_PROTO_ERROR;

    if (s->is_chacha20) {
        /* chacha20-poly1305@openssh.com key derivation:
         * K_1 (main key, 32 bytes) = derive_key 'C'/'D'
         * K_2 (header key, 32 bytes) = derive_key with higher bytes of the 64-byte key
         * Per OpenSSH: the cipher key is 64 bytes, first 32 = K_2 (header), last 32 = K_1 (main)
         * But in practice: derive 64 bytes total, K_2 = bytes 0..31, K_1 = bytes 32..63
         * We store K_1 in key[] and K_2 in mac_key[] */
        unsigned char full_key_c2s[64], full_key_s2c[64];
        derive_key(s, 'C', 64, full_key_c2s);
        derive_key(s, 'D', 64, full_key_s2c);

        /* K_1 (main encryption) = first 32 bytes, K_2 (header) = last 32 bytes */
        memcpy(s->c2s.key, full_key_c2s, 32);      /* K_1 */
        memcpy(s->c2s.mac_key, full_key_c2s + 32, 32); /* K_2 */
        memcpy(s->s2c.key, full_key_s2c, 32);      /* K_1 */
        memcpy(s->s2c.mac_key, full_key_s2c + 32, 32); /* K_2 */

        /* No persistent cipher context needed - chacha20-poly1305 creates
         * fresh contexts per-packet with sequence number as nonce */
        s->c2s.ctx = NULL;
        s->s2c.ctx = NULL;
        s->c2s.cipher_block = 8;
        s->s2c.cipher_block = 8;
        s->c2s.key_len = 32;
        s->s2c.key_len = 32;
        s->c2s.mac_len = 0; /* Poly1305 replaces HMAC */
        s->s2c.mac_len = 0;
    } else {
        int kl = s->cipher_key_len;
        int bl = 16;
        int mac_kl = s->mac_is_sha256 ? 32 : 20;

        derive_key(s, 'A', bl, s->c2s.iv);
        derive_key(s, 'B', bl, s->s2c.iv);
        derive_key(s, 'C', kl, s->c2s.key);
        derive_key(s, 'D', kl, s->s2c.key);
        derive_key(s, 'E', mac_kl, s->c2s.mac_key);
        derive_key(s, 'F', mac_kl, s->s2c.mac_key);

        const EVP_CIPHER *cipher = (kl == 32) ? EVP_aes_256_ctr() : EVP_aes_128_ctr();

        s->c2s.ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(s->c2s.ctx, cipher, NULL, s->c2s.key, s->c2s.iv);
        s->c2s.cipher_block = bl;
        s->c2s.key_len = kl;
        s->c2s.mac_len = mac_kl;

        s->s2c.ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(s->s2c.ctx, cipher, NULL, s->s2c.key, s->s2c.iv);
        s->s2c.cipher_block = bl;
        s->s2c.key_len = kl;
        s->s2c.mac_len = mac_kl;

        EVP_CIPHER_CTX_set_padding(s->c2s.ctx, 0);
        EVP_CIPHER_CTX_set_padding(s->s2c.ctx, 0);
    }
    s->encrypted = 1;
    return RAWSSH_OK;
}

/* ========== KEX: DH group14/group16 ========== */
static int do_kex_dh(rawssh_session *s) {
    s->dh_p = BN_new(); s->dh_g = BN_new();
    s->dh_x = BN_new(); s->dh_e = BN_new();

    if (s->kex_type == 1) /* group16 */
        BN_hex2bn(&s->dh_p, dh_group16_p_hex);
    else
        BN_hex2bn(&s->dh_p, dh_group14_p_hex);
    BN_set_word(s->dh_g, 2);

    BN_rand(s->dh_x, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    BN_CTX *bnctx = BN_CTX_new();
    BN_mod_exp(s->dh_e, s->dh_g, s->dh_x, s->dh_p, bnctx);

    unsigned char payload[1024];
    int off = 0;
    payload[off++] = SSH_MSG_KEXDH_INIT;
    put_mpint(payload, s->dh_e, &off);

    int rc = send_packet(s, payload, off);
    if (rc < 0) { BN_CTX_free(bnctx); return rc; }

    unsigned char rpayload[RAWSSH_MAX_PAYLOAD];
    int rplen;
    rc = recv_packet(s, rpayload, &rplen);
    if (rc < 0) { BN_CTX_free(bnctx); return rc; }
    if (rpayload[0] != SSH_MSG_KEXDH_REPLY) { BN_CTX_free(bnctx); return RAWSSH_PROTO_ERROR; }

    off = 1;
    const unsigned char *k_s_data; uint32_t k_s_len;
    if (get_string(rpayload, rplen, &off, &k_s_data, &k_s_len) < 0) { BN_CTX_free(bnctx); return RAWSSH_PROTO_ERROR; }
    const unsigned char *f_data; uint32_t f_len;
    if (get_string(rpayload, rplen, &off, &f_data, &f_len) < 0) { BN_CTX_free(bnctx); return RAWSSH_PROTO_ERROR; }

    s->dh_f = BN_new();
    BN_bin2bn(f_data, f_len, s->dh_f);
    s->dh_k = BN_new();
    BN_mod_exp(s->dh_k, s->dh_f, s->dh_x, s->dh_p, bnctx);
    BN_CTX_free(bnctx);

    rc = compute_exchange_hash(s, k_s_data, k_s_len, s->dh_e, s->dh_f, s->dh_k);
    if (rc < 0) return rc;
    return complete_kex(s);
}

/* ========== KEX: curve25519-sha256 ========== */
static int do_kex_curve25519(rawssh_session *s) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return RAWSSH_ALLOC_FAIL;
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY *ckey = NULL;
    EVP_PKEY_keygen(pctx, &ckey);
    EVP_PKEY_CTX_free(pctx);
    if (!ckey) return RAWSSH_ALLOC_FAIL;

    unsigned char cpub[32];
    size_t cpub_len = 32;
    EVP_PKEY_get_raw_public_key(ckey, cpub, &cpub_len);

    unsigned char payload[64];
    int off = 0;
    payload[off++] = SSH_MSG_KEXDH_INIT; /* 30 */
    put_string(payload, cpub, 32, &off);

    int rc = send_packet(s, payload, off);
    if (rc < 0) { EVP_PKEY_free(ckey); return rc; }

    unsigned char rpayload[RAWSSH_MAX_PAYLOAD];
    int rplen;
    rc = recv_packet(s, rpayload, &rplen);
    if (rc < 0) { EVP_PKEY_free(ckey); return rc; }
    if (rpayload[0] != SSH_MSG_KEXDH_REPLY) { EVP_PKEY_free(ckey); return RAWSSH_PROTO_ERROR; }

    off = 1;
    const unsigned char *k_s; uint32_t k_s_len;
    if (get_string(rpayload, rplen, &off, &k_s, &k_s_len) < 0) { EVP_PKEY_free(ckey); return RAWSSH_PROTO_ERROR; }
    const unsigned char *spub; uint32_t spub_len;
    if (get_string(rpayload, rplen, &off, &spub, &spub_len) < 0) { EVP_PKEY_free(ckey); return RAWSSH_PROTO_ERROR; }

    EVP_PKEY *skey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, spub, spub_len);
    if (!skey) { EVP_PKEY_free(ckey); return RAWSSH_PROTO_ERROR; }

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(ckey, NULL);
    EVP_PKEY_derive_init(dctx);
    EVP_PKEY_derive_set_peer(dctx, skey);
    size_t sec_len = 32;
    unsigned char secret[32];
    EVP_PKEY_derive(dctx, secret, &sec_len);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(skey);
    EVP_PKEY_free(ckey);

    s->dh_k = BN_new();
    BN_bin2bn(secret, sec_len, s->dh_k);

    rc = compute_exchange_hash_ecdh(s, k_s, k_s_len, cpub, 32, spub, spub_len);
    if (rc < 0) return rc;
    return complete_kex(s);
}

/* ========== KEX: ecdh-sha2-nistp256 ========== */
static int do_kex_ecdh_p256(rawssh_session *s) {
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return RAWSSH_ALLOC_FAIL;
    if (!EC_KEY_generate_key(ec)) { EC_KEY_free(ec); return RAWSSH_ALLOC_FAIL; }

    const EC_GROUP *grp = EC_KEY_get0_group(ec);
    const EC_POINT *pub = EC_KEY_get0_public_key(ec);
    size_t cpub_len = EC_POINT_point2oct(grp, pub, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    unsigned char *cpub = malloc(cpub_len);
    EC_POINT_point2oct(grp, pub, POINT_CONVERSION_UNCOMPRESSED, cpub, cpub_len, NULL);

    unsigned char payload[128];
    int off = 0;
    payload[off++] = SSH_MSG_KEXDH_INIT;
    put_string(payload, cpub, cpub_len, &off);

    int rc = send_packet(s, payload, off);
    if (rc < 0) { free(cpub); EC_KEY_free(ec); return rc; }

    unsigned char rpayload[RAWSSH_MAX_PAYLOAD];
    int rplen;
    rc = recv_packet(s, rpayload, &rplen);
    if (rc < 0) { free(cpub); EC_KEY_free(ec); return rc; }
    if (rpayload[0] != SSH_MSG_KEXDH_REPLY) { free(cpub); EC_KEY_free(ec); return RAWSSH_PROTO_ERROR; }

    off = 1;
    const unsigned char *k_s; uint32_t k_s_len;
    if (get_string(rpayload, rplen, &off, &k_s, &k_s_len) < 0) { free(cpub); EC_KEY_free(ec); return RAWSSH_PROTO_ERROR; }
    const unsigned char *spub_data; uint32_t spub_len;
    if (get_string(rpayload, rplen, &off, &spub_data, &spub_len) < 0) { free(cpub); EC_KEY_free(ec); return RAWSSH_PROTO_ERROR; }

    EC_POINT *spub = EC_POINT_new(grp);
    if (!EC_POINT_oct2point(grp, spub, spub_data, spub_len, NULL)) {
        EC_POINT_free(spub); free(cpub); EC_KEY_free(ec);
        return RAWSSH_PROTO_ERROR;
    }

    int field_size = (EC_GROUP_get_degree(grp) + 7) / 8;
    unsigned char *secret = malloc(field_size);
    int sec_len = ECDH_compute_key(secret, field_size, spub, ec, NULL);
    EC_POINT_free(spub);

    if (sec_len <= 0) { free(secret); free(cpub); EC_KEY_free(ec); return RAWSSH_PROTO_ERROR; }

    s->dh_k = BN_new();
    BN_bin2bn(secret, sec_len, s->dh_k);
    free(secret);

    rc = compute_exchange_hash_ecdh(s, k_s, k_s_len, cpub, cpub_len, spub_data, spub_len);
    free(cpub);
    EC_KEY_free(ec);
    if (rc < 0) return rc;
    return complete_kex(s);
}

/* ========== KEX: diffie-hellman-group-exchange-sha256 (RFC 4419) ========== */

/* Exchange hash for DH-GEX includes min/n/max and p/g from server */
static int compute_exchange_hash_gex(rawssh_session *s,
                                      const unsigned char *k_s, int k_s_len,
                                      uint32_t gex_min, uint32_t gex_n, uint32_t gex_max,
                                      const BIGNUM *p, const BIGNUM *g,
                                      const BIGNUM *e, const BIGNUM *f,
                                      const BIGNUM *k) {
    const EVP_MD *md = get_kex_md(s);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);

    int off = 0;
    unsigned char tmp[8192];
    put_cstring(tmp, s->client_version, &off);
    EVP_DigestUpdate(ctx, tmp, off);
    off = 0;
    put_cstring(tmp, s->server_version, &off);
    EVP_DigestUpdate(ctx, tmp, off);

    put_u32(tmp, s->my_kexinit_len);
    EVP_DigestUpdate(ctx, tmp, 4);
    EVP_DigestUpdate(ctx, s->my_kexinit, s->my_kexinit_len);
    put_u32(tmp, s->peer_kexinit_len);
    EVP_DigestUpdate(ctx, tmp, 4);
    EVP_DigestUpdate(ctx, s->peer_kexinit, s->peer_kexinit_len);

    off = 0;
    put_string(tmp, k_s, k_s_len, &off);
    EVP_DigestUpdate(ctx, tmp, off);

    /* GEX-specific: min, preferred, max */
    unsigned char gex_buf[12];
    put_u32(gex_buf, gex_min);
    put_u32(gex_buf + 4, gex_n);
    put_u32(gex_buf + 8, gex_max);
    EVP_DigestUpdate(ctx, gex_buf, 12);

    /* p, g as mpints */
    off = 0; put_mpint(tmp, p, &off); EVP_DigestUpdate(ctx, tmp, off);
    off = 0; put_mpint(tmp, g, &off); EVP_DigestUpdate(ctx, tmp, off);

    /* e, f, K as mpints */
    off = 0; put_mpint(tmp, e, &off); EVP_DigestUpdate(ctx, tmp, off);
    off = 0; put_mpint(tmp, f, &off); EVP_DigestUpdate(ctx, tmp, off);
    off = 0; put_mpint(tmp, k, &off); EVP_DigestUpdate(ctx, tmp, off);

    unsigned int hlen;
    EVP_DigestFinal_ex(ctx, s->exchange_hash, &hlen);
    EVP_MD_CTX_free(ctx);

    s->session_id_len = hlen;
    if (!s->session_id[0] && !s->session_id[1])
        memcpy(s->session_id, s->exchange_hash, hlen);
    return RAWSSH_OK;
}

static int do_kex_dh_gex(rawssh_session *s) {
    /* Step 1: Send GEX_REQUEST with min/preferred/max bits */
    uint32_t gex_min = 2048, gex_n = 4096, gex_max = 8192;

    unsigned char payload[64];
    int off = 0;
    payload[off++] = SSH_MSG_KEX_DH_GEX_REQUEST; /* 34 */
    put_u32(payload + off, gex_min); off += 4;
    put_u32(payload + off, gex_n); off += 4;
    put_u32(payload + off, gex_max); off += 4;

    int rc = send_packet(s, payload, off);
    if (rc < 0) return rc;

    /* Step 2: Receive GEX_GROUP (p, g from server) */
    unsigned char rpayload[RAWSSH_MAX_PAYLOAD];
    int rplen;
    rc = recv_packet(s, rpayload, &rplen);
    if (rc < 0) return rc;
    if (rpayload[0] != SSH_MSG_KEX_DH_GEX_GROUP) return RAWSSH_PROTO_ERROR;

    off = 1;
    const unsigned char *p_data; uint32_t p_len;
    if (get_string(rpayload, rplen, &off, &p_data, &p_len) < 0) return RAWSSH_PROTO_ERROR;
    const unsigned char *g_data; uint32_t g_len;
    if (get_string(rpayload, rplen, &off, &g_data, &g_len) < 0) return RAWSSH_PROTO_ERROR;

    s->dh_p = BN_new(); s->dh_g = BN_new();
    s->dh_x = BN_new(); s->dh_e = BN_new();
    BN_bin2bn(p_data, p_len, s->dh_p);
    BN_bin2bn(g_data, g_len, s->dh_g);

    /* Step 3: Generate client DH key and send GEX_INIT */
    BN_rand(s->dh_x, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    BN_CTX *bnctx = BN_CTX_new();
    BN_mod_exp(s->dh_e, s->dh_g, s->dh_x, s->dh_p, bnctx);

    unsigned char init_payload[1024];
    off = 0;
    init_payload[off++] = SSH_MSG_KEX_DH_GEX_INIT; /* 32 */
    put_mpint(init_payload, s->dh_e, &off);

    rc = send_packet(s, init_payload, off);
    if (rc < 0) { BN_CTX_free(bnctx); return rc; }

    /* Step 4: Receive GEX_REPLY */
    rc = recv_packet(s, rpayload, &rplen);
    if (rc < 0) { BN_CTX_free(bnctx); return rc; }
    if (rpayload[0] != SSH_MSG_KEX_DH_GEX_REPLY) { BN_CTX_free(bnctx); return RAWSSH_PROTO_ERROR; }

    off = 1;
    const unsigned char *k_s_data; uint32_t k_s_len;
    if (get_string(rpayload, rplen, &off, &k_s_data, &k_s_len) < 0) { BN_CTX_free(bnctx); return RAWSSH_PROTO_ERROR; }
    const unsigned char *f_data; uint32_t f_len;
    if (get_string(rpayload, rplen, &off, &f_data, &f_len) < 0) { BN_CTX_free(bnctx); return RAWSSH_PROTO_ERROR; }

    s->dh_f = BN_new();
    BN_bin2bn(f_data, f_len, s->dh_f);
    s->dh_k = BN_new();
    BN_mod_exp(s->dh_k, s->dh_f, s->dh_x, s->dh_p, bnctx);
    BN_CTX_free(bnctx);

    /* Compute exchange hash (includes GEX-specific fields) */
    rc = compute_exchange_hash_gex(s, k_s_data, k_s_len,
                                    gex_min, gex_n, gex_max,
                                    s->dh_p, s->dh_g,
                                    s->dh_e, s->dh_f, s->dh_k);
    if (rc < 0) return rc;
    return complete_kex(s);
}

/* ========== Service Request & User Auth ========== */

static int request_service(rawssh_session *s, const char *service) {
    unsigned char payload[256];
    int off = 0;
    payload[off++] = SSH_MSG_SERVICE_REQUEST;
    put_cstring(payload, service, &off);

    int rc = send_packet(s, payload, off);
    if (rc < 0) return rc;

    unsigned char rpayload[RAWSSH_MAX_PAYLOAD];
    int rplen;
    rc = recv_packet(s, rpayload, &rplen);
    if (rc < 0) return rc;

    /* Accept SSH_MSG_SERVICE_ACCEPT - skip any banners */
    while (rpayload[0] == SSH_MSG_USERAUTH_BANNER) {
        rc = recv_packet(s, rpayload, &rplen);
        if (rc < 0) return rc;
    }

    if (rpayload[0] != SSH_MSG_SERVICE_ACCEPT) return RAWSSH_PROTO_ERROR;

    return RAWSSH_OK;
}

/* ========== Public API ========== */

int rawssh_global_init(void) {
    /* OpenSSL 1.1.0+ auto-inits and is thread-safe by default */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
#endif
    return RAWSSH_OK;
}

void rawssh_global_cleanup(void) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_cleanup();
    ERR_free_strings();
#endif
}

rawssh_session *rawssh_session_new(void) {
    rawssh_session *s = calloc(1, sizeof(rawssh_session));
    if (!s) return NULL;
    s->sock = -1;
    s->timeout_sec = 5;
    s->nic[0] = 0;
    snprintf(s->client_version, sizeof(s->client_version), "SSH-2.0-RawSSH_1.0");
    return s;
}

void rawssh_session_free(rawssh_session *s) {
    if (!s) return;
    if (s->sock >= 0) close(s->sock);
    if (s->my_kexinit) free(s->my_kexinit);
    if (s->peer_kexinit) free(s->peer_kexinit);
    if (s->dh_p) BN_free(s->dh_p);
    if (s->dh_g) BN_free(s->dh_g);
    if (s->dh_x) BN_free(s->dh_x);
    if (s->dh_e) BN_free(s->dh_e);
    if (s->dh_f) BN_free(s->dh_f);
    if (s->dh_k) BN_free(s->dh_k);
    if (s->c2s.ctx) EVP_CIPHER_CTX_free(s->c2s.ctx);
    if (s->s2c.ctx) EVP_CIPHER_CTX_free(s->s2c.ctx);
    free(s);
}

void rawssh_set_timeout(rawssh_session *s, int timeout_sec) {
    s->timeout_sec = timeout_sec;
}

void rawssh_bind_nic(rawssh_session *s, const char *iface_name) {
    if (iface_name)
        strncpy(s->nic, iface_name, sizeof(s->nic) - 1);
}

int rawssh_connect(rawssh_session *s, const char *host, int port) {
    s->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (s->sock < 0) return RAWSSH_TCP_ERROR;

    /* Reuse address to avoid port exhaustion */
    int one = 1;
    setsockopt(s->sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    /* Bind to specific NIC if configured (soft-fail: ignore if not permitted) */
    if (s->nic[0]) {
        setsockopt(s->sock, SOL_SOCKET, SO_BINDTODEVICE,
                   s->nic, strlen(s->nic) + 1);
        /* Ignore errors - SO_BINDTODEVICE requires CAP_NET_RAW */
    }

    /* Set TCP_NODELAY for speed */
    setsockopt(s->sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    /* Non-blocking connect */
    int fl = fcntl(s->sock, F_GETFL, 0);
    fcntl(s->sock, F_SETFL, fl | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(s->sock);
        s->sock = -1;
        return RAWSSH_TCP_ERROR;
    }

    connect(s->sock, (struct sockaddr *)&addr, sizeof(addr));

    struct pollfd pf = {s->sock, POLLOUT, 0};
    if (poll(&pf, 1, s->timeout_sec * 1000) <= 0) {
        close(s->sock);
        s->sock = -1;
        return RAWSSH_TIMEOUT;
    }
    if (pf.revents & (POLLERR | POLLHUP)) {
        close(s->sock);
        s->sock = -1;
        return RAWSSH_TCP_ERROR;
    }

    int err;
    socklen_t el = sizeof(err);
    getsockopt(s->sock, SOL_SOCKET, SO_ERROR, &err, &el);
    if (err) {
        close(s->sock);
        s->sock = -1;
        return RAWSSH_TCP_ERROR;
    }

    /* Back to blocking with timeout */
    fcntl(s->sock, F_SETFL, fl);
    struct timeval tv = {s->timeout_sec, 0};
    setsockopt(s->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s->sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Reduce socket linger to avoid TIME_WAIT buildup */
    struct linger lg = {1, 0};
    setsockopt(s->sock, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));

    /* Enable TCP keepalive with aggressive timers to kill zombie sockets */
    setsockopt(s->sock, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    int keepidle = 5, keepintvl = 3, keepcnt = 3;
    setsockopt(s->sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    setsockopt(s->sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    setsockopt(s->sock, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));

#ifdef TCP_QUICKACK
    setsockopt(s->sock, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
#endif

    return RAWSSH_OK;
}

int rawssh_handshake(rawssh_session *s) {
    /* Send our version string */
    char ver[128];
    int vlen = snprintf(ver, sizeof(ver), "%s\r\n", s->client_version);
    int rc = raw_send(s, ver, vlen);
    if (rc < 0) return rc;

    /* Read server version - skip any banner lines that don't start with SSH- */
    for (int i = 0; i < 20; i++) {
        rc = read_line(s, s->server_version, sizeof(s->server_version));
        if (rc < 0) return rc;
        if (strncmp(s->server_version, "SSH-", 4) == 0)
            break;
    }
    if (strncmp(s->server_version, "SSH-", 4) != 0)
        return RAWSSH_PROTO_ERROR;

    /* Send KEXINIT */
    rc = build_kexinit(s);
    if (rc < 0) return rc;

    /* Receive server KEXINIT */
    unsigned char rpayload[RAWSSH_MAX_PAYLOAD];
    int rplen;
    rc = recv_packet(s, rpayload, &rplen);
    if (rc < 0) return rc;
    if (rpayload[0] != SSH_MSG_KEXINIT) return RAWSSH_PROTO_ERROR;

    /* Parse and negotiate */
    rc = parse_kexinit(s, rpayload, rplen);
    if (rc < 0) return rc;

    /* Perform key exchange based on negotiated algorithm */
    switch (s->kex_type) {
        case 2: rc = do_kex_curve25519(s); break;
        case 3: rc = do_kex_ecdh_p256(s); break;
        case 4: rc = do_kex_dh_gex(s); break; /* group-exchange-sha256 */
        default: rc = do_kex_dh(s); break; /* group14 or group16 */
    }
    if (rc < 0) return rc;

    /* Request ssh-userauth service */
    rc = request_service(s, "ssh-userauth");
    if (rc < 0) return rc;

    return RAWSSH_OK;
}

int rawssh_auth_password(rawssh_session *s, const char *user, const char *pass) {
    unsigned char payload[1024];
    int off = 0;

    payload[off++] = SSH_MSG_USERAUTH_REQUEST;
    put_cstring(payload, user, &off);
    put_cstring(payload, "ssh-connection", &off);
    put_cstring(payload, "password", &off);
    payload[off++] = 0; /* FALSE = not changing password */
    put_cstring(payload, pass, &off);

    int rc = send_packet(s, payload, off);
    if (rc < 0) return RAWSSH_CLOSED; /* Can't send = connection dead */

    unsigned char rpayload[RAWSSH_MAX_PAYLOAD];
    int rplen;

    for (int i = 0; i < 10; i++) {
        rc = recv_packet(s, rpayload, &rplen);
        if (rc < 0) {
            /* Server dropped connection - likely MaxAuthTries exceeded.
             * Return CLOSED so caller reconnects cleanly instead of
             * counting it as an unexpected error. */
            return RAWSSH_CLOSED;
        }

        if (rpayload[0] == SSH_MSG_USERAUTH_SUCCESS) {
            s->authenticated = 1;
            return RAWSSH_OK;
        }
        if (rpayload[0] == SSH_MSG_USERAUTH_FAILURE) {
            return RAWSSH_AUTH_FAIL;
        }
        if (rpayload[0] == SSH_MSG_USERAUTH_BANNER) {
            continue; /* skip banner, try next message */
        }
        /* Unknown message - skip */
    }

    return RAWSSH_AUTH_FAIL;
}

void rawssh_disconnect(rawssh_session *s) {
    if (!s || s->sock < 0) return;

    if (s->encrypted) {
        unsigned char payload[64];
        int off = 0;
        payload[off++] = SSH_MSG_DISCONNECT;
        put_u32(payload + off, 11); /* SSH_DISCONNECT_BY_APPLICATION */
        off += 4;
        put_cstring(payload, "", &off);
        put_cstring(payload, "", &off);
        send_packet(s, payload, off);
    }

    shutdown(s->sock, SHUT_RDWR);
    close(s->sock);
    s->sock = -1;
}

rawssh_channel *rawssh_channel_open(rawssh_session *s) {
    if (!s->authenticated) return NULL;

    rawssh_channel *ch = calloc(1, sizeof(rawssh_channel));
    if (!ch) return NULL;
    ch->session = s;
    ch->local_id = s->next_channel_id++;

    unsigned char payload[256];
    int off = 0;
    payload[off++] = SSH_MSG_CHANNEL_OPEN;
    put_cstring(payload, "session", &off);
    put_u32(payload + off, ch->local_id); off += 4;   /* sender channel */
    put_u32(payload + off, 0x100000); off += 4;        /* initial window */
    put_u32(payload + off, 0x4000); off += 4;          /* max packet */

    int rc = send_packet(s, payload, off);
    if (rc < 0) { free(ch); return NULL; }

    unsigned char rpayload[RAWSSH_MAX_PAYLOAD];
    int rplen;

    for (int i = 0; i < 10; i++) {
        rc = recv_packet(s, rpayload, &rplen);
        if (rc < 0) { free(ch); return NULL; }

        if (rpayload[0] == SSH_MSG_CHANNEL_OPEN_CONFIRM) {
            int roff = 1;
            roff += 4; /* recipient channel (our id) */
            ch->remote_id = get_u32(rpayload + roff); roff += 4;
            ch->remote_window = get_u32(rpayload + roff); roff += 4;
            ch->remote_maxpkt = get_u32(rpayload + roff);
            return ch;
        }
        if (rpayload[0] == SSH_MSG_CHANNEL_OPEN_FAILURE) {
            free(ch);
            return NULL;
        }
        /* Skip banners, debug, etc */
    }

    free(ch);
    return NULL;
}

int rawssh_channel_exec(rawssh_channel *ch, const char *cmd) {
    rawssh_session *s = ch->session;

    unsigned char payload[2048];
    int off = 0;
    payload[off++] = SSH_MSG_CHANNEL_REQUEST;
    put_u32(payload + off, ch->remote_id); off += 4;
    put_cstring(payload, "exec", &off);
    payload[off++] = 1; /* want reply */
    put_cstring(payload, cmd, &off);

    int rc = send_packet(s, payload, off);
    if (rc < 0) return rc;

    /* Wait for channel success/failure */
    unsigned char rpayload[RAWSSH_MAX_PAYLOAD];
    int rplen;

    for (int i = 0; i < 20; i++) {
        rc = recv_packet(s, rpayload, &rplen);
        if (rc < 0) return rc;

        if (rpayload[0] == SSH_MSG_CHANNEL_SUCCESS) return RAWSSH_OK;
        if (rpayload[0] == SSH_MSG_CHANNEL_FAILURE) return RAWSSH_CHANNEL_FAIL;

        if (rpayload[0] == SSH_MSG_CHANNEL_WINDOW_ADJUST) continue;

        if (rpayload[0] == SSH_MSG_CHANNEL_DATA) {
            /* Buffer the data */
            int doff = 1;
            doff += 4; /* recipient channel */
            const unsigned char *data;
            uint32_t dlen;
            if (get_string(rpayload, rplen, &doff, &data, &dlen) == 0) {
                int space = sizeof(ch->data_buf) - ch->data_len;
                int copy = dlen < (uint32_t)space ? dlen : space;
                memcpy(ch->data_buf + ch->data_len, data, copy);
                ch->data_len += copy;
            }
            continue;
        }

        if (rpayload[0] == SSH_MSG_CHANNEL_EOF) { ch->eof = 1; continue; }
        if (rpayload[0] == SSH_MSG_CHANNEL_CLOSE) { ch->closed = 1; return RAWSSH_OK; }
    }

    return RAWSSH_OK;
}

int rawssh_channel_read(rawssh_channel *ch, char *buf, int len) {
    rawssh_session *s = ch->session;

    /* First return any buffered data */
    if (ch->data_pos < ch->data_len) {
        int avail = ch->data_len - ch->data_pos;
        int copy = avail < len ? avail : len;
        memcpy(buf, ch->data_buf + ch->data_pos, copy);
        ch->data_pos += copy;
        return copy;
    }

    if (ch->eof || ch->closed) return 0;

    /* Try to read more packets */
    for (int i = 0; i < 50; i++) {
        unsigned char rpayload[RAWSSH_MAX_PAYLOAD];
        int rplen;

        /* Quick timeout check */
        struct pollfd pf = {s->sock, POLLIN, 0};
        int pr = poll(&pf, 1, s->timeout_sec * 1000);
        if (pr <= 0) return 0;

        int rc = recv_packet(s, rpayload, &rplen);
        if (rc < 0) return 0;

        if (rpayload[0] == SSH_MSG_CHANNEL_DATA) {
            int doff = 1;
            doff += 4;
            const unsigned char *data;
            uint32_t dlen;
            if (get_string(rpayload, rplen, &doff, &data, &dlen) == 0) {
                int copy = dlen < (uint32_t)len ? dlen : len;
                memcpy(buf, data, copy);
                return copy;
            }
        }

        if (rpayload[0] == SSH_MSG_CHANNEL_EOF) { ch->eof = 1; return 0; }
        if (rpayload[0] == SSH_MSG_CHANNEL_CLOSE) { ch->closed = 1; return 0; }
        if (rpayload[0] == SSH_MSG_CHANNEL_WINDOW_ADJUST) continue;
    }

    return 0;
}

void rawssh_channel_close(rawssh_channel *ch) {
    if (!ch || ch->closed) return;
    rawssh_session *s = ch->session;

    unsigned char payload[16];
    int off = 0;
    payload[off++] = SSH_MSG_CHANNEL_CLOSE;
    put_u32(payload + off, ch->remote_id);
    off += 4;

    send_packet(s, payload, off);
    ch->closed = 1;

    /* Drain pending close from server - fast timeout for brute force */
    for (int i = 0; i < 3; i++) {
        struct pollfd pf = {s->sock, POLLIN, 0};
        if (poll(&pf, 1, 100) <= 0) break;

        unsigned char rpayload[RAWSSH_MAX_PAYLOAD];
        int rplen;
        int rc = recv_packet(s, rpayload, &rplen);
        if (rc < 0) break;
        if (rpayload[0] == SSH_MSG_CHANNEL_CLOSE) break;
    }
}

void rawssh_channel_free(rawssh_channel *ch) {
    free(ch);
}

const char *rawssh_error_str(int err) {
    switch (err) {
        case RAWSSH_OK:             return "OK";
        case RAWSSH_ERROR:          return "Generic error";
        case RAWSSH_TIMEOUT:        return "Timeout";
        case RAWSSH_TCP_ERROR:      return "TCP error";
        case RAWSSH_HANDSHAKE_FAIL: return "Handshake failed";
        case RAWSSH_AUTH_FAIL:      return "Auth failed";
        case RAWSSH_ALLOC_FAIL:     return "Allocation failed";
        case RAWSSH_CHANNEL_FAIL:   return "Channel failed";
        case RAWSSH_PROTO_ERROR:    return "Protocol error";
        case RAWSSH_CLOSED:         return "Connection closed";
        default:                    return "Unknown error";
    }
}

int rawssh_get_sock(rawssh_session *s) {
    return s ? s->sock : -1;
}
