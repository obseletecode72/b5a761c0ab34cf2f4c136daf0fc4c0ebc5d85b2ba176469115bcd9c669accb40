/*
 * rawssh.c - Biblioteca SSH2 propria, thread-safe, alta performance
 * Implementa RFC 4253/4252/4254 sobre TCP com OpenSSL
 * Cada sessao e 100% independente - zero estado global compartilhado
 * Suporte a bind direto na NIC (SO_BINDTODEVICE)
 *
 * Algoritmos suportados:
 *   KEX: diffie-hellman-group14-sha256, diffie-hellman-group14-sha1
 *   Host key: ssh-rsa
 *   Cipher: aes128-ctr, aes256-ctr
 *   MAC: hmac-sha2-256, hmac-sha1
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

/* ========== Internal structures ========== */

/* Cipher state for one direction */
typedef struct {
    EVP_CIPHER_CTX *ctx;
    unsigned char key[RAWSSH_KEY_SIZE];
    unsigned char iv[RAWSSH_IV_SIZE];
    unsigned char mac_key[RAWSSH_KEY_SIZE];
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
    unsigned char session_id[RAWSSH_HASH_SIZE];
    int session_id_len;
    unsigned char exchange_hash[RAWSSH_HASH_SIZE];

    /* Crypto state */
    crypto_dir c2s; /* client to server */
    crypto_dir s2c; /* server to client */
    int encrypted;

    /* KEX algorithm selection */
    int use_sha256; /* 1 = SHA-256, 0 = SHA-1 */
    int cipher_key_len; /* 16 or 32 */

    /* Read buffer */
    unsigned char rbuf[RAWSSH_MAX_PACKET * 2];
    int rpos;
    int rlen;

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
    return poll(&pf, 1, timeout_ms);
}

static int raw_send(rawssh_session *s, const void *data, int len) {
    const unsigned char *p = data;
    int sent = 0;
    while (sent < len) {
        int r = sock_wait(s->sock, POLLOUT, s->timeout_sec * 1000);
        if (r <= 0) return RAWSSH_TIMEOUT;
        r = send(s->sock, p + sent, len - sent, MSG_NOSIGNAL);
        if (r <= 0) return RAWSSH_TCP_ERROR;
        sent += r;
    }
    return sent;
}

static int raw_recv(rawssh_session *s, void *data, int len) {
    unsigned char *p = data;
    int got = 0;
    while (got < len) {
        int r = sock_wait(s->sock, POLLIN, s->timeout_sec * 1000);
        if (r <= 0) return RAWSSH_TIMEOUT;
        r = recv(s->sock, p + got, len - got, 0);
        if (r <= 0) return RAWSSH_TCP_ERROR;
        got += r;
    }
    return got;
}

/* Read a line (for version exchange) */
static int read_line(rawssh_session *s, char *buf, int maxlen) {
    int pos = 0;
    while (pos < maxlen - 1) {
        int r = sock_wait(s->sock, POLLIN, s->timeout_sec * 1000);
        if (r <= 0) return RAWSSH_TIMEOUT;
        char c;
        r = recv(s->sock, &c, 1, 0);
        if (r <= 0) return RAWSSH_TCP_ERROR;
        if (c == '\n') {
            if (pos > 0 && buf[pos - 1] == '\r') pos--;
            buf[pos] = 0;
            return pos;
        }
        buf[pos++] = c;
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
    s->c2s.seq++;
    return rc > 0 ? RAWSSH_OK : rc;
}

/* Send an encrypted SSH packet */
static int send_packet_encrypted(rawssh_session *s, const unsigned char *payload, int plen) {
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
        if (s->use_sha256) {
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
    int outl = 0;
    EVP_EncryptUpdate(s->c2s.ctx, enc, &outl, plain, total);
    free(plain);

    /* Send encrypted data + MAC */
    int rc = raw_send(s, enc, total);
    free(enc);
    if (rc < 0) return rc;

    if (mac_len > 0) {
        rc = raw_send(s, mac, mac_len);
        if (rc < 0) return rc;
    }

    s->c2s.seq++;
    return RAWSSH_OK;
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

/* Receive an encrypted SSH packet */
static int recv_packet_encrypted(rawssh_session *s, unsigned char *payload, int *plen) {
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
        if (s->use_sha256) {
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

static int recv_packet(rawssh_session *s, unsigned char *payload, int *plen) {
    if (s->encrypted)
        return recv_packet_encrypted(s, payload, plen);
    else
        return recv_packet_plain(s, payload, plen);
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

/* Build KEXINIT packet */
static int build_kexinit(rawssh_session *s) {
    unsigned char payload[2048];
    int off = 0;

    payload[off++] = SSH_MSG_KEXINIT;

    /* 16 bytes cookie */
    RAND_bytes(payload + off, 16);
    off += 16;

    /* kex_algorithms */
    put_cstring(payload, "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1", &off);
    /* server_host_key_algorithms */
    put_cstring(payload, "ssh-rsa,rsa-sha2-256,rsa-sha2-512", &off);
    /* encryption_algorithms_client_to_server */
    put_cstring(payload, "aes128-ctr,aes256-ctr,aes128-cbc,aes256-cbc", &off);
    /* encryption_algorithms_server_to_client */
    put_cstring(payload, "aes128-ctr,aes256-ctr,aes128-cbc,aes256-cbc", &off);
    /* mac_algorithms_client_to_server */
    put_cstring(payload, "hmac-sha2-256,hmac-sha1", &off);
    /* mac_algorithms_server_to_client */
    put_cstring(payload, "hmac-sha2-256,hmac-sha1", &off);
    /* compression_algorithms_client_to_server */
    put_cstring(payload, "none", &off);
    /* compression_algorithms_server_to_client */
    put_cstring(payload, "none", &off);
    /* languages_client_to_server */
    put_cstring(payload, "", &off);
    /* languages_server_to_client */
    put_cstring(payload, "", &off);
    /* first_kex_packet_follows */
    payload[off++] = 0;
    /* reserved */
    put_u32(payload + off, 0);
    off += 4;

    /* Save for hash computation */
    s->my_kexinit = malloc(off);
    memcpy(s->my_kexinit, payload, off);
    s->my_kexinit_len = off;

    return send_packet(s, payload, off);
}

/* Find first matching algorithm from comma-separated lists */
static int find_match(const char *client, const char *server, char *out, int outlen) {
    char *ccopy = strdup(client);
    char *tok = strtok(ccopy, ",");
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
        tok = strtok(NULL, ",");
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
    char chosen_kex[64], chosen_cipher[64], chosen_mac[64];

    if (find_match("diffie-hellman-group14-sha256,diffie-hellman-group14-sha1",
                   server_kex, chosen_kex, sizeof(chosen_kex)) < 0)
        return RAWSSH_PROTO_ERROR;

    s->use_sha256 = (strstr(chosen_kex, "sha256") != NULL);

    if (find_match("aes128-ctr,aes256-ctr,aes128-cbc,aes256-cbc",
                   server_enc_c2s, chosen_cipher, sizeof(chosen_cipher)) < 0)
        return RAWSSH_PROTO_ERROR;

    /* Determine key length from cipher */
    if (strstr(chosen_cipher, "aes256"))
        s->cipher_key_len = 32;
    else
        s->cipher_key_len = 16;

    if (find_match("hmac-sha2-256,hmac-sha1",
                   server_mac_c2s, chosen_mac, sizeof(chosen_mac)) < 0)
        return RAWSSH_PROTO_ERROR;

    return RAWSSH_OK;
}

/* Derive a key using the SSH key derivation (RFC 4253 Section 7.2) */
static void derive_key(rawssh_session *s, char id, int need,
                       unsigned char *out) {
    const EVP_MD *md = s->use_sha256 ? EVP_sha256() : EVP_sha1();
    int hash_len = EVP_MD_size(md);

    /* K (as mpint) */
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

    /* If we need more bytes, keep hashing */
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

/* Compute exchange hash H */
static int compute_exchange_hash(rawssh_session *s,
                                  const unsigned char *k_s, int k_s_len,
                                  const BIGNUM *e, const BIGNUM *f,
                                  const BIGNUM *k) {
    const EVP_MD *md = s->use_sha256 ? EVP_sha256() : EVP_sha1();
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);

    /* V_C (client version) */
    int off = 0;
    unsigned char tmp[8192];
    put_cstring(tmp, s->client_version, &off);
    EVP_DigestUpdate(ctx, tmp, off);

    /* V_S (server version) */
    off = 0;
    put_cstring(tmp, s->server_version, &off);
    EVP_DigestUpdate(ctx, tmp, off);

    /* I_C (client KEXINIT) */
    off = 0;
    put_u32(tmp, s->my_kexinit_len);
    off = 4;
    EVP_DigestUpdate(ctx, tmp, 4);
    EVP_DigestUpdate(ctx, s->my_kexinit, s->my_kexinit_len);

    /* I_S (server KEXINIT) */
    put_u32(tmp, s->peer_kexinit_len);
    EVP_DigestUpdate(ctx, tmp, 4);
    EVP_DigestUpdate(ctx, s->peer_kexinit, s->peer_kexinit_len);

    /* K_S (host key) */
    off = 0;
    put_string(tmp, k_s, k_s_len, &off);
    EVP_DigestUpdate(ctx, tmp, off);

    /* e (client DH public) */
    off = 0;
    put_mpint(tmp, e, &off);
    EVP_DigestUpdate(ctx, tmp, off);

    /* f (server DH public) */
    off = 0;
    put_mpint(tmp, f, &off);
    EVP_DigestUpdate(ctx, tmp, off);

    /* K (shared secret) */
    off = 0;
    put_mpint(tmp, k, &off);
    EVP_DigestUpdate(ctx, tmp, off);

    unsigned int hlen;
    EVP_DigestFinal_ex(ctx, s->exchange_hash, &hlen);
    EVP_MD_CTX_free(ctx);

    s->session_id_len = hlen;
    if (!s->session_id[0] && !s->session_id[1]) {
        /* First KEX - set session id */
        memcpy(s->session_id, s->exchange_hash, hlen);
    }

    return RAWSSH_OK;
}

/* Perform DH key exchange - group14 */
static int do_kex_dh(rawssh_session *s) {
    /* Initialize DH parameters - group 14 */
    s->dh_p = BN_new();
    s->dh_g = BN_new();
    s->dh_x = BN_new();
    s->dh_e = BN_new();

    BN_hex2bn(&s->dh_p, dh_group14_p_hex);
    BN_set_word(s->dh_g, 2);

    /* Generate private key x (random, 256 bits) */
    BN_rand(s->dh_x, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);

    /* Compute e = g^x mod p */
    BN_CTX *bnctx = BN_CTX_new();
    BN_mod_exp(s->dh_e, s->dh_g, s->dh_x, s->dh_p, bnctx);

    /* Send SSH_MSG_KEXDH_INIT */
    unsigned char payload[1024];
    int off = 0;
    payload[off++] = SSH_MSG_KEXDH_INIT;
    put_mpint(payload, s->dh_e, &off);

    int rc = send_packet(s, payload, off);
    if (rc < 0) { BN_CTX_free(bnctx); return rc; }

    /* Receive SSH_MSG_KEXDH_REPLY */
    unsigned char rpayload[RAWSSH_MAX_PAYLOAD];
    int rplen;
    rc = recv_packet(s, rpayload, &rplen);
    if (rc < 0) { BN_CTX_free(bnctx); return rc; }
    if (rpayload[0] != SSH_MSG_KEXDH_REPLY) { BN_CTX_free(bnctx); return RAWSSH_PROTO_ERROR; }

    /* Parse: K_S (host key), f (server DH public), signature */
    off = 1;
    const unsigned char *k_s_data;
    uint32_t k_s_len;
    if (get_string(rpayload, rplen, &off, &k_s_data, &k_s_len) < 0) {
        BN_CTX_free(bnctx);
        return RAWSSH_PROTO_ERROR;
    }

    const unsigned char *f_data;
    uint32_t f_len;
    if (get_string(rpayload, rplen, &off, &f_data, &f_len) < 0) {
        BN_CTX_free(bnctx);
        return RAWSSH_PROTO_ERROR;
    }

    /* Parse f as BIGNUM */
    s->dh_f = BN_new();
    BN_bin2bn(f_data, f_len, s->dh_f);

    /* Skip signature (we don't verify host key for brute force) */

    /* Compute shared secret K = f^x mod p */
    s->dh_k = BN_new();
    BN_mod_exp(s->dh_k, s->dh_f, s->dh_x, s->dh_p, bnctx);
    BN_CTX_free(bnctx);

    /* Compute exchange hash */
    rc = compute_exchange_hash(s, k_s_data, k_s_len, s->dh_e, s->dh_f, s->dh_k);
    if (rc < 0) return rc;

    /* Send SSH_MSG_NEWKEYS */
    unsigned char nk = SSH_MSG_NEWKEYS;
    rc = send_packet(s, &nk, 1);
    if (rc < 0) return rc;

    /* Receive SSH_MSG_NEWKEYS */
    rc = recv_packet(s, rpayload, &rplen);
    if (rc < 0) return rc;
    if (rpayload[0] != SSH_MSG_NEWKEYS) return RAWSSH_PROTO_ERROR;

    /* Derive keys */
    int kl = s->cipher_key_len;
    int bl = 16; /* AES block size */
    int mac_kl = s->use_sha256 ? 32 : 20;

    /* IV client to server */
    derive_key(s, 'A', bl, s->c2s.iv);
    /* IV server to client */
    derive_key(s, 'B', bl, s->s2c.iv);
    /* Encryption key c2s */
    derive_key(s, 'C', kl, s->c2s.key);
    /* Encryption key s2c */
    derive_key(s, 'D', kl, s->s2c.key);
    /* MAC key c2s */
    derive_key(s, 'E', mac_kl, s->c2s.mac_key);
    /* MAC key s2c */
    derive_key(s, 'F', mac_kl, s->s2c.mac_key);

    /* Initialize cipher contexts */
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

    /* CTR mode doesn't need padding */
    EVP_CIPHER_CTX_set_padding(s->c2s.ctx, 0);
    EVP_CIPHER_CTX_set_padding(s->s2c.ctx, 0);

    s->encrypted = 1;

    return RAWSSH_OK;
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

    /* Accept SSH_MSG_SERVICE_ACCEPT or SSH_MSG_USERAUTH_BANNER */
    while (rpayload[0] == SSH_MSG_DEBUG || rpayload[0] == SSH_MSG_IGNORE ||
           rpayload[0] == SSH_MSG_USERAUTH_BANNER) {
        rc = recv_packet(s, rpayload, &rplen);
        if (rc < 0) return rc;
    }

    if (rpayload[0] != SSH_MSG_SERVICE_ACCEPT) return RAWSSH_PROTO_ERROR;

    return RAWSSH_OK;
}

/* ========== Public API ========== */

int rawssh_global_init(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    return RAWSSH_OK;
}

void rawssh_global_cleanup(void) {
    EVP_cleanup();
    ERR_free_strings();
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

    /* Enable TCP keepalive */
    setsockopt(s->sock, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));

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

    /* Perform DH key exchange */
    rc = do_kex_dh(s);
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
    if (rc < 0) return rc;

    unsigned char rpayload[RAWSSH_MAX_PAYLOAD];
    int rplen;

    for (int i = 0; i < 10; i++) {
        rc = recv_packet(s, rpayload, &rplen);
        if (rc < 0) return rc;

        if (rpayload[0] == SSH_MSG_USERAUTH_SUCCESS) {
            s->authenticated = 1;
            return RAWSSH_OK;
        }
        if (rpayload[0] == SSH_MSG_USERAUTH_FAILURE) {
            return RAWSSH_AUTH_FAIL;
        }
        if (rpayload[0] == SSH_MSG_USERAUTH_BANNER ||
            rpayload[0] == SSH_MSG_DEBUG ||
            rpayload[0] == SSH_MSG_IGNORE) {
            continue;
        }
        if (rpayload[0] == SSH_MSG_DISCONNECT) {
            return RAWSSH_CLOSED;
        }
        /* Unknown message - skip */
    }

    return RAWSSH_AUTH_FAIL;
}

void rawssh_disconnect(rawssh_session *s) {
    if (s->sock < 0) return;

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

    unsigned char payload[RAWSSH_MAX_PAYLOAD];
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

    /* Drain pending close from server */
    for (int i = 0; i < 5; i++) {
        struct pollfd pf = {s->sock, POLLIN, 0};
        if (poll(&pf, 1, 500) <= 0) break;

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
