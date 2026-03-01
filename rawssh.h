/*
 * rawssh.h - Biblioteca SSH2 propria, thread-safe, alta performance
 * Implementa RFC 4253 (Transport), RFC 4252 (Auth), RFC 4254 (Connection)
 * Usa OpenSSL para criptografia (thread-safe nativo)
 * Suporte a binding direto na NIC para maximo throughput
 */
#ifndef RAWSSH_H
#define RAWSSH_H

#include <stdint.h>
#include <stddef.h>

/* Error codes */
#define RAWSSH_OK              0
#define RAWSSH_ERROR          -1
#define RAWSSH_TIMEOUT        -2
#define RAWSSH_TCP_ERROR      -3
#define RAWSSH_HANDSHAKE_FAIL -4
#define RAWSSH_AUTH_FAIL      -5
#define RAWSSH_ALLOC_FAIL     -6
#define RAWSSH_CHANNEL_FAIL   -7
#define RAWSSH_PROTO_ERROR    -8
#define RAWSSH_CLOSED         -9

/* SSH message types (RFC 4253) */
#define SSH_MSG_DISCONNECT        1
#define SSH_MSG_IGNORE            2
#define SSH_MSG_UNIMPLEMENTED     3
#define SSH_MSG_DEBUG             4
#define SSH_MSG_SERVICE_REQUEST   5
#define SSH_MSG_SERVICE_ACCEPT    6
#define SSH_MSG_KEXINIT          20
#define SSH_MSG_NEWKEYS          21
#define SSH_MSG_KEXDH_INIT       30
#define SSH_MSG_KEXDH_REPLY      31

/* SSH message types (RFC 4252 - User Auth) */
#define SSH_MSG_USERAUTH_REQUEST      50
#define SSH_MSG_USERAUTH_FAILURE      51
#define SSH_MSG_USERAUTH_SUCCESS      52
#define SSH_MSG_USERAUTH_BANNER       53

/* SSH message types (RFC 4254 - Connection) */
#define SSH_MSG_GLOBAL_REQUEST        80
#define SSH_MSG_CHANNEL_OPEN          90
#define SSH_MSG_CHANNEL_OPEN_CONFIRM  91
#define SSH_MSG_CHANNEL_OPEN_FAILURE  92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST 93
#define SSH_MSG_CHANNEL_DATA          94
#define SSH_MSG_CHANNEL_EOF           96
#define SSH_MSG_CHANNEL_CLOSE         97
#define SSH_MSG_CHANNEL_REQUEST       98
#define SSH_MSG_CHANNEL_SUCCESS       99
#define SSH_MSG_CHANNEL_FAILURE      100

/* Buffer sizes */
#define RAWSSH_MAX_PACKET    16384
#define RAWSSH_MAX_PAYLOAD   8192
#define RAWSSH_BLOCK_SIZE    16
#define RAWSSH_IV_SIZE       16
#define RAWSSH_KEY_SIZE      32
#define RAWSSH_MAC_SIZE      32
#define RAWSSH_HASH_SIZE     32

/* Forward declarations */
typedef struct rawssh_session rawssh_session;
typedef struct rawssh_channel rawssh_channel;

/* Global init/cleanup - call once */
int rawssh_global_init(void);
void rawssh_global_cleanup(void);

/* Session management - each session is independent and thread-safe */
rawssh_session *rawssh_session_new(void);
void rawssh_session_free(rawssh_session *s);

/* Configuration */
void rawssh_set_timeout(rawssh_session *s, int timeout_sec);
void rawssh_bind_nic(rawssh_session *s, const char *iface_name);

/* Connection */
int rawssh_connect(rawssh_session *s, const char *host, int port);
int rawssh_handshake(rawssh_session *s);
int rawssh_auth_password(rawssh_session *s, const char *user, const char *pass);
void rawssh_disconnect(rawssh_session *s);

/* Channel operations */
rawssh_channel *rawssh_channel_open(rawssh_session *s);
int rawssh_channel_exec(rawssh_channel *ch, const char *cmd);
int rawssh_channel_read(rawssh_channel *ch, char *buf, int len);
void rawssh_channel_close(rawssh_channel *ch);
void rawssh_channel_free(rawssh_channel *ch);

/* Utility */
const char *rawssh_error_str(int err);
int rawssh_get_sock(rawssh_session *s);

#endif /* RAWSSH_H */
