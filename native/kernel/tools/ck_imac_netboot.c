/* ck_imac_netboot.c -- host side of the AIENOS lab netboot (NETLDR.EFI on the
 * iMac; wire format native/boot/netboot_proto.h). Hosted C (POSIX sockets),
 * tooling only, never in an image. No Python, no outside libraries: Ed25519
 * and SHA-512 are native/sig.
 *
 *   ck_imac_netboot keygen KEY PUB    new lab signing key: KEY = 32-byte seed
 *                                     (created 0600, never overwritten), PUB =
 *                                     "owner_root_ed25519 <hex>" for
 *                                     make imac-netldr CK_NETLDR_KEYS=PUB
 *   ck_imac_netboot pubkey KEY        print the public key (64 hex)
 *   ck_imac_netboot sign KEY TBS SIG  Ed25519 over the to-be-signed bytes
 *                                     (ck_slot_tool tbs) -> 64-byte SIG
 *   ck_imac_netboot serve SPOOL [--bcast A.B.C.D] [--mac M] [--seconds N]
 *                                     [--qemu-dgram LOCALPORT:REMOTEPORT]
 *
 * serve answers NETLDR. A job is SPOOL/next.job: a signed slot manifest
 * (CK_SLOT_UNIT bytes) followed by the image; write it elsewhere and rename()
 * it in. On a HELLO the job moves to SPOOL/serving.job and is offered; the
 * loader's DONE moves it to SPOOL/booted-<time>.job (status 0, verified) or
 * SPOOL/refused-<time>.job (status 1). With no job every HELLO gets WAIT, so
 * the iMac sits in its loader until the next job arrives. One line per event
 * goes to stdout. This tool never signs or checks what it serves: the loader
 * verifies every byte against its built-in key, so a bad job is refused there.
 *
 * Transports: UDP (default) binds 0.0.0.0:NB_PORT_SERVER and answers to the
 * broadcast address --bcast (default 255.255.255.255) port NB_PORT_LOADER.
 * --qemu-dgram speaks raw Ethernet frames over a UDP pair on 127.0.0.1, the
 * QEMU "-netdev dgram" backend, so the QEMU test runs the real loader without
 * root or a tap device. --mac answers only HELLOs from that address.
 * Exit 0 at --seconds, 2 usage, 3 socket or file error. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "aienos_net.h"
#include "aienos_sig.h"
#include "netboot_proto.h"

#define MANIFEST_BYTES 4096u /* CK_SLOT_UNIT (slot_format.h) */
#define TBS_BYTES 448u       /* CK_SLOT_TBS_BYTES */
#define WAIT_S 5u

static int usage(void)
{
    fprintf(stderr, "usage: ck_imac_netboot keygen KEY PUB | pubkey KEY | sign KEY TBS SIG |\n"
                    "       serve SPOOL [--bcast A.B.C.D] [--mac xx:xx:xx:xx:xx:xx] [--seconds N]\n"
                    "             [--qemu-dgram LOCALPORT:REMOTEPORT]\n");
    return 2;
}

static void hex(const uint8_t *b, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = 0;
}

static int read_exact(const char *path, uint8_t *b, size_t n)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, b + got, n - got);
        if (r <= 0)
            break;
        got += (size_t)r;
    }
    uint8_t extra;
    int more = read(fd, &extra, 1) > 0;
    close(fd);
    return got == n && !more ? 0 : -1;
}

static int write_new(const char *path, const void *b, size_t n, mode_t mode, int excl)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC | (excl ? O_EXCL : O_TRUNC), mode);
    if (fd < 0)
        return -1;
    int ok = write(fd, b, n) == (ssize_t)n;
    return close(fd) == 0 && ok ? 0 : -1;
}

static int load_key(const char *path, uint8_t sk[32])
{
    struct stat st;
    if (stat(path, &st) != 0 || (st.st_mode & 077) != 0) {
        fprintf(stderr, "ck_imac_netboot: %s must exist and be readable by its owner only (0600)\n", path);
        return -1;
    }
    if (read_exact(path, sk, 32) != 0) {
        fprintf(stderr, "ck_imac_netboot: %s is not a 32-byte key\n", path);
        return -1;
    }
    return 0;
}

static int cmd_keygen(const char *key, const char *pub)
{
    uint8_t sk[32], pk[32];
    char h[65], text[160];
    if (getrandom(sk, sizeof sk, 0) != (ssize_t)sizeof sk || aienos_ed25519_public_key(pk, sk) != AIENOS_SIG_OK) {
        fprintf(stderr, "ck_imac_netboot: no randomness or key derivation failed\n");
        return 3;
    }
    if (write_new(key, sk, sizeof sk, 0600, 1) != 0) {
        fprintf(stderr, "ck_imac_netboot: cannot create %s (%s); an existing key is never overwritten\n", key,
                strerror(errno));
        memset(sk, 0, sizeof sk);
        return 3;
    }
    memset(sk, 0, sizeof sk);
    hex(pk, 32, h);
    int n = snprintf(text, sizeof text, "# AIENOS lab netboot key (iMac NETLDR.EFI), public half\nowner_root_ed25519 %s\n", h);
    if (write_new(pub, text, (size_t)n, 0644, 0) != 0) {
        fprintf(stderr, "ck_imac_netboot: cannot write %s\n", pub);
        return 3;
    }
    printf("keygen: public key %s\n", h);
    return 0;
}

static int cmd_pubkey(const char *key)
{
    uint8_t sk[32], pk[32];
    char h[65];
    if (load_key(key, sk) != 0)
        return 3;
    int rc = aienos_ed25519_public_key(pk, sk);
    memset(sk, 0, sizeof sk);
    if (rc != AIENOS_SIG_OK)
        return 3;
    hex(pk, 32, h);
    printf("%s\n", h);
    return 0;
}

static int cmd_sign(const char *key, const char *tbs, const char *out)
{
    uint8_t sk[32], msg[TBS_BYTES], sig[64];
    if (load_key(key, sk) != 0)
        return 3;
    if (read_exact(tbs, msg, sizeof msg) != 0) {
        memset(sk, 0, sizeof sk);
        fprintf(stderr, "ck_imac_netboot: %s is not %u to-be-signed bytes\n", tbs, TBS_BYTES);
        return 3;
    }
    int rc = aienos_ed25519_sign(sig, msg, sizeof msg, sk);
    memset(sk, 0, sizeof sk);
    if (rc != AIENOS_SIG_OK || write_new(out, sig, sizeof sig, 0644, 0) != 0) {
        fprintf(stderr, "ck_imac_netboot: signing failed\n");
        return 3;
    }
    printf("sign: %s\n", out);
    return 0;
}

/* ---- serve ------------------------------------------------------------------ */
static int sock = -1, dgram = 0;
static struct sockaddr_in peer;
static const uint8_t host_mac[6] = {0x52, 0x54, 0x00, 0x4e, 0x42, 0x01};

static void logf_(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void logf_(const char *fmt, ...)
{
    char ts[32];
    time_t t = time(0);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &tm);
    printf("%s ", ts);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

static void send_msg(const struct nb_msg *m)
{
    uint8_t msg[NB_MSG_MAX];
    size_t n = nb_build(m, msg, sizeof msg);
    if (!n)
        return;
    if (!dgram) {
        sendto(sock, msg, n, 0, (struct sockaddr *)&peer, sizeof peer);
        return;
    }
    static uint8_t udp[8 + NB_MSG_MAX], ip[20 + sizeof udp], fr[14 + sizeof ip];
    const net_ipv4 any = {{0, 0, 0, 0}}, bcast = {{255, 255, 255, 255}};
    net_udp_header uh = {NB_PORT_SERVER, NB_PORT_LOADER};
    net_ipv4_header ih = {0, 0, 1, NET_IPPROTO_UDP, any, bcast};
    net_eth_frame e;
    size_t uw, iw, ew;
    if (net_udp_build(&uh, msg, n, any, bcast, udp, sizeof udp, &uw) != NET_OK ||
        net_ipv4_build(&ih, udp, uw, ip, sizeof ip, &iw) != NET_OK)
        return;
    memset(e.destination.b, 0xff, 6);
    memcpy(e.source.b, host_mac, 6);
    e.ethertype = NET_ETHERTYPE_IPV4;
    e.payload = ip;
    e.payload_len = iw;
    if (net_eth_build(&e, fr, sizeof fr, &ew) == NET_OK)
        sendto(sock, fr, ew, 0, (struct sockaddr *)&peer, sizeof peer);
}

/* Receive one netboot message (payload view into buf). 0 or -1. */
static int recv_msg(uint8_t *buf, size_t cap, struct nb_msg *m)
{
    ssize_t n = recv(sock, buf, cap, 0);
    if (n <= 0)
        return -1;
    if (!dgram)
        return nb_parse(buf, (size_t)n, m);
    net_eth_frame e;
    net_ipv4_header ih;
    net_udp_header uh;
    const uint8_t *ipp, *up;
    size_t ipn, un;
    if (net_eth_parse(buf, (size_t)n, &e) != NET_OK || e.ethertype != NET_ETHERTYPE_IPV4 ||
        net_ipv4_parse(e.payload, e.payload_len, &ih, &ipp, &ipn) != NET_OK || ih.protocol != NET_IPPROTO_UDP ||
        net_udp_parse(ipp, ipn, ih.source, ih.destination, &uh, &up, &un) != NET_OK ||
        uh.destination_port != NB_PORT_SERVER || uh.source_port != NB_PORT_LOADER)
        return -1;
    return nb_parse(up, un, m);
}

static uint8_t *job;
static uint32_t job_len;
static uint8_t job_nonce[16];
static int job_offered;
/* Chunks sent at least once to the current nonce. A loader that got every chunk and
 * then asks again with a new nonce without a DONE we heard has finished that transfer:
 * the job is retired as unconfirmed, never offered again (no restart loop on one lost DONE). */
static uint8_t *served;
static uint32_t served_n;

static void served_reset(void)
{
    free(served);
    served = job ? calloc(1, nb_chunks(job_len) / 8 + 1) : 0;
    served_n = 0;
}

static int load_job(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return -1;
    if (st.st_size < (off_t)NB_OBJECT_MIN || st.st_size > (off_t)NB_OBJECT_MAX) {
        logf_("job %s refused here: %lld bytes is outside %u..%u", path, (long long)st.st_size, NB_OBJECT_MIN,
              NB_OBJECT_MAX);
        return -1;
    }
    uint8_t *b = malloc((size_t)st.st_size);
    if (!b || read_exact(path, b, (size_t)st.st_size) != 0) {
        free(b);
        logf_("job %s unreadable", path);
        return -1;
    }
    free(job);
    job = b;
    job_len = (uint32_t)st.st_size;
    job_offered = 0;
    served_reset();
    return 0;
}

static void retire_job(const char *spool, const char *how)
{
    char from[4096], to[4096];
    snprintf(from, sizeof from, "%s/serving.job", spool);
    snprintf(to, sizeof to, "%s/%s-%lld.job", spool, how, (long long)time(0));
    rename(from, to);
    free(job);
    job = 0;
    job_len = 0;
    job_offered = 0;
    served_reset();
}

static int parse_mac(const char *s, uint8_t mac[6])
{
    unsigned v[6];
    if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac[i] = (uint8_t)v[i];
    return 0;
}

static int cmd_serve(int argc, char **argv)
{
    const char *spool = argv[2], *bcast = "255.255.255.255", *qd = 0;
    uint8_t only_mac[6];
    int have_mac = 0;
    long seconds = 0;
    for (int i = 3; i < argc; i++) {
        if (i + 1 >= argc)
            return usage();
        if (strcmp(argv[i], "--bcast") == 0)
            bcast = argv[++i];
        else if (strcmp(argv[i], "--mac") == 0 && parse_mac(argv[i + 1], only_mac) == 0)
            have_mac = 1, i++;
        else if (strcmp(argv[i], "--seconds") == 0)
            seconds = strtol(argv[++i], 0, 10);
        else if (strcmp(argv[i], "--qemu-dgram") == 0)
            qd = argv[++i];
        else
            return usage();
    }
    char next[4096], serving[4096];
    snprintf(next, sizeof next, "%s/next.job", spool);
    snprintf(serving, sizeof serving, "%s/serving.job", spool);

    struct sockaddr_in me = {0};
    me.sin_family = AF_INET;
    peer.sin_family = AF_INET;
    if (qd) {
        unsigned lp, rp;
        if (sscanf(qd, "%u:%u", &lp, &rp) != 2 || !lp || lp > 65535 || !rp || rp > 65535)
            return usage();
        dgram = 1;
        me.sin_port = htons((uint16_t)lp);
        me.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        peer.sin_port = htons((uint16_t)rp);
        peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else {
        me.sin_port = htons(NB_PORT_SERVER);
        me.sin_addr.s_addr = htonl(INADDR_ANY);
        peer.sin_port = htons(NB_PORT_LOADER);
        if (inet_pton(AF_INET, bcast, &peer.sin_addr) != 1)
            return usage();
    }
    int one = 1;
    sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0 || setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0 ||
        (!dgram && setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &one, sizeof one) != 0) ||
        bind(sock, (struct sockaddr *)&me, sizeof me) != 0) {
        fprintf(stderr, "ck_imac_netboot: socket/bind: %s\n", strerror(errno));
        return 3;
    }
    if (load_job(serving) == 0)
        logf_("resuming %s (%u bytes)", serving, job_len);
    logf_("serving spool=%s transport=%s answer_to=%s:%u", spool, dgram ? "qemu-dgram" : "udp",
          dgram ? "127.0.0.1" : bcast, dgram ? (unsigned)ntohs(peer.sin_port) : NB_PORT_LOADER);

    time_t end = seconds > 0 ? time(0) + seconds : 0;
    uint8_t buf[2048];
    while (!end || time(0) < end) {
        struct pollfd p = {sock, POLLIN, 0};
        if (poll(&p, 1, 500) <= 0)
            continue;
        struct nb_msg m, r = {0};
        if (recv_msg(buf, sizeof buf, &m) != 0)
            continue;
        memcpy(r.nonce, m.nonce, 16);
        if (m.type == NB_HELLO) {
            if (have_mac && memcmp(m.mac, only_mac, 6) != 0)
                continue;
            if (job && job_offered && memcmp(job_nonce, m.nonce, 16) != 0 && served_n == nb_chunks(job_len)) {
                logf_("the loader got every chunk but no DONE was heard; retired as unconfirmed");
                retire_job(spool, "unconfirmed");
            }
            if (!job && rename(next, serving) == 0 && load_job(serving) == 0)
                logf_("queued job picked up (%u bytes)", job_len);
            if (job) {
                if (!job_offered || memcmp(job_nonce, m.nonce, 16) != 0)
                    logf_("offer %u bytes to %02x:%02x:%02x:%02x:%02x:%02x", job_len, m.mac[0], m.mac[1], m.mac[2],
                          m.mac[3], m.mac[4], m.mac[5]);
                if (!job_offered || memcmp(job_nonce, m.nonce, 16) != 0)
                    served_reset();
                memcpy(job_nonce, m.nonce, 16);
                job_offered = 1;
                r.type = NB_OFFER;
                r.total = job_len;
            } else {
                r.type = NB_WAIT;
                r.seconds = WAIT_S;
            }
            send_msg(&r);
        } else if (m.type == NB_GET && job && job_offered && memcmp(job_nonce, m.nonce, 16) == 0) {
            for (uint32_t i = 0; i < m.count; i++) {
                uint64_t off = (uint64_t)m.offset + (uint64_t)i * NB_CHUNK;
                if (off >= job_len)
                    break;
                r.type = NB_DATA;
                r.offset = (uint32_t)off;
                r.len = (uint16_t)(job_len - off < NB_CHUNK ? job_len - off : NB_CHUNK);
                r.data = job + off;
                uint32_t c = (uint32_t)(off / NB_CHUNK);
                if (served && !(served[c / 8] & (1u << (c % 8)))) {
                    served[c / 8] |= (uint8_t)(1u << (c % 8));
                    served_n++;
                }
                send_msg(&r);
            }
        } else if (m.type == NB_DONE && job && job_offered && memcmp(job_nonce, m.nonce, 16) == 0) {
            char text[NB_TEXT_MAX + 1];
            memcpy(text, m.data, m.len);
            text[m.len] = 0;
            logf_("loader says: %s (%s)", m.status == 0 ? "VERIFIED, starting" : "REFUSED", text);
            retire_job(spool, m.status == 0 ? "booted" : "refused");
        }
    }
    logf_("serve: deadline reached");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "keygen") == 0)
        return cmd_keygen(argv[2], argv[3]);
    if (argc == 3 && strcmp(argv[1], "pubkey") == 0)
        return cmd_pubkey(argv[2]);
    if (argc == 5 && strcmp(argv[1], "sign") == 0)
        return cmd_sign(argv[2], argv[3], argv[4]);
    if (argc >= 3 && strcmp(argv[1], "serve") == 0)
        return cmd_serve(argc, argv);
    return usage();
}
