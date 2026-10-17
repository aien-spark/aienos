/* ck_imac_bsdp.c -- LAB-ONLY Apple NetBoot answerer for the 2017 iMac: lets the iMac start
 * NETLDR.EFI (native/boot/net_loader.c) straight from the Spark, with no stick, when it is
 * powered on with the N key held. Hosted C (POSIX sockets), tooling only. No Python.
 *
 * Two small servers in one process:
 *   BSDP (UDP 67)  Apple's Boot Service Discovery Protocol: DHCP INFORM packets with vendor
 *                  class "AAPLBSDPC/..." and BSDP sub-options in option 43. INFORM[LIST] is
 *                  answered with one image (AIENOS, the default); INFORM[SELECT] naming that
 *                  image and this server is answered with the boot file name and this
 *                  server's address (siaddr). Nothing else is answered: never DISCOVER or
 *                  REQUEST (the router stays the DHCP server), never another vendor class.
 *   TFTP (UDP 69)  read-only, one file: RRQ for BOOT_NAME (octet mode) gets the booter; the
 *                  blksize and tsize options (RFC 2348/2349) are honoured. Every other request
 *                  gets an error. Nothing is ever written.
 * Wire reference: Apple bootp project (bsdp.h, bootpd) as traced in "Analysis of the Use of
 * the Boot Server Discovery Protocol in NetBoot" (afp548): option 43 sub-options
 * 1 message type (1 LIST, 2 SELECT, 3 FAILED), 3 server id, 4 priority, 5 reply port,
 * 7 default image, 8 selected image, 9 image list (id[4] len[1] name), 130 machine name.
 * Answers are DHCP ACKs (also carrying subnet mask and router)
 * with option 60 "AAPLBSDPC" sent to the client's ciaddr, port 68 or its reply port.
 *
 * UNAUTHENTICATED: the iMac firmware runs whatever booter it is handed. Anyone on the LAN can
 * answer first. What makes this safe enough for the lab is the booter: NETLDR.EFI starts only
 * kernels signed with the lab key. A forged booter is not prevented here.
 *
 *   ck_imac_bsdp serve --booter FILE --server-ip A.B.C.D [--mac XX:..] [--bsdp-port N]
 *                      [--tftp-port N] [--seconds N]
 * --mac answers only that client. Ports 67/69 need CAP_NET_BIND_SERVICE (setcap) or root.
 * Log lines go to stdout with a UTC timestamp. Exit 0 at the deadline, 2 usage, 3 socket. */
#define _DEFAULT_SOURCE
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
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define BOOT_NAME "aienos/netldr.efi"
#define IMAGE_NAME "AIENOS"
/* Image id: install image (bit 31: the firmware fetches the booter and runs it, no network
 * disk), kind 1 (Mac OS X class) in bits 24..30, index 1 (< 4096: local to this server).
 * The working ISC/FOG Intel Mac configs all use the install bit. */
#define IMAGE_ID 0x81000001u
#define DHCP_MAGIC 0x63825363u
#define BOOTP_MIN 240
#define BLK_MAX 1428

static uint8_t *booter;
static size_t booter_len;
static struct in_addr server_ip, netmask, router;
static int also_bcast;
static uint8_t only_mac[6];
static int have_mac;

static void logf_(const char *fmt, ...)
{
    char ts[32];
    time_t t = time(0);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    va_list ap;
    va_start(ap, fmt);
    printf("%s ", ts);
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
}

static int bind_udp(uint16_t port, int bcast)
{
    int one = 1, s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (s < 0 || setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0 ||
        (bcast && setsockopt(s, SOL_SOCKET, SO_BROADCAST, &one, sizeof one) != 0) ||
        bind(s, (struct sockaddr *)&a, sizeof a) != 0) {
        fprintf(stderr, "ck_imac_bsdp: bind UDP %u: %s\n", port, strerror(errno));
        return -1;
    }
    return s;
}

/* ---- BSDP ---- */

/* Find DHCP option code in opts[0..n); returns its value and length, or 0. */
static const uint8_t *opt_find(const uint8_t *o, size_t n, uint8_t code, uint8_t *len)
{
    size_t i = 0;
    while (i < n) {
        uint8_t c = o[i];
        if (c == 255)
            break;
        if (c == 0) {
            i++;
            continue;
        }
        if (i + 2 > n || i + 2 + o[i + 1] > n)
            break;
        if (c == code) {
            *len = o[i + 1];
            return o + i + 2;
        }
        i += 2 + (size_t)o[i + 1];
    }
    return 0;
}

static size_t opt_put(uint8_t *p, size_t at, size_t cap, uint8_t code, const void *v, uint8_t len)
{
    if (at + 2u + len > cap)
        return cap + 1;
    p[at] = code;
    p[at + 1] = len;
    memcpy(p + at + 2, v, len);
    return at + 2u + len;
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void bsdp_packet(int s, const uint8_t *in, size_t n)
{
    if (n < BOOTP_MIN || in[0] != 1 || in[1] != 1 || in[2] != 6 || get32(in + 236) != DHCP_MAGIC)
        return;
    const uint8_t *opts = in + BOOTP_MIN, *v;
    size_t on = n - BOOTP_MIN;
    uint8_t l = 0;
    if (!(v = opt_find(opts, on, 53, &l)) || l != 1 || v[0] != 8) /* INFORM only */
        return;
    if (!(v = opt_find(opts, on, 60, &l)) || l < 10 || memcmp(v, "AAPLBSDPC/", 10) != 0)
        return;
    char vclass[64];
    snprintf(vclass, sizeof vclass, "%.*s", (int)l, (const char *)v);
    const uint8_t *mac = in + 28;
    if (have_mac && memcmp(mac, only_mac, 6) != 0)
        return;
    const uint8_t *vo = opt_find(opts, on, 43, &l);
    uint8_t vl = l, ml = 0, sl = 0, pl = 0;
    const uint8_t *mt = vo ? opt_find(vo, vl, 1, &ml) : 0;
    if (!mt || ml != 1)
        return;
    struct in_addr ci;
    memcpy(&ci.s_addr, in + 12, 4);
    if (ci.s_addr == 0)
        return;
    uint16_t port = 68;
    const uint8_t *rp = opt_find(vo, vl, 5, &pl);
    if (rp && pl == 2 && ((rp[0] << 8) | rp[1]) >= 1024)
        port = (uint16_t)((rp[0] << 8) | rp[1]);

    uint8_t out[576] = {0}, sub[255];
    size_t sn = 0, at = BOOTP_MIN;
    out[0] = 2;
    out[1] = 1;
    out[2] = 6;
    memcpy(out + 4, in + 4, 4);   /* xid */
    memcpy(out + 12, in + 12, 4); /* ciaddr */
    memcpy(out + 20, &server_ip.s_addr, 4);
    memcpy(out + 28, in + 28, 16); /* chaddr */
    put32(out + 236, DHCP_MAGIC);
    uint8_t ack = 5;
    at = opt_put(out, at, sizeof out, 53, &ack, 1);
    at = opt_put(out, at, sizeof out, 54, &server_ip.s_addr, 4);
    at = opt_put(out, at, sizeof out, 60, "AAPLBSDPC", 9);
    /* Subnet mask and router, as the ISC config known to boot Intel Macs forces into the
     * answer (its parameter list 1,3,17,43,60); the iMac only asked for 43 and 60. */
    at = opt_put(out, at, sizeof out, 1, &netmask.s_addr, 4);
    if (router.s_addr)
        at = opt_put(out, at, sizeof out, 3, &router.s_addr, 4);
    if (mt[0] == 1) { /* LIST */
        uint8_t id[4];
        put32(id, IMAGE_ID);
        sub[sn++] = 1, sub[sn++] = 1, sub[sn++] = 1;
        sub[sn++] = 4, sub[sn++] = 2, sub[sn++] = 0x80, sub[sn++] = 0x00;
        sub[sn++] = 7, sub[sn++] = 4, memcpy(sub + sn, id, 4), sn += 4;
        sub[sn++] = 9, sub[sn++] = (uint8_t)(5 + strlen(IMAGE_NAME));
        memcpy(sub + sn, id, 4), sn += 4;
        sub[sn++] = (uint8_t)strlen(IMAGE_NAME);
        memcpy(sub + sn, IMAGE_NAME, strlen(IMAGE_NAME)), sn += strlen(IMAGE_NAME);
        logf_("LIST from %s %02x:%02x:%02x:%02x:%02x:%02x (%s): offered image %s", inet_ntoa(ci), mac[0], mac[1],
              mac[2], mac[3], mac[4], mac[5], vclass, IMAGE_NAME);
    } else if (mt[0] == 2) { /* SELECT */
        const uint8_t *sel = opt_find(vo, vl, 8, &sl), *sid;
        uint8_t il = 0;
        if (!sel || sl != 4 || get32(sel) != IMAGE_ID)
            return;
        if ((sid = opt_find(vo, vl, 3, &il)) && (il != 4 || memcmp(sid, &server_ip.s_addr, 4) != 0))
            return; /* the client chose another server */
        sub[sn++] = 1, sub[sn++] = 1, sub[sn++] = 2;
        sub[sn++] = 8, sub[sn++] = 4, memcpy(sub + sn, sel, 4), sn += 4;
        sub[sn++] = 130, sub[sn++] = 6, memcpy(sub + sn, "AIENOS", 6), sn += 6; /* machine name */
        snprintf((char *)out + 44, 64, "spark");
        snprintf((char *)out + 108, 128, "%s", BOOT_NAME);
        char root[64];
        snprintf(root, sizeof root, "tftp:%s:/aienos/none", inet_ntoa(server_ip));
        at = opt_put(out, at, sizeof out, 17, root, (uint8_t)strlen(root));
        logf_("SELECT from %s %02x:%02x:%02x:%02x:%02x:%02x: boot file %s from %s", inet_ntoa(ci), mac[0], mac[1],
              mac[2], mac[3], mac[4], mac[5], BOOT_NAME, inet_ntoa(server_ip));
    } else {
        logf_("BSDP message type %u from %s ignored", mt[0], inet_ntoa(ci));
        return;
    }
    at = opt_put(out, at, sizeof out, 43, sub, (uint8_t)sn);
    if (at + 1 > sizeof out)
        return;
    out[at++] = 255;
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr = ci};
    if (sendto(s, out, at < 300 ? 300 : at, 0, (struct sockaddr *)&to, sizeof to) < 0)
        logf_("BSDP send to %s failed: %s", inet_ntoa(ci), strerror(errno));
    /* --also-broadcast: a second copy to everyone on the segment, for firmware that does not
     * take the unicast; other DHCP clients drop it (chaddr is the iMac's). */
    to.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    if (also_bcast && sendto(s, out, at < 300 ? 300 : at, 0, (struct sockaddr *)&to, sizeof to) < 0)
        logf_("BSDP broadcast copy failed: %s", strerror(errno));
}

/* ---- TFTP (read-only, one file) ---- */

static void tftp_error(int s, const struct sockaddr_in *to, uint16_t code, const char *msg)
{
    uint8_t b[128];
    size_t n = 4 + strlen(msg) + 1;
    b[0] = 0, b[1] = 5, b[2] = (uint8_t)(code >> 8), b[3] = (uint8_t)code;
    memcpy(b + 4, msg, strlen(msg) + 1);
    sendto(s, b, n, 0, (const struct sockaddr *)to, sizeof *to);
}

/* Send b[0..n) and wait for ACK of block; 0 acked, -1 gave up. */
static int tftp_xfer(int s, const struct sockaddr_in *peer, const uint8_t *b, size_t n, uint16_t block)
{
    uint8_t r[516];
    for (int tries = 0; tries < 6; tries++) {
        if (send(s, b, n, 0) < 0)
            return -1;
        struct pollfd p = {s, POLLIN, 0};
        while (poll(&p, 1, 1000) > 0) {
            struct sockaddr_in from;
            socklen_t fl = sizeof from;
            ssize_t k = recvfrom(s, r, sizeof r, 0, (struct sockaddr *)&from, &fl);
            if (k < 4 || from.sin_addr.s_addr != peer->sin_addr.s_addr || from.sin_port != peer->sin_port)
                continue;
            if (r[1] == 5)
                return -1;
            if (r[1] == 4 && ((r[2] << 8) | r[3]) == block)
                return 0;
        }
    }
    return -1;
}

static void tftp_request(const uint8_t *in, size_t n, const struct sockaddr_in *peer)
{
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in me = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (s < 0 || bind(s, (struct sockaddr *)&me, sizeof me) != 0 ||
        connect(s, (const struct sockaddr *)peer, sizeof *peer) != 0) {
        if (s >= 0)
            close(s);
        return;
    }
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer->sin_addr, ip, sizeof ip);
    /* RRQ: 0 1 filename 0 mode 0 [option 0 value 0]... */
    const char *f = (const char *)in + 2, *end = (const char *)in + n;
    const char *mode = memchr(f, 0, (size_t)(end - f)) ? f + strlen(f) + 1 : 0;
    if (in[1] != 1 || !mode || mode >= end || !memchr(mode, 0, (size_t)(end - mode))) {
        tftp_error(s, peer, 4, "read requests only");
        close(s);
        return;
    }
    while (*f == '/')
        f++;
    if (strcmp(f, BOOT_NAME) != 0 || strcasecmp(mode, "octet") != 0) {
        logf_("TFTP %s asked for \"%s\" (%s): refused", ip, f, mode);
        tftp_error(s, peer, 1, "file not found");
        close(s);
        return;
    }
    size_t blk = 512;
    uint8_t oack[128];
    size_t on = 2;
    oack[0] = 0, oack[1] = 6;
    for (const char *o = mode + strlen(mode) + 1; o < end && memchr(o, 0, (size_t)(end - o));) {
        const char *val = o + strlen(o) + 1;
        if (val >= end || !memchr(val, 0, (size_t)(end - val)))
            break;
        char num[24];
        if (strcasecmp(o, "blksize") == 0) {
            long b = strtol(val, 0, 10);
            if (b >= 8) {
                blk = (size_t)(b > BLK_MAX ? BLK_MAX : b);
                on += (size_t)snprintf((char *)oack + on, sizeof oack - on, "blksize%c%zu", 0, blk) + 1;
            }
        } else if (strcasecmp(o, "tsize") == 0) {
            snprintf(num, sizeof num, "%zu", booter_len);
            on += (size_t)snprintf((char *)oack + on, sizeof oack - on, "tsize%c%s", 0, num) + 1;
        }
        o = val + strlen(val) + 1;
    }
    logf_("TFTP %s: sending %s (%zu bytes, block %zu)", ip, BOOT_NAME, booter_len, blk);
    if (on > 2 && tftp_xfer(s, peer, oack, on, 0) != 0) {
        logf_("TFTP %s: no ACK for the option answer; gave up", ip);
        close(s);
        return;
    }
    static uint8_t b[4 + BLK_MAX];
    uint16_t block = 1;
    for (size_t off = 0;; off += blk, block++) {
        size_t k = off < booter_len ? (booter_len - off < blk ? booter_len - off : blk) : 0;
        b[0] = 0, b[1] = 3, b[2] = (uint8_t)(block >> 8), b[3] = (uint8_t)block;
        memcpy(b + 4, booter + off, k);
        if (tftp_xfer(s, peer, b, 4 + k, block) != 0) {
            logf_("TFTP %s: transfer stopped at byte %zu", ip, off);
            break;
        }
        if (k < blk) {
            logf_("TFTP %s: %s delivered", ip, BOOT_NAME);
            break;
        }
    }
    close(s);
}

static int usage(void)
{
    fprintf(stderr, "usage: ck_imac_bsdp serve --booter FILE --server-ip A.B.C.D [--mac XX:XX:XX:XX:XX:XX]\n"
                    "                          [--netmask A.B.C.D] [--router A.B.C.D] [--also-broadcast yes|no]\n"
                    "                          [--bsdp-port N] [--tftp-port N] [--seconds N]\n");
    return 2;
}

int main(int argc, char **argv)
{
    const char *path = 0;
    long bport = 67, tport = 69, secs = 0;
    netmask.s_addr = htonl(0xffffff00u);
    if (argc < 2 || strcmp(argv[1], "serve") != 0)
        return usage();
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : 0;
        if (!v)
            return usage();
        if (strcmp(a, "--booter") == 0)
            path = v;
        else if (strcmp(a, "--server-ip") == 0) {
            if (inet_pton(AF_INET, v, &server_ip) != 1)
                return usage();
        } else if (strcmp(a, "--netmask") == 0) {
            if (inet_pton(AF_INET, v, &netmask) != 1)
                return usage();
        } else if (strcmp(a, "--router") == 0) {
            if (inet_pton(AF_INET, v, &router) != 1)
                return usage();
        } else if (strcmp(a, "--also-broadcast") == 0) {
            also_bcast = strcmp(v, "yes") == 0;
        } else if (strcmp(a, "--mac") == 0) {
            unsigned m[6];
            if (sscanf(v, "%2x:%2x:%2x:%2x:%2x:%2x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
                return usage();
            for (int k = 0; k < 6; k++)
                only_mac[k] = (uint8_t)m[k];
            have_mac = 1;
        } else if (strcmp(a, "--bsdp-port") == 0)
            bport = strtol(v, 0, 10);
        else if (strcmp(a, "--tftp-port") == 0)
            tport = strtol(v, 0, 10);
        else if (strcmp(a, "--seconds") == 0)
            secs = strtol(v, 0, 10);
        else
            return usage();
        i++;
    }
    if (!path || !server_ip.s_addr || bport < 1 || bport > 65535 || tport < 1 || tport > 65535 || secs < 0)
        return usage();
    struct stat st;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) != 0 || st.st_size < 2 || st.st_size > 16 * 1024 * 1024) {
        fprintf(stderr, "ck_imac_bsdp: cannot use booter %s\n", path);
        return 2;
    }
    booter_len = (size_t)st.st_size;
    booter = malloc(booter_len);
    if (!booter || read(fd, booter, booter_len) != (ssize_t)booter_len || booter[0] != 'M' || booter[1] != 'Z') {
        fprintf(stderr, "ck_imac_bsdp: %s is not a readable PE image\n", path);
        return 2;
    }
    close(fd);
    int bs = bind_udp((uint16_t)bport, 1), ts = bind_udp((uint16_t)tport, 0);
    if (bs < 0 || ts < 0)
        return 3;
    logf_("serving BSDP on %ld and TFTP on %ld as %s; booter %s (%zu bytes)%s", bport, tport, inet_ntoa(server_ip),
          path, booter_len, have_mac ? "; one client only" : "");
    time_t end = secs ? time(0) + secs : 0;
    uint8_t buf[1500];
    while (!end || time(0) < end) {
        struct pollfd p[2] = {{bs, POLLIN, 0}, {ts, POLLIN, 0}};
        if (poll(p, 2, 500) <= 0)
            continue;
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        if (p[0].revents & POLLIN) {
            ssize_t k = recvfrom(bs, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
            if (k > 0)
                bsdp_packet(bs, buf, (size_t)k);
        }
        fl = sizeof from;
        if (p[1].revents & POLLIN) {
            ssize_t k = recvfrom(ts, buf, sizeof buf - 1, 0, (struct sockaddr *)&from, &fl);
            if (k >= 4) {
                buf[k] = 0;
                tftp_request(buf, (size_t)k, &from);
            }
        }
    }
    logf_("deadline reached");
    return 0;
}
