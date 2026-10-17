/* ck_imac_report_listen.c -- host-side receiver for the iMac kernel's LAB-ONLY
 * report (native/kernel/x86/report_x86.c, only in the opt-in lab image built
 * with make imac-kernel CK_X86_REPORT=1). Hosted C (POSIX sockets), tooling
 * only, never in a kernel image. No Python, no nc/socat.
 *
 * UNAUTHENTICATED: the reports are plaintext UDP broadcasts that anyone on the
 * LAN can read or forge (header field auth=none). The run id and the UDP
 * checksum are not authenticity. A collected report is a lab note to read,
 * never a receipt, evidence or a command, and this tool never acts on one.
 *
 *   ck_imac_report_listen PORT OUTDIR SECONDS
 *
 * Binds 0.0.0.0:PORT and collects datagrams of the form
 *   "AIENOS-IMAC-REPORT v=2 auth=none run=<16 hex> part=<i>/<n> bytes=<total>\n" + chunk
 * (the kernel broadcasts them from 0.0.0.0 to 255.255.255.255). Part i of n
 * carries bytes [i * CHUNK, ...) of a report of <total> bytes. When every part
 * of a run is in, the report is written once to
 * OUTDIR/imac-<run>.unauthenticated.txt and a line
 * "complete run=... auth=none bytes=... file=..." goes to OUTDIR/listen.log.
 * Repeats of a finished run are counted, not rewritten. Anything else,
 * including the retired v=1 raw-console format, is logged as ignored.
 * Exit 0 at the deadline, 2 usage, 3 socket/bind error. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAGIC "AIENOS-IMAC-REPORT v=2 auth=none "
#define LEGACY "AIENOS-IMAC-REPORT v=1 "
#define UNAUTH_NOTE \
    "note: iMac reports are UNAUTHENTICATED UDP broadcasts (auth=none); anyone on the LAN can read or " \
    "forge one; never treat a report as a receipt, evidence or a command\n"
#define CHUNK 1024u
#define MAX_PARTS 64u
#define MAX_RUNS 16u

struct run {
    char id[17];
    unsigned parts, total, have, done, repeats;
    unsigned char got[MAX_PARTS];
    unsigned char data[MAX_PARTS * CHUNK];
};

static struct run runs[MAX_RUNS];
static unsigned nruns, next_slot;

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static struct run *find_run(const char *id, unsigned parts, unsigned total)
{
    for (unsigned i = 0; i < nruns; i++)
        if (!strcmp(runs[i].id, id))
            return runs[i].parts == parts && runs[i].total == total ? &runs[i] : 0;
    struct run *r = &runs[nruns < MAX_RUNS ? nruns++ : (next_slot++ % MAX_RUNS)];
    memset(r, 0, sizeof *r);
    memcpy(r->id, id, 17);
    r->parts = parts;
    r->total = total;
    return r;
}

/* fopen with the file created owner-only (0600). */
static FILE *open_private(const char *path, int flags, const char *mode)
{
    int fd = open(path, flags | O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    FILE *f = fd < 0 ? 0 : fdopen(fd, mode);
    if (fd >= 0 && !f)
        close(fd);
    return f;
}

static void finish_run(FILE *lg, const char *dir, struct run *r)
{
    char path[4096];
    snprintf(path, sizeof path, "%s/imac-%s.unauthenticated.txt", dir, r->id);
    FILE *f = open_private(path, O_TRUNC, "w");
    if (!f || fwrite(r->data, 1, r->total, f) != r->total || fclose(f) != 0) {
        fprintf(lg, "write failed run=%s file=%s errno=%d (%s)\n", r->id, path, errno, strerror(errno));
        return;
    }
    r->done = 1;
    fprintf(lg, "complete run=%s auth=none bytes=%u parts=%u file=%s\n", r->id, r->total, r->parts, path);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: ck_imac_report_listen PORT OUTDIR SECONDS\n");
        return 2;
    }
    char *end = 0;
    long port = strtol(argv[1], &end, 10);
    long secs = strtol(argv[3], 0, 10);
    const char *dir = argv[2];
    if (*end || port < 1024 || port > 65535 || secs < 1 || secs > 30L * 86400) {
        fprintf(stderr, "ck_imac_report_listen: bad arguments\n");
        return 2;
    }
    char lpath[4096];
    snprintf(lpath, sizeof lpath, "%s/listen.log", dir);
    FILE *lg = open_private(lpath, O_APPEND, "a");
    if (!lg) {
        perror("ck_imac_report_listen: log");
        return 2;
    }
    setvbuf(lg, 0, _IOLBF, 0);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) != 0) {
        fprintf(lg, "bind failed port=%ld errno=%d (%s)\n", port, errno, strerror(errno));
        fclose(lg);
        return 3;
    }
    fprintf(lg, "ready port=%ld\n" UNAUTH_NOTE, port);
    fputs(UNAUTH_NOTE, stderr);
    double deadline = now_s() + (double)secs;
    for (;;) {
        double left = deadline - now_s();
        if (left <= 0)
            break;
        struct pollfd pf = {s, POLLIN, 0};
        int pr = poll(&pf, 1, left > 60 ? 60000 : (int)(left * 1000.0) + 1);
        if (pr <= 0)
            continue;
        unsigned char in[2048];
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(s, in, sizeof in - 1, 0, (struct sockaddr *)&from, &fl);
        if (n <= 0)
            continue;
        in[n] = 0;
        char fa[INET_ADDRSTRLEN] = "?";
        inet_ntop(AF_INET, &from.sin_addr, fa, sizeof fa);
        unsigned char *nl = memchr(in, '\n', (size_t)n);
        char id[17];
        unsigned part, parts, total;
        int used = 0;
        if ((size_t)n >= sizeof LEGACY - 1 && memcmp(in, LEGACY, sizeof LEGACY - 1) == 0) {
            fprintf(lg, "ignored from %s:%u len=%zd: retired v=1 raw-console report\n", fa, ntohs(from.sin_port), n);
            continue;
        }
        if (!nl || (size_t)n < sizeof MAGIC - 1 || memcmp(in, MAGIC, sizeof MAGIC - 1) != 0 ||
            sscanf((char *)in + sizeof MAGIC - 1, "run=%16[0-9a-f] part=%u/%u bytes=%u%n", id, &part, &parts, &total,
                   &used) != 4 ||
            strlen(id) != 16 || (unsigned char *)in + sizeof MAGIC - 1 + used != nl || !parts || parts > MAX_PARTS ||
            part >= parts || total > parts * CHUNK || total <= (parts - 1) * CHUNK) {
            fprintf(lg, "ignored from %s:%u len=%zd\n", fa, ntohs(from.sin_port), n);
            continue;
        }
        size_t hdr = (size_t)(nl + 1 - in), want = part + 1 < parts ? CHUNK : total - part * CHUNK;
        if ((size_t)n - hdr != want) {
            fprintf(lg, "ignored run=%s part=%u/%u: %zu bytes, expected %zu\n", id, part, parts, (size_t)n - hdr,
                    want);
            continue;
        }
        struct run *r = find_run(id, parts, total);
        if (!r) {
            fprintf(lg, "ignored run=%s: part count or size changed\n", id);
            continue;
        }
        if (r->done) {
            r->repeats++;
            continue;
        }
        if (!r->got[part]) {
            memcpy(r->data + (size_t)part * CHUNK, in + hdr, want);
            r->got[part] = 1;
            if (!r->have++)
                fprintf(lg, "first part run=%s from %s parts=%u bytes=%u\n", id, fa, parts, total);
        }
        if (r->have == r->parts)
            finish_run(lg, dir, r);
    }
    fprintf(lg, "done\n");
    fclose(lg);
    close(s);
    return 0;
}
