#!/usr/bin/env bash
# ck_imac_bsdp_test.sh -- host test for tools/ck_imac_bsdp.c (Apple NetBoot answerer).
# Runs the answerer on loopback high ports and plays the iMac with a small C client that
# sends the INFORM[LIST] the real iMac18,3 sent on 2026-10-17 (vendor class
# "AAPLBSDPC/i386/iMac18,3", option 43 = 01 01 01 02 02 01 01) plus a reply port, then an
# INFORM[SELECT] for the offered image; checks every answer field; then fetches the booter
# with curl over TFTP (blksize + tsize) and compares bytes; checks a wrong file name and a
# DHCP DISCOVER get nothing. Loopback says nothing about the iMac firmware.
# Final line: AIENOS_IMAC_BSDP: PASS|FAIL   exit 0 / 1
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tag="AIENOS_IMAC_BSDP"
W="$(mktemp -d)"
spid=""
trap '[[ -z "${spid}" ]] || kill "${spid}" 2>/dev/null || true; rm -rf "${W}"' EXIT
fail() { echo "FAIL  $1"; echo "${tag}: FAIL"; exit 1; }
pass() { echo "PASS  $1"; }
command -v curl >/dev/null || { echo "${tag}: NOT_RUN (curl missing)"; exit 2; }
cc -std=gnu11 -O2 -Wall -Wextra -Werror -o "${W}/bsdp" "${repo_root}/native/kernel/tools/ck_imac_bsdp.c"
cat >"${W}/client.c" <<'EOF'
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
/* client SERVER_PORT REPLY_PORT list|select|discover -> prints the answer's fields */
int main(int argc, char **argv)
{
    int sp = atoi(argv[1]), rp = atoi(argv[2]);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in me = {.sin_family = AF_INET, .sin_port = htons(rp), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(sp), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (bind(s, (struct sockaddr *)&me, sizeof me) != 0)
        return 3;
    uint8_t p[400] = {0};
    size_t n = 240;
    p[0] = 1, p[1] = 1, p[2] = 6;
    p[4] = 0xd7, p[5] = 0xfe, p[6] = 0xa7, p[7] = 0x48;
    p[12] = 127, p[15] = 1; /* ciaddr 127.0.0.1 (the iMac sent its leased address) */
    uint8_t mac[6] = {0x78, 0x7b, 0x8a, 0xbd, 0xd0, 0x51};
    memcpy(p + 28, mac, 6);
    p[236] = 0x63, p[237] = 0x82, p[238] = 0x53, p[239] = 0x63;
    int disc = strcmp(argv[3], "discover") == 0, sel = strcmp(argv[3], "select") == 0;
    p[n++] = 53, p[n++] = 1, p[n++] = disc ? 1 : 8;
    p[n++] = 55, p[n++] = 2, p[n++] = 43, p[n++] = 60;
    p[n++] = 57, p[n++] = 2, p[n++] = 0x05, p[n++] = 0xdc;
    p[n++] = 60, p[n++] = 23;
    memcpy(p + n, "AAPLBSDPC/i386/iMac18,3", 23), n += 23;
    if (sel) {
        uint8_t v[] = {1, 1, 2, 2, 2, 1, 1, 5, 2, (uint8_t)(rp >> 8), (uint8_t)rp, 8, 4, 0x81, 0, 0, 1, 3, 4, 127, 0, 0, 1};
        p[n++] = 43, p[n++] = sizeof v, memcpy(p + n, v, sizeof v), n += sizeof v;
    } else {
        uint8_t v[] = {1, 1, 1, 2, 2, 1, 1, 5, 2, (uint8_t)(rp >> 8), (uint8_t)rp};
        p[n++] = 43, p[n++] = sizeof v, memcpy(p + n, v, sizeof v), n += sizeof v;
    }
    p[n++] = 255;
    sendto(s, p, n, 0, (struct sockaddr *)&to, sizeof to);
    struct pollfd pf = {s, POLLIN, 0};
    if (poll(&pf, 1, 2000) <= 0) {
        printf("no answer\n");
        return 0;
    }
    uint8_t r[600];
    ssize_t k = recv(s, r, sizeof r, 0);
    printf("op=%u xid=%02x%02x%02x%02x siaddr=%u.%u.%u.%u chaddr_ok=%d file=%s sname=%s\n", r[0], r[4], r[5], r[6],
           r[7], r[20], r[21], r[22], r[23], memcmp(r + 28, mac, 6) == 0, (char *)r + 108, (char *)r + 44);
    for (ssize_t i = 240; i < k && r[i] != 255;) {
        uint8_t c = r[i], l = r[i + 1];
        printf("opt %u:", c);
        for (int j = 0; j < l; j++)
            printf(c == 60 || c == 17 ? "%c" : " %02x", r[i + 2 + j]);
        printf("\n");
        i += 2 + l;
    }
    return 0;
}
EOF
cc -std=gnu11 -O2 -Wall -o "${W}/client" "${W}/client.c"
head -c 45056 /dev/urandom >"${W}/booter.efi"
printf 'MZ' | dd of="${W}/booter.efi" conv=notrunc status=none
bp=$((41000 + RANDOM % 4000)); tp=$((bp + 1)); rp=$((bp + 2))
"${W}/bsdp" serve --booter "${W}/booter.efi" --server-ip 127.0.0.1 --mac 78:7b:8a:bd:d0:51 \
    --bsdp-port "${bp}" --tftp-port "${tp}" --seconds 60 >"${W}/log" 2>&1 &
spid=$!
for _ in $(seq 1 50); do grep -q '^.* serving BSDP' "${W}/log" && break; sleep 0.1; done
grep -q 'serving BSDP' "${W}/log" || fail "server did not start: $(cat "${W}/log")"

"${W}/client" "${bp}" "${rp}" list >"${W}/list"
grep -q '^op=2 xid=d7fea748 siaddr=127.0.0.1 chaddr_ok=1 ' "${W}/list" || fail "LIST answer header: $(cat "${W}/list")"
grep -q '^opt 53: 05$' "${W}/list" || fail "LIST answer is not a DHCP ACK"
grep -q '^opt 54: 7f 00 00 01$' "${W}/list" || fail "LIST answer server id"
grep -q '^opt 60:AAPLBSDPC$' "${W}/list" || fail "LIST answer vendor class"
grep -q "^opt 1: ff ff ff 00$" "${W}/list" || fail "LIST answer subnet mask"
grep -q '^opt 43: 01 01 01 04 02 80 00 07 04 81 00 00 01 09 0b 81 00 00 01 06 41 49 45 4e 4f 53$' "${W}/list" ||
    fail "LIST answer BSDP options: $(grep 'opt 43' "${W}/list")"
pass "INFORM[LIST] from iMac18,3 answered: ACK, one default image AIENOS (id 0x81000001, install image)"

"${W}/client" "${bp}" "${rp}" select >"${W}/sel"
grep -q '^op=2 xid=d7fea748 siaddr=127.0.0.1 chaddr_ok=1 file=aienos/netldr.efi sname=spark$' "${W}/sel" ||
    fail "SELECT answer header: $(head -1 "${W}/sel")"
grep -q '^opt 43: 01 01 02 08 04 81 00 00 01 82 06 41 49 45 4e 4f 53$' "${W}/sel" || fail "SELECT answer BSDP options: $(grep 'opt 43' "${W}/sel")"
grep -q '^opt 17:tftp:127.0.0.1:/aienos/none$' "${W}/sel" || fail "SELECT answer root path"
pass "INFORM[SELECT] answered: boot file aienos/netldr.efi from this server"

"${W}/client" "${bp}" "${rp}" discover >"${W}/disc"
grep -q '^no answer$' "${W}/disc" || fail "a DHCP DISCOVER got an answer (the router must stay the DHCP server)"
pass "DHCP DISCOVER ignored"

curl -s --tftp-blksize 1428 -o "${W}/got" "tftp://127.0.0.1:${tp}/aienos/netldr.efi" || fail "TFTP fetch failed: $(tail -3 "${W}/log")"
cmp -s "${W}/got" "${W}/booter.efi" || fail "TFTP bytes differ"
pass "TFTP delivered the booter byte for byte (blksize 1428)"
curl -s -o "${W}/got512" "tftp://127.0.0.1:${tp}/aienos/netldr.efi" && cmp -s "${W}/got512" "${W}/booter.efi" ||
    fail "TFTP default block size"
pass "TFTP delivered the booter with the default 512-byte blocks"
if curl -s -o "${W}/nope" "tftp://127.0.0.1:${tp}/etc/passwd"; then fail "TFTP served a file it should refuse"; fi
grep -q 'asked for "etc/passwd" (octet): refused' "${W}/log" || fail "refusal not logged"
pass "TFTP refused any other file"
echo "---- server log ----"; cat "${W}/log"
echo "${tag}: PASS"
