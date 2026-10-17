#!/bin/sh
# ck_imac_report_test.sh -- test of the iMac kernel's LAB-ONLY network report.
#  1. Build check: the default image (make imac-kernel) links no report code
#     and no frame transmit; the opt-in lab image (CK_X86_REPORT=1) has them.
#  2. Host checks of x86/report_x86.c: the allowlist filter (sentinel chat,
#     key, token and memory lines, control bytes and over-long lines never
#     reach the exported copy or a frame; allowed lines survive byte for
#     byte) and the frames (Ethernet broadcast, IPv4, UDP with a checksum,
#     "v=2 auth=none" part headers).
#  3. The receiver tools/ck_imac_report_listen.c rebuilds the report byte for
#     byte from parts sent out of order and repeated, labels it
#     unauthenticated, and refuses the retired v=1 raw-console format.
# Hosted only; the BCM57766 itself cannot be emulated, and nothing here
# touches a real network interface (the round trip runs over 127.0.0.1).
# Ends with "AIENOS_IMAC_REPORT: PASS", "AIENOS_IMAC_REPORT: FAIL <why>" or
# "AIENOS_IMAC_REPORT: NOT_RUN <why>" (no x86_64 toolchain for step 1).
set -u
cd "$(dirname "$0")/.."
K=native/kernel
W=$(mktemp -d "${TMPDIR:-/tmp}/ck_imac_report.XXXXXX")
trap 'kill $LP 2>/dev/null; rm -rf "$W"' EXIT
LP=
fail() { echo "AIENOS_IMAC_REPORT: FAIL $*"; exit 1; }
CC=${HOSTCC:-cc}
CF="-std=gnu11 -O2 -Wall -Wextra -Werror"

# 1. Build check, into a scratch output directory.
X=""
[ "$(uname -m)" = x86_64 ] || X="x86_64-linux-gnu-"
for t in "${X}gcc" "${X}ld" "${X}nm"; do
    command -v "$t" >/dev/null || { echo "AIENOS_IMAC_REPORT: NOT_RUN ($t missing)"; exit 2; }
done
SYMS='ck_x86_report_(hold|frame|filter|parts)|ck_x86_tg3_(send|drain)|net_udp_build'
make -s -C $K X86_CROSS="$X" OUT="$W/build" imac-kernel >"$W/build.log" 2>&1 ||
    fail "default imac-kernel build: $(tail -3 "$W/build.log")"
make -s -C $K X86_CROSS="$X" OUT="$W/build" CK_X86_REPORT=1 imac-kernel >>"$W/build.log" 2>&1 ||
    fail "lab imac-kernel build: $(tail -3 "$W/build.log")"
d=$("${X}nm" "$W/build/imackern/imackern.elf" | grep -E " ($SYMS)\$" || true)
[ -z "$d" ] || fail "default image has report symbols: $(echo $d)"
grep -aq "AIENOS-IMAC-REPORT" "$W/build/IMACKERN.EFI" && fail "default image carries the report header"
l=$("${X}nm" "$W/build/imackern-lab/imackern.elf" | grep -cE " ($SYMS)\$" || true)
[ "$l" = 7 ] || fail "lab image has $l of 7 report symbols"
grep -aq "AIENOS-IMAC-REPORT v=2 auth=none " "$W/build/IMACKERN-LAB.EFI" || fail "lab image lacks the v=2 auth=none header"
echo "build: default image report_symbols=0, lab image report_symbols=7"

# 2. Host checks of the filter and frames.
$CC $CF -o "$W/listen" $K/tools/ck_imac_report_listen.c || fail "listener does not build"
$CC $CF -DCK_X86_REPORT_HOST -I$K/x86 -I$K/tests -Inative/net -o "$W/test" \
    $K/tests/test_imac_report.c $K/x86/report_x86.c native/net/aienos_net.c || fail "test does not build"
"$W/test" || fail "filter and frame checks"

# 3. Listener round trip over loopback.
PORT=$((47100 + $$ % 800))
mkdir -p "$W/out"
"$W/listen" $PORT "$W/out" 20 2>/dev/null &
LP=$!
i=0
until grep -q "^ready port=$PORT" "$W/out/listen.log" 2>/dev/null; do
    i=$((i + 1)); [ $i -gt 50 ] && fail "listener not ready: $(cat "$W/out/listen.log" 2>/dev/null)"
    sleep 0.1
done
grep -q '^note: iMac reports are UNAUTHENTICATED UDP broadcasts (auth=none)' "$W/out/listen.log" ||
    fail "listener does not label reports unauthenticated"
"$W/test" legacy $PORT >/dev/null || fail "legacy send"
"$W/test" send $PORT "$W/sent.txt" >/dev/null || fail "send"
i=0
until grep -q "^complete run=0123456789abcdef auth=none " "$W/out/listen.log"; do
    i=$((i + 1)); [ $i -gt 50 ] && fail "report not completed: $(cat "$W/out/listen.log")"
    sleep 0.1
done
cmp -s "$W/sent.txt" "$W/out/imac-0123456789abcdef.unauthenticated.txt" || fail "rebuilt report differs"
[ "$(grep -c '^complete ' "$W/out/listen.log")" = 1 ] || fail "report written more than once"
[ "$(grep -c '^ignored .*retired v=1 raw-console report$' "$W/out/listen.log")" = 1 ] ||
    fail "listener did not refuse the v=1 datagram"
ls "$W/out" | grep -q '00000000000000ff' && fail "listener wrote the v=1 datagram"
grep '^ignored' "$W/out/listen.log" | grep -vq 'retired v=1' && fail "listener ignored a valid part"
echo "AIENOS_IMAC_REPORT: PASS"
