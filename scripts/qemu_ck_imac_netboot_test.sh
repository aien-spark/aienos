#!/usr/bin/env bash
# qemu_ck_imac_netboot_test.sh -- QEMU test for the iMac lab network loader
# (NETLDR.EFI, native/boot/net_loader.c) and its server (tools/ck_imac_netboot.c).
# QEMU is an emulator: a PASS here qualifies nothing about a 2017 iMac, its
# firmware's network driver or its Ethernet chip.
#
# One q35 + OVMF machine with a virtio NIC on the QEMU "-netdev dgram" backend
# (raw Ethernet over a UDP pair on 127.0.0.1: no root, no tap) and NETLDR.EFI
# as EFI/BOOT/BOOTX64.EFI, built with a fresh TEST key made here and an 8 s
# fallback. The default IMACKERN.EFI sits beside it as \EFI\AIENOS\IMACKERN.EFI.
# One boot, four stages, in order:
#   1. good job: the lab kernel (IMACKERN-LAB.EFI) signed with the built-in key
#      is fetched, verified and started; it runs to DONE and restarts the
#      machine through the ACPI reset register; the loader comes back and the
#      server says WAIT.
#   2. tampered job: the same signed job with one image byte flipped is refused
#      (image SHA-512 mismatch) and nothing starts.
#   3. wrong key: a job signed with a second TEST key is refused (signer_id
#      names no trusted key) and nothing starts.
#   4. server gone: after 8 s of silence the loader starts the kernel on its
#      own disk, which powers QEMU off through ACPI S5.
# Needs qemu-system-x86_64 (>= 7.2 for dgram), OVMF, mtools and an x86_64 gcc.
# Final line: AIENOS_IMAC_NETBOOT: PASS|FAIL|NOT_RUN   exit 0 / 1 / 2 (tools) / 3 (NOT_RUN)
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
tag="AIENOS_IMAC_NETBOOT"
code_fd="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
vars_fd="${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
cross=""
if [ "$(uname -m)" != "x86_64" ]; then cross="x86_64-linux-gnu-"; fi
for t in qemu-system-x86_64 mformat mmd mcopy "${cross}gcc" "${cross}ld"; do
    command -v "${t}" >/dev/null || { echo "${tag}: NOT_RUN (${t} missing)"; exit 2; }
done
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "${tag}: NOT_RUN (no OVMF)"; exit 2; }

. "${repo_root}/scripts/lib_gate_hold.sh"
if ! gh_quiet_check || ! gh_lock_take qemu_ck_imac_netboot_test "${AIENOS_GATE_MINUTES:-60}"; then
    echo "${tag}: NOT_RUN (${gh_why})"
    exit 3
fi
work="$(mktemp -d)"
qpid=""
spid=""
cleanup() {
    [[ -z "${qpid}" ]] || kill "${qpid}" 2>/dev/null || true
    [[ -z "${spid}" ]] || kill "${spid}" 2>/dev/null || true
    rm -rf "${work}"
    gh_lock_release
}
trap cleanup EXIT

out="${work}/out"
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
mk() { make -s -C native/kernel X86_CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" "$@" >/dev/null; }
mk slot-tool imac-netboot-tool
nb="${out}/host/ck_imac_netboot"
"${nb}" keygen "${work}/test.key" "${work}/test.pub" >/dev/null
"${nb}" keygen "${work}/other.key" "${work}/other.pub" >/dev/null
mk CK_NETLDR_KEYS="${work}/test.pub" CK_NETLDR_FALLBACK_S=8 imac-netldr
mk CK_X86_REPORT=1 imac-kernel
mk imac-kernel
push() { # image key -> next.job
    NETBOOT_TOOL_OUT="${out}" bash scripts/ck_imac_netboot_push.sh "$1" "$2" "${work}/spool" >/dev/null
}

img="${work}/esp.img"
truncate -s 64M "${img}"
mformat -i "${img}" -F ::
mmd -i "${img}" ::/EFI ::/EFI/BOOT ::/EFI/AIENOS
mcopy -i "${img}" "${out}/NETLDR.EFI" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "${img}" "${out}/IMACKERN.EFI" ::/EFI/AIENOS/IMACKERN.EFI

fails=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; fails=$((fails + 1)); }
chk() { # description, file, pattern
    if grep -aqE -- "$2" "$3"; then pass "$1"; else fail "$1 (no match for: $2)"; fi
}
count() { grep -acE -- "$1" "$2" || true; }
log="${work}/serial.log"
txt="${work}/serial.txt"
slog="${work}/serve.log"
snap() { tr -d '\r' <"${log}" >"${txt}" 2>/dev/null || : >"${txt}"; }
wait_for() { # pattern file seconds [min count]
    local n="${4:-1}"
    for _ in $(seq 1 "$3"); do
        snap
        [[ "$(count "$1" "$2")" -ge "${n}" ]] && return 0
        kill -0 "${qpid}" 2>/dev/null || return 1
        sleep 1
    done
    return 1
}

# Free UDP ports for the dgram pair.
lp=$((40000 + RANDOM % 10000))
rp=$((lp + 1))
mkdir -p "${work}/spool"
push "${out}/IMACKERN-LAB.EFI" "${work}/test.key"
"${nb}" serve "${work}/spool" --qemu-dgram "${rp}:${lp}" >"${slog}" 2>&1 &
spid=$!
cp "${vars_fd}" "${work}/vars.fd"
qemu-system-x86_64 -M q35 -accel tcg -cpu max -smp 2 -m 1024 \
    -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
    -drive if=pflash,format=raw,file="${work}/vars.fd" \
    -drive if=none,id=esp,format=raw,file="${img}" -device ide-hd,drive=esp,bus=ide.0,bootindex=1 \
    -netdev dgram,id=n0,local.type=inet,local.host=127.0.0.1,local.port="${lp}",remote.type=inet,remote.host=127.0.0.1,remote.port="${rp}" \
    -device virtio-net-pci,netdev=n0,mac=52:54:00:12:34:56 \
    -display none -serial file:"${log}" &
qpid=$!

echo "== stage 1: good job =="
wait_for '^netldr: AIENOS NETLDR v1 ' "${txt}" 240 || true
chk "loader started" '^netldr: AIENOS NETLDR v1 commit=[0-9a-f]+ keys=1 fallback=8s$' "${txt}"
wait_for '^power: restart via ' "${txt}" 400 || true
chk "NIC found" '^netldr: nic [0-9]+ of [0-9]+ mac=52:54:00:12:34:56 type=1 ' "${txt}"
chk "cable link seen" '^netldr: nic [0-9]+ link up$' "${txt}"
chk "offer received" '^netldr: the Spark offers a kernel: [0-9]+ bytes$' "${txt}"
chk "signature and digest verified" "^netldr: signature and SHA-512 verified: gen=[0-9]+ commit=${commit:0:12} len=[0-9]+\$" "${txt}"
chk "network kernel started" '^netldr: starting the network kernel \([0-9]+ bytes\)$' "${txt}"
chk "lab kernel ran to DONE" '^AIENOS-IMAC-KERNEL-0 DONE$' "${txt}"
chk "lab kernel W^X audit" '^wx_audit: ok wx_leaves=0 ' "${txt}"
chk "restart through the ACPI reset register" '^power: restart via the ACPI reset register port=0x[0-9a-f]+ value=0x[0-9a-f]+$' "${txt}"
chk "loader told the Spark VERIFIED" '^netldr: told the Spark: verified, starting \([1-3]/3 sent\)$' "${txt}"
chk "server saw VERIFIED" 'loader says: VERIFIED, starting' "${slog}"
ls "${work}/spool"/booted-*.job >/dev/null 2>&1 && pass "job retired as booted" || fail "job retired as booted"
wait_for '^netldr: the Spark answered: nothing queued' "${txt}" 240 || true
[[ "$(count '^netldr: AIENOS NETLDR v1 ' "${txt}")" -ge 2 ]] && pass "loader came back after the restart" || fail "loader came back after the restart"
chk "server answers WAIT with nothing queued" '^netldr: the Spark answered: nothing queued; asking again every 5 s$' "${txt}"
if grep -aqE '^(panic|power: off via ACPI S5)' "${txt}"; then fail "no panic, no power off in stage 1"; else pass "no panic, no power off in stage 1"; fi

echo "== stage 2: tampered job =="
push "${out}/IMACKERN-LAB.EFI" "${work}/test.key"
j="${work}/spool/next.job"
mv "${j}" "${work}/t.job"
off=$((4096 + 512))
b="$(od -An -tu1 -j "${off}" -N 1 "${work}/t.job" | tr -d " ")"
printf "\\x$(printf %02x $((b ^ 0xff)))" | dd of="${work}/t.job" bs=1 seek="${off}" conv=notrunc status=none # invert one image byte
mv "${work}/t.job" "${j}"
wait_for '^netldr: REFUSED the network kernel' "${txt}" 120 || true
chk "tampered image refused" '^netldr: REFUSED the network kernel \(image SHA-512 mismatch\): nothing was started$' "${txt}"
chk "server saw REFUSED (digest)" 'loader says: REFUSED \(image SHA-512 mismatch\)' "${slog}"

echo "== stage 3: wrong key =="
push "${out}/IMACKERN-LAB.EFI" "${work}/other.key"
wait_for '^netldr: REFUSED the network kernel' "${txt}" 120 2 || true
chk "other key refused" '^netldr: REFUSED the network kernel \(signer_id names no trusted key\): nothing was started$' "${txt}"
chk "server saw REFUSED (key)" 'loader says: REFUSED \(signer_id names no trusted key\)' "${slog}"
[[ "$(count '^netldr: starting the network kernel' "${txt}")" == 1 ]] && pass "only the good job ever started" || fail "only the good job ever started"

echo "== stage 4: server gone =="
wait_for '^netldr: the Spark answered: nothing queued' "${txt}" 60 3 || true
kill "${spid}" 2>/dev/null || true
wait "${spid}" 2>/dev/null || true
spid=""
self_exit=0
for _ in $(seq 1 300); do
    if ! kill -0 "${qpid}" 2>/dev/null; then self_exit=1; break; fi
    sleep 1
done
snap
chk "fallback after 8 s of silence" '^netldr: no answer from the Spark \(frames sent, nothing came back\); starting the kernel on this stick in 10 s$' "${txt}"
chk "local kernel started" '^netldr: starting the local kernel \([0-9]+ bytes\)$' "${txt}"
chk "local (default) kernel powered off through ACPI S5" '^power: off via ACPI S5 ' "${txt}"
[[ ${self_exit} == 1 ]] && pass "QEMU powered off by itself" || fail "QEMU powered off by itself"
if grep -aqE '^panic' "${txt}"; then fail "no panic"; else pass "no panic"; fi
echo "---- server log ----"; cat "${slog}"
echo "---- serial (netldr and power lines) ----"; grep -aE '^(netldr|power):' "${txt}" || true
echo "----"
if [[ ${fails} == 0 ]]; then echo "${tag}: PASS"; exit 0; fi
echo "${tag}: FAIL (${fails})"
exit 1
