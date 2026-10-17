#!/usr/bin/env bash
# ck_imac_netboot_push.sh -- sign an iMac kernel image and queue it for NETLDR.EFI
# (native/boot/net_loader.c). The next time the iMac's loader asks (at power-on,
# or within seconds while it waits), the server (ck_imac_netboot serve) offers
# this job; the loader starts it only if the signature and SHA-512 verify.
#
#   scripts/ck_imac_netboot_push.sh IMAGE.EFI [KEY] [SPOOL]
#
# KEY    lab signing key, 32-byte seed, mode 0600 (default ~/.config/aienos/imac-netboot.key;
#        make it once with: ck_imac_netboot keygen KEY PUB)
# SPOOL  the server's spool directory (default ~/.local/state/aienos/imac-netboot)
# Steps: ck_slot_tool make-manifest (generation = unix time, commit = HEAD) -> tbs ->
# ck_imac_netboot sign -> ck_slot_tool attach-sig (which verifies the signature) ->
# manifest + image written beside SPOOL/next.job and renamed into place.
# Final line: "NETBOOT_PUSH: QUEUED <job> sha256=<image sha256>" (exit 0) or an error (exit 1).
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
img="${1:?usage: ck_imac_netboot_push.sh IMAGE.EFI [KEY] [SPOOL]}"
key="${2:-${HOME}/.config/aienos/imac-netboot.key}"
spool="${3:-${HOME}/.local/state/aienos/imac-netboot}"
out="${NETBOOT_TOOL_OUT:-${repo_root}/target/native-kernel-imac-netboot}"
make -s -C "${repo_root}/native/kernel" OUT="${out}" slot-tool imac-netboot-tool >/dev/null
st="${out}/host/ck_slot_tool"
nb="${out}/host/ck_imac_netboot"
[[ -r "${img}" ]] || { echo "NETBOOT_PUSH: no image ${img}"; exit 1; }
[[ "$(head -c 2 "${img}")" == "MZ" ]] || { echo "NETBOOT_PUSH: ${img} is not a PE image"; exit 1; }
mkdir -p "${spool}"
work="$(mktemp -d "${spool}/.push.XXXXXX")"
trap 'rm -rf "${work}"' EXIT
commit="$(git -C "${repo_root}" rev-parse HEAD)"
pk="$("${nb}" pubkey "${key}")"
"${st}" make-manifest --image "${img}" --generation "$(date +%s)" --commit "${commit}" \
    --provenance "imac-netboot lab $(basename "${img}")" --out "${work}/m0" >/dev/null
"${st}" tbs "${work}/m0" --pubkey "${pk}" --out "${work}/tbs" >/dev/null
"${nb}" sign "${key}" "${work}/tbs" "${work}/sig" >/dev/null
"${st}" attach-sig "${work}/m0" --sig "${work}/sig" --pubkey "${pk}" --out "${work}/m1" >/dev/null
[[ "$(stat -c %s "${work}/m1")" == 4096 ]] || { echo "NETBOOT_PUSH: manifest is not 4096 bytes"; exit 1; }
cat "${work}/m1" "${img}" >"${work}/job"
mv "${work}/job" "${spool}/next.job"
echo "NETBOOT_PUSH: QUEUED ${spool}/next.job sha256=$(sha256sum "${img}" | cut -d' ' -f1)"
