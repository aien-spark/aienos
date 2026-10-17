#!/usr/bin/env bash
# ck_imac_lab_services.sh -- keep the iMac lab services running on the Spark:
#   ck_imac_netboot serve   answers NETLDR.EFI on the iMac (UDP 47032) with queued kernels
#   ck_imac_report_listen   collects the lab kernel's UNAUTHENTICATED report (UDP 47031)
#   ck_imac_bsdp            answers the iMac's Apple NetBoot (N key held, UDP 67) and hands it
#                           NETLDR.EFI over TFTP (UDP 69): the iMac starts with no stick at all
# Detached with setsid/nohup (no systemd). For a restart after a Spark reboot, a crontab line:
#   @reboot <repo>/scripts/ck_imac_lab_services.sh start
#
#   scripts/ck_imac_lab_services.sh start|stop|status
#
# State (spool, logs, reports, pids) lives in ${IMAC_LAB_STATE:-~/.local/state/aienos/imac-netboot}:
#   next.job (queued by scripts/ck_imac_netboot_push.sh), serve.log, reports/listen.log.
# Binaries are built into target/native-kernel-imac-netboot. IMAC_LAB_BCAST (default
# 192.168.1.255) is where server answers go; IMAC_LAB_MAC limits answers to one loader.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
state="${IMAC_LAB_STATE:-${HOME}/.local/state/aienos/imac-netboot}"
out="${repo_root}/target/native-kernel-imac-netboot"
bcast="${IMAC_LAB_BCAST:-192.168.1.255}"
imac_mac="${IMAC_LAB_IMAC_MAC:-78:7b:8a:bd:d0:51}"
server_ip="${IMAC_LAB_SERVER_IP:-192.168.1.108}"
router="${IMAC_LAB_ROUTER:-192.168.1.1}"
booter="${IMAC_LAB_BOOTER:-${out}/NETLDR.EFI}"
mkdir -p "${state}/reports"

alive() { [[ -r "${state}/$1.pid" ]] && kill -0 "$(cat "${state}/$1.pid")" 2>/dev/null; }

start() {
    make -s -C "${repo_root}/native/kernel" OUT="${out}" imac-netboot-tool >/dev/null
    mkdir -p "${out}/host"
    cc -O2 -Wall -Wextra -o "${out}/host/ck_imac_report_listen" \
        "${repo_root}/native/kernel/tools/ck_imac_report_listen.c"
    if alive serve; then echo "serve: already running (pid $(cat "${state}/serve.pid"))"; else
        local mac=()
        [[ -z "${IMAC_LAB_MAC:-}" ]] || mac=(--mac "${IMAC_LAB_MAC}")
        setsid nohup "${out}/host/ck_imac_netboot" serve "${state}" --bcast "${bcast}" "${mac[@]}" \
            >>"${state}/serve.log" 2>&1 </dev/null &
        echo $! >"${state}/serve.pid"
        echo "serve: started (pid $!, log ${state}/serve.log)"
    fi
    if alive listen; then echo "listen: already running (pid $(cat "${state}/listen.pid"))"
    elif ss -Hulpn 'sport = :47031' | grep -q .; then
        echo "listen: another receiver already holds UDP 47031, left as is: $(ss -Hulpn 'sport = :47031' | grep -o 'users:.*')"
    else
        # 30 days is the listener's longest deadline; the @reboot line or a rerun starts the next one.
        setsid nohup "${out}/host/ck_imac_report_listen" 47031 "${state}/reports" 2592000 \
            >>"${state}/reports/listen.out" 2>&1 </dev/null &
        echo $! >"${state}/listen.pid"
        echo "listen: started (pid $!, log ${state}/reports/listen.log)"
    fi
    if alive bsdp; then echo "bsdp: already running (pid $(cat "${state}/bsdp.pid"))"; else
        # The booter is copied so a rebuild cannot change it under a running transfer; ports 67/69
        # are below 1024, so the binary gets CAP_NET_BIND_SERVICE (never run as root).
        install -m 0644 "${booter}" "${state}/netldr.efi"
        sudo -n setcap cap_net_bind_service=+ep "${out}/host/ck_imac_bsdp"
        setsid nohup "${out}/host/ck_imac_bsdp" serve --booter "${state}/netldr.efi" --server-ip "${server_ip}" \
            --mac "${imac_mac}" --router "${router}" --also-broadcast yes >>"${state}/bsdp.log" 2>&1 </dev/null &
        echo $! >"${state}/bsdp.pid"
        echo "bsdp: started (pid $!, log ${state}/bsdp.log, booter sha256 $(sha256sum "${state}/netldr.efi" | cut -c1-16))"
    fi
}

stop() {
    for s in serve listen bsdp; do
        if alive "${s}"; then kill "$(cat "${state}/${s}.pid")"; echo "${s}: stopped"; else echo "${s}: not running"; fi
        rm -f "${state}/${s}.pid"
    done
}

status() {
    for s in serve listen bsdp; do
        if alive "${s}"; then echo "${s}: running (pid $(cat "${state}/${s}.pid"))"; else echo "${s}: not running"; fi
    done
    echo "UDP 47031 (reports): $(ss -Hulpn 'sport = :47031' | grep -o 'users:.*' || echo 'nobody')"
    ls "${state}" | grep -E '\.job$' || echo "jobs: none"
}

case "${1:-}" in
start) start ;;
stop) stop ;;
status) status ;;
*) echo "usage: ck_imac_lab_services.sh start|stop|status"; exit 2 ;;
esac
