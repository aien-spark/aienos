# native/kernel: AIENOS C kernel core (Lane 18)

The first AIENOS kernel written in C for AArch64. It boots in QEMU through
UEFI (AAVMF) the way the Rust kernel does and prints the same observables.
QEMU qualifies nothing physical: a PASS here says nothing about real hardware.

## Layout

| Path | What |
| --- | --- |
| `include/ck.h` | Frozen contract for stage code (devices, security, store). Lane 18 core added only `ck_irq_register`, `ck_irq_enable`, `ck_irq_cpu_enable`. |
| `arch/` | Vectors, EL2 -> EL1h entry (ADR 0009), recoverable probe, exception and IRQ dispatch, GICv3 or GICv2 (picked from the MADT; GICv2 is the Raspberry Pi 5 GIC-400 shape, QEMU gate `AIENOS_QEMU_GIC=2 scripts/qemu_ck_boot_test.sh`), EL1 physical timer. |
| `mm/` | Frame allocator (UEFI map), 4 KiB-granule page-table builder, heap, the kernel address space (`mmu.c`). |
| `core/` | Console, printf, ACPI, reports/panic/PSCI reset, M3 (threads, scheduler, EL0, capabilities, IPC), `kmain.c`. |
| `tests/` | Host unit tests. |
| `third_party/omega/` | The canonical Omega Cortex store, byte for byte from the omega commit in `omega.lock` (checked by `scripts/omega_lock_check.sh`); built freestanding by `svc/cortex_store.c` over the sealed Store through `svc/cortex_journal.c` (native v1 plan P06). |
| `x86/` | x86_64 port, first cut (AIENOS-IMAC-KERNEL-0, 2017 iMac): UEFI stub, descriptor tables and interrupt stubs, page tables, local APIC timer, ACPI power off, console, secondary-core start, PCI walk, read-only AHCI and NVMe disks, BCM57766 Ethernet link detection; a lab-only, opt-in network report (`CK_X86_REPORT=1`). |
| `../boot/` | Minimal UEFI entry stub (one image with the kernel). |

## Build and test

    make -C native/kernel            # target/native-kernel/BOOTAA64.EFI
    make -C native/kernel test       # host tests, ends CK_CORE_HOST: PASS
    make -C native/kernel sanitize   # same under ASan + UBSan
    make -C native/kernel full       # + stages: target/native-kernel/full/BOOTAA64.EFI
    make -C native/kernel stage-test # stage host tests (also stage-sanitize, stage-free)
    scripts/qemu_ck_boot_test.sh     # QEMU boot of the core-only image, ends AIENOS_CK_M1: PASS
    scripts/qemu_ck_store_test.sh    # QEMU NVMe + Store gate (full image, QEMU-only
                                     # CK_QEMU_UNSAFE_DMA=1 build), ends AIENOS_CK_M4_NVME,
                                     # AIENOS_CK_M4_STORE, AIENOS_CK_ARGUS1_REVOKE
    scripts/qemu_ck_disk_layout_test.sh # QEMU GPT / AIENOS partition gate, ends AIENOS_CK_DISK_LAYOUT

Toolchain: gcc, binutils (ld, objcopy, nm, readelf), make, shell. On a
non-aarch64 host the Makefile uses the `aarch64-linux-gnu-` prefix.
Output lands in `<repo>/target/native-kernel` (ignored by git).

## Owner provisioning (hardware staging image)

The default and QEMU images use the labelled TEST Store keys
(`ck_store_test_keys`, public label, `M5_ID_TEST`), the TEST store uuid and
the TEST ARGUS machine id (0xA1; the default image prints `argus: TEST machine id 0xA1 ...` on the serial console). The hardware staging image never embeds any
of them:

    make -C native/kernel full CK_HARDWARE_STAGING=1 \
        CK_OWNER_PUBKEYS=<owner public keys file> CK_MACHINE_ID=<machine id file>
    # -> target/native-kernel/full-hardware-staging/BOOTAA64.EFI

- Without both files the Makefile stops with `CK_HARDWARE_STAGING refuses the
  TEST Store keys and TEST machine id`. `svc/store_boot.c` and
  `svc/security.c` also `#error` in a `CK_HARDWARE_STAGING` build without the
  generated header, and the linked image is checked (Makefile `owner_check`)
  to carry no TEST Store label, uuid, TEST print line or TEST key symbol.
- The files hold PUBLIC material only, as text lines `<name> <hex>` (`#`
  comments; each name exactly once). Owner file:
  `owner_root_ed25519 <64 hex>` (the Gate 3 Owner Root public key). Machine
  file: `machine_id <64 hex>` (ARGUS machine id, 32 bytes) and
  `store_uuid <32 hex>` (boot Store uuid). `tools/ck_owner_gen.c` checks them
  and writes `ck_owner_prov.h` into the OUT directory (never committed). It
  refuses the RFC 8032 TEST 1/2/3 public keys, the TEST machine id, the TEST
  store uuid, all-equal bytes, wrong lengths, non-hex, duplicates and unknown
  names. Real owner files are never committed.
  The owner file for a YubiKey-held owner key is made by `scripts/pi5-8/owner_pubkey_file.sh` from the exported PIV public key
  (`docs/native/PI5-8-OWNER-CEREMONY.md`, gate `scripts/ck_pi5_owner_check.sh`).
- What the image uses: the machine id becomes the ARGUS machine id, the store
  uuid the boot Store uuid, and the boot log prints a SHA-256 fingerprint of
  the owner root key. Nothing in the kernel verifies with the owner root key
  yet.
- **Production Store keys: TPM Slot 0 is BLOCKED_HARDWARE, Slot 1 recovery
  unlock is implemented (P04 cut 1).** Store keys derive from K_vol (ADR
  0017), which is secret and cannot come from public material.
  `ck_store_production_keys` (the TPM Slot 0 path) still always refuses
  (`CK_SB_E_BLOCKED_OPERATOR`), so a diagnostic hardware staging boot prints
  `store: REFUSED proof=keyed step="production Store key source"` and neither
  reads nor formats the disk. A `CK_SERVICE` image instead keeps the NVMe
  bound and comes up LOCKED; the operator types `unlock <64-hex recovery
  secret>` on the serial console and `ck_store_unlock_boot`
  (`svc/store_boot.c`) runs the ADR 0017 section 2.4 Slot 1 path: on a blank
  disk it draws K_vol, salt and nonce from the entropy service (refused when
  RNDR is), wraps K_vol into a Recovery_RawSecret descriptor (HKDF-SHA256
  KEK) and commits the KeySlotManifest (kind 21) with the first boot record;
  on a non-blank disk it reads the manifest before any key exists, unwraps
  K_vol and opens the Store with PRODUCTION-class keys. A wrong secret fails
  the AES-GCM-SIV tag before the disk is opened; the secret is echoed as `*`
  and never printed. Under `CK_HARDWARE_STAGING` the manifest uuid must be
  the provisioned store uuid. Limits: no TPM path, no key rotation
  (`active_key_epoch` 1), manifest not yet bound into the secman
  `keyslot_manifest_id`. `store_boot_run` refuses TEST-identity keys in a
  hardware staging build before any disk access (host test `stage_test`,
  including `test_unlock_recovery`; QEMU rows 168-170).
- **Production continuity on the service lifecycle (P05 cut 1).** Every
  Store open of a `CK_SERVICE` image (boot with keys, or `unlock`) runs
  `svc/continuity_service.c`: an unprovisioned Store gets the identity
  (AgentRoot, AgentState, Manifest) and the ALLEN subject minted in one
  sealed transaction with RNDR entropy (no entropy: refused, nothing
  written); a provisioned Store has the subject restored read-only, then the
  identity resumed at incarnation + 1. A refusal erases the Store keys and
  keeps the lifecycle LOCKED. The TEST-ONLY mode selection
  (`continuity_boot.c`, `CK_TEST_CONTINUITY`, the `AIENCONT` plan line) and
  the Recovery Core are never in a service image (`cont_check`). Serial lines
  `continuity: PROVISIONED|RESUMED|REFUSED ...` and `allen: GENESIS|RESTORED
  ...`; `status` appends `continuity=...`. Limits: the approved note is not a
  Cortex record yet (P06); no Recovery Core, no TPM; aienos#285 not
  triggered; physical disk qualification NOT_RUN (host test
  `test_continuity_service`; QEMU rows 171-173).
- **Resident inference in the hardware service image (aienos#34, gate N3).**
  The one supported hardware inference build is the service image with the
  model from the verified boot disk:

      cargo build --release --target aarch64-unknown-none --manifest-path crates/aienos-infer-kernel/Cargo.toml
      make -C native/kernel full CK_SERVICE=1 CK_HARDWARE_STAGING=1 \
          CK_OWNER_PUBKEYS=<owner public keys file> CK_MACHINE_ID=<machine id file> \
          CK_INFER_LIB=<path to libaienos_infer_kernel.a> CK_FB_HOLD_S=120
      # -> target/native-kernel/full-service-hardware-staging/BOOTAA64.EFI

  It compiles `core/infer.c` with `CK_INFER_DISK_ONLY`: the fw_cfg model
  reader is not compiled in (Makefile `fwcfg_check` greps the image for
  `fw_cfg`, `opt/aienos/model` and the `fw_dma_read` symbol), the model comes
  only from `MODEL.MAP` read by the UEFI stub (`native/boot/efi_model.c`),
  the kernel recomputes the pinned SHA-256 before decoding, and with no map
  it prints `infer: ingest REFUSED (no boot-disk model ...)` and the
  lifecycle refuses `prompt` ("no inference unit"). The Makefile still
  refuses with hardware staging: `CK_INFER_LIB` without `CK_SERVICE` (the
  one-shot probe image), `CK_SERVICE_TEST_KEYS`, `CK_TEST_FWCFG_ARTIFACTS`,
  every other `CK_TEST_*` flag, `CK_RUST_LIBS`, `CK_QEMU_UNSAFE_DMA`,
  `CK_CONSOLE_SESSION` and missing owner files. The QEMU inference images
  (probe, test-keys service) keep their TEST-ONLY fw_cfg source unchanged.
  Staging: `scripts/stage_one_time_boot_ck_service.sh --dry-run|--apply`
  builds the image twice in clean folders, makes `MODEL.MAP` against the
  pinned model, prints every write with its SHA-256 and (dry run) writes
  nothing; `--target-image IMG --extents ...` stages a disk image instead of
  the machine. Proof: `scripts/qemu_ck_service_disk_test.sh` (GATES.md
  SERVICE_DISK rows 200-210: refusals, dry run byte-identical, two cold boots
  on one emulated disk with generated owner files and secrets, two negative
  controls); `--build-only` runs the `make` refusals alone. Limits: QEMU
  only; Spark NVMe, Spark console input and the owner key ceremony NOT_RUN.
- Proof: `scripts/ck_owner_keys_check.sh` (build only, takes the quiet flag)
  checks the refusals, the generator refusals, and builds the hardware staging
  image from the labelled TEST-fixture files in `tests/fixtures/owner/`
  (public bytes only, distinct from every old TEST constant), then greps the
  ELF and EFI. Ends `CK_OWNER_KEYS_CHECK: PASS`. CI runs it.
- Not covered: the untrusted RFC 8032 TEST 1/2 public key constants
  (`artifact/format.c`, used only by the `CK_SEED0B_TEST_ANCHOR` build and the
  host tools) are still present as data in every image, including hardware
  staging; the ordinary loader trusts no anchor.

## 2017 iMac image (AIENOS-IMAC-KERNEL-0, x86_64)

    make -C native/kernel imac-kernel        # target/native-kernel/IMACKERN.EFI
    scripts/qemu_ck_imac_kernel_test.sh      # QEMU q35 + OVMF, two CPU models, ends AIENOS_IMAC_KERNEL

The first cut of the C kernel core on x86_64, for the owner's 2017 iMac
(iMac18,3, Core i5-7500; hardware facts in
`evidence/imac_boot0_2026-10-16/`). `x86/efi_x86.c` is the UEFI stub (GOP via
`../boot/efi_gop.c`, RSDP, memory map, ExitBootServices) and hands over the same
CHANDOF3 record, checked by `core/handoff_check.c`; `x86/kmain_x86.c` loads its
own GDT, TSS and IDT (`x86/trap.S`), builds its own identity page tables (2 MiB
pages: RAM write-back, everything else uncached, the framebuffer write-combining,
a 4 KiB guard page under the stack), proves the guard page faults and the fault
is contained, measures the TSC against the HPET, runs the local APIC timer
(xAPIC) for 20 interrupts at 100 Hz, starts every other core the MADT lists
(INIT-SIPI-SIPI into the `x86/smp_x86.S` trampoline below 1 MiB; each core loads
the kernel's tables, checks in and halts), then walks PCI (`x86/pci_x86.c`, MCFG
ECAM window; device registers above the identity map are mapped on demand) and
reads every disk without writing. SATA through `x86/ahci_x86.c` (polled, no
controller or port reset, only IDENTIFY DEVICE and READ DMA EXT exist and the
build refuses any other ATA command); NVMe through the shared
`../disk/disk_nvme.c` (the build refuses any nvme_write or nvme_flush call from
`x86/`). Both disk_dev write hooks always refuse, serial numbers and MAC
addresses are never printed, and each disk's GPT is checked by the shared
`dev/disk_part.c` (both copies, CRCs, the AIENOS partition located if present).
The Broadcom BCM57766 Ethernet chip (14e4:1686) gets a polled driver
(`x86/tg3_x86.c`: core reset, bootcode handshake, rings in one DMA block below
4 GiB, PHY autonegotiation; it never reads received frames and the MAC address
is never printed). In the default image it only detects the link: frame
transmit is not compiled in. The last line before the hold is a one-line
`summary:`. It prints `kernel: alive`, holds the screen 60 s and powers off
through ACPI S5.

**Network report: lab-only, opt-in, unauthenticated.** `make -C native/kernel
imac-kernel CK_X86_REPORT=1` builds a separate lab image,
`IMACKERN-LAB.EFI`, that adds `x86/report_x86.c`, `../net/aienos_net.c` and
tg3 transmit. The default `IMACKERN.EFI`, and any resident or service (ALLEN)
build, contain none of it; the link step fails a default image that has a
report symbol. During the hold the lab image sends, every 2 s while the link
is up, an allowlisted copy of the console (`ck_x86_report_filter`: only
complete, printable lines of at most 240 bytes whose key is on a fixed list of
kernel diagnostic keys; everything else, including `memory:`, is dropped
whole, so chat, keys, tokens and credentials cannot enter it), as UDP
broadcast from 0.0.0.0 to 255.255.255.255 port 47031 (TTL 1), in 1 KiB parts
that each start with
`AIENOS-IMAC-REPORT v=2 auth=none run=<id> part=<i>/<n> bytes=<total>`.
Anyone on the LAN can read or forge these datagrams; the run id and checksum
are not authenticity, so a report is never a receipt, evidence or a command.
Future service diagnostics belong on the authenticated transport with an
explicitly authorized peer. `tools/ck_imac_report_listen.c` (`make -C
native/kernel imac-report-listen`, run as `ck_imac_report_listen 47031 OUTDIR
SECONDS`) says so when it starts, refuses the retired v=1 raw-console format
and rebuilds each run into `OUTDIR/imac-<run>.unauthenticated.txt`;
`scripts/ck_imac_report_test.sh` checks the default and lab builds' symbols,
the allowlist (sentinel lines never leave), the frames and reassembly on the
host.

Output: the GOP framebuffer
(`core/fbcon.c`, lines from before ExitBootServices replayed onto it) and COM1
when a 16550 answers there (QEMU; the iMac has none). Shared, unchanged:
`core/fbcon.c`, `fmt.c`, `acpi.c`, `handoff_check.c`, `mm/frames.c`, `heap.c`,
`dev/disk_part.c`, `../disk/disk.c`, `../disk/disk_nvme.c`. The QEMU test runs four
cores and attaches a SATA data disk and an NVMe disk, each with a GPT from
`ck_gpt_image`, and fails unless three cores check in, the kernel finds each
AIENOS partition where the tool wrote it and both disks are byte-identical
afterwards. Not yet: work scheduled on the other cores, x2APIC, NX, disk writes,
VT-d, receiving on the network, a store. QEMU (no BCM57766 there)
qualifies nothing physical; copy the image to a FAT stick as
`EFI/BOOT/BOOTX64.EFI` and start it from the Option-key boot picker.

## Raspberry Pi 5 image (AIENOS-PI5 step 1)

    make -C native/kernel pi5            # target/native-kernel-pi5/BOOTAA64.EFI (-DCK_PI5=1 -DCK_KLOG=1)
    scripts/ck_pi5_build_check.sh        # build only, ends CK_PI5_BUILD: PASS

The Pi image is the default core image plus board glue (`core/pi5.c`). The
default and QEMU images link none of it: the hooks in `include/ck.h` are weak
and absent, and `scripts/ck_pi5_build_check.sh` checks both images.

**Pi unlock image (PI5-4 cut 1, `make pi5-unlock`, `CK_PI5_UNLOCK=1`).** A
separate image from `pi5-store`: the Store opens only through the ADR 0017
Slot 1 recovery-secret path (`ck_store_pi5_unlock_run` calls
`ck_store_unlock_boot` with the hardware policy). `ck_store_test_keys` and
`ck_store_test_uuid` are not compiled, a TEST-identity key is refused before
any disk access, a Store without a KeySlotManifest (for example a TEST-tier
Store) is refused, a wrong secret fails the K_vol unwrap tag, and every refusal
writes nothing. The secret source is `ck_pi5_unlock_secret` in `core/pi5.c`;
this cut compiles in no source, so the Store stays closed
(`unlock_source: none`). The Makefile refuses the flag with `CK_PI5_STORE`,
`CK_SERVICE`, `CK_HARDWARE_STAGING` and the test flags. Host test:
`make pi5-unlock-test` (`dev/tests/pi5_unlock_test.c`); image checks:
`scripts/ck_pi5_build_check.sh`. Tier label in receipts:
`PI5-UNLOCK-QUALIFICATION`. Not a production image: no TPM, no operator
ceremony.

**Card unlock request (PI5-4 cut 2, `make pi5-unlock-card`, QUALIFICATION ONLY).**
`CK_PI5_UNLOCK_CARD=1` (needs `CK_PI5_UNLOCK=1`, own OUT directory) adds the
one secret source the Pi can have without a TPM or a serial reader: a
THROWAWAY recovery secret in `\EFI\AIENOS\UNLOCK.REQ` on the card (`core/unlock_req.h`,
512 bytes, tier tag `QUALIF-THROWAWAY`). The UEFI stub reads it before
ExitBootServices (`boot/efi_unlock.c`, reads only), the Store stage takes the
secret once and runs the Slot 1 path as if the operator had typed `unlock`
(first-time setup on a blank Store). The boot log says
`unlock_source: card request file (QUALIFICATION ONLY, throwaway secret)`; the
secret is never printed. `pi5-run.sh UNLOCK_REQ=<file>` places the file and
zeroes and deletes it from the card after the run, checking it is gone;
`scripts/pi5_unlock_req.sh` writes a throwaway request (never inside a git
checkout). `CK_PI5_PRODUCTION` is reserved for a future production Pi image: the
Makefile refuses it, so the card source can never be combined with it. A
production image must read its secret from the operator, never from the card.

| Piece | What |
| --- | --- |
| `dev/pi5_wdt.c` | BCM2712 PM watchdog (Linux `bcm2835_wdt.c` registers), armed for `CK_PI5_WDT_S` (15 s) at start, petted at every `ck_set_stage`. A hang resets the board; on the hub the tryboot one-shot flag is already cleared, so it comes back on normal Linux. |
| `core/pi5.c` | Brings up the microSD host with `native/disk/disk_sdhci.c` at a fixed address (the DSDT computes `\_SB.SDC0` `_CRS` in a method the static ACPI scanner does not run; same range as Linux `bcm2712.dtsi` sdio1), clock 200 MHz (`clk_emmc2`), PIO only, so the missing SMMU does not matter. Reads sector 0 and checks the MBR signature. |
| `core/klog.c` | RAM copy of everything printed: the first 192 KiB plus the last 64 KiB. |
| `core/klog_slot.h`, `../boot/efi_klog.c` | The card log slot. Before ExitBootServices the UEFI stub reads `\EFI\AIENOS\KLOG.MAP` (absolute first sector, sector count, nonce) and keeps it only if it checks and exactly one whole disk holds a matching empty slot header there. |
| `ck_pi5_before_reset` | Runs inside `ck_reset` (the normal end and every panic). It re-reads the slot header with the kernel's own SD driver, refuses on any mismatch or if the card size differs from what the firmware saw, writes the log text after the header, flushes, then writes the WRITTEN header last and reads it back. One try only. |

The image cannot boot in QEMU (the SD host and PM addresses are Pi 5 only). It
runs on the hub Pi with the one-shot tryboot runner, which prepares the slot
(one contiguous 2 MiB file, its raw card sector read back and compared before
the map is written) and pulls the log back after the hub returns to Linux.
The runner is `scripts/pi5/pi5-run.sh` (run from the Spark). A Pi build made from a
tree with uncommitted changes to tracked files stamps `aienos_commit: <HEAD>-dirty`
(the default image never does); the runner reads the stamp out of the EFI, logs it in
`run.log`, and says "NOT commit-bound (dirty build)" for a `-dirty` image. Hardware
receipts from earlier runs are in `evidence/pi5_hardware_runs_2026-10-13/`.

## Known hardware risk: disk footprint (CK gate DISK_LAYOUT: NOT_RUN)

**Do not boot the C kernel on a disk holding data until CK gate `DISK_LAYOUT`
is PASS on a forge receipt.** That gate is NOT_RUN (MISSING_IMPLEMENTATION, fix
in progress).

The kernel is partition-unaware. At every boot it writes and restores the last
4 KiB unit of the whole NVMe namespace (`dev/nvme_bind.c:93-127`, called at
`:224`) and uses the first 16 KiB as the anti-rollback anchor
(`dev/disk_layout.h:3,12`; `svc/store_boot.c:164-170`). On a GPT disk those
areas hold the protective MBR, the primary GPT and the backup GPT. Details and
the operator-facing warning: `docs/TRUST-1-OPERATOR-STEPS.md`.

## Operator input and recovery access (C kernel)

Status: **QEMU only.** CK gate `KEYBOARD` (rows 25-32, 30a-30c, 32a and 32b in
`GATES.md`) runs in QEMU; no physical keyboard, xHCI controller or SMMU has
been exercised by this code. Hardware NOT_RUN.

What is implemented (NEXT-PHASE-3 cut 1):

- **Device discovery.** The devices stage finds the USB host controller on
  the PCI ECAM walk by class code 0x0c0330 (xHCI), after ExitBootServices and
  after the bus-master sweep. It gets DMA only through the xHCI DMA fence
  (`dev/xhci_fence.c`): SMMU window first, no SMMU means no DMA. Then
  `dev/usb_kbd.c` resets the controller, finds the first connected port with
  a USB HID boot keyboard, addresses it, configures its interrupt IN
  endpoint and polls it. Polled only: no interrupts, no scheduler, no Store.
- **Key decode** to one small fixed US keymap (`dev/usb_hid.c`): a-z (with
  Shift: A-Z), 0-9, space, `-`, `.`, `/`, Enter, Backspace, Escape. Every
  other key is ignored. A held key produces one event, not a repeat.
- **Line input** with echo and a bound of 64 characters. One key past the
  bound makes the whole line fail closed: at Enter it is refused
  (`keyboard_line: overflow (line refused: N keys typed, limit 64)`) and never
  run. The Rust shell drops the extra keys instead; this is the one deliberate
  difference. The line feeds the same six commands as the Rust shell: `help`,
  `mem`, `el`, `report`, `uptime`, `exit`.
- **Recovery-access hook.** Right after the keyboard is ready the kernel
  prints `recovery_access: waiting 5000 ms for an operator key (r = recovery
  console; any other key or no key = normal boot)` and records the first key:
  `r` gives `recovery_access: choice=recovery reason=key-r`, any other key
  gives `choice=normal reason=other-key`, no key gives `choice=normal
  reason=timeout`. Without a usable keyboard it prints `recovery_access:
  unavailable (no operator keyboard: xhci=<state>); choice=normal
  reason=no-keyboard` and does not wait.
- **Recovery console: a stub.** On `r` the xHCI is halted and fenced, then
  the NVMe and virtio-net DMA are released, then the screen shows
  `recovery_console: STUB ...`, `recovery_console: identity
  build_sha256=<64 hex> commit=<commit> (image build identity; not an owner
  or machine identity)` and `recovery_console: halted (no device DMA live;
  power-cycle to leave)`. The digest is SHA-256 over
  `AIENOS-CK-RECOVERY-IDENTITY-V1`, one zero byte, and the commit the image
  was built from, so anyone can recompute it from the commit. The CPU then
  stops for good. It never touches the disk and has no commands.

Bus. The Rust kernel and both QEMU gates use a PCI xHCI controller
(`qemu-xhci`, class 0x0c0330) with a `usb-kbd` attached. The C driver looks
there first, then at the ACPI platform controllers (below).

**The Spark's USB controllers are not on PCI** (MEASURED under Ubuntu on
2026-10-05, read only: no PCI function has class 0x0c03). They are six ACPI
platform devices, bound by Linux `xhci_plat_hcd` through the ACPI id
`PNP0D15` (an xHCI controller). The DSDT describes each one as
`Device (USBn) { Name (_HID, "NVDA8000") Name (_CID, "PNP0D15") ...
Method (_CRS) { Name (RBUF, Buffer () { Memory32Fixed ... }) Return (RBUF) } }`
(`_DSD` names a MediaTek xHCI, `xhci-nvidia-mediatek-host`). The DGX Spark
hardware guide lists four USB Type-C ports on the rear panel and is silent on
the controllers behind them. Which controller serves which rear port is
UNKNOWN.

Platform xHCI discovery (NEXT-PHASE-3 cut 2). The fence now tries the PCI
xHCI first (QEMU, and any machine with one) and, when there is none or it
has no keyboard, the ACPI platform controllers:

- **Walker** (`core/acpi_dev.c`, `core/acpi_platform.c`): a bounded static
  scan of the DSDT (from the FADT) and every SSDT in the XSDT for `Device`
  objects with `_HID` or `_CID` in `NVDA8000`, `NVDA8001`, `PNP0D10`,
  `PNP0D15`, reading the first memory range of a constant `_CRS` template.
  Nothing is executed: `_STA` is not evaluated. A table with a bad
  signature, a bad checksum or a length past what is mapped is refused and
  counted (`acpi_scan: tables=N refused=R first_refusal=E devices=M`).
  Positive control on every boot: the Arm PL011 UART id `ARMH0011`.
- **SMMU stream by ACPI name** (`ck_dma_confine_named`, `core/smmu_svc.c`):
  the IORT named component whose name ends in the device's name gives the
  stream id, as the IORT root-complex mapping does for the NVMe and the PCI
  xHCI. Two components with that name, no single-id mapping, or a stream
  behind an SMMU other than the one this kernel drives (`OtherSmmu`) are
  refused: the controller is left halted and gets no DMA.
- **Per controller** (`dev/xhci_fence.c`): map the range, halt whatever the
  firmware left running, ask for the confined window, run the same keyboard
  phase, then halt, reset (HCRST) and return the stream to abort. A platform
  controller has no bus-master bit; the SMMU stream is the gate.

Spark firmware tables (MEASURED, read only with `sudo cat
/sys/firmware/acpi/tables/<name>`; acpidump and iasl are not installed;
decoded by `tools/ck_acpi_scan.c`, which runs the kernel's own scan; Linux
names and SMMU placement from `/sys`):

| Linux device | ACPI name | `_HID` / `_CID` | main MMIO (`_CRS` first range) | IORT stream | SMMUv3 |
| --- | --- | --- | --- | --- | --- |
| NVDA8000:00 | `\_SB_.USB0` | NVDA8000 / PNP0D15 | 0x1db60000 + 0x7800 | 0x0 | 0x13800000 (first in IORT) |
| NVDA8000:01 | `\_SB_.USB1` | NVDA8000 / PNP0D15 | 0x1db90000 + 0x7800 | 0x1 | 0x13800000 |
| NVDA8000:02 | `\_SB_.USB2` | NVDA8000 / PNP0D15 | 0x1dde0000 + 0x7800 | 0x2 | 0x13800000 |
| NVDA8000:03 | `\_SB_.USB3` | NVDA8000 / PNP0D15 | 0x1de10000 + 0x7800 | 0x3 | 0x13800000 |
| NVDA8001:00 | `\_SB_.USB4` | NVDA8001 / PNP0D15 | 0x1d860000 + 0x7800 | 0x4 | 0x13800000 |
| NVDA8000:04 | `\_SB_.USB5` | NVDA8000 / PNP0D15 | 0x1d870000 + 0x7800 | 0x5 | 0x13800000 |

Each `_CRS` has three more memory ranges (+0x8000 size 0x100, a 0x4000 or
0x5000 block, and a 0x18-byte register window), an interrupt and a GPIO
interrupt; the walker takes only the first, the xHCI register block that
Linux `xhci_plat_hcd` maps. Table digests are in
`tests/fixtures/spark_xhci_acpi_expected.txt`.

**What the Spark will print** (INFERRED from those tables, high confidence;
hardware NOT_RUN): the walker finds all six controllers, and every one is
then **denied** with `dma_gate: xhci USBn denied (SmmuNotReady), controller
left halted`. The reason is not USB: the kernel's SMMU service refuses the
Spark's IORT as a whole (`smmu: IORT malformed, SMMU unusable (fail
closed)`), because the first SMMUv3 (0x13800000, the one behind the USB
controllers) has 15 PCI root-complex mappings (the service keeps at most 8)
with stream ids up to 0xfffff (its linear stream table holds 0x0-0xfff).
The same refusal already applies to the NVMe on the Spark. The USB streams
themselves (0x0-0x5) would fit. So on the Spark this cut still gives
`keyboard: unavailable (no keyboard on any platform xHCI)` and normal boot,
now for a stated reason, and fails closed. Making the SMMU service accept
the Spark IORT (a two-level stream table, more root-complex mappings) is
the next cut. Also UNKNOWN until a hardware run: whether the MediaTek glue
around each controller is powered and clocked when the kernel reads its
registers (Linux handles that in firmware `_STA`/`_PS0` and its own glue
driver; reading a powered-down block could fault), and whether
`ck_mm_mmio_try_map` accepts these ranges. The exact expected lines are in
`tests/fixtures/spark_xhci_acpi_expected.txt` (KEYBOARD row 32b, NOT_RUN).


### Service lifecycle serial input (native v1 N1, aienos#328)

Status: **host-tested 16550, QEMU PL011.** `GATES.md` rows 167c-167f. Hardware NOT_RUN.

- **One console table.** The boot stub picks the console UART from the ACPI SPCR once (`ck_console_set_uart`); output and operator input both use it. PL011/SBSA (types 0x03, 0x0d, 0x0e: QEMU virt) and 16550 (types 0x00, 0x01, 0x12). The DGX Spark's SPCR (read on the machine 2026-10-12) is type 0x01, a 32-bit dword-spaced 16550 at 0x16A00000; before this cut the kernel refused that type, so by the code (not observed on the machine) it had no serial console on the Spark at all.
- **Polled, never interrupt driven.** The lifecycle polls the receiver between its steps and, while the model generates, between generation steps, so `cancel` works. No UART register is written: the line speed is whatever the firmware left (the SPCR says 115200; UNVERIFIED on the machine).
- **Bounded lines.** `core/line_rx.c`: 144 bytes; an overlong line, or one in which the UART reported an overrun, parity, framing or break error, is refused whole and never run.
- **Refusals.** No supported UART: `lifecycle: REFUSED console input unsupported on this platform` and the stop order. Receiver off or not answering: `REFUSED console input not ready`.
- **Operator step.** A serial cable (3.3 V) to that UART and a terminal on the other end. Whether the Spark exposes it on a reachable connector is UNVERIFIED. The local USB keyboard on the service image is a separate cut.

### Console session (Campaign 3 cut C3-1a, QEMU test image only)

Status: **QEMU only.** CK gate `CONSOLE` (rows 146-155 in `GATES.md`). Hardware NOT_RUN. The default image does not contain it.

`make full CK_CONSOLE_SESSION=1` builds a TEST-ONLY image with a final boot stage `console`, entered only after every other boot step. The bounded boot shell above (60 s, idle 15 s) and the recovery window are unchanged. The session then keeps taking input for as long as the operator uses it, with no time limit and no idle exit, until the shell's `exit`:

- **Two sources, one line.** Serial receive (polled, on the UART the console already prints to: PL011/SBSA or 16550 per the ACPI SPCR, `core/uart_rx.h`; the kernel only reads UART registers and never reconfigures the UART) and the USB keyboard both feed the same 64-byte line editor and the same shell. Printable keys only; a 65th key makes the whole line refused.
- **No interleaving inside a line.** The first source that types into a line owns it until Enter. Keys from the other source are dropped and counted in a printed line: `console_input: dropped N key(s) from <source> while <owner> owned the line`.
- **DMA confinement unchanged.** The USB half runs inside a second xHCI fence: SMMU window first, no SMMU means no DMA, and its DMA stays in that one window for the whole session. `exit` halts the controller, turns bus mastering off, returns the stream to abort and prints the same revoke lines. If the keyboard is unavailable, is unplugged (PORTSC connect bit clear) or its endpoint halts, the fence is revoked and serial goes on alone. Only a printable key claims a line, so Backspace on an empty line cannot lock the other source out.
- **No new authority.** The console runs the existing commands only (`help mem el report uptime exit`).

Not yet: any recovery-access change and any hardware run (the Spark's UART and USB are unmeasured by this code; 16550 receive, aienos#328, is host-tested only).

### Physical attended boot: what it will look like

Both prerequisites named in cut 1 now exist: ACPI discovery of the Spark's
platform xHCI controllers (above) and a staging command for the full
hardware image, `scripts/stage_one_time_boot_ck_full.sh` (`--dry-run` prints
every command and touches nothing; `--apply` builds `make full
CK_HARDWARE_STAGING=1` with the operator's own owner files, copies it to
`\EFI\AIENOS\aienos-ck-full.efi`, and sets BootNext once; it never
reboots). The B7b probe boot has its own variant,
`scripts/stage_one_time_boot_ck_b7b.sh` (adds `CK_B7B_PROBE=1`, builds
twice and refuses on a digest mismatch, stages `aienos-ck-b7b.efi`). Do not run it yet: until the SMMU service accepts the Spark IORT,
the run can only show the fail-closed deny lines above, not a keyboard.
The steps below are the procedure that run will follow, so it can be
reviewed now.

Ground rules: nothing here changes firmware settings, Secure Boot keys or the
TPM. The boot is one-time (BootNext): the next restart returns to Ubuntu on
its own. If anything looks different from "What you should see", write down
or photograph the screen and hand it to the orchestrator. Do not retry or
improvise.

1. **Plug in.** At the Spark, with Ubuntu running:
   - the HDMI monitor on the rear HDMI port (the kernel writes to the screen;
     there is no other console you can see);
   - a plain wired USB keyboard in one rear USB Type-C port (use a USB-A to
     USB-C adapter if needed; a wireless or Bluetooth keyboard will not work,
     and a keyboard with a built-in hub may not);
   - the AIENOSRECOV recovery stick, so the firmware's recovery entry
     (Boot0004) is there if anything goes wrong.

   *You should see:* nothing changes on screen yet.

2. **Stage the one-time boot** with `scripts/stage_one_time_boot_ck_full.sh`,
   `--dry-run` first, then `--apply`, with `AIENOS_OWNER_PUBKEYS` and
   `AIENOS_MACHINE_ID` set to the operator's own files (the orchestrator
   names them for that run; the TEST-FIXTURE files are refused). *Changes:* it copies the
   image to the EFI system partition and sets BootNext once; it never
   reboots. *You should see:* the dry run's list of commands, then the apply
   ending without `FAIL`.

3. **Restart** with `sudo reboot`. Do not touch the keyboard until the screen
   shows AIENOS lines (white text on black, starting with the boot report).

4. **Normal boot (do nothing).** Watch for, in order:
   `xhci_acpi: 6 platform controller(s)`, `xhci_plat: USBn try ...`,
   `dma_gate: xhci USBn granted (Confined) smmu=0x13800000 stream=0xn`,
   `keyboard: ready (port P, slot S, endpoint 0x81)`, then
   `recovery_access: waiting 5000 ms ...`. Keep your hands off for those 5
   seconds. *You should see:* `recovery_access: choice=normal reason=timeout`,
   then `keyboard: shell ready` and the prompt `aienos> `.

5. **Type a line.** Type `help` and press Enter. *You should see:* the
   letters appear as you type, then `keyboard_line: help` and `commands: help
   mem el report uptime exit`. Type `exit` and press Enter. *You should see:*
   `keyboard: done (exit)`, `dma_gate: xhci bus master revoked`, and later
   `report_kind: final`. The screen holds the last report, then the Spark
   restarts into Ubuntu by itself.

6. **Recovery boot (second attended boot, staged again as in step 2).** This
   time, as soon as `recovery_access: waiting 5000 ms ...` appears, press
   `r` once. *You should see:* `recovery_access: choice=recovery
   reason=key-r`, `devices: recovery halt nvme=released
   virtio_net=released xhci=released`, `recovery_console: STUB ...`,
   `recovery_console: identity build_sha256=<64 hex> commit=<commit>` and
   `recovery_console: halted (no device DMA live; power-cycle to leave)`. The
   machine then stays on that screen. Photograph it. Then hold the power
   button until the Spark turns off, wait ten seconds, and press it again.
   *You should see:* Ubuntu starts as usual (BootNext was used up).

What success looks like: steps 4 to 6 show exactly those lines, the identity
digest on the photo equals the one the orchestrator recomputes from the
commit, and Ubuntu comes back after each boot with nothing changed on its
disk. Any `report_kind: panic` or `report_kind: fault`, a missing
`bus master revoked` line, or a keyboard that is ready but ignores typing is
a FAIL to report, not to retry.

## Boot sequence

1. UEFI stub: pre-exit report on ConOut, memory map, `ExitBootServices`.
2. `ck_kernel_entry` (firmware EL, firmware MMU): vectors, PSCI conduit
   from the FADT (HVC or SMC, default SMC), own page tables, stack, heap,
   DMA pool.
3. `ck_enter_el1`: EL2 -> EL1h with the MMU already on our tables.
4. EL1: `mmu: enabled`, `mmu_switch: ...` read back from the registers,
   heap check, guard-page self test, GICv3 from the MADT, 200 ms timer window
   (INTID 30, 10 ms period), `kernel: alive`, `kernel_el: EL1h`.
5. Stages, in order, if linked: `ck_stage_devices`, `ck_stage_security`,
   `ck_stage_store`. Each prints `stage <name>: ok`, `stage <name>: FAIL
   rc=<n>` or `stage <name>: not linked`.
6. `report_kind: final`, then PSCI SYSTEM_RESET (WFI loop if refused).

Every reset (final, panic or fault) first calls the stage hook
`ck_stage_quiesce` once, if linked: the devices stage releases a still-live
NVMe controller (NVMe normal shutdown, CC.SHN = 01b then wait for CSTS.SHST
= 10b, bounded 5 s; if it cannot (fatal status, not ready, timeout) it clears
CC.EN and waits up to 1 s for CSTS.RDY = 0, printing `nvme: shutdown
fallback disable ...`; then bus master off; then the SMMU stream back to abort)
and prints `devices: quiesce before reset nvme=none|released-now|already-released`.
The normal store path already released it, printing `nvme: shutdown normal
cc=..->.. csts=.. shst=complete waited_us=N` before `dma_gate: nvme bus master
revoked`. Code: `dev/nvme_shutdown.c` (register sequence, host-tested in
`svc/tests/stage_test.c`), `dev/devices.c`.

A panic prints `report_kind: panic`; an unexpected exception prints
`report_kind: fault` with ESR, FAR and ELR. Both then reset. Before the drop
to EL1, VBAR_EL2 points at a separate fatal-only table (`ck_vectors_el2`):
any EL2 exception reports ESR_EL2/FAR_EL2/ELR_EL2 (`el=2`) from the emergency
stack and resets; it never returns or touches EL1 state. After the stages,
`mm_usage:` prints the stack high-water mark (painted stack) and the heap
low-water free bytes.

## Memory map the kernel builds

- RAM (UEFI RAM types with the WB attribute): Normal write-back, RW,
  never executable.
- Kernel image: text read-only + executable, rodata and relocations
  read-only, data and BSS read-write. Nothing is writable and executable.
- Kernel stack 256 KiB (stages need >= 128 KiB) with an unmapped guard page below. An exception taken
  with SP below the stack floor switches to a 16 KiB emergency stack so the
  fault report still prints.
- Heap 64 MiB (`ck_alloc`, zeroed, 16-byte aligned) with an unmapped guard
  page on both sides.
- DMA pool 8 MiB, Normal Non-cacheable (`ck_dma_alloc`, never freed).
- MMIO via `ck_mmio_map`: Device-nGnRE, never executable; panics if the
  range overlaps RAM.
- The frame allocator only hands out EfiConventionalMemory, minus the image
  and the handoff, and minus the RSDP, the XSDT/RSDT and every table the root
  lists (whole pages). Tables, stack, heap and pool come from it and are never
  handed out again.

## Notes for stage code

- `ck_puts` prints the string as given; it does not add a newline.
- `\n` is sent as CR LF on the UART.
- IRQs are masked when a stage starts and are masked again after it returns.
  Use `ck_irq_register` + `ck_irq_enable` + `ck_irq_cpu_enable(1)`.
- Stage code is listed in `stage.mk` and linked by `make full`, compiled with
  `STAGE_CFLAGS` first, then the kernel flags and `-U_FORTIFY_SOURCE`. The
  core defines no `ck_stage_*` defaults; the core-only image is checked to
  contain none and the full image to contain all three.
- NVMe DMA is granted only SMMU-confined: the core SMMUv3 service
  (`core/smmu.c`, `core/smmu_svc.c`; ck.h `ck_dma_confine` /
  `ck_dma_unconfine` / `ck_dma_faults`) finds the SMMU through the ACPI IORT
  and maps only the NVMe DMA region for the NVMe stream. With no SMMU, NVMe
  DMA is refused. `CK_QEMU_UNSAFE_DMA=1` (TEST-ONLY, QEMU only, refused with
  `CK_HARDWARE_STAGING`) builds the unconfined bypass used only when no SMMU
  exists, and prints the `WARNING: UNSAFE NVME DMA BYPASS` lines.
- The IORT stream id of a PCI device is resolved within its PCI segment
  (`ck_dma_confine(segment, rid, ...)`, `ck_iort_stream_id(s, segment, rid,
  ...)`): each root-complex mapping keeps the root complex's
  `pci_segment_number` (IORT root complex node offset 28, ACPICA
  `actbl2.h`), and a mapping of another segment never matches. The parse
  keeps at most `CK_IORT_MAX_MAPS` (32) mappings to the SMMU and refuses the
  whole table beyond that, and refuses two mappings whose input ranges
  overlap in one segment. The DGX Spark's IORT (MEASURED, read under Ubuntu
  2026-10-05) has 15 root complexes, segment n mapping requester ids
  0-0xffff to streams `0x10000*(n+1)` on the first SMMUv3 (0x13800000), and
  segment 15 on the second SMMUv3. Its NVMe (MEASURED: PCI 0004:01:00.0,
  behind that first SMMU) resolves to stream 0x50000 + (bus 1 << 8 | dev 0
  << 3 | fn 0 = 0x100) = 0x50100. The PCI walk itself (`dev/pci.c`) still
  covers segment 0 only, so every `pci_func` carries segment 0 today.
- Stream table format: when the SMMU reports two-level support
  (`SMMU_IDR0.ST_LEVEL == 0b01`), `core/smmu_svc.c` runs a two-level stream
  table (Arm IHI 0070 H.a, `SMMU_STRTAB_BASE_CFG` FMT 0b01, SPLIT 6, L1STD
  section 5.1) of `MIN(SMMU_IDR1.SIDSIZE, 20)` StreamID bits, so stream ids
  up to 0xfffff (the Spark's 0x50100 included) can be granted; otherwise the
  linear table of 4096 entries as before. Every L1 descriptor starts with
  Span 0 (its streams are terminated by the SMMU); the first grant in a
  64-stream span takes one 4 KiB page, fills it with abort STEs, and only
  then publishes the descriptor (Span 7) with a non-leaf `CMD_CFGI_STE`. Boot
  prints `smmu: stream table 2-level log2size=.. split=6 (spans allocated per
  grant)` or `smmu: stream table linear entries=4096`. QEMU 8.2.2
  `iommu=smmuv3` takes the two-level path (log2size=16), so the existing
  QEMU SMMU rows exercise it; the Spark SMMU's ST_LEVEL and SIDSIZE are
  UNKNOWN until a hardware boot reads them (the NVMe working under Linux at
  stream 0x50100 implies SIDSIZE >= 19, INFERRED). `make smmu-l2-mutants`
  (run by `make test`) checks that test_smmu fails against an overflowing
  Span, L1 descriptors valid before any grant, a misaligned L1 table, and an
  L2 page published without abort STEs.

- The kernel writes only inside the AIENOS partition of the boot disk
  (`dev/disk_part.h`, gate `DISK_LAYOUT`). The GPT is parsed read-only:
  protective MBR, primary and backup headers and entry arrays, all CRC32
  checked and required to agree. Exactly one partition must carry the AIENOS
  type GUID `38DAAC89-5EAD-4B40-8B1E-3687A7418061` (on-disk bytes
  `89 AC DA 38 AD 5E 40 4B 8B 1E 36 87 A7 41 80 61`), inside the usable range
  and overlapping no other partition. The Store, torn-slot device and rw probe
  get only that partition's `disk_dev` view, whose every read, write and
  flush goes through `ck_part_xlate` (bounds-checked partition LBA -> disk
  LBA). Otherwise the kernel prints `disk: no AIENOS partition, refusing
  writes` and the Store reports `no boot disk`; there is no whole-disk mode.
  `CK_TEST_DISK_XLATE_BYPASS=1` (TEST-ONLY mutation, refused with
  `CK_HARDWARE_STAGING`) drops the partition offset so the gate can prove it
  catches that. QEMU disk images come from `make gpt-image`
  (`tools/ck_gpt_image.c`); `ck_store_image` also opens only the AIENOS
  partition.

## Differences from the Rust kernel

- `guard_page: ok fault=contained` is an addition: the C kernel proves its
  guard pages fault and that the fault is handled. The Rust kernel has no
  such test.
- M3 (threads, EL0, preemption, placement, IPC) runs in the core before the
  stages (`core/m3.c`, `core/sched.c`, `core/ipc.c`, `arch/m3.S`; host tests
  `tests/test_sched.c`, `tests/test_ipc.c`) and prints the same five lines as
  the Rust kernel, plus an extra `ipc_detail:` line. Differences in how:
  the EL0 return uses SPSR 0x3c5 (Rust 0x5); EL0 entry zeroes all general
  registers and TPIDR_EL0/TPIDRRO_EL0; the EL0 window uses ASID 0 with a
  full TLB flush (Rust ASID 1); context switches save x19-x30 and sp only
  (no FP/SIMD; EL0 FP/SIMD traps). Placement is computed from the MADT; no
  secondary core is started (same as Rust). See GATES.md rows 16-20.
- MAIR adds a Normal Non-cacheable attribute (index 2) for the DMA pool.
