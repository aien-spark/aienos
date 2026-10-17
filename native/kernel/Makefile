# AIENOS C kernel core (Lane 18): UEFI entry stub + kernel core as one
# AArch64 PE32+ image, plus host unit tests. Toolchain: gcc, binutils, make.
#
#   make                 core-only image $(OUT)/BOOTAA64.EFI (stages print
#                        "not linked"; the M1 gate boots this one)
#   make full            full image with the boot stages (devices, security,
#                        Store) from stage.mk: $(OUT)/full/BOOTAA64.EFI,
#                        NVMe DMA SMMU-confined, refused without an SMMU
#   make full CK_QEMU_UNSAFE_DMA=1
#                        TEST-ONLY QEMU image with the unconfined NVMe DMA bypass:
#                        $(OUT)/full-qemu-unsafe-dma/BOOTAA64.EFI (only
#                        scripts/qemu_ck_store_test.sh sets this; refused
#                        together with CK_HARDWARE_STAGING=1)
#   make full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS=<file> CK_MACHINE_ID=<file>
#                        hardware staging image $(OUT)/full-hardware-staging/:
#                        no TEST Store keys/uuid/machine id (refused without
#                        both files; tools/ck_owner_gen.c checks them); its
#                        Store stage refuses (production key source is
#                        BLOCKED_OPERATOR). scripts/ck_owner_keys_check.sh
#   make full CK_SERVICE=1 CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS=<file> CK_MACHINE_ID=<file> CK_INFER_LIB=<lib>
#                        the production service image with resident inference,
#                        model from the boot disk only (MODEL.MAP, no fw_cfg code):
#                        $(OUT)/full-service-hardware-staging/. Staged by
#                        scripts/stage_one_time_boot_ck_service.sh; proof
#                        scripts/qemu_ck_service_disk_test.sh (aienos#34, gate N3)
#   make full CK_TEST_XHCI_MUTATION=bm-left-on|no-revoke|grant-no-smmu|no-sweep
#                        TEST-ONLY image that breaks one xHCI DMA fence row on
#                        purpose: $(OUT)/full-test-xhci-<name>/ (only
#                        scripts/qemu_ck_keyboard_test.sh --mutation; refused
#                        with CK_HARDWARE_STAGING=1 or CK_QEMU_UNSAFE_DMA=1)
#   make full CK_CONSOLE_SESSION=1 [CK_TEST_CONSOLE_MUTATION=bm-left-on-after-exit]
#                        TEST-ONLY QEMU image with the final "console" boot stage
#                        (serial + USB keyboard input until "exit", no time limit):
#                        $(OUT)/full-console-session/ (the mutation image:
#                        full-test-console-mutation/, bus master left on after the
#                        exit); only scripts/qemu_ck_console_test.sh; refused with
#                        CK_HARDWARE_STAGING=1 or CK_QEMU_UNSAFE_DMA=1
#   make full CK_TEST_STORE_CRASH=1 [CK_TEST_STORE_CRASH_MUTANT=<name>]
#                        TEST-ONLY Store crash hook image
#                        $(OUT)/full-test-store-crash[-mutant-<name>]/ for
#                        scripts/qemu_ck_store_crash_test.sh (M4_STORE_CRASH);
#                        refused with CK_HARDWARE_STAGING / CK_QEMU_UNSAFE_DMA
#   make owner-gen       host tool $(OUT)/host/ck_owner_gen
#   make [full] CK_TEST_FWCFG_ARTIFACTS=1
#                        TEST-ONLY: loader takes candidates from the QEMU fw_cfg
#                        side channel instead of the boot disk Store; own OUT
#                        (target/native-kernel-test-fwcfg); announces itself and
#                        never counts toward a PASS. Default images are checked
#                        to contain no fw_cfg artifact code.
#   make CK_TEST_ROLLBACK=bad-magic|cpu-fault|hang
#                        TEST-ONLY M0_ROLLBACK candidates (bad handoff magic, CPU
#                        fault after "kernel: alive", hang with interrupts masked);
#                        own OUT (target/native-kernel-test-rollback-<mode>); only
#                        scripts/qemu_ck_rollback_test.sh; refused with CK_HARDWARE_STAGING
#   make uefi-vars       host tool $(OUT)/host/ck_uefi_vars: reads BootOrder, BootNext
#                        and Boot#### from an edk2 vars.fd (read-only, M0_ROLLBACK)
#   make [full] CK_B7B_PROBE=1 [CK_B7B_PROBE_TEST_SEGMENT0=1]
#                        B7b preparation probe image (aienos#286): confine the
#                        GB10 requester once, read SMMU_IDR0/IDR1, unconfine;
#                        own OUT (target/native-kernel-b7b-probe); the segment-0
#                        variant is TEST-ONLY (QEMU positive path). Gate:
#                        scripts/qemu_ck_b7b_probe_test.sh
#   make CK_TEST_SMP_SKIP_CPU=1
#                        TEST-ONLY SMP mutation: CPU_ON skipped for one secondary
#                        core (core/smp.c); own OUT (target/native-kernel-test-smp-skip);
#                        the SMP gate must FAIL on it (scripts/qemu_ck_smp_test.sh
#                        --mutation); refused with CK_HARDWARE_STAGING
#   make store-image     host tool $(OUT)/host/ck_store_image: signed artifacts
#                        into the sealed Store inside the AIENOS GPT partition
#                        of an NVMe disk image
#   make gpt-image       host tool $(OUT)/host/ck_gpt_image: GPT boot-disk images
#                        (AIENOS partition between two sentinels, hostile variants)
#                        for the QEMU gates; "find" runs the kernel GPT parser
#   make full CK_TEST_DISK_XLATE_BYPASS=1
#                        TEST-ONLY mutation image for the DISK_LAYOUT gate: the
#                        LBA translation layer (dev/disk_part.c) adds no partition
#                        offset; $(OUT)/full-test-xlate-bypass/ (refused with
#                        CK_HARDWARE_STAGING; never counted toward a PASS)
#   make test            host unit tests            -> CK_CORE_HOST: PASS
#                        (also builds the handoff_check reserved0 mutant
#                        and requires test_handoff to FAIL against it)
#   make sanitize        same under ASan + UBSan    -> CK_CORE_HOST: PASS
#   make continuity-mutants
#                        TEST-only -D mutants of svc/continuity_codec.c must
#                        each fail test_continuity_codec -> CK_CONTINUITY_CODEC_MUTANTS: PASS
#   make continuity-resolve-mutants
#                        TEST-only -D mutants of svc/continuity_resolve.c must each fail
#                        test_continuity_resolve -> CK_CONTINUITY_RESOLVE_MUTANTS: PASS
#   make continuity-commit-mutants
#                        TEST-only -D mutants of svc/continuity_commit.c (and MC-11 of the codec) must
#                        each fail test_continuity_commit -> CK_CONTINUITY_COMMIT_MUTANTS: PASS
#   make continuity-recovery-mutants
#                        TEST-only -D mutants of svc/continuity_recovery.c (MR-1, MR-5, MR-6, MR-7, MR-9) must
#                        each fail test_continuity_recovery -> CK_CONTINUITY_RECOVERY_MUTANTS: PASS
#   make stage-test | stage-sanitize | stage-free   stage host tests (stage.mk)
#   make print-kcflags   flags stage code must be built with
#   make udp-echo        host UDP echo helper for scripts/qemu_ck_net_test.sh:
#                        $(OUT)/host/ck_udp_echo (hosted, test tooling only)
#   make slot-loader CK_SLOT_KEYS=<file> | CK_TEST_SLOT_KEY=1
#                        SLOTLDR.EFI, the signed A/B slot loader in front of the
#                        unchanged image (native/boot/slot_loader.c, P11 cut 2a):
#                        $(OUT)/SLOTLDR.EFI; owner keys baked in from CK_SLOT_KEYS,
#                        or the TEST-ONLY RFC 8032 TEST 1 key; the TEST key is
#                        refused with CK_HARDWARE_STAGING. Gate:
#                        scripts/qemu_ck_slot_loader_test.sh
#   make slot-loader-check  build checks + refusals -> SLOT_LOADER_BUILD: PASS
#
#   CK_EXTRA_CFLAGS=... extra kernel flags for one-off checks, e.g.
#                    -DCK_SELFTEST_EL2_FAULT (brk at EL2: the EL2 fatal path)
# The stages are weak references in ck.h (the core defines no defaults):
# with none linked the kernel prints "stage <name>: not linked".
#
# Output goes to <repo>/target/native-kernel (ignored by git) unless OUT is set.
# Builds natively on an aarch64 host, else with the aarch64-linux-gnu- prefix.
# QEMU is not hardware: nothing built here is physically qualified.

KDIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
NATIVE := $(abspath $(KDIR)/..)
REPO := $(abspath $(NATIVE)/..)
BOOT := $(NATIVE)/boot

HOST_ARCH := $(shell uname -m)
ifeq ($(HOST_ARCH),aarch64)
CROSS ?=
else
CROSS ?= aarch64-linux-gnu-
endif
KCC := $(CROSS)gcc
KLD := $(CROSS)ld
KOBJCOPY := $(CROSS)objcopy
KNM := $(CROSS)nm
KREADELF := $(CROSS)readelf
HOSTCC ?= cc

# Raspberry Pi 5 board image (CK_PI5=1, "make pi5"): the core image plus
# core/pi5.c (PM watchdog, microSD bring-up, console log written to the
# card), core/klog*.c, dev/pi5_wdt.c, the PIO SD driver (native/disk) and the
# UEFI stub's KLOG.MAP reader (native/boot/efi_klog.c). Own OUT, so it never
# replaces a default image. Not for the Spark or QEMU: pi5_wdt.c and pi5.c
# touch BCM2712-only addresses and refuse to build without CK_PI5.
CK_PI5_STORE ?=
ifneq ($(strip $(CK_PI5_STORE)),)
ifneq ($(strip $(CK_PI5_STORE)),1)
$(error CK_PI5_STORE must be empty or 1)
endif
ifneq ($(strip $(CK_SERVICE)$(CK_TEST_STORE_CRASH)$(CK_TEST_CONTINUITY)$(CK_HARDWARE_STAGING)),)
$(error CK_PI5_STORE is the TEST-key qualification tier (SEED-0B-PI5): it cannot be combined with CK_SERVICE, CK_TEST_STORE_CRASH, CK_TEST_CONTINUITY or CK_HARDWARE_STAGING)
endif
CK_PI5 := 1
OUT ?= $(REPO)/target/native-kernel-pi5-store
CK_EXTRA_CFLAGS += -DCK_PI5_STORE=1
endif
# Pi 5 inference image (CK_PI5_INFER=1, "make pi5-infer", PI5-6 cut 2): the plain Pi image plus
# the Rust inference unit (CK_INFER_LIB) and core/infer.c as the one-shot boot-disk probe. Model
# source is MODEL.MAP only (-DCK_INFER_DISK_ONLY=1): no fw_cfg code, and with no map the kernel
# refuses. No Store stage, no service, no resident session. Own OUT; plain pi5 / pi5-store unchanged.
CK_PI5_INFER ?=
ifneq ($(strip $(CK_PI5_INFER)),)
ifneq ($(strip $(CK_PI5_INFER)),1)
$(error CK_PI5_INFER must be empty or 1)
endif
ifneq ($(strip $(CK_PI5_STORE)$(CK_PI5_UNLOCK)$(CK_PI5_AGENT)$(CK_SERVICE)$(CK_HARDWARE_STAGING)$(CK_TEST_FWCFG_ARTIFACTS)$(CK_RUST_LIBS)),)
$(error CK_PI5_INFER is the one-shot Pi inference image: it cannot be combined with CK_PI5_STORE, CK_PI5_UNLOCK, CK_PI5_AGENT, CK_SERVICE, CK_HARDWARE_STAGING, CK_TEST_FWCFG_ARTIFACTS or CK_RUST_LIBS)
endif
ifeq ($(strip $(CK_INFER_LIB)),)
$(error CK_PI5_INFER needs CK_INFER_LIB=<libaienos_infer_kernel.a> (use "make pi5-infer", which builds it))
endif
CK_PI5 := 1
OUT ?= $(REPO)/target/native-kernel-pi5-infer
CK_EXTRA_CFLAGS += -DCK_PI5_INFER=1 -DCK_INFER_DISK_ONLY=1
endif
# Pi 5 PCIe/RP1 enumerator image (CK_PI5_PCIE=1, "make pi5-pcie", AIENOS-PI5 network lane step 1): the plain Pi
# image plus dev/pi5_pcie.c (read-only look at the BCM2712 PCIe2 root complex, RP1's config space and BARs, and
# the inbound DMA window judged against the ADR 0020 bounce region) and dev/dma_window.c. Own OUT; the plain
# pi5, pi5-store and pi5-infer images and the default image carry none of this code.
CK_PI5_PCIE ?=
ifneq ($(strip $(CK_PI5_PCIE)),)
ifneq ($(strip $(CK_PI5_PCIE)),1)
$(error CK_PI5_PCIE must be empty or 1)
endif
ifneq ($(strip $(CK_PI5_NET)$(CK_PI5_STORE)$(CK_PI5_INFER)$(CK_PI5_UNLOCK)$(CK_PI5_AGENT)$(CK_SERVICE)$(CK_HARDWARE_STAGING)),)
$(error CK_PI5_PCIE is the Pi PCIe/RP1 enumerator image: it cannot be combined with CK_PI5_NET, CK_PI5_STORE, CK_PI5_INFER, CK_PI5_UNLOCK, CK_PI5_AGENT, CK_SERVICE or CK_HARDWARE_STAGING)
endif
CK_PI5 := 1
OUT ?= $(REPO)/target/native-kernel-pi5-pcie
CK_EXTRA_CFLAGS += -DCK_PI5_PCIE=1
endif

# Pi 5 network bring-up image (CK_PI5_NET=1, "make pi5-net", AIENOS-PI5 network lane cut 2): the plain Pi image plus
# dev/pi5_net.c (narrows the BCM2712 PCIe2 inbound DMA window to the ADR 0020 bounce region, then brings RP1's
# Ethernet up to the PHY and reads the PHY ID; no frames). Own OUT; no other image carries this code.
CK_PI5_NET ?=
ifneq ($(strip $(CK_PI5_NET)),)
ifneq ($(strip $(CK_PI5_NET)),1)
$(error CK_PI5_NET must be empty or 1)
endif
ifneq ($(strip $(CK_PI5_STORE)$(CK_PI5_INFER)$(CK_PI5_UNLOCK)$(CK_PI5_AGENT)$(CK_PI5_FACT)$(CK_PI5_PCIE)$(CK_SERVICE)$(CK_HARDWARE_STAGING)),)
$(error CK_PI5_NET is the Pi network bring-up image: it cannot be combined with CK_PI5_STORE, CK_PI5_INFER, CK_PI5_UNLOCK, CK_PI5_AGENT, CK_PI5_FACT, CK_PI5_PCIE, CK_SERVICE or CK_HARDWARE_STAGING)
endif
CK_PI5 := 1
OUT ?= $(REPO)/target/native-kernel-pi5-net
CK_EXTRA_CFLAGS += -DCK_PI5_NET=1
endif

# Pi unlock image (CK_PI5_UNLOCK=1, "make pi5-unlock", PI5-4 cut 1): the same Store stage, but the Store opens
# ONLY through the ADR 0017 Slot 1 recovery-secret path (ck_store_unlock_boot, PRODUCTION-class keys).
# ck_store_test_keys and ck_store_test_uuid are not compiled, so no TEST key or TEST uuid can reach it.
# It is a separate image from CK_PI5_STORE (TEST keys) and cannot be combined with any other tier flag.
# PI5-4 cut 2: CK_PI5_UNLOCK_CARD=1 (QUALIFICATION ONLY, "make pi5-unlock-card") adds one secret source to the
# unlock image: a THROWAWAY recovery secret from \EFI\AIENOS\UNLOCK.REQ on the card (core/unlock_req.h). It
# needs CK_PI5_UNLOCK=1 and is a separate image with its own OUT. CK_PI5_PRODUCTION is reserved for a future
# production Pi image; it is not implemented and can never be combined with the card request source.
CK_PI5_UNLOCK_CARD ?=
CK_PI5_PRODUCTION ?=
ifneq ($(strip $(CK_PI5_PRODUCTION)),)
$(error CK_PI5_PRODUCTION is reserved and not implemented: there is no production Pi image yet)
endif
ifneq ($(strip $(CK_PI5_UNLOCK_CARD)),)
ifneq ($(strip $(CK_PI5_UNLOCK_CARD)),1)
$(error CK_PI5_UNLOCK_CARD must be empty or 1)
endif
ifeq ($(strip $(CK_PI5_UNLOCK)),)
$(error CK_PI5_UNLOCK_CARD (card request file, throwaway secret, QUALIFICATION ONLY) needs CK_PI5_UNLOCK=1)
endif
endif
CK_PI5_UNLOCK ?=
ifneq ($(strip $(CK_PI5_UNLOCK)),)
ifneq ($(strip $(CK_PI5_UNLOCK)),1)
$(error CK_PI5_UNLOCK must be empty or 1)
endif
ifneq ($(strip $(CK_PI5_STORE)),)
$(error CK_PI5_UNLOCK (production-class keys from the recovery secret) cannot be combined with CK_PI5_STORE (public TEST keys))
endif
ifneq ($(strip $(CK_SERVICE)$(CK_TEST_STORE_CRASH)$(CK_TEST_CONTINUITY)$(CK_HARDWARE_STAGING)$(CK_SERVICE_TEST_KEYS)),)
$(error CK_PI5_UNLOCK cannot be combined with CK_SERVICE, CK_SERVICE_TEST_KEYS, CK_TEST_STORE_CRASH, CK_TEST_CONTINUITY or CK_HARDWARE_STAGING)
endif
CK_PI5 := 1
OUT ?= $(REPO)/target/native-kernel-pi5-unlock$(if $(strip $(CK_PI5_UNLOCK_CARD)),-card)$(if $(strip $(CK_PI5_FACT)),-fact)$(if $(strip $(CK_PI5_AGENT)),-agent)$(if $(strip $(CK_PI5_LIFECYCLE)),-lifecycle)
CK_EXTRA_CFLAGS += -DCK_PI5_UNLOCK=1
ifneq ($(strip $(CK_PI5_UNLOCK_CARD)),)
CK_EXTRA_CFLAGS += -DCK_PI5_UNLOCK_CARD=1
endif
endif

# Pi Cortex fact image (CK_PI5_FACT=1, "make pi5-fact", PI5-5): the Pi unlock-card image (production-class Store
# opened by the Slot 1 recovery secret from the card request file) plus the Cortex fact stage (svc/pi5_fact.c): a
# fact from \EFI\AIENOS\FACT.REQ (QUALIFICATION ONLY, core/fact_req.h) is appended to the Cortex journal of the
# sealed Store, and a boot without that file recalls it. It needs CK_PI5_UNLOCK=1 and CK_PI5_UNLOCK_CARD=1, refuses
# every other tier flag and has its own OUT.
CK_PI5_FACT ?=
ifneq ($(strip $(CK_PI5_FACT)),)
ifneq ($(strip $(CK_PI5_FACT)),1)
$(error CK_PI5_FACT must be empty or 1)
endif
ifneq ($(strip $(CK_PI5_UNLOCK))$(strip $(CK_PI5_UNLOCK_CARD)),11)
$(error CK_PI5_FACT (Cortex fact stage, QUALIFICATION ONLY) needs CK_PI5_UNLOCK=1 and CK_PI5_UNLOCK_CARD=1)
endif
ifneq ($(strip $(CK_PI5_STORE)$(CK_PI5_INFER)$(CK_PI5_PCIE)$(CK_PI5_NET)$(CK_PI5_AGENT)$(CK_PI5_LIFECYCLE)),)
$(error CK_PI5_FACT cannot be combined with CK_PI5_STORE, CK_PI5_INFER, CK_PI5_PCIE, CK_PI5_NET, CK_PI5_AGENT or CK_PI5_LIFECYCLE)
endif
CK_EXTRA_CFLAGS += -DCK_PI5_FACT=1
endif

# Pi agent image (CK_PI5_AGENT=1, "make pi5-agent", PI5-6 final cut, QUALIFICATION ONLY while the secret comes from the card request
# file): the Pi unlock-card image (production-class Store opened by the Slot 1 recovery secret) plus the resident inference unit
# (CK_INFER_LIB, model from MODEL.MAP only) plus the agent stage (svc/pi5_agent.c): after the Store opened it recovers the persisted
# reply, or (no reply yet) generates a bounded reply and commits it as a sealed R1 object. It needs CK_PI5_UNLOCK=1, CK_PI5_UNLOCK_CARD=1
# and CK_INFER_LIB, refuses every other tier flag (CK_PI5_INFER and CK_PI5_FACT included) and has its own OUT.
CK_PI5_AGENT ?=
ifneq ($(strip $(CK_PI5_AGENT)),)
ifneq ($(strip $(CK_PI5_AGENT)),1)
$(error CK_PI5_AGENT must be empty or 1)
endif
ifneq ($(strip $(CK_PI5_UNLOCK))$(strip $(CK_PI5_UNLOCK_CARD)),11)
$(error CK_PI5_AGENT (Store plus inference, QUALIFICATION ONLY) needs CK_PI5_UNLOCK=1 and CK_PI5_UNLOCK_CARD=1)
endif
ifneq ($(strip $(CK_PI5_STORE)$(CK_PI5_INFER)$(CK_PI5_PCIE)$(CK_PI5_NET)$(CK_PI5_FACT)$(CK_PI5_LIFECYCLE)$(CK_SERVICE)$(CK_HARDWARE_STAGING)$(CK_TEST_FWCFG_ARTIFACTS)),)
$(error CK_PI5_AGENT cannot be combined with CK_PI5_STORE, CK_PI5_INFER, CK_PI5_PCIE, CK_PI5_NET, CK_PI5_FACT, CK_PI5_LIFECYCLE, CK_SERVICE, CK_HARDWARE_STAGING or CK_TEST_FWCFG_ARTIFACTS)
endif
ifeq ($(strip $(CK_INFER_LIB)),)
$(error CK_PI5_AGENT needs CK_INFER_LIB=<libaienos_infer_kernel.a> (use "make pi5-agent", which builds it))
endif
CK_EXTRA_CFLAGS += -DCK_PI5_AGENT=1 -DCK_INFER_DISK_ONLY=1 -DCK_INFER_RESIDENT=1
endif

# Pi resident-lifecycle image (CK_PI5_LIFECYCLE=1, "make pi5-lifecycle", PI5-7 cut 2, QUALIFICATION ONLY while the secret comes from the
# card request file): the Pi unlock-card image (production-class Store opened by the Slot 1 recovery secret) plus the resident
# production lifecycle (core/lifecycle.c: remember, prefer, update, recall, approve, status, help, N3 context assembly) plus the resident
# inference unit (CK_INFER_LIB, model from MODEL.MAP only). Nothing reads the Pi's serial port, so the lifecycle takes its lines from the
# card command script \EFI\AIENOS\AGENT.CMD (core/agent_cmd.h) instead of the console and then runs its stop order. The lifecycle sources
# are the CK_SERVICE ones (-DCK_SERVICE=1 reaches only the stage sources, see the service block below); the secret still comes from the
# card (unlock and rotate are not script verbs). Needs CK_PI5_UNLOCK=1, CK_PI5_UNLOCK_CARD=1 and CK_INFER_LIB, refuses every other tier
# flag and has its own OUT.
CK_PI5_LIFECYCLE ?=
ifneq ($(strip $(CK_PI5_LIFECYCLE)),)
ifneq ($(strip $(CK_PI5_LIFECYCLE)),1)
$(error CK_PI5_LIFECYCLE must be empty or 1)
endif
ifneq ($(strip $(CK_PI5_UNLOCK))$(strip $(CK_PI5_UNLOCK_CARD)),11)
$(error CK_PI5_LIFECYCLE (resident lifecycle, QUALIFICATION ONLY) needs CK_PI5_UNLOCK=1 and CK_PI5_UNLOCK_CARD=1)
endif
ifneq ($(strip $(CK_PI5_STORE)$(CK_PI5_INFER)$(CK_PI5_PCIE)$(CK_PI5_NET)$(CK_PI5_FACT)$(CK_PI5_AGENT)$(CK_SERVICE)$(CK_SERVICE_TEST_KEYS)$(CK_HARDWARE_STAGING)$(CK_TEST_FWCFG_ARTIFACTS)),)
$(error CK_PI5_LIFECYCLE cannot be combined with CK_PI5_STORE, CK_PI5_INFER, CK_PI5_PCIE, CK_PI5_NET, CK_PI5_FACT, CK_PI5_AGENT, CK_SERVICE, CK_SERVICE_TEST_KEYS, CK_HARDWARE_STAGING or CK_TEST_FWCFG_ARTIFACTS)
endif
ifeq ($(strip $(CK_INFER_LIB)),)
$(error CK_PI5_LIFECYCLE needs CK_INFER_LIB=<libaienos_infer_kernel.a> (use "make pi5-lifecycle", which builds it))
endif
CK_EXTRA_CFLAGS += -DCK_PI5_LIFECYCLE=1 -DCK_INFER_DISK_ONLY=1 -DCK_INFER_RESIDENT=1
endif
# EL0 artifact qualification image (CK_ARTIFACT_CARD=1, "make pi5-artifact" for the Pi, PI5-7 cut 3, QUALIFICATION ONLY, TEST keys only):
# the plain core image (no Store stage, no NVMe) whose signed artifact candidates come from ONE card file, \EFI\AIENOS\ARTIFACT.BND
# (core/artifact_card.h, read by native/boot/efi_artifact.c), and which trusts the RFC 8032 TEST 1 public key only
# (CK_SEED0B_TEST_ANCHOR=1, forced by CK_PI5_ARTIFACT=1; the image prints "artifact_trust: ... TEST ONLY"). CK_PI5_ARTIFACT=1 is the Pi
# image (CK_PI5=1); CK_ARTIFACT_CARD=1 CK_SEED0B_TEST_ANCHOR=1 alone is its QEMU twin (scripts/qemu_ck_artifact_card_test.sh). Both
# refuse every other tier flag (so the other images refuse it too) and the "full" image (its Store stage owns the same hook), and each
# has its own OUT. No other image changes: the code is behind -DCK_ARTIFACT_CARD.
CK_ARTIFACT_CARD ?=
CK_PI5_ARTIFACT ?=
ifneq ($(strip $(CK_PI5_ARTIFACT)),)
ifneq ($(strip $(CK_PI5_ARTIFACT)),1)
$(error CK_PI5_ARTIFACT must be empty or 1)
endif
CK_ARTIFACT_CARD := 1
CK_PI5 := 1
CK_SEED0B_TEST_ANCHOR := 1
OUT ?= $(REPO)/target/native-kernel-pi5-artifact
endif
ifneq ($(strip $(CK_ARTIFACT_CARD)),)
ifneq ($(strip $(CK_ARTIFACT_CARD)),1)
$(error CK_ARTIFACT_CARD must be empty or 1)
endif
ifeq ($(strip $(CK_SEED0B_TEST_ANCHOR)),)
$(error CK_ARTIFACT_CARD (card artifact bundle, QUALIFICATION ONLY) needs CK_SEED0B_TEST_ANCHOR=1: it only ever trusts the public TEST key)
endif
ifneq ($(strip $(CK_PI5_STORE)$(CK_PI5_INFER)$(CK_PI5_PCIE)$(CK_PI5_NET)$(CK_PI5_UNLOCK)$(CK_PI5_UNLOCK_CARD)$(CK_PI5_FACT)$(CK_PI5_AGENT)$(CK_PI5_LIFECYCLE)$(CK_SERVICE)$(CK_SERVICE_TEST_KEYS)$(CK_HARDWARE_STAGING)$(CK_TEST_FWCFG_ARTIFACTS)$(CK_INFER_LIB)),)
$(error CK_ARTIFACT_CARD / CK_PI5_ARTIFACT cannot be combined with CK_PI5_STORE, CK_PI5_INFER, CK_PI5_PCIE, CK_PI5_NET, CK_PI5_UNLOCK, CK_PI5_UNLOCK_CARD, CK_PI5_FACT, CK_PI5_AGENT, CK_PI5_LIFECYCLE, CK_SERVICE, CK_SERVICE_TEST_KEYS, CK_HARDWARE_STAGING, CK_TEST_FWCFG_ARTIFACTS or CK_INFER_LIB)
endif
ifneq ($(filter full,$(MAKECMDGOALS)),)
$(error CK_ARTIFACT_CARD / CK_PI5_ARTIFACT build the core image only: the "full" image's Store stage owns the artifact hook)
endif
OUT ?= $(REPO)/target/native-kernel-artifact-card
CK_EXTRA_CFLAGS += -DCK_ARTIFACT_CARD=1
endif
CK_PI5 ?=
ifneq ($(strip $(CK_PI5)),)
ifneq ($(strip $(CK_PI5)),1)
$(error CK_PI5 must be empty or 1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_PI5 cannot be combined with CK_HARDWARE_STAGING)
endif
OUT ?= $(REPO)/target/native-kernel-pi5
CK_EXTRA_CFLAGS += -DCK_PI5=1 -DCK_KLOG=1
endif

# TEST-ONLY artifact source: CK_TEST_FWCFG_ARTIFACTS=1 compiles the QEMU fw_cfg
# side channel (opt/aienos/artifacts) into the loader instead of the boot disk
# Store. Every image built without it is checked to contain no fw_cfg artifact
# code. Such an image announces itself on the console and never counts toward
# a PASS. Its default OUT is separate so it never replaces a default image.
CK_TEST_FWCFG_ARTIFACTS ?=
ifneq ($(strip $(CK_TEST_FWCFG_ARTIFACTS)),)
ifneq ($(strip $(CK_TEST_FWCFG_ARTIFACTS)),1)
$(error CK_TEST_FWCFG_ARTIFACTS must be empty or 1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_TEST_FWCFG_ARTIFACTS (QEMU fw_cfg test source) cannot be combined with CK_HARDWARE_STAGING)
endif
OUT ?= $(REPO)/target/native-kernel-test-fwcfg
endif

# TEST-ONLY SMP mutation: CK_TEST_SMP_SKIP_CPU=1 builds a kernel that never
# calls PSCI CPU_ON for one secondary core (core/smp.c) but still waits for
# it, so the SMP gate must FAIL on it (scripts/qemu_ck_smp_test.sh
# --mutation). Own OUT; announces itself; refused with CK_HARDWARE_STAGING
# and with the fw_cfg test source. Default images are checked to carry no
# trace of it (smp_check).
CK_TEST_SMP_SKIP_CPU ?=
ifneq ($(strip $(CK_TEST_SMP_SKIP_CPU)),)
ifneq ($(strip $(CK_TEST_SMP_SKIP_CPU)),1)
$(error CK_TEST_SMP_SKIP_CPU must be empty or 1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_TEST_SMP_SKIP_CPU (TEST-only SMP mutation) cannot be combined with CK_HARDWARE_STAGING)
endif
ifneq ($(strip $(CK_TEST_FWCFG_ARTIFACTS)),)
$(error CK_TEST_SMP_SKIP_CPU cannot be combined with CK_TEST_FWCFG_ARTIFACTS)
endif
OUT ?= $(REPO)/target/native-kernel-test-smp-skip
SMP_TEST_FLAGS := -DCK_TEST_SMP_SKIP_CPU=1
else
SMP_TEST_FLAGS :=
endif
# B7b preparation probe (aienos#286, core/smmu_svc.c): CK_B7B_PROBE=1 builds an
# image that confines PCI segment 15 requester 0x100 (the Spark's GB10) once on
# a one-page window, prints the route and SMMU_IDR0/IDR1, and unconfines. Own
# OUT; allowed with CK_HARDWARE_STAGING (it is meant for the attended B7b
# window); refused with CK_QEMU_UNSAFE_DMA. CK_B7B_PROBE_TEST_SEGMENT0=1
# (TEST-ONLY, needs CK_B7B_PROBE=1) probes segment 0 for the QEMU positive path
# and is refused with CK_HARDWARE_STAGING. Default images are checked to carry
# no probe (b7b_check). Gate: scripts/qemu_ck_b7b_probe_test.sh.
CK_B7B_PROBE ?=
CK_B7B_PROBE_TEST_SEGMENT0 ?=
ifneq ($(strip $(CK_B7B_PROBE_TEST_SEGMENT0)),)
ifneq ($(strip $(CK_B7B_PROBE_TEST_SEGMENT0)),1)
$(error CK_B7B_PROBE_TEST_SEGMENT0 must be empty or 1)
endif
ifneq ($(strip $(CK_B7B_PROBE)),1)
$(error CK_B7B_PROBE_TEST_SEGMENT0 needs CK_B7B_PROBE=1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_B7B_PROBE_TEST_SEGMENT0 (TEST-only QEMU positive path) cannot be combined with CK_HARDWARE_STAGING)
endif
OUT ?= $(REPO)/target/native-kernel-test-b7b-seg0
SMP_TEST_FLAGS += -DCK_B7B_PROBE_TEST_SEGMENT0=1
endif
ifneq ($(strip $(CK_B7B_PROBE)),)
ifneq ($(strip $(CK_B7B_PROBE)),1)
$(error CK_B7B_PROBE must be empty or 1)
endif
ifneq ($(strip $(CK_QEMU_UNSAFE_DMA)),)
$(error CK_B7B_PROBE cannot be combined with CK_QEMU_UNSAFE_DMA)
endif
OUT ?= $(REPO)/target/native-kernel-b7b-probe
SMP_TEST_FLAGS += -DCK_B7B_PROBE=1
endif
# TEST-ONLY stale handoff (AIENOS_CK_SCREEN negative control,
# scripts/qemu_ck_screen_test.sh): the stub hands the kernel a CHANDOF2 magic;
# the kernel must refuse it ("panic: handoff: unsupported version 2 ...").
# Own OUT; announces itself; refused with CK_HARDWARE_STAGING. The default
# image is checked to carry no trace of it ($(ELF) rule).
CK_TEST_STALE_HANDOFF ?=
ifneq ($(strip $(CK_TEST_STALE_HANDOFF)),)
ifneq ($(strip $(CK_TEST_STALE_HANDOFF)),2)
$(error CK_TEST_STALE_HANDOFF must be empty or 2)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_TEST_STALE_HANDOFF (TEST-only stale handoff) cannot be combined with CK_HARDWARE_STAGING)
endif
OUT ?= $(REPO)/target/native-kernel-test-stale-handoff
SMP_TEST_FLAGS += -DCK_TEST_STALE_HANDOFF=2
endif
# TEST-ONLY rollback candidates (CK gate M0_ROLLBACK,
# scripts/qemu_ck_rollback_test.sh; docs/BOOT_HANDOFF_CONTRACT.md 7.1 rows 43-44):
#   bad-magic  the stub flips one bit of the handoff magic after
#              ExitBootServices; the kernel must panic "handoff: bad magic"
#   cpu-fault  after "kernel: alive" the kernel executes BRK at EL1; the
#              fault report must print and the kernel must reset
#   hang       after "kernel: alive" the kernel prints one marker and spins
#              with interrupts masked; only an outside reset ends it
# Own OUT; announces itself; refused with CK_HARDWARE_STAGING. The default
# image is checked to carry no trace of it (rollback_check).
CK_TEST_ROLLBACK ?=
ifneq ($(strip $(CK_TEST_ROLLBACK)),)
ifeq ($(filter $(strip $(CK_TEST_ROLLBACK)),bad-magic cpu-fault hang),)
$(error CK_TEST_ROLLBACK must be empty or one of bad-magic cpu-fault hang)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_TEST_ROLLBACK (TEST-only rollback candidate) cannot be combined with CK_HARDWARE_STAGING)
endif
ifneq ($(strip $(CK_TEST_STALE_HANDOFF)),)
$(error CK_TEST_ROLLBACK cannot be combined with CK_TEST_STALE_HANDOFF)
endif
OUT ?= $(REPO)/target/native-kernel-test-rollback-$(strip $(CK_TEST_ROLLBACK))
SMP_TEST_FLAGS += -DCK_TEST_ROLLBACK_$(subst -,_,$(shell echo '$(strip $(CK_TEST_ROLLBACK))' | tr a-z A-Z))=1
endif
# SLOTLDR.EFI trusted keys (native v1 plan P11 cut 2a; native/boot/slot_loader.c,
# make slot-loader):
#   CK_SLOT_KEYS=<file>  owner public keys, "owner_root_ed25519 <64 hex>" lines
#                        (tools/ck_owner_gen.c format; ck_slot_tool keys-c refuses
#                        every known TEST key)
#   CK_TEST_SLOT_KEY=1   TEST-ONLY: RFC 8032 TEST 1; the loader prints
#                        "slot_loader: TEST-ONLY key ..."; refused with
#                        CK_HARDWARE_STAGING and together with CK_SLOT_KEYS.
# Checked here, before the hardware staging owner-file checks, so the refusal
# names the TEST key itself.
CK_SLOT_KEYS ?=
CK_TEST_SLOT_KEY ?=
ifneq ($(strip $(CK_TEST_SLOT_KEY)),)
ifneq ($(strip $(CK_TEST_SLOT_KEY)),1)
$(error CK_TEST_SLOT_KEY must be empty or 1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_TEST_SLOT_KEY (TEST-ONLY slot loader key) cannot be combined with CK_HARDWARE_STAGING)
endif
ifneq ($(strip $(CK_SLOT_KEYS)),)
$(error CK_TEST_SLOT_KEY and CK_SLOT_KEYS are exclusive: one trusted key source per slot loader)
endif
endif

OUT ?= $(REPO)/target/native-kernel
# Pi builds only (CK_PI5=1: "make pi5" and anything built on it): when a tracked
# file differs from HEAD the stamp ends in "-dirty", so the kernel's report
# ("aienos_commit: <stamp>") and the EFI itself say the image is not the bare
# commit. Pi hardware runs are cited as evidence; a bare hash on an image built
# from an edited tree would name a commit that does not contain its source.
# Untracked files are ignored (build output lives in untracked target/).
# Non-Pi builds are untouched: the suffix stays empty and git status is not run
# (the QEMU gates compare "aienos_commit: <HEAD>"). An AIENOS_COMMIT given on
# the command line or in the environment is used as is, with no suffix.
AIENOS_COMMIT_SUFFIX :=
ifeq ($(strip $(CK_PI5)),1)
ifneq ($(strip $(shell GIT_OPTIONAL_LOCKS=0 git -C $(REPO) status --porcelain --untracked-files=no 2>/dev/null)),)
AIENOS_COMMIT_SUFFIX := -dirty
endif
endif
AIENOS_COMMIT ?= $(shell git -C $(REPO) rev-parse HEAD 2>/dev/null || echo unknown)$(AIENOS_COMMIT_SUFFIX)

CK_EXTRA_CFLAGS ?=
# Build-time DMA policy for the full image (see dev/nvme_bind.c):
# default SMMU-confined or refuse; 1 = TEST-ONLY QEMU unconfined bypass when
# no SMMU exists. Never with hardware staging.
CK_QEMU_UNSAFE_DMA ?=
CK_HARDWARE_STAGING ?=

# FP/SIMD probe (aienos#34 lane 0): CK_RUST_LIBS=<path to libaienos_fpu_probe.a>
# links that Rust no_std staticlib into the image and compiles core/fpu.c's
# probe (-DCK_FPU_PROBE=1). The C compile flags stay -mgeneral-regs-only; only
# the Rust unit uses FP/SIMD. Empty (default) = no Rust, no FP code. QEMU
# gate only: never combined with hardware staging.
CK_RUST_LIBS ?=
ifneq ($(strip $(CK_RUST_LIBS)),)
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_RUST_LIBS (FP probe, QEMU gate only) cannot be combined with CK_HARDWARE_STAGING)
endif
CK_EXTRA_CFLAGS += -DCK_FPU_PROBE=1
endif

# Inference ingest probe (aienos#34 lane 4): CK_INFER_LIB=<path to
# libaienos_infer_kernel.a> links that Rust no_std staticlib (aienos-infer +
# bump allocator) and compiles core/infer.c (-DCK_INFER_PROBE=1): the kernel
# ingests a GGUF from the boot disk (MODEL.MAP, read by the UEFI stub) or, in
# the QEMU images only, from fw_cfg, and calls the Rust unit. C flags stay
# -mgeneral-regs-only. Not combinable with CK_RUST_LIBS (two Rust staticlibs
# would duplicate compiler_builtins).
# The same image then runs the bounded session API (native v1 P06:
# open/prompt/step/cancel/close in crates/aienos-infer-kernel/src/session.rs).
#
# Hardware staging (native v1 P06 / gate N3, aienos#34): exactly one inference
# image may be built with CK_HARDWARE_STAGING, the resident production service
# image
#   make full CK_SERVICE=1 CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS=<file>
#        CK_MACHINE_ID=<file> CK_INFER_LIB=<lib>
# It gets -DCK_INFER_DISK_ONLY=1: the QEMU fw_cfg ingest is compiled out (the
# fwcfg_check below requires no fw_cfg code or string in the image), and with
# no MODEL.MAP the kernel refuses instead of looking anywhere else. The
# one-shot probe image (no CK_SERVICE) stays QEMU only.
CK_INFER_LIB ?=
ifneq ($(strip $(CK_INFER_LIB)),)
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
ifneq ($(strip $(CK_SERVICE)),1)
$(error CK_INFER_LIB with CK_HARDWARE_STAGING needs CK_SERVICE=1: only the resident service image (boot-disk model, MODEL.MAP) is a hardware inference image; the one-shot probe stays QEMU only)
endif
CK_EXTRA_CFLAGS += -DCK_INFER_DISK_ONLY=1
endif
ifneq ($(strip $(CK_RUST_LIBS)),)
$(error CK_INFER_LIB and CK_RUST_LIBS cannot be combined: two Rust staticlibs duplicate compiler_builtins)
endif
CK_EXTRA_CFLAGS += -DCK_INFER_PROBE=1
# native v1 P06 cut 2: in a service image the model and one bounded session
# stay resident for the lifecycle's `prompt` verb (core/lifecycle.c) instead
# of running the one-shot probe. Model source: the boot disk (MODEL.MAP); the
# QEMU test images also keep the TEST-ONLY fw_cfg fallback.
ifeq ($(strip $(CK_SERVICE)),1)
CK_EXTRA_CFLAGS += -DCK_INFER_RESIDENT=1
endif
endif
ifneq ($(strip $(CK_QEMU_UNSAFE_DMA)),)
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_QEMU_UNSAFE_DMA (unconfined DMA, QEMU debug only) cannot be combined with CK_HARDWARE_STAGING: no SMMU confinement means no DMA)
endif
ifneq ($(strip $(CK_QEMU_UNSAFE_DMA)),1)
$(error CK_QEMU_UNSAFE_DMA must be empty or 1)
endif
endif

# TEST-ONLY xHCI DMA fence mutations (dev/xhci_fence.h), for the self-test of
# scripts/qemu_ck_keyboard_test.sh --mutation only: each one breaks one
# keyboard DMA-safety row on purpose. Own FULL_NAME, never a hardware image.
CK_TEST_XHCI_MUTATION ?=
ifneq ($(strip $(CK_TEST_XHCI_MUTATION)),)
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_TEST_XHCI_MUTATION (TEST-ONLY xHCI DMA fence mutation) cannot be combined with CK_HARDWARE_STAGING)
endif
ifneq ($(strip $(CK_QEMU_UNSAFE_DMA)),)
$(error CK_TEST_XHCI_MUTATION cannot be combined with CK_QEMU_UNSAFE_DMA)
endif
XHCI_MUT_NUM := $(if $(filter bm-left-on,$(CK_TEST_XHCI_MUTATION)),1,$(if $(filter no-revoke,$(CK_TEST_XHCI_MUTATION)),2,$(if $(filter grant-no-smmu,$(CK_TEST_XHCI_MUTATION)),3,$(if $(filter no-sweep,$(CK_TEST_XHCI_MUTATION)),4,))))
ifeq ($(XHCI_MUT_NUM),)
$(error CK_TEST_XHCI_MUTATION must be one of bm-left-on no-revoke grant-no-smmu no-sweep)
endif
endif

# TEST-ONLY console session (C3-1a, dev/devices.c ck_stage_console_session):
# CK_CONSOLE_SESSION=1 adds a final boot stage that keeps taking serial and USB
# keyboard input until the shell's "exit". QEMU test image only: own FULL_NAME,
# refused with CK_HARDWARE_STAGING and CK_QEMU_UNSAFE_DMA. The default image
# carries none of it. CK_TEST_CONSOLE_MUTATION=bm-left-on-after-exit (needs
# CK_CONSOLE_SESSION=1) leaves the xHCI bus master on after the session exit,
# for the CONSOLE gate's red-before-green self-test.
CK_CONSOLE_SESSION ?=
CK_TEST_CONSOLE_MUTATION ?=
ifneq ($(strip $(CK_CONSOLE_SESSION)),)
ifneq ($(strip $(CK_CONSOLE_SESSION)),1)
$(error CK_CONSOLE_SESSION must be empty or 1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_CONSOLE_SESSION (QEMU test console session) cannot be combined with CK_HARDWARE_STAGING)
endif
ifneq ($(strip $(CK_QEMU_UNSAFE_DMA)),)
$(error CK_CONSOLE_SESSION cannot be combined with CK_QEMU_UNSAFE_DMA)
endif
ifneq ($(strip $(CK_TEST_XHCI_MUTATION)),)
$(error CK_CONSOLE_SESSION cannot be combined with CK_TEST_XHCI_MUTATION)
endif
endif
ifneq ($(strip $(CK_TEST_CONSOLE_MUTATION)),)
ifneq ($(strip $(CK_TEST_CONSOLE_MUTATION)),bm-left-on-after-exit)
$(error CK_TEST_CONSOLE_MUTATION must be bm-left-on-after-exit)
endif
ifneq ($(strip $(CK_CONSOLE_SESSION)),1)
$(error CK_TEST_CONSOLE_MUTATION needs CK_CONSOLE_SESSION=1)
endif
endif

# CK_SERVICE=1 builds the resident production lifecycle image (core/lifecycle.c,
# native v1 plan P03): after every boot stage the kernel serves bounded operator
# requests on the serial console until "shutdown" (Store closed, NVMe released,
# then reset), instead of resetting at once. Own OUT subdirectory full-service/.
# Allowed with CK_HARDWARE_STAGING (it is the production entry); refused with
# every TEST-only flag. The production key source refuses today, so this image
# stays LOCKED. CK_SERVICE_TEST_KEYS=1 (TEST-ONLY, full-service-testkeys/, only
# scripts/qemu_ck_lifecycle_test.sh) opens the Store with the TEST keys so the
# ready/serve/commit paths run in QEMU; refused with CK_HARDWARE_STAGING.
CK_SERVICE ?=
CK_SERVICE_TEST_KEYS ?=
ifneq ($(strip $(CK_SERVICE)),)
ifneq ($(strip $(CK_SERVICE)),1)
$(error CK_SERVICE must be empty or 1)
endif
ifneq ($(strip $(CK_QEMU_UNSAFE_DMA)),)
$(error CK_SERVICE cannot be combined with CK_QEMU_UNSAFE_DMA)
endif
ifneq ($(strip $(CK_CONSOLE_SESSION)),)
$(error CK_SERVICE cannot be combined with CK_CONSOLE_SESSION)
endif
ifneq ($(strip $(CK_TEST_XHCI_MUTATION)$(CK_TEST_STORE_CRASH)$(CK_TEST_CONTINUITY)$(CK_TEST_FWCFG_ARTIFACTS)$(CK_TEST_SMP_SKIP_CPU)$(CK_TEST_ROLLBACK)$(CK_TEST_STALE_HANDOFF)$(CK_TEST_DISK_XLATE_BYPASS)),)
$(error CK_SERVICE cannot be combined with a CK_TEST_* flag)
endif
endif
ifneq ($(strip $(CK_SERVICE_TEST_KEYS)),)
ifneq ($(strip $(CK_SERVICE_TEST_KEYS)),1)
$(error CK_SERVICE_TEST_KEYS must be empty or 1)
endif
ifneq ($(strip $(CK_SERVICE)),1)
$(error CK_SERVICE_TEST_KEYS needs CK_SERVICE=1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_SERVICE_TEST_KEYS (TEST keys) cannot be combined with CK_HARDWARE_STAGING)
endif
endif

# TEST-ONLY Store crash hook (svc/store_crash.h; only
# scripts/qemu_ck_store_crash_test.sh sets it): the Store stage reads a crash
# plan from the scratch unit, runs on a volatile write cache and halts at the
# planned checkpoint. Own OUT subdirectory; announces itself; never counts
# toward a PASS of M4_STORE; refused with CK_HARDWARE_STAGING and
# CK_QEMU_UNSAFE_DMA. CK_TEST_STORE_CRASH_MUTANT (only with it) builds a
# deliberately broken Store the crash gate must catch:
#   skip_root_flush      no flush between the commit record and the root write
#   accept_bad_root_crc  superblock CRC never checked
CK_TEST_STORE_CRASH ?=
CK_TEST_STORE_CRASH_MUTANT ?=
ifneq ($(strip $(CK_TEST_STORE_CRASH)),)
ifneq ($(strip $(CK_TEST_STORE_CRASH)),1)
$(error CK_TEST_STORE_CRASH must be empty or 1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_TEST_STORE_CRASH (TEST-ONLY Store crash hook) cannot be combined with CK_HARDWARE_STAGING)
endif
ifneq ($(strip $(CK_QEMU_UNSAFE_DMA)),)
$(error CK_TEST_STORE_CRASH (TEST-ONLY Store crash hook) cannot be combined with CK_QEMU_UNSAFE_DMA)
endif
endif
ifneq ($(strip $(CK_TEST_STORE_CRASH_MUTANT)),)
ifneq ($(strip $(CK_TEST_STORE_CRASH)),1)
$(error CK_TEST_STORE_CRASH_MUTANT needs CK_TEST_STORE_CRASH=1 (TEST-ONLY))
endif
ifeq ($(strip $(CK_TEST_STORE_CRASH_MUTANT)),skip_root_flush)
STORE_MUTANT_FLAGS := -DCK_TEST_STORE_MUTANT_SKIP_ROOT_FLUSH=1
else ifeq ($(strip $(CK_TEST_STORE_CRASH_MUTANT)),accept_bad_root_crc)
STORE_MUTANT_FLAGS := -DCK_TEST_STORE_MUTANT_ACCEPT_BAD_ROOT_CRC=1
else
$(error CK_TEST_STORE_CRASH_MUTANT must be skip_root_flush or accept_bad_root_crc)
endif
endif


# TEST-ONLY continuity / Recovery Core mode selection (svc/continuity_boot.h,
# contract K-7; only scripts/qemu_ck_continuity_test.sh and
# scripts/qemu_ck_recovery_test.sh set it): the Store stage reads a mode plan
# from the scratch unit and runs the continuity or Recovery Core wiring instead
# of the boot-record commit. Own OUT subdirectory; announces itself; refused
# with CK_HARDWARE_STAGING, CK_QEMU_UNSAFE_DMA and CK_TEST_STORE_CRASH.
# CK_TEST_CONTINUITY_MUTANT (only with it) builds a deliberately broken
# continuity layer the gates must catch:
#   resume_no_commit             resume does not commit the new incarnation
#   resume_provisions            resume mints an identity on an unprovisioned Store
#   degraded_is_unprovisioned    a degraded mount reads as unprovisioned (MR-5)
#   compare_16                   operator response compared on 16 of 32 bytes
#   bare_sha256                  operator response is a bare SHA-256, not an HMAC
#   subject_restore_mints        restore mints an ALLEN subject when it finds none (OS-0018)
#   subject_accept_foreign       restore accepts a subject bound to another agent (MS-1)
CK_TEST_CONTINUITY ?=
CK_TEST_CONTINUITY_MUTANT ?=
ifneq ($(strip $(CK_TEST_CONTINUITY)),)
ifneq ($(strip $(CK_TEST_CONTINUITY)),1)
$(error CK_TEST_CONTINUITY must be empty or 1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_TEST_CONTINUITY (TEST-ONLY continuity mode selection) cannot be combined with CK_HARDWARE_STAGING)
endif
ifneq ($(strip $(CK_QEMU_UNSAFE_DMA)),)
$(error CK_TEST_CONTINUITY (TEST-ONLY continuity mode selection) cannot be combined with CK_QEMU_UNSAFE_DMA)
endif
ifneq ($(strip $(CK_TEST_STORE_CRASH)),)
$(error CK_TEST_CONTINUITY (TEST-ONLY continuity mode selection) cannot be combined with CK_TEST_STORE_CRASH)
endif
endif
ifneq ($(strip $(CK_TEST_CONTINUITY_MUTANT)),)
ifneq ($(strip $(CK_TEST_CONTINUITY)),1)
$(error CK_TEST_CONTINUITY_MUTANT needs CK_TEST_CONTINUITY=1 (TEST-ONLY))
endif
ifeq ($(strip $(CK_TEST_CONTINUITY_MUTANT)),resume_no_commit)
CONT_MUTANT_FLAGS := -DCM_MUTANT_RESUME_NO_COMMIT=1
else ifeq ($(strip $(CK_TEST_CONTINUITY_MUTANT)),resume_provisions)
CONT_MUTANT_FLAGS := -DCM_MUTANT_RESUME_PROVISIONS=1
else ifeq ($(strip $(CK_TEST_CONTINUITY_MUTANT)),degraded_is_unprovisioned)
CONT_MUTANT_FLAGS := -DRC_MUTANT_DEGRADED_IS_UNPROVISIONED=1
else ifeq ($(strip $(CK_TEST_CONTINUITY_MUTANT)),compare_16)
CONT_MUTANT_FLAGS := -DCR_MUTANT_COMPARE_16=1
else ifeq ($(strip $(CK_TEST_CONTINUITY_MUTANT)),bare_sha256)
CONT_MUTANT_FLAGS := -DCR_MUTANT_BARE_SHA256=1
else ifeq ($(strip $(CK_TEST_CONTINUITY_MUTANT)),subject_restore_mints)
CONT_MUTANT_FLAGS := -DCS_MUTANT_RESTORE_MINTS=1
else ifeq ($(strip $(CK_TEST_CONTINUITY_MUTANT)),subject_accept_foreign)
CONT_MUTANT_FLAGS := -DCS_MUTANT_ACCEPT_FOREIGN=1
else
$(error CK_TEST_CONTINUITY_MUTANT must be resume_no_commit, resume_provisions, degraded_is_unprovisioned, compare_16, bare_sha256, subject_restore_mints or subject_accept_foreign)
endif
endif

# Owner provisioning. The hardware staging image never embeds the TEST Store
# keys, the TEST store uuid or the TEST machine id: it needs owner PUBLIC
# material and the machine identity as files (format: tools/ck_owner_gen.c;
# relative paths are relative to native/kernel), checked and turned into a
# generated header that refuses every known TEST value. Nothing secret is
# read: the production Store key source stays BLOCKED_OPERATOR
# (svc/store_boot.c ck_store_production_keys, TRUST-1 key ceremony).
CK_OWNER_PUBKEYS ?=
CK_MACHINE_ID ?=
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
ifneq ($(strip $(CK_HARDWARE_STAGING)),1)
$(error CK_HARDWARE_STAGING must be empty or 1)
endif
ifeq ($(strip $(CK_OWNER_PUBKEYS)),)
$(error CK_HARDWARE_STAGING refuses the TEST Store keys and TEST machine id: give CK_OWNER_PUBKEYS=<owner public keys file> and CK_MACHINE_ID=<machine id file> (native/kernel/README.md, Owner provisioning))
endif
ifeq ($(strip $(CK_MACHINE_ID)),)
$(error CK_HARDWARE_STAGING refuses the TEST Store keys and TEST machine id: give CK_OWNER_PUBKEYS=<owner public keys file> and CK_MACHINE_ID=<machine id file> (native/kernel/README.md, Owner provisioning))
endif
OWNER_PUBKEYS_FILE := $(abspath $(CK_OWNER_PUBKEYS))
OWNER_MACHINE_FILE := $(abspath $(CK_MACHINE_ID))
ifeq ($(wildcard $(OWNER_PUBKEYS_FILE)),)
$(error CK_OWNER_PUBKEYS file not found: $(OWNER_PUBKEYS_FILE))
endif
ifeq ($(wildcard $(OWNER_MACHINE_FILE)),)
$(error CK_MACHINE_ID file not found: $(OWNER_MACHINE_FILE))
endif
else
ifneq ($(strip $(CK_OWNER_PUBKEYS)$(CK_MACHINE_ID)),)
$(error CK_OWNER_PUBKEYS and CK_MACHINE_ID are only used with CK_HARDWARE_STAGING=1 (the default QEMU build keeps the labelled TEST keys))
endif
endif

# TEST-ONLY DISK_LAYOUT mutation (dev/disk_part.h): the partition translation
# layer is bypassed. Its own FULL_NAME; never with hardware staging.
CK_TEST_DISK_XLATE_BYPASS ?=
ifneq ($(strip $(CK_TEST_DISK_XLATE_BYPASS)),)
ifneq ($(strip $(CK_TEST_DISK_XLATE_BYPASS)),1)
$(error CK_TEST_DISK_XLATE_BYPASS must be empty or 1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_TEST_DISK_XLATE_BYPASS (TEST-ONLY translation bypass mutation) cannot be combined with CK_HARDWARE_STAGING)
endif
endif

# SEED-0B qualification build: trusts the RFC 8032 TEST 1 public key only.
# TEST ONLY; never combined with hardware staging. Use its own OUT.
CK_SEED0B_TEST_ANCHOR ?=
ifneq ($(strip $(CK_SEED0B_TEST_ANCHOR)),)
ifneq ($(strip $(CK_SEED0B_TEST_ANCHOR)),1)
$(error CK_SEED0B_TEST_ANCHOR must be empty or 1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_SEED0B_TEST_ANCHOR (TEST key trust) cannot be combined with CK_HARDWARE_STAGING)
endif
ART_TRUST_FLAGS := -DCK_SEED0B_TEST_ANCHOR=1
else
ART_TRUST_FLAGS :=
endif
ifeq ($(strip $(CK_TEST_FWCFG_ARTIFACTS)),1)
ART_TRUST_FLAGS += -DCK_TEST_FWCFG_ARTIFACTS=1
endif
# C3-3a: the launch self-test (core/osc_admit.c) runs scripted launches of the admitted units. TEST ONLY.
CK_OSC_LAUNCH_TEST ?=
ifeq ($(strip $(CK_OSC_LAUNCH_TEST)),1)
ifeq ($(strip $(CK_SEED0B_TEST_ANCHOR)),)
$(error CK_OSC_LAUNCH_TEST needs CK_SEED0B_TEST_ANCHOR=1 (it launches TEST-signed units))
endif
ART_TRUST_FLAGS += -DCK_OSC_LAUNCH_TEST=1
endif
# aienos#383: the receipt self-test variant of the launch self-test (CK_OSC_LAUNCH_TEST=1 CK_OSC_RECEIPT_TEST=1) runs
# a fixed script of launches with valid, missing and refused realization receipts instead of the C3-3a script.
# TEST ONLY, QEMU only.
CK_OSC_RECEIPT_TEST ?=
ifeq ($(strip $(CK_OSC_RECEIPT_TEST)),1)
ifneq ($(strip $(CK_OSC_LAUNCH_TEST)),1)
$(error CK_OSC_RECEIPT_TEST needs CK_OSC_LAUNCH_TEST=1)
endif
ART_TRUST_FLAGS += -DCK_OSC_RECEIPT_TEST=1
endif
# OSH-AIENOS-0: the shell-core self-test (core/osh_test.c) runs the three osh units over embedded fixture scripts and
# prints the step trace. TEST ONLY, QEMU only; not combined with the launch self-test.
CK_OSH_TEST ?=
OSH_TEST_C :=
ifeq ($(strip $(CK_OSH_TEST)),1)
ifeq ($(strip $(CK_SEED0B_TEST_ANCHOR)),)
$(error CK_OSH_TEST needs CK_SEED0B_TEST_ANCHOR=1 (it launches TEST-signed units))
endif
ifeq ($(strip $(CK_OSC_LAUNCH_TEST)),1)
$(error CK_OSH_TEST and CK_OSC_LAUNCH_TEST are exclusive)
endif
ART_TRUST_FLAGS += -DCK_OSH_TEST=1
OSH_TEST_C := $(KDIR)/core/osh_test.c
# OSH-AIENOS-OP: instead of the fixture traces, drive a real capability-authorized operation (core/osh_op.c) through the same shell units.
CK_OSH_OP_TEST ?=
ifeq ($(strip $(CK_OSH_OP_TEST)),1)
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_OSH_OP_TEST (test-only OSH adapter with injection hooks) cannot be combined with CK_HARDWARE_STAGING)
endif
ART_TRUST_FLAGS += -DCK_OSH_OP_TEST=1
OSH_TEST_C += $(KDIR)/core/osh_op.c
endif
endif

# Screen hold before reset (core/console.c ck_console_fb_hold): seconds the
# GOP framebuffer console keeps the last report on screen before the PSCI
# reset, so an operator can read or photograph it. 0 (default) in every QEMU
# gate; scripts/stage_one_time_boot_ck.sh builds the hardware image with 120.
CK_FB_HOLD_S ?= 0
ifeq ($(shell echo '$(CK_FB_HOLD_S)' | grep -Ex '[0-9]{1,4}'),)
$(error CK_FB_HOLD_S must be 0..9999 seconds)
endif

KINC := -I$(KDIR)/include -I$(KDIR)/core -I$(KDIR)/mm -I$(KDIR)/arch -I$(BOOT)
MODULE_INC := -I$(NATIVE)/disk -I$(NATIVE)/store -I$(NATIVE)/m5 -I$(NATIVE)/crypto \
	-I$(NATIVE)/capability -I$(NATIVE)/argus -I$(NATIVE)/net
KCFLAGS := -std=gnu11 -O2 -Wall -Wextra -Werror -ffreestanding -nostdlib -fno-builtin \
	-fno-stack-protector -fno-tree-loop-distribute-patterns -mstrict-align \
	-mgeneral-regs-only -mno-outline-atomics -fno-asynchronous-unwind-tables -fpie \
	-fvisibility=hidden -fno-plt $(KINC) $(SMP_TEST_FLAGS) -DCK_FB_HOLD_S=$(CK_FB_HOLD_S) $(CK_EXTRA_CFLAGS)
KLDFLAGS := -nostdlib -pie --no-dynamic-linker -z norelro -z noexecstack -z max-page-size=4096 --no-warn-rwx-segments \
	-T $(BOOT)/image.ld

CORE_C := $(BOOT)/efi_main.c $(BOOT)/efi_model.c $(BOOT)/efi_gop.c \
	$(KDIR)/arch/exception.c $(KDIR)/arch/gic.c $(KDIR)/arch/timer.c \
	$(KDIR)/core/acpi.c $(KDIR)/core/acpi_dev.c $(KDIR)/core/acpi_platform.c $(KDIR)/core/console.c $(KDIR)/core/fbcon.c $(KDIR)/core/fmt.c \
	$(KDIR)/core/kmain.c $(KDIR)/core/handoff_check.c $(KDIR)/core/libc_min.c $(KDIR)/core/report.c \
	$(KDIR)/core/smmu.c $(KDIR)/core/smmu_svc.c $(KDIR)/core/sched.c $(KDIR)/core/ipc.c \
	$(KDIR)/core/fpu.c $(KDIR)/core/cpufeat.c $(KDIR)/core/infer.c $(KDIR)/core/m3.c $(KDIR)/core/entropy.c $(KDIR)/arch/rndr.c $(KDIR)/core/smp.c \
	$(KDIR)/mm/frames.c $(KDIR)/mm/heap.c $(KDIR)/mm/mmu.c $(KDIR)/mm/pt.c
ifeq ($(strip $(CK_PI5)),1)
CORE_C += $(BOOT)/efi_klog.c $(KDIR)/core/pi5.c $(KDIR)/core/pi5_marker.c $(KDIR)/dev/disk_part.c $(KDIR)/core/klog.c $(KDIR)/core/klog_slot.c \
	$(KDIR)/dev/pi5_wdt.c $(KDIR)/dev/pi5_rng.c $(NATIVE)/disk/disk.c $(NATIVE)/disk/disk_sdhci.c
endif
ifeq ($(strip $(CK_PI5_PCIE)),1)
CORE_C += $(KDIR)/dev/pi5_pcie.c $(KDIR)/dev/dma_window.c
endif
ifeq ($(strip $(CK_PI5_NET)),1)
CORE_C += $(KDIR)/dev/pi5_pcie.c $(KDIR)/dev/dma_window.c $(KDIR)/dev/pi5_net.c $(KDIR)/dev/pi5_gem.c
endif
ifneq ($(strip $(CK_PI5_UNLOCK_CARD)),)
CORE_C += $(BOOT)/efi_unlock.c $(KDIR)/core/unlock_req.c
endif
ifneq ($(strip $(CK_PI5_FACT)),)
CORE_C += $(BOOT)/efi_fact.c $(KDIR)/core/fact_req.c
endif
ifneq ($(strip $(CK_PI5_LIFECYCLE)),)
CORE_C += $(BOOT)/efi_agentcmd.c $(KDIR)/core/agent_cmd.c
endif
# P2 sealed-artifact loader: format/admission/receipt (artifact/), SHA-256
# (argus), Ed25519/SHA-512 (sig). Built into the core so every image carries
# the loader; the TEST-anchor qualification build is CK_SEED0B_TEST_ANCHOR=1.
ART_C := $(KDIR)/core/artifact_loader.c $(KDIR)/core/osc_admit.c $(KDIR)/core/osc_task.c $(KDIR)/artifact/osc_launch.c $(KDIR)/artifact/format.c $(KDIR)/artifact/admission.c \
	$(KDIR)/artifact/receipt.c $(KDIR)/artifact/osc_unit.c $(KDIR)/artifact/osc_receipt.c $(NATIVE)/argus/sha256.c $(NATIVE)/sig/sha512.c \
	$(NATIVE)/sig/ed25519.c $(NATIVE)/sig/ct.c
ART_INC := -I$(KDIR)/svc/compat -I$(KDIR)/artifact -I$(NATIVE)/sig -I$(NATIVE)/argus
ART_C += $(OSH_TEST_C)
ifneq ($(strip $(CK_ARTIFACT_CARD)),)
ART_C += $(KDIR)/core/artifact_card.c $(KDIR)/core/artifact_card_stage.c
CORE_C += $(BOOT)/efi_artifact.c
endif
CORE_C += $(ART_C)
CORE_S := $(BOOT)/efi_entry.S $(KDIR)/arch/vectors.S $(KDIR)/arch/m3.S $(KDIR)/arch/smp_entry.S
HDRS := $(wildcard $(KDIR)/include/*.h $(KDIR)/*/*.h $(BOOT)/*.h)

KOBJ := $(OUT)/obj
CORE_OBJS := $(patsubst $(NATIVE)/%.c,$(KOBJ)/%.o,$(CORE_C)) \
	$(patsubst $(NATIVE)/%.S,$(KOBJ)/%.o,$(CORE_S))

.DEFAULT_GOAL := all

# ---- boot stages (stage.mk: STAGE_SRCS, STAGE_CFLAGS, stage-* host targets) ----
include $(KDIR)/stage.mk
ifeq ($(strip $(CK_QEMU_UNSAFE_DMA)),1)
FULL_NAME := full-qemu-unsafe-dma
STAGE_DMA_FLAGS := -DCK_QEMU_UNSAFE_DMA=1
else
FULL_NAME := full
STAGE_DMA_FLAGS :=
endif
ifneq ($(strip $(CK_TEST_XHCI_MUTATION)),)
FULL_NAME := full-test-xhci-$(strip $(CK_TEST_XHCI_MUTATION))
STAGE_DMA_FLAGS += -DCK_TEST_XHCI_MUTATION=$(XHCI_MUT_NUM)
endif
ifeq ($(strip $(CK_CONSOLE_SESSION)),1)
FULL_NAME := full-console-session
STAGE_DMA_FLAGS += -DCK_CONSOLE_SESSION=1
ifneq ($(strip $(CK_TEST_CONSOLE_MUTATION)),)
FULL_NAME := full-test-console-mutation
STAGE_DMA_FLAGS += -DCK_TEST_CONSOLE_MUTATION=1
endif
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
# Own OUT subdirectory: stage objects built with these flags never mix with
# the default full image's objects.
FULL_NAME := full-hardware-staging
OWNER_HDR := $(OUT)/gen-$(FULL_NAME)/ck_owner_prov.h
STAGE_DMA_FLAGS += -DCK_HARDWARE_STAGING=1 -I$(dir $(OWNER_HDR))
else
OWNER_HDR :=
endif
ifeq ($(strip $(CK_TEST_STORE_CRASH)),1)
# Own OUT subdirectory: TEST hook objects never mix with a default image.
ifneq ($(strip $(CK_TEST_STORE_CRASH_MUTANT)),)
FULL_NAME := full-test-store-crash-mutant-$(strip $(CK_TEST_STORE_CRASH_MUTANT))
else
FULL_NAME := full-test-store-crash
endif
STAGE_DMA_FLAGS += -DCK_TEST_STORE_CRASH=1 $(STORE_MUTANT_FLAGS)
endif
ifeq ($(strip $(CK_TEST_CONTINUITY)),1)
# Own OUT subdirectory: TEST objects never mix with a default image. The
# continuity layer is linked only here (default images carry none of it).
ifneq ($(strip $(CK_TEST_CONTINUITY_MUTANT)),)
FULL_NAME := full-test-continuity-mutant-$(strip $(CK_TEST_CONTINUITY_MUTANT))
else
FULL_NAME := full-test-continuity
endif
STAGE_DMA_FLAGS += -DCK_TEST_CONTINUITY=1 $(CONT_MUTANT_FLAGS) -I$(KDIR)/core
STAGE_SRCS += $(KDIR)/svc/continuity_codec.c $(KDIR)/svc/continuity_resolve.c \
	$(KDIR)/svc/continuity_resolve_sealed.c $(KDIR)/svc/continuity_commit.c $(KDIR)/svc/continuity_recovery.c \
	$(KDIR)/svc/continuity_boot.c $(KDIR)/svc/continuity_subject.c $(KDIR)/svc/continuity_subject_provision.c
endif
ifneq ($(strip $(CK_SERVICE)$(CK_PI5_LIFECYCLE)),)
SVC_STAGE_BASE := $(STAGE_SRCS)
# Own OUT subdirectory: service objects never mix with a diagnostic image.
ifeq ($(strip $(CK_SERVICE_TEST_KEYS)),1)
FULL_NAME := full-service-testkeys
STAGE_DMA_FLAGS += -DCK_SERVICE=1 -DCK_SERVICE_TEST_KEYS=1
else
FULL_NAME := full-service$(if $(strip $(CK_HARDWARE_STAGING)),-hardware-staging,)
STAGE_DMA_FLAGS += -DCK_SERVICE=1
endif
STAGE_SRCS += $(KDIR)/core/lifecycle.c $(KDIR)/core/lifecycle_fsm.c $(KDIR)/core/line_rx.c
# N3 (aienos#329): context assembly and the exact approval binding (pure C, host-tested by test_context).
STAGE_SRCS += $(KDIR)/core/context.c $(KDIR)/core/context_proposal.c
# P06 cut 3: the canonical Omega Cortex store over the sealed Store (svc/cortex_journal.c).
STAGE_SRCS += $(STAGE_CORTEX_SRCS)
# P05 cut 1: production continuity on the service lifecycle (svc/continuity_service.c):
# the continuity layer without its TEST-ONLY mode selection (continuity_boot.c)
# and without the Recovery Core (continuity_recovery.c, TEST operator key).
STAGE_DMA_FLAGS += -I$(KDIR)/core
STAGE_SRCS += $(KDIR)/svc/continuity_codec.c $(KDIR)/svc/continuity_resolve.c \
	$(KDIR)/svc/continuity_resolve_sealed.c $(KDIR)/svc/continuity_commit.c \
	$(KDIR)/svc/continuity_subject.c $(KDIR)/svc/continuity_subject_provision.c $(KDIR)/svc/continuity_service.c
# P11 cut 2b: kernel-side slot promotion / abandon (svc/slot_service.c) over the shared
# slot decision rules and control-commit routine of SLOTLDR.EFI (native/boot).
STAGE_SRCS += $(KDIR)/svc/slot_service.c $(BOOT)/slot_select.c $(BOOT)/slot_control.c
# P11 cut 3: the inactive-slot updater (svc/slot_service.c verb `update`, native/boot/slot_update.c)
# verifies the inbox image against the key table SLOTLDR.EFI is built with (ck_slot_tool keys-c):
# RFC 8032 TEST 1 in the TEST-keys image, the Owner Root (CK_OWNER_PUBKEYS) under CK_HARDWARE_STAGING.
# The plain service image gets no table and refuses every update.
STAGE_SRCS += $(BOOT)/slot_update.c
SVC_SLOT_KEY_SRC := $(if $(strip $(CK_SERVICE_TEST_KEYS)),--test-key,$(if $(strip $(CK_HARDWARE_STAGING)),--keys $(OWNER_PUBKEYS_FILE),))
ifneq ($(SVC_SLOT_KEY_SRC),)
SVC_SLOT_KEYS_C := $(OUT)/gen-$(FULL_NAME)/svc_slot_keys.c
STAGE_SRCS += $(SVC_SLOT_KEYS_C)
STAGE_DMA_FLAGS += -DCK_SLOT_UPDATE_KEYS=1
endif
# The sources this block added: the Pi block below restarts STAGE_SRCS, the lifecycle image takes them over.
SVC_STAGE_ADDED := $(filter-out $(SVC_STAGE_BASE),$(STAGE_SRCS))
endif
ifeq ($(strip $(CK_TEST_DISK_XLATE_BYPASS)),1)
FULL_NAME := $(FULL_NAME)-test-xlate-bypass
STAGE_DMA_FLAGS += -DCK_TEST_DISK_XLATE_BYPASS=1
endif
# AIENOS-PI5 step 3b: the sealed Store stage on the Pi card, in the TEST-key qualification tier
# (SEED-0B-PI5, the Pi counterpart of the QEMU full image). Only the Store stage and what it needs
# are linked: no PCI, NVMe, USB, virtio, SMMU or security stage (none of that hardware is on the
# Pi path). core/pi5.c supplies ck_dev_boot_disk and ck_dev_nvme_release over the SD partition view.
FULL_STAGE_SYMS := ck_stage_devices ck_stage_security ck_stage_store ck_stage_quiesce ck_stage_disk_artifacts
ifneq ($(strip $(CK_PI5_STORE)$(CK_PI5_UNLOCK)),)
FULL_NAME := $(if $(strip $(CK_PI5_UNLOCK)),full-pi5-unlock$(if $(strip $(CK_PI5_UNLOCK_CARD)),-card)$(if $(strip $(CK_PI5_FACT)),-fact)$(if $(strip $(CK_PI5_AGENT)),-agent)$(if $(strip $(CK_PI5_LIFECYCLE)),-lifecycle),full-pi5-store)
FULL_STAGE_SYMS := ck_stage_store ck_stage_disk_artifacts
STAGE_SRCS := $(KDIR)/svc/store_boot.c $(KDIR)/svc/artifact_store.c $(KDIR)/svc/store_crash.c $(KDIR)/svc/ck_compat.c \
  $(foreach m,store/store_v1 store/store_engine store/store_disk store/store_sealed store/torn_slot m5/m5_keys m5/m5_envelope m5/m5_state crypto/aes crypto/polyval crypto/gcm_siv crypto/hmac crypto/ct argus/sha256,$(NATIVE)/$(m).c)
ifneq ($(strip $(CK_PI5_FACT)),)
STAGE_SRCS += $(KDIR)/svc/pi5_fact.c $(STAGE_CORTEX_SRCS)
endif
ifneq ($(strip $(CK_PI5_AGENT)),)
STAGE_SRCS += $(KDIR)/svc/pi5_agent.c
endif
ifneq ($(strip $(CK_PI5_LIFECYCLE)),)
# The NVMe image-slot service is not part of the Pi image: its four hooks are answered by svc/slot_service_pi5.c.
STAGE_SRCS += $(filter-out $(KDIR)/svc/slot_service.c $(BOOT)/slot_select.c $(BOOT)/slot_control.c $(BOOT)/slot_update.c,$(SVC_STAGE_ADDED)) $(KDIR)/svc/slot_service_pi5.c
endif
endif
FULL_OUT := $(OUT)/$(FULL_NAME)
STAGE_KOBJ := $(OUT)/obj/stage-$(FULL_NAME)
STAGE_HDRS := $(HDRS) $(wildcard $(NATIVE)/*/*.h $(NATIVE)/argus/bridge/*.h $(KDIR)/svc/compat/*.h)
STAGE_BUILT := $(foreach s,$(STAGE_SRCS),$(STAGE_KOBJ)/$(subst /,_,$(patsubst $(REPO)/%,%,$(abspath $(s)))).o)
# STAGE_CFLAGS first: svc/compat must shadow the hosted headers. No fortify.
STAGE_KCFLAGS := $(STAGE_CFLAGS) $(KCFLAGS) $(MODULE_INC) -U_FORTIFY_SOURCE $(STAGE_DMA_FLAGS)
# The core already links argus/sha256.c (artifact loader); link it once.
STAGE_LINK := $(filter-out %/native_argus_sha256.c.o,$(STAGE_BUILT))

ELF := $(OUT)/aienos-ck.elf
EFI := $(OUT)/BOOTAA64.EFI
FULL_ELF := $(FULL_OUT)/aienos-ck.elf
FULL_EFI := $(FULL_OUT)/BOOTAA64.EFI

all: $(EFI)
full: $(FULL_EFI)

print-kcflags:
	@echo $(KCFLAGS) $(MODULE_INC)

$(OUT)/commit.stamp: FORCE
	@mkdir -p $(OUT)
	@echo '$(AIENOS_COMMIT)' | cmp -s - $@ || echo '$(AIENOS_COMMIT)' > $@

$(KOBJ)/%.o: $(NATIVE)/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) -c -o $@ $<

$(KOBJ)/kernel/core/report.o: $(KDIR)/core/report.c $(HDRS) $(OUT)/commit.stamp
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) -DAIENOS_COMMIT='"$(AIENOS_COMMIT)"' -c -o $@ $<

# Artifact loader objects: compat headers for <string.h>, TEST-anchor flag.
ART_OBJS := $(patsubst $(NATIVE)/%.c,$(KOBJ)/%.o,$(ART_C))
ART_HDRS := $(wildcard $(NATIVE)/sig/*.h $(NATIVE)/argus/sha256.h $(KDIR)/svc/compat/*.h)
$(ART_OBJS): KCFLAGS += $(ART_INC)
$(ART_OBJS): $(ART_HDRS)

# core/pi5.c drives the SD card through native/disk.
$(KOBJ)/kernel/core/pi5.o: KCFLAGS += -I$(NATIVE)/disk
$(KOBJ)/kernel/core/pi5_marker.o: KCFLAGS += -I$(NATIVE)/disk
$(KOBJ)/kernel/arch/rndr.o: KCFLAGS += -I$(KDIR)/dev
$(KOBJ)/kernel/dev/disk_part.o: KCFLAGS += -I$(NATIVE)/disk

# core/infer.c uses the in-core SHA-256 (argus) to prove the ingested bytes.
$(KOBJ)/kernel/core/infer.o: KCFLAGS += -I$(NATIVE)/argus

$(OUT)/trust.stamp: FORCE
	@mkdir -p $(OUT)
	@echo '$(ART_TRUST_FLAGS)' | cmp -s - $@ || echo '$(ART_TRUST_FLAGS)' > $@

$(KOBJ)/kernel/core/artifact_loader.o: $(KDIR)/core/artifact_loader.c $(HDRS) $(ART_HDRS) \
		$(OUT)/commit.stamp $(OUT)/trust.stamp
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) $(ART_TRUST_FLAGS) -DAIENOS_COMMIT='"$(AIENOS_COMMIT)"' -c -o $@ $<

$(KOBJ)/kernel/core/osc_admit.o: $(KDIR)/core/osc_admit.c $(HDRS) $(ART_HDRS) $(OUT)/trust.stamp
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) $(ART_TRUST_FLAGS) -c -o $@ $<

# core/osh_op.c refuses to build without CK_OSH_OP_TEST (and with CK_HARDWARE_STAGING): it takes the trust flags too.
$(KOBJ)/kernel/core/osh_op.o: $(KDIR)/core/osh_op.c $(KDIR)/core/osh_op.h $(HDRS) $(OUT)/trust.stamp
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) $(ART_TRUST_FLAGS) -c -o $@ $<

# core/osh_test.c reads CK_OSH_OP_TEST, so it takes the trust flags too (and is rebuilt when they change).
$(KOBJ)/kernel/core/osh_test.o: $(KDIR)/core/osh_test.c $(HDRS) $(ART_HDRS) $(OUT)/trust.stamp
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) $(ART_TRUST_FLAGS) -c -o $@ $<

$(KOBJ)/%.o: $(NATIVE)/%.S
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) -c -o $@ $<

define stage_rule
$(STAGE_KOBJ)/$(subst /,_,$(patsubst $(REPO)/%,%,$(abspath $(1)))).o: $(1) $(STAGE_HDRS) $(OWNER_HDR)
	@mkdir -p $$(dir $$@)
	$(KCC) $(STAGE_KCFLAGS) -c -o $$@ $(1)
endef
$(foreach s,$(STAGE_SRCS),$(eval $(call stage_rule,$(s))))

# fwcfg_check(elf): a default image (no CK_TEST_FWCFG_ARTIFACTS) must carry no
# fw_cfg artifact code or strings; a test image must carry its announcement.
# The QEMU inference images (CK_INFER_LIB without hardware staging, aienos#34
# lane 4) read their model over fw_cfg when no MODEL.MAP is found: they must
# carry their own TEST-ONLY announcement instead. The hardware service image
# with inference (CK_INFER_LIB + CK_HARDWARE_STAGING, boot-disk only) must
# carry the boot-disk source line, the resident session, and no fw_cfg code.
define fwcfg_check
	@if [ -n "$(strip $(CK_INFER_LIB))" ] && [ -z "$(strip $(CK_HARDWARE_STAGING))" ] && [ -z "$(strip $(CK_PI5_INFER))" ] && [ -z "$(strip $(CK_PI5_AGENT))" ] && [ -z "$(strip $(CK_PI5_LIFECYCLE))" ]; then \
	  grep -aqF "TEST-ONLY QEMU fw_cfg model ingest" $(1) || { echo "inference probe image lacks its TEST-ONLY fw_cfg announcement"; rm -f $(1); exit 1; }; \
	elif [ "$(strip $(CK_TEST_FWCFG_ARTIFACTS))" = 1 ]; then \
	  grep -aqF "TEST-ONLY QEMU fw_cfg side channel" $(1) || { echo "test fw_cfg image lacks its TEST-ONLY announcement"; rm -f $(1); exit 1; }; \
	else \
	  s=$$(grep -aoE "opt/aienos/artifacts|opt/aienos/model|fw_cfg|QEMU0002" $(1) | sort -u | tr "\n" " "); \
	  y=$$($(KNM) $(1) | grep -E " (fw_select|fw_read|fw_skip|fw_find|fw_dma_read|fwcfg_from_dsdt|fwcfg_source|fwcfg)$$" | tr "\n" " "); \
	  if [ -n "$$s$$y" ]; then echo "default image carries fw_cfg artifact code: $$s$$y"; rm -f $(1); exit 1; fi; \
	  if [ -n "$(strip $(CK_INFER_LIB))" ]; then \
	    grep -aqF "infer_source_mode: boot-disk model" $(1) || { echo "hardware inference image lacks the boot-disk model source"; rm -f $(1); exit 1; }; \
	    if [ -z "$(strip $(CK_PI5_INFER))" ]; then grep -aqF "infer: resident open" $(1) || { echo "hardware inference image lacks the resident session"; rm -f $(1); exit 1; }; fi; \
	    echo "hardware inference image: boot-disk model source only, no fw_cfg code in $(1)"; \
	  fi; \
	  echo "no fw_cfg artifact code in $(1)"; \
	fi
endef

# console_check(elf): only a CK_CONSOLE_SESSION image may carry the console
# session code; only a CK_TEST_CONSOLE_MUTATION image its mutation banner.
define console_check
	@if [ "$(strip $(CK_CONSOLE_SESSION))" = 1 ]; then \
	  grep -aqF "console_session: begin" $(1) || { echo "console session image lacks its stage"; rm -f $(1); exit 1; }; \
	else \
	  if grep -aqF "console_session:" $(1); then echo "default image carries the console session"; rm -f $(1); exit 1; fi; \
	  echo "no console session code in $(1)"; \
	fi
	@if [ -n "$(strip $(CK_TEST_CONSOLE_MUTATION))" ]; then \
	  grep -aqF "TEST-ONLY console session MUTATION BUILD" $(1) || { echo "console mutation image lacks its TEST-ONLY banner"; rm -f $(1); exit 1; }; \
	else \
	  if grep -aqF "TEST-ONLY console session MUTATION" $(1); then echo "image carries the console mutation without asking"; rm -f $(1); exit 1; fi; \
	fi
endef

# service_check(elf): only a CK_SERVICE image may carry the resident lifecycle;
# only a CK_SERVICE_TEST_KEYS image its TEST-ONLY banner.
define service_check
	@if [ "$(strip $(CK_SERVICE))" = 1 ] || [ -n "$(strip $(CK_PI5_LIFECYCLE))" ]; then \
	  grep -aqF "lifecycle: ready" $(1) || { echo "service image lacks the resident lifecycle"; rm -f $(1); exit 1; }; \
	else \
	  if grep -aqF "lifecycle: ready" $(1); then echo "diagnostic image carries the resident lifecycle"; rm -f $(1); exit 1; fi; \
	  echo "no resident lifecycle in $(1)"; \
	fi
	@if [ "$(strip $(CK_SERVICE_TEST_KEYS))" = 1 ]; then \
	  grep -aqF "TEST-ONLY service image" $(1) || { echo "service test-keys image lacks its TEST-ONLY banner"; rm -f $(1); exit 1; }; \
	else \
	  if grep -aqF "TEST-ONLY service image" $(1); then echo "image carries TEST Store keys without asking"; rm -f $(1); exit 1; fi; \
	fi
endef

# xhci_mut_check(elf): only a CK_TEST_XHCI_MUTATION image may carry the
# TEST-ONLY xHCI mutation banner (and it must carry it).
define xhci_mut_check
	@if [ -n "$(strip $(CK_TEST_XHCI_MUTATION))" ]; then \
	  grep -aqF "TEST-ONLY xHCI MUTATION BUILD" $(1) || { echo "xHCI mutation image lacks its TEST-ONLY banner"; rm -f $(1); exit 1; }; \
	else \
	  if grep -aqF "TEST-ONLY xHCI MUTATION" $(1); then echo "default image carries the TEST-ONLY xHCI mutation"; rm -f $(1); exit 1; fi; \
	  echo "no xHCI mutation code in $(1)"; \
	fi
endef

# owner_check(elf): a hardware staging image must carry no TEST Store label,
# TEST store uuid, TEST Store print lines or TEST key symbols.
define owner_check
	@if [ "$(strip $(CK_HARDWARE_STAGING))" = 1 ]; then \
	  s=$$(grep -aoE "AIENOS-LANE18-TEST-KVOL-NOT-SECRET|AIEN-TEST-BOOT01|TEST identity, TEST keys|formatted TEST store|TEST machine id 0xA1" $(1) | sort -u | tr "\n" " "); \
	  y=$$($(KNM) $(1) | grep -E " (ck_store_test_keys|ck_store_test_uuid)$$" | tr "\n" " "); \
	  if [ -n "$$s$$y" ]; then echo "hardware staging image carries the TEST Store identity: $$s$$y"; rm -f $(1); exit 1; fi; \
	  echo "no TEST Store label, uuid or key code in $(1)"; \
	fi
endef

# rollback_check(elf): only a CK_TEST_ROLLBACK image may carry a TEST-only
# rollback candidate, and it must announce itself.
define rollback_check
	@if [ -n "$(strip $(CK_TEST_ROLLBACK))" ]; then \
	  grep -aqF "TEST-ONLY rollback candidate ($(strip $(CK_TEST_ROLLBACK)))" $(1) || { echo "rollback test image lacks its TEST-ONLY announcement"; rm -f $(1); exit 1; }; \
	else \
	  if grep -aqF "TEST-ONLY rollback candidate" $(1); then echo "default image carries a TEST-ONLY rollback candidate"; rm -f $(1); exit 1; fi; \
	fi
endef

# smp_check(elf): only a CK_TEST_SMP_SKIP_CPU image may carry the SMP mutation
# announcement, and such an image must carry it.
define smp_check
	@if [ "$(strip $(CK_TEST_SMP_SKIP_CPU))" = 1 ]; then \
	  grep -aqF "TEST-ONLY SMP mutation" $(1) || { echo "SMP mutation image lacks its TEST-ONLY announcement"; rm -f $(1); exit 1; }; \
	else \
	  if grep -aqF "TEST-ONLY SMP mutation" $(1); then echo "default image carries the TEST-ONLY SMP mutation"; rm -f $(1); exit 1; fi; \
	fi
endef

# b7b_check(elf): only a CK_B7B_PROBE image may carry the B7b probe, and such an
# image must; only a CK_B7B_PROBE_TEST_SEGMENT0 image may carry the TEST-ONLY
# segment-0 announcement, and such an image must.
define b7b_check
	@if [ "$(strip $(CK_B7B_PROBE))" = 1 ]; then \
	  grep -aqF "b7b_probe: start segment=" $(1) || { echo "B7b probe image lacks the probe"; rm -f $(1); exit 1; }; \
	else \
	  if grep -aqF "b7b_probe:" $(1); then echo "default image carries the B7b probe"; rm -f $(1); exit 1; fi; \
	fi
	@if [ "$(strip $(CK_B7B_PROBE_TEST_SEGMENT0))" = 1 ]; then \
	  grep -aqF "TEST-ONLY B7b probe on PCI segment 0" $(1) || { echo "segment-0 probe image lacks its TEST-ONLY announcement"; rm -f $(1); exit 1; }; \
	else \
	  if grep -aqF "TEST-ONLY B7b probe" $(1); then echo "image carries the TEST-ONLY segment-0 probe"; rm -f $(1); exit 1; fi; \
	fi
endef

# crash_check(elf): a full image built without CK_TEST_STORE_CRASH must carry
# no Store crash hook code or strings; a TEST crash image must announce itself.
# The bare "TEST-ONLY MUTANT" phrase is refused here except in the TEST
# continuity image, whose own mutants print it (cont_check refuses it in every
# image built without CK_TEST_CONTINUITY; crash-hook mutants are still caught
# by their "store_crash:" prefix).
define crash_check
	@if [ "$(strip $(CK_TEST_STORE_CRASH))" = 1 ]; then \
	  grep -aqF "TEST-ONLY Store crash hook image" $(1) || { echo "TEST crash image lacks its TEST-ONLY announcement"; rm -f $(1); exit 1; }; \
	else \
	  m="|TEST-ONLY MUTANT"; [ "$(strip $(CK_TEST_CONTINUITY))" = 1 ] && m=""; \
	  s=$$(grep -aoE "store_crash:|AIENCRSH$$m" $(1) | sort -u | tr "\n" " "); \
	  y=$$($(KNM) $(1) | grep -E " ck_store_crash_[a-z_]+$$" | tr "\n" " "); \
	  if [ -n "$$s$$y" ]; then echo "default image carries the TEST Store crash hook: $$s$$y"; rm -f $(1); exit 1; fi; \
	  echo "no Store crash hook code in $(1)"; \
	fi
endef

# cont_check(elf): a full image built without CK_TEST_CONTINUITY must carry no
# TEST continuity wiring code or strings; a TEST continuity image must announce
# itself. A CK_SERVICE image carries the production continuity layer (P05 cut 1:
# cr_provision/cr_resume through svc/continuity_service.c) and must still carry
# neither the TEST mode selection (ck_cont_boot_stage, AIENCONT plan line) nor
# the Recovery Core (rc_inspect, the TEST operator key).
define cont_check
	@if [ "$(strip $(CK_TEST_CONTINUITY))" = 1 ]; then \
	  grep -aqF "TEST-ONLY continuity mode selection image" $(1) || { echo "TEST continuity image lacks its TEST-ONLY announcement"; rm -f $(1); exit 1; }; \
	else \
	  m="|TEST-ONLY MUTANT"; [ "$(strip $(CK_TEST_STORE_CRASH))" = 1 ] && m=""; \
	  if [ "$(strip $(CK_SERVICE))" = 1 ] || [ -n "$(strip $(CK_PI5_LIFECYCLE))" ]; then \
	    s=$$(grep -aoE "AIENCONT|RECOVERY_OPERATOR_KEY|RECOVERY_CORE:|CONTINUITY: $$m" $(1) | sort -u | tr "\n" " "); \
	    y=$$($(KNM) $(1) | grep -E " (ck_cont_boot_stage|rc_inspect)$$" | tr "\n" " "); \
	    grep -aqF "continuity: REFUSED" $(1) || { echo "service image lacks the production continuity wiring"; rm -f $(1); exit 1; }; \
	  else \
	    s=$$(grep -aoE "AIENCONT|RECOVERY_OPERATOR_KEY|RECOVERY_CORE:|CONTINUITY: |continuity: REFUSED$$m" $(1) | sort -u | tr "\n" " "); \
	    y=$$($(KNM) $(1) | grep -E " (ck_cont_boot_stage|cr_resume|cr_provision|rc_inspect|ck_cont_service_start)$$" | tr "\n" " "); \
	  fi; \
	  if [ -n "$$s$$y" ]; then echo "image carries the TEST continuity wiring: $$s$$y"; rm -f $(1); exit 1; fi; \
	  echo "no TEST continuity wiring in $(1)"; \
	fi
endef

# link_image(output elf, objects): refuses undefined symbols (weak stage
# references excepted) and any relocation other than R_AARCH64_RELATIVE.
define link_image
	@mkdir -p $(dir $(1))
	$(KLD) $(KLDFLAGS) -o $(1) $(2)
	@u=$$($(KNM) -u $(1) | grep -v ' w ' || true); \
	if [ -n "$$u" ]; then echo "image has undefined symbols: $$u"; rm -f $(1); exit 1; fi
	@bad=$$($(KREADELF) -rW $(1) | grep -E '^[0-9a-f]+ ' | grep -v R_AARCH64_RELATIVE || true); \
	if [ -n "$$bad" ]; then echo "image has non-RELATIVE relocations:"; echo "$$bad"; rm -f $(1); exit 1; fi
endef
define pe_image
	$(KOBJCOPY) -O binary $(1) $(2)
	@sz=$$(stat -c %s $(2)); pad=$$(( (4096 - sz % 4096) % 4096 )); \
	if [ $$pad -gt 0 ]; then head -c $$pad /dev/zero >> $(2); fi
	@[ "$$(head -c 2 $(2))" = "MZ" ] || { echo "not a PE image"; rm -f $(2); exit 1; }
	@echo "built $(2) (commit $(AIENOS_COMMIT))"
endef

$(ELF): $(CORE_OBJS) $(BOOT)/image.ld
	$(call link_image,$@,$(CORE_OBJS) $(CK_RUST_LIBS) $(CK_INFER_LIB))
	@if [ -z "$(strip $(CK_TEST_STALE_HANDOFF))" ] && grep -aqF "TEST-ONLY stale handoff" $@; then \
	  echo "default image carries the TEST-only stale handoff"; rm -f $@; exit 1; fi
	$(call rollback_check,$@)
	@s=$$($(KNM) $@ | grep -E ' [TtDdBbWwVv] ck_stage_(devices|security|store|quiesce)$$' || true); \
	if [ -n "$$s" ]; then echo "core image defines stage symbols: $$s"; rm -f $@; exit 1; fi
	$(call fwcfg_check,$@)
	$(call smp_check,$@)
	$(call b7b_check,$@)

$(FULL_ELF): $(CORE_OBJS) $(STAGE_BUILT) $(BOOT)/image.ld
	$(call link_image,$@,$(CORE_OBJS) $(STAGE_LINK) $(CK_RUST_LIBS) $(CK_INFER_LIB))
	$(call rollback_check,$@)
	@for s in $(FULL_STAGE_SYMS); do \
	  $(KNM) $@ | grep -qE " [TW] $$s$$" || { echo "full image lacks $$s"; rm -f $@; exit 1; }; done
	$(call fwcfg_check,$@)
	$(call owner_check,$@)
	$(call xhci_mut_check,$@)
	$(call console_check,$@)
	$(call service_check,$@)
	$(call smp_check,$@)
	$(call crash_check,$@)
	$(call b7b_check,$@)
	$(call cont_check,$@)

$(EFI): $(ELF)
	$(call pe_image,$<,$@)

$(FULL_EFI): $(FULL_ELF)
	$(call pe_image,$<,$@)

# ---- host unit tests ----
HOST_SRCS := $(KDIR)/core/fmt.c $(KDIR)/core/acpi.c $(KDIR)/core/smmu.c $(KDIR)/mm/frames.c \
	$(KDIR)/mm/pt.c $(KDIR)/mm/heap.c $(KDIR)/core/sched.c $(KDIR)/core/ipc.c $(KDIR)/core/entropy.c \
	$(KDIR)/core/handoff_check.c $(KDIR)/core/fbcon.c $(KDIR)/core/acpi_dev.c $(KDIR)/core/lifecycle_fsm.c \
	$(KDIR)/core/line_rx.c $(KDIR)/core/klog.c $(KDIR)/core/klog_slot.c $(KDIR)/core/cpufeat.c $(KDIR)/core/unlock_req.c $(KDIR)/core/agent_cmd.c $(KDIR)/core/artifact_card.c
TESTS := test_fmt test_frames test_pt test_acpi test_acpi_dev test_heap test_smmu test_sched test_ipc test_artifact test_osc_unit test_osc_launch test_osc_admit test_osc_receipt test_entropy test_handoff test_fbcon test_osh_op \
	test_continuity_codec test_continuity_resolve test_continuity_commit test_continuity_recovery test_continuity_geometry \
	test_continuity_subject test_continuity_subject_provision test_lifecycle test_console_rx test_klog test_klog_slot test_pi5 test_pi5_marker test_pi5_rng test_cpufeat test_dma_window test_pi5_pcie test_pi5_net test_pi5_gem test_unlock_req test_context test_agent_cmd test_artifact_card
HCFLAGS := -std=gnu11 -O1 -g -Wall -Wextra -Werror -I$(KDIR)/core -I$(KDIR)/mm -I$(KDIR)/tests -I$(BOOT)
SANFLAGS := -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer

$(OUT)/host/%: $(KDIR)/tests/%.c $(HOST_SRCS) $(KDIR)/tests/ck_test.h $(HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -o $@ $< $(HOST_SRCS)

$(OUT)/host-san/%: $(KDIR)/tests/%.c $(HOST_SRCS) $(KDIR)/tests/ck_test.h $(HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) -o $@ $< $(HOST_SRCS)

# OSH adapter operation layer (core/osh_op.c, aien-architecture#158): pure logic over ipc.c capabilities, SHA-256 for the
# request digest. Its own rule because it needs the argus SHA-256 source.
OSH_OP_SRCS := $(KDIR)/core/osh_op.c $(KDIR)/core/ipc.c $(KDIR)/core/fmt.c $(NATIVE)/argus/sha256.c
$(OUT)/host/test_osh_op: $(KDIR)/tests/test_osh_op.c $(OSH_OP_SRCS) $(KDIR)/tests/ck_test.h $(HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -DCK_OSH_OP_TEST -I$(NATIVE)/argus -o $@ $< $(OSH_OP_SRCS)

$(OUT)/host-san/test_osh_op: $(KDIR)/tests/test_osh_op.c $(OSH_OP_SRCS) $(KDIR)/tests/ck_test.h $(HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) -DCK_OSH_OP_TEST -I$(NATIVE)/argus -o $@ $< $(OSH_OP_SRCS)

# TEST-ONLY mutant of core/osh_op.c: the permission check always says OK. test_osh_op must FAIL against it (red before
# green); "make test" fails if the test stops catching it. Host only (osh_op.c refuses the flag freestanding).
$(OUT)/host/test_osh_op_mutant: $(KDIR)/tests/test_osh_op.c $(OSH_OP_SRCS) $(KDIR)/tests/ck_test.h $(HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -DCK_OSH_OP_TEST -I$(NATIVE)/argus -DCK_OSH_OP_MUTANT_SKIP_PERM -o $@ $< $(OSH_OP_SRCS)

osh-op-mutant: $(OUT)/host/test_osh_op_mutant
	@if $< > $<.log 2>&1; then cat $<.log; echo "test_osh_op mutant (permission check always OK): PASSED, test does not catch it"; exit 1; \
	else grep -F "test_osh_op: FAIL" $<.log && echo "test_osh_op mutant (permission check always OK): FAILS as required"; fi

# N3 context assembly + approval binding (core/context.c, core/context_proposal.c, aienos#329): pure logic over
# the argus SHA-256. Own rule (needs sha256.c). The mutant skips the foreign-binding check: test_context must
# FAIL against it (red before green); "make test" fails if the test stops catching it. Host only (context.c
# refuses the flag outside CK_CTX_HOST_TEST).
CONTEXT_SRCS := $(KDIR)/core/context.c $(KDIR)/core/context_proposal.c $(NATIVE)/argus/sha256.c
$(OUT)/host/test_context: $(KDIR)/tests/test_context.c $(CONTEXT_SRCS) $(KDIR)/tests/ck_test.h $(HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -DCK_CTX_HOST_TEST -o $@ $< $(CONTEXT_SRCS)

$(OUT)/host-san/test_context: $(KDIR)/tests/test_context.c $(CONTEXT_SRCS) $(KDIR)/tests/ck_test.h $(HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) -DCK_CTX_HOST_TEST -o $@ $< $(CONTEXT_SRCS)

$(OUT)/host/test_context_mutant: $(KDIR)/tests/test_context.c $(CONTEXT_SRCS) $(KDIR)/tests/ck_test.h $(HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -DCK_CTX_HOST_TEST -DCK_CTX_MUTANT_SKIP_BINDING -o $@ $< $(CONTEXT_SRCS)

context-mutant: $(OUT)/host/test_context_mutant
	@if $< > $<.log 2>&1; then cat $<.log; echo "test_context mutant (foreign binding check skipped): PASSED, test does not catch it"; exit 1; \
	else grep -F "test_context: FAIL" $<.log && echo "test_context mutant (foreign binding check skipped): FAILS as required"; fi

# PI5-7 cut 2 card command script parser (core/agent_cmd.c): the mutant accepts any word as a verb (a script could then carry unlock
# or rotate); test_agent_cmd must FAIL against it (red before green). Host only, never part of an image.
$(OUT)/host/test_agent_cmd_mutant: $(KDIR)/tests/test_agent_cmd.c $(KDIR)/core/agent_cmd.c $(KDIR)/core/agent_cmd.h $(KDIR)/tests/ck_test.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -DCK_AGENT_CMD_MUTANT_ANY_VERB -o $@ $< $(KDIR)/core/agent_cmd.c

agent-cmd-mutant: $(OUT)/host/test_agent_cmd_mutant
	@if $< > $<.log 2>&1; then cat $<.log; echo "test_agent_cmd mutant (any verb allowed): PASSED, test does not catch it"; exit 1; \
	else grep -F "test_agent_cmd: FAIL" $<.log && echo "test_agent_cmd mutant (any verb allowed): FAILS as required"; fi

# PI5-7 cut 3 card artifact bundle parser (core/artifact_card.c): the mutant accepts bytes after the last entry (a second, unchecked
# payload could ride along); test_artifact_card must FAIL against it (red before green). Host only, never part of an image.
$(OUT)/host/test_artifact_card_mutant: $(KDIR)/tests/test_artifact_card.c $(KDIR)/core/artifact_card.c $(KDIR)/core/artifact_card.h $(KDIR)/tests/ck_test.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -DCK_ACARD_MUTANT_TRAILING -o $@ $< $(KDIR)/core/artifact_card.c

artifact-card-mutant: $(OUT)/host/test_artifact_card_mutant
	@if $< > $<.log 2>&1; then cat $<.log; echo "test_artifact_card mutant (trailing bytes accepted): PASSED, test does not catch it"; exit 1; \
	else grep -F "test_artifact_card: FAIL" $<.log && echo "test_artifact_card mutant (trailing bytes accepted): FAILS as required"; fi

# TEST-ONLY mutant of core/handoff_check.c (reserved0 check removed): the
# handoff test must FAIL against it, so "make test" fails if the test stops
# catching the mutation. Host only (handoff_check.c refuses it freestanding
# and with CK_HARDWARE_STAGING); never part of an image.
$(OUT)/host/test_handoff_mutant: $(KDIR)/tests/test_handoff.c $(HOST_SRCS) $(KDIR)/tests/ck_test.h $(HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -DCK_HANDOFF_MUTANT_SKIP_RESERVED -o $@ $< $(HOST_SRCS)

handoff-mutant: $(OUT)/host/test_handoff_mutant
	@if $< > $<.log 2>&1; then cat $<.log; echo "test_handoff mutant (reserved0 check removed): PASSED, test does not catch it"; exit 1; \
	else grep -F "test_handoff: FAIL" $<.log && echo "test_handoff mutant (reserved0 check removed): FAILS as required"; fi

# TEST-ONLY mutants of core/acpi_dev.c (NEXT-PHASE-3 cut 2): 1 = table
# signature check removed, 2 = checksum check removed, 3 = length-versus-
# buffer check removed (truncated table trusted). test_acpi_dev must FAIL
# against each. Host only (acpi_dev.c refuses CK_AML_MUTANT freestanding).
acpi-dev-mutant: $(KDIR)/tests/test_acpi_dev.c $(HOST_SRCS) $(KDIR)/tests/ck_test.h $(HDRS)
	@mkdir -p $(OUT)/host
	@for m in 1 2 3; do b=$(OUT)/host/test_acpi_dev_mutant$$m; \
	  $(HOSTCC) $(HCFLAGS) -DCK_AML_MUTANT=$$m -o $$b $(KDIR)/tests/test_acpi_dev.c $(HOST_SRCS) || exit 1; \
	  if $$b > $$b.log 2>&1; then cat $$b.log; echo "test_acpi_dev mutant $$m: PASSED, test does not catch it"; exit 1; \
	  else grep -F "test_acpi_dev: FAIL" $$b.log >/dev/null && echo "test_acpi_dev mutant $$m: FAILS as required" || { cat $$b.log; exit 1; }; fi; done

# TEST-ONLY mutants of the IORT parse/lookup in core/acpi.c: test_smmu must
# FAIL against each (TRUNCATE: extra mappings dropped instead of the table
# refused; SEGMENT_BLIND: lookup ignores the PCI segment; OVERLAP_OK:
# overlapping input ranges in one segment accepted; OTHER_BLIND: mappings to
# a second SMMUv3 node forgotten, so a GB10-shaped requester reads as "no
# stream" instead of "behind another SMMU"; RMR_BLIND: RMR nodes ignored, so
# the GB10 stream would lose its firmware-reserved ranges; RMR_EXCLUSIVE:
# the RMR stream range read as exclusive, dropping the last stream (the
# GB10, 0x100); ROUTE_FIRST: every requester routed to the first SMMU, so the
# GB10 would be programmed on the wrong SMMU). Host only (acpi.c refuses them
# freestanding and with CK_HARDWARE_STAGING).
IORT_MUTANTS := CK_IORT_MUTANT_TRUNCATE CK_IORT_MUTANT_SEGMENT_BLIND CK_IORT_MUTANT_OVERLAP_OK CK_IORT_MUTANT_OTHER_BLIND \
                CK_IORT_MUTANT_RMR_BLIND CK_IORT_MUTANT_RMR_EXCLUSIVE CK_IORT_MUTANT_ROUTE_FIRST
iort-mutants: $(OUT)/host/test_smmu
	@mkdir -p $(OUT)/host-mut; fail=0; \
	$(OUT)/host/test_smmu > $(OUT)/host-mut/iort-base.log 2>&1 || { echo "unmutated test_smmu fails"; fail=1; }; \
	for m in $(IORT_MUTANTS); do \
	  b=$(OUT)/host-mut/test_smmu_$$m; \
	  if ! $(HOSTCC) $(HCFLAGS) -D$$m -o $$b $(KDIR)/tests/test_smmu.c $(HOST_SRCS); then \
	    echo "mutant $$m: does not build (FAIL)"; fail=1; continue; fi; \
	  if $$b > $$b.log 2>&1; then echo "mutant $$m: SURVIVED (FAIL)"; fail=1; \
	  elif grep -q "^test_smmu: FAIL" $$b.log; then \
	    echo "mutant $$m: killed ($$(grep -c '^  FAIL ' $$b.log) checks failed)"; \
	  else echo "mutant $$m: no FAIL verdict (crashed?) (FAIL)"; fail=1; fi; \
	done; \
	if $(HOSTCC) $(HCFLAGS) -DCK_HARDWARE_STAGING=1 -DCK_IORT_MUTANT_SEGMENT_BLIND \
	    -fsyntax-only $(KDIR)/core/acpi.c 2>/dev/null; then \
	  echo "mutant flag accepted under CK_HARDWARE_STAGING (FAIL)"; fail=1; \
	else echo "mutant flag refused under CK_HARDWARE_STAGING"; fi; \
	if [ $$fail = 0 ]; then echo "CK_IORT_MUTANTS: PASS"; else echo "CK_IORT_MUTANTS: FAIL"; exit 1; fi

# TEST-ONLY mutants of the two-level stream table in core/smmu.c: test_smmu
# must FAIL against each (SPAN_OVERFLOW: L1STD Span past SPLIT + 1;
# UNGRANTED_VALID: L1STDs valid before any grant; BAD_L1_PTR: misaligned L1
# table accepted; L2_NO_FILL: a new L2 page published without abort STEs).
# Host only (smmu.c refuses them freestanding and with CK_HARDWARE_STAGING).
SMMU_L2_MUTANTS := CK_SMMU_MUTANT_SPAN_OVERFLOW CK_SMMU_MUTANT_UNGRANTED_VALID CK_SMMU_MUTANT_BAD_L1_PTR CK_SMMU_MUTANT_L2_NO_FILL
smmu-l2-mutants: $(OUT)/host/test_smmu
	@mkdir -p $(OUT)/host-mut; fail=0; \
	$(OUT)/host/test_smmu > $(OUT)/host-mut/smmu-l2-base.log 2>&1 || { echo "unmutated test_smmu fails"; fail=1; }; \
	for m in $(SMMU_L2_MUTANTS); do \
	  b=$(OUT)/host-mut/test_smmu_$$m; \
	  if ! $(HOSTCC) $(HCFLAGS) -D$$m -o $$b $(KDIR)/tests/test_smmu.c $(HOST_SRCS); then \
	    echo "mutant $$m: does not build (FAIL)"; fail=1; continue; fi; \
	  if $$b > $$b.log 2>&1; then echo "mutant $$m: SURVIVED (FAIL)"; fail=1; \
	  elif grep -q "^test_smmu: FAIL" $$b.log; then \
	    echo "mutant $$m: killed ($$(grep -c '^  FAIL ' $$b.log) checks failed)"; \
	  else echo "mutant $$m: no FAIL verdict (crashed?) (FAIL)"; fail=1; fi; \
	done; \
	if $(HOSTCC) $(HCFLAGS) -DCK_HARDWARE_STAGING=1 -DCK_SMMU_MUTANT_SPAN_OVERFLOW \
	    -fsyntax-only $(KDIR)/core/smmu.c 2>/dev/null; then \
	  echo "mutant flag accepted under CK_HARDWARE_STAGING (FAIL)"; fail=1; \
	else echo "mutant flag refused under CK_HARDWARE_STAGING"; fi; \
	if [ $$fail = 0 ]; then echo "CK_SMMU_L2_MUTANTS: PASS"; else echo "CK_SMMU_L2_MUTANTS: FAIL"; exit 1; fi

test: $(addprefix $(OUT)/host/,$(TESTS)) osc-receipt-mutants osc-receipt-release handoff-mutant acpi-dev-mutant iort-mutants smmu-l2-mutants osh-op-mutant context-mutant agent-cmd-mutant artifact-card-mutant artifact-tier-pi5 artifact-tier-mutant test-continuity-subject-restart gsp-fw-inspect-test gsp-cot-test gsp-bindata-test gsp-bootargs-test gsp-rpc-test slot-test slot-free package-test slot-loader-check
	@fail=0; for t in $(filter-out osc-receipt-mutants osc-receipt-release handoff-mutant acpi-dev-mutant iort-mutants smmu-l2-mutants osh-op-mutant context-mutant agent-cmd-mutant artifact-card-mutant artifact-tier-pi5 artifact-tier-mutant test-continuity-subject-restart gsp-fw-inspect-test gsp-cot-test gsp-bindata-test gsp-bootargs-test gsp-rpc-test slot-test slot-free package-test slot-loader-check,$^); do $$t || fail=1; done; \
	if [ $$fail = 0 ]; then echo "CK_CORE_HOST: PASS"; else echo "CK_CORE_HOST: FAIL"; exit 1; fi

sanitize: $(addprefix $(OUT)/host-san/,$(TESTS))
	@fail=0; for t in $^; do ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 $$t || fail=1; done; \
	if [ $$fail = 0 ]; then echo "CK_CORE_HOST: PASS (sanitize)"; else echo "CK_CORE_HOST: FAIL (sanitize)"; exit 1; fi

# ---- host tool for the M0_ROLLBACK gate (scripts/qemu_ck_rollback_test.sh) ----
uefi-vars: $(OUT)/host/ck_uefi_vars
$(OUT)/host/ck_uefi_vars: $(KDIR)/tools/ck_uefi_vars.c
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -o $@ $<

# ---- host tool for the AIENOS_CK_NET gate (scripts/qemu_ck_net_test.sh) ----
udp-echo: $(OUT)/host/ck_udp_echo
$(OUT)/host/ck_udp_echo: $(KDIR)/tools/ck_udp_echo.c
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -o $@ $<

# ---- receiver for the iMac kernel's network report (run on a machine on the iMac's network) ----
imac-report-listen: $(OUT)/host/ck_imac_report_listen
$(OUT)/host/ck_imac_report_listen: $(KDIR)/tools/ck_imac_report_listen.c
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -o $@ $<

# Artifact library host test and the in-tree C artifact tool (pack, sign with
# TEST keys, negative corpus, bundle, receipt check) used by the QEMU gate.
ART_HOST_SRCS := $(KDIR)/artifact/format.c $(KDIR)/artifact/admission.c $(KDIR)/artifact/receipt.c $(KDIR)/artifact/osc_unit.c $(KDIR)/artifact/osc_receipt.c $(KDIR)/artifact/osc_launch.c \
	$(NATIVE)/argus/sha256.c $(NATIVE)/sig/sha512.c $(NATIVE)/sig/ed25519.c $(NATIVE)/sig/ct.c
ART_HOST_INC := -I$(KDIR)/artifact -I$(NATIVE)/sig -I$(NATIVE)/argus
ART_HOST_DEPS := $(ART_HOST_SRCS) $(wildcard $(KDIR)/artifact/*.h) $(ART_HDRS)

$(OUT)/host/test_artifact: $(KDIR)/tests/test_artifact.c $(ART_HOST_DEPS) $(KDIR)/tests/ck_test.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(ART_HOST_INC) -o $@ $< $(ART_HOST_SRCS)

# PI5-8 Q3: the receipt tier is chosen by the image. test_artifact built with -DCK_PI5 (the Pi image's define) must see
# SEED-0B-PI5; the mutant (-DCKA_TIER_MUTANT, Pi image still writes the QEMU tier) must make that test FAIL.
$(OUT)/host/test_artifact_pi5: $(KDIR)/tests/test_artifact.c $(ART_HOST_DEPS) $(KDIR)/tests/ck_test.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(ART_HOST_INC) -DCK_PI5 -o $@ $< $(ART_HOST_SRCS)

$(OUT)/host/test_artifact_pi5_mutant: $(KDIR)/tests/test_artifact.c $(ART_HOST_DEPS) $(KDIR)/tests/ck_test.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(ART_HOST_INC) -DCK_PI5 -DCKA_TIER_MUTANT -o $@ $< $(ART_HOST_SRCS)

artifact-tier-pi5: $(OUT)/host/test_artifact_pi5
	@$<

artifact-tier-mutant: $(OUT)/host/test_artifact_pi5_mutant
	@if $< > $<.log 2>&1; then cat $<.log; echo "test_artifact Pi tier mutant (Pi image writes the QEMU tier): PASSED, test does not catch it"; exit 1; \
	else echo "test_artifact Pi tier mutant (Pi image writes the QEMU tier): FAILS as required"; fi

$(OUT)/host/test_osc_unit: $(KDIR)/tests/test_osc_unit.c $(ART_HOST_DEPS) $(KDIR)/tests/ck_test.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(ART_HOST_INC) -DOSC_FIXTURE_DIR='"$(abspath $(KDIR)/tests/fixtures/osc_unit)"' -o $@ $< $(ART_HOST_SRCS)

$(OUT)/host-san/test_osc_unit: $(KDIR)/tests/test_osc_unit.c $(ART_HOST_DEPS) $(KDIR)/tests/ck_test.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(ART_HOST_INC) -DOSC_FIXTURE_DIR='"$(abspath $(KDIR)/tests/fixtures/osc_unit)"' -o $@ $< $(ART_HOST_SRCS)

$(OUT)/host-san/test_artifact: $(KDIR)/tests/test_artifact.c $(ART_HOST_DEPS) $(KDIR)/tests/ck_test.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(ART_HOST_INC) -o $@ $< $(ART_HOST_SRCS)

# C3-3a launch: pure parts (artifact/osc_launch.c) plus the spec's own C reference for the argument rule.
$(OUT)/host/osc-launch-check: $(KDIR)/tests/fixtures/osc_unit/launch/osc-launch-check.c
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=c99 -O1 -Wall -Wextra -Werror -o $@ $<

$(OUT)/host/test_osc_launch: $(KDIR)/tests/test_osc_launch.c $(ART_HOST_DEPS) $(KDIR)/tests/ck_test.h $(OUT)/host/osc-launch-check
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(ART_HOST_INC) -DOSC_FIXTURE_DIR='"$(abspath $(KDIR)/tests/fixtures/osc_unit)"' -DOSC_LAUNCH_REF='"$(abspath $(OUT)/host/osc-launch-check)"' -o $@ $< $(ART_HOST_SRCS)

$(OUT)/host-san/test_osc_launch: $(KDIR)/tests/test_osc_launch.c $(ART_HOST_DEPS) $(KDIR)/tests/ck_test.h $(OUT)/host/osc-launch-check
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(ART_HOST_INC) -DOSC_FIXTURE_DIR='"$(abspath $(KDIR)/tests/fixtures/osc_unit)"' -DOSC_LAUNCH_REF='"$(abspath $(OUT)/host/osc-launch-check)"' -o $@ $< $(ART_HOST_SRCS)

# osc_admit.c reporting (oversize Store entry): host test with ck_printf captured.
$(OUT)/host/test_osc_admit: $(KDIR)/tests/test_osc_admit.c $(KDIR)/core/osc_admit.c $(ART_HOST_DEPS) $(KDIR)/tests/ck_test.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(ART_HOST_INC) -I$(KDIR)/include -o $@ $< $(KDIR)/core/osc_admit.c $(ART_HOST_SRCS)

$(OUT)/host-san/test_osc_admit: $(KDIR)/tests/test_osc_admit.c $(KDIR)/core/osc_admit.c $(ART_HOST_DEPS) $(KDIR)/tests/ck_test.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(ART_HOST_INC) -I$(KDIR)/include -o $@ $< $(KDIR)/core/osc_admit.c $(ART_HOST_SRCS)

# aienos#383 realization receipts (artifact/osc_receipt.c): host test over the checker2-minted fixtures
# (tests/fixtures/osc_receipt) and the kernel's own policy (core/osc_admit.c, release and qualification builds), plus
# the mutation run: each MUT(n) guard of osc_receipt.c removed in turn (-DOSC_RCPT_MUTANT=n) must make the test FAIL.
# The run refuses a guard count that differs from OSC_RCPT_MUTANTS, and a kernel-side build of a mutant.
OSC_RCPT_MUTANTS := 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25
OSC_RCPT_TEST_DEF := -DOSC_RCPT_HOST_TEST -I$(KDIR)/include -DOSC_FIXTURE_DIR='"$(abspath $(KDIR)/tests/fixtures)"'
OSC_RCPT_TEST_SRCS := $(KDIR)/tests/test_osc_receipt.c $(KDIR)/core/osc_admit.c $(ART_HOST_SRCS)
$(OUT)/host/test_osc_receipt: $(KDIR)/tests/test_osc_receipt.c $(KDIR)/core/osc_admit.c $(ART_HOST_DEPS) $(KDIR)/tests/ck_test.h $(wildcard $(KDIR)/tests/fixtures/osc_receipt/*) $(wildcard $(KDIR)/tests/fixtures/osc_receipt_owner/*)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(ART_HOST_INC) $(OSC_RCPT_TEST_DEF) -DCK_SEED0B_TEST_ANCHOR=1 -o $@ $(OSC_RCPT_TEST_SRCS)

$(OUT)/host-san/test_osc_receipt: $(KDIR)/tests/test_osc_receipt.c $(KDIR)/core/osc_admit.c $(ART_HOST_DEPS) $(KDIR)/tests/ck_test.h $(wildcard $(KDIR)/tests/fixtures/osc_receipt/*) $(wildcard $(KDIR)/tests/fixtures/osc_receipt_owner/*)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(ART_HOST_INC) $(OSC_RCPT_TEST_DEF) -DCK_SEED0B_TEST_ANCHOR=1 -o $@ $(OSC_RCPT_TEST_SRCS)

# the same test against the release policy of core/osc_admit.c (no CK_SEED0B_TEST_ANCHOR): every TEST receipt refused
$(OUT)/host/test_osc_receipt_release: $(KDIR)/tests/test_osc_receipt.c $(KDIR)/core/osc_admit.c $(ART_HOST_DEPS) $(KDIR)/tests/ck_test.h $(wildcard $(KDIR)/tests/fixtures/osc_receipt/*) $(wildcard $(KDIR)/tests/fixtures/osc_receipt_owner/*)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(ART_HOST_INC) $(OSC_RCPT_TEST_DEF) -o $@ $(OSC_RCPT_TEST_SRCS)

osc-receipt-release: $(OUT)/host/test_osc_receipt_release
	@$<

osc-receipt-mutants: $(OUT)/host/test_osc_receipt
	@mkdir -p $(OUT)/host-mut; fail=0; \
	tags=$$(grep -o 'MUT([0-9]*)' $(KDIR)/artifact/osc_receipt.c | sort -u | wc -l); \
	uses=$$(grep -o 'MUT([0-9]*)' $(KDIR)/artifact/osc_receipt.c | wc -l); \
	if [ $$tags != $(words $(OSC_RCPT_MUTANTS)) ] || [ $$uses != $$tags ]; then \
	  echo "guard count: $$uses uses, $$tags distinct, $(words $(OSC_RCPT_MUTANTS)) mutants listed (FAIL)"; fail=1; fi; \
	$(OUT)/host/test_osc_receipt > $(OUT)/host-mut/osc_receipt_base.log 2>&1 || { echo "unmutated test_osc_receipt fails"; fail=1; }; \
	killed=0; \
	for m in $(OSC_RCPT_MUTANTS); do \
	  b=$(OUT)/host-mut/test_osc_receipt_m$$m; \
	  if ! $(HOSTCC) $(HCFLAGS) $(ART_HOST_INC) $(OSC_RCPT_TEST_DEF) -DCK_SEED0B_TEST_ANCHOR=1 -DOSC_RCPT_MUTANT=$$m -o $$b $(OSC_RCPT_TEST_SRCS); then \
	    echo "mutant $$m: does not build (FAIL)"; fail=1; continue; fi; \
	  if $$b > $$b.log 2>&1; then echo "mutant $$m: SURVIVED (FAIL)"; fail=1; \
	  elif grep -q "^test_osc_receipt: FAIL" $$b.log; then killed=$$((killed + 1)); \
	    echo "mutant $$m: killed ($$(grep -c '^  FAIL ' $$b.log) checks failed)"; \
	  else echo "mutant $$m: no FAIL verdict (crashed?) (FAIL)"; fail=1; fi; \
	done; \
	if $(HOSTCC) $(HCFLAGS) $(ART_HOST_INC) -DOSC_RCPT_MUTANT=1 -fsyntax-only $(KDIR)/artifact/osc_receipt.c 2>/dev/null; then \
	  echo "mutant flag accepted without OSC_RCPT_HOST_TEST (FAIL)"; fail=1; \
	else echo "mutant flag refused without OSC_RCPT_HOST_TEST"; fi; \
	if [ $$fail = 0 ]; then echo "CK_OSC_RECEIPT_MUTANTS: PASS ($$killed of $(words $(OSC_RCPT_MUTANTS)) killed)"; else echo "CK_OSC_RECEIPT_MUTANTS: FAIL"; exit 1; fi

# Continuity codec (C port cut 1, contract CONTINUITY_RECOVERY_CONTRACT.md,
# aienos#222): host test plus TEST-only -D mutants, each of which must make
# the test print its FAIL verdict. Mutant flags are refused under
# CK_HARDWARE_STAGING (svc/continuity_codec.h).
CC_HOST_SRCS := $(KDIR)/svc/continuity_codec.c $(NATIVE)/argus/sha256.c $(NATIVE)/store/store_v1.c
CC_HOST_INC := -I$(KDIR)/svc -I$(NATIVE)/argus -I$(NATIVE)/store
CC_HOST_DEPS := $(wildcard $(KDIR)/tests/fixtures/continuity_*.txt) $(CC_HOST_SRCS) $(KDIR)/svc/continuity_codec.h $(NATIVE)/argus/sha256.h \
	$(NATIVE)/store/store_v1.h $(KDIR)/tests/ck_test.h
# Cut 2 adds UNCHECKED_FORK_SUM (wrapping fork-count sum), MANIFEST_LAST_WAL_ZERO
# (only the golden vectors see it), SKIP_D1 and SKIP_D2 (test-side: the golden
# or the decode-agreement comparison is skipped; the test counts its
# comparisons, so skipping one is a FAIL).
CC_MUTANTS := CC_MUTANT_SKIP_TAKE_BOUND CC_MUTANT_ACCEPT_RESERVED CC_MUTANT_CHILD_INDEX_LE \
	CC_MUTANT_TRUNCATE_AT_CAP CC_MUTANT_UNCHECKED_FORK_SUM CC_MUTANT_MANIFEST_LAST_WAL_ZERO \
	CC_MUTANT_SKIP_D1 CC_MUTANT_SKIP_D2
# Rust-emitted fixtures (D-1, D-2) read by the test at run time.
CC_FIXTURES := $(abspath $(KDIR)/tests/fixtures)
CC_FIXTURE_DEF := -DCC_FIXTURE_DIR='"$(CC_FIXTURES)"'

$(OUT)/host/test_continuity_codec: $(KDIR)/tests/test_continuity_codec.c $(CC_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(CC_HOST_INC) $(CC_FIXTURE_DEF) -o $@ $< $(CC_HOST_SRCS)

$(OUT)/host-san/test_continuity_codec: $(KDIR)/tests/test_continuity_codec.c $(CC_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(CC_HOST_INC) $(CC_FIXTURE_DEF) -o $@ $< $(CC_HOST_SRCS)

continuity-mutants: $(OUT)/host/test_continuity_codec continuity-resolve-mutants continuity-commit-mutants continuity-recovery-mutants continuity-subject-mutants continuity-subject-provision-mutants
	@mkdir -p $(OUT)/host-mut; fail=0; \
	$(OUT)/host/test_continuity_codec > $(OUT)/host-mut/base.log 2>&1 || { echo "unmutated test_continuity_codec fails"; fail=1; }; \
	for m in $(CC_MUTANTS); do \
	  b=$(OUT)/host-mut/test_continuity_codec_$$m; \
	  if ! $(HOSTCC) $(HCFLAGS) $(CC_HOST_INC) $(CC_FIXTURE_DEF) -D$$m -o $$b $(KDIR)/tests/test_continuity_codec.c $(CC_HOST_SRCS); then \
	    echo "mutant $$m: does not build (FAIL)"; fail=1; continue; fi; \
	  if $$b > $$b.log 2>&1; then echo "mutant $$m: SURVIVED (FAIL)"; fail=1; \
	  elif grep -q "^test_continuity_codec: FAIL" $$b.log; then \
	    echo "mutant $$m: killed ($$(grep -c '^  FAIL ' $$b.log) checks failed)"; \
	  else echo "mutant $$m: no FAIL verdict (crashed?) (FAIL)"; fail=1; fi; \
	done; \
	if $(HOSTCC) $(HCFLAGS) $(CC_HOST_INC) -DCK_HARDWARE_STAGING=1 -DCC_MUTANT_SKIP_TAKE_BOUND \
	    -fsyntax-only $(KDIR)/svc/continuity_codec.c 2>/dev/null; then \
	  echo "mutant flag accepted under CK_HARDWARE_STAGING (FAIL)"; fail=1; \
	else echo "mutant flag refused under CK_HARDWARE_STAGING"; fi; \
	if [ $$fail = 0 ]; then echo "CK_CONTINUITY_CODEC_MUTANTS: PASS"; else echo "CK_CONTINUITY_CODEC_MUTANTS: FAIL"; exit 1; fi

# Continuity resolve + challenge/HMAC (C port cut 3): host test over the REAL
# sealed Store in a file (native/store + m5 + crypto + disk), TEST-only -D
# mutants, each of which must make the test print its FAIL verdict. Mutant flags
# are refused under CK_HARDWARE_STAGING (svc/continuity_resolve.h).
CR_STORE_SRCS := $(NATIVE)/store/store_v1.c $(NATIVE)/store/store_engine.c $(NATIVE)/store/store_disk.c \
	$(NATIVE)/store/store_sealed.c $(NATIVE)/store/torn_slot.c $(NATIVE)/disk/disk.c $(NATIVE)/disk/disk_file.c \
	$(NATIVE)/m5/m5_keys.c $(NATIVE)/m5/m5_envelope.c $(NATIVE)/m5/m5_state.c $(NATIVE)/crypto/aes.c \
	$(NATIVE)/crypto/polyval.c $(NATIVE)/crypto/gcm_siv.c $(NATIVE)/crypto/hmac.c $(NATIVE)/crypto/ct.c
CR_HOST_SRCS := $(KDIR)/svc/continuity_resolve.c $(KDIR)/svc/continuity_resolve_sealed.c \
	$(KDIR)/svc/continuity_codec.c $(NATIVE)/argus/sha256.c $(CR_STORE_SRCS)
CR_HOST_INC := -I$(KDIR)/svc -I$(NATIVE)/argus -I$(NATIVE)/store -I$(NATIVE)/disk -I$(NATIVE)/m5 -I$(NATIVE)/crypto
CR_HOST_DEPS := $(wildcard $(KDIR)/tests/fixtures/continuity_*.txt) $(CR_HOST_SRCS) $(wildcard $(KDIR)/svc/continuity_*.h) \
	$(wildcard $(NATIVE)/store/*.h $(NATIVE)/m5/*.h $(NATIVE)/disk/*.h $(NATIVE)/crypto/*.h) $(KDIR)/tests/ck_test.h
CR_FIXTURE_DEF := -DCR_FIXTURE_DIR='"$(CC_FIXTURES)"'
# MC-2 orphan check, MC-4 previous, MC-12 conflict, MR-2 digest, MR-3 action,
# MR-4 16-byte compare, MR-8 bare SHA-256 and no domain.
CR_MUTANTS := CR_MUTANT_NO_ORPHAN_CHECK CR_MUTANT_IGNORE_PREVIOUS CR_MUTANT_SKIP_CONFLICT \
	CR_MUTANT_CHALLENGE_NO_DIGEST CR_MUTANT_CHALLENGE_NO_ACTION CR_MUTANT_COMPARE_16 \
	CR_MUTANT_BARE_SHA256 CR_MUTANT_NO_DOMAIN

$(OUT)/host/test_continuity_resolve: $(KDIR)/tests/test_continuity_resolve.c $(CR_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(CR_HOST_INC) $(CR_FIXTURE_DEF) -o $@ $< $(CR_HOST_SRCS)

$(OUT)/host-san/test_continuity_resolve: $(KDIR)/tests/test_continuity_resolve.c $(CR_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(CR_HOST_INC) $(CR_FIXTURE_DEF) -o $@ $< $(CR_HOST_SRCS)

continuity-resolve-mutants: $(OUT)/host/test_continuity_resolve
	@mkdir -p $(OUT)/host-mut; fail=0; \
	$(OUT)/host/test_continuity_resolve > $(OUT)/host-mut/resolve_base.log 2>&1 || { echo "unmutated test_continuity_resolve fails"; fail=1; }; \
	for m in $(CR_MUTANTS); do \
	  b=$(OUT)/host-mut/test_continuity_resolve_$$m; \
	  if ! $(HOSTCC) $(HCFLAGS) $(CR_HOST_INC) $(CR_FIXTURE_DEF) -D$$m -o $$b $(KDIR)/tests/test_continuity_resolve.c $(CR_HOST_SRCS); then \
	    echo "mutant $$m: does not build (FAIL)"; fail=1; continue; fi; \
	  if $$b > $$b.log 2>&1; then echo "mutant $$m: SURVIVED (FAIL)"; fail=1; \
	  elif grep -q "^test_continuity_resolve: FAIL" $$b.log; then \
	    echo "mutant $$m: killed ($$(grep -c '^  FAIL ' $$b.log) checks failed)"; \
	  else echo "mutant $$m: no FAIL verdict (crashed?) (FAIL)"; fail=1; fi; \
	done; \
	for m in $(CR_MUTANTS); do \
	  if $(HOSTCC) $(HCFLAGS) $(CR_HOST_INC) -DCK_HARDWARE_STAGING=1 -D$$m \
	      -fsyntax-only $(KDIR)/svc/continuity_resolve.c 2>/dev/null; then \
	    echo "mutant flag $$m accepted under CK_HARDWARE_STAGING (FAIL)"; fail=1; \
	  else echo "mutant flag $$m refused under CK_HARDWARE_STAGING"; fi; \
	done; \
	if [ $$fail = 0 ]; then echo "CK_CONTINUITY_RESOLVE_MUTANTS: PASS"; else echo "CK_CONTINUITY_RESOLVE_MUTANTS: FAIL"; exit 1; fi


# Continuity provision/commit/resume (C port cut 4): host test over the REAL sealed
# Store in a file with the real ck_rng over a mocked RNDR, power cuts at every
# checkpoint and block boundary, and TEST-only -D mutants, each of which must make
# the test print its FAIL verdict. Mutant flags are refused under
# CK_HARDWARE_STAGING (svc/continuity_commit.h; MC-11 in svc/continuity_codec.h).
CM_HOST_SRCS := $(KDIR)/svc/continuity_commit.c $(CR_HOST_SRCS) $(KDIR)/core/entropy.c
CM_HOST_INC := $(CR_HOST_INC) -I$(KDIR)/core
CM_HOST_DEPS := $(CM_HOST_SRCS) $(wildcard $(KDIR)/svc/continuity_*.h) $(KDIR)/core/entropy.h \
	$(wildcard $(NATIVE)/store/*.h $(NATIVE)/m5/*.h $(NATIVE)/disk/*.h $(NATIVE)/crypto/*.h) $(KDIR)/tests/ck_test.h
# MC-1 resume provisions, MC-3 resume skips the commit, MC-7 provision with a root,
# MC-8 split transaction, MC-9 writable check removed, MC-10 fixed agent id,
# MC-11 silent truncation (the codec's CC_MUTANT_TRUNCATE_AT_CAP).
CM_MUTANTS := CM_MUTANT_RESUME_PROVISIONS CM_MUTANT_RESUME_NO_COMMIT CM_MUTANT_PROVISION_WITH_ROOT \
	CM_MUTANT_SPLIT_TXN CM_MUTANT_NO_WRITABLE_CHECK CM_MUTANT_FIXED_AGENT CC_MUTANT_TRUNCATE_AT_CAP

$(OUT)/host/test_continuity_commit: $(KDIR)/tests/test_continuity_commit.c $(CM_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -o $@ $< $(CM_HOST_SRCS)

$(OUT)/host-san/test_continuity_commit: $(KDIR)/tests/test_continuity_commit.c $(CM_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(CM_HOST_INC) -o $@ $< $(CM_HOST_SRCS)

continuity-commit-mutants: $(OUT)/host/test_continuity_commit
	@mkdir -p $(OUT)/host-mut; fail=0; \
	$(OUT)/host/test_continuity_commit > $(OUT)/host-mut/commit_base.log 2>&1 || { echo "unmutated test_continuity_commit fails"; fail=1; }; \
	for m in $(CM_MUTANTS); do \
	  b=$(OUT)/host-mut/test_continuity_commit_$$m; \
	  if ! $(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -D$$m -o $$b $(KDIR)/tests/test_continuity_commit.c $(CM_HOST_SRCS); then \
	    echo "mutant $$m: does not build (FAIL)"; fail=1; continue; fi; \
	  if $$b > $$b.log 2>&1; then echo "mutant $$m: SURVIVED (FAIL)"; fail=1; \
	  elif grep -q "^test_continuity_commit: FAIL" $$b.log; then \
	    echo "mutant $$m: killed ($$(grep -c '^  FAIL ' $$b.log) checks failed)"; \
	  else echo "mutant $$m: no FAIL verdict (crashed?) (FAIL)"; fail=1; fi; \
	done; \
	for m in $(CM_MUTANTS); do \
	  if $(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -DCK_HARDWARE_STAGING=1 -D$$m \
	      -fsyntax-only $(KDIR)/svc/continuity_commit.c 2>/dev/null; then \
	    echo "mutant flag $$m accepted under CK_HARDWARE_STAGING (FAIL)"; fail=1; \
	  else echo "mutant flag $$m refused under CK_HARDWARE_STAGING"; fi; \
	done; \
	if [ $$fail = 0 ]; then echo "CK_CONTINUITY_COMMIT_MUTANTS: PASS"; else echo "CK_CONTINUITY_COMMIT_MUTANTS: FAIL"; exit 1; fi

# ALLEN subject state (continuity object kind 24; ARCH-0035 / OS-0018, PROPOSED):
# host test over the REAL sealed Store in a file, a two-process restart proof
# (test-continuity-subject-restart) and TEST-only -D mutants, each of which must
# make the test print its FAIL verdict. Mutant flags are refused under
# CK_HARDWARE_STAGING (svc/continuity_subject.h).
CS_HOST_SRCS := $(KDIR)/svc/continuity_subject.c $(CM_HOST_SRCS)
CS_HOST_DEPS := $(CS_HOST_SRCS) $(wildcard $(KDIR)/svc/continuity_*.h) $(KDIR)/core/entropy.h \
	$(wildcard $(NATIVE)/store/*.h $(NATIVE)/m5/*.h $(NATIVE)/disk/*.h $(NATIVE)/crypto/*.h) $(KDIR)/tests/ck_test.h
# MS-1 foreign root/agent accepted at resolve, MS-2 two active intents in one slot
# accepted, MS-3 intent id derivation not checked, MS-4 chain fork accepted.
CS_MUTANTS := CS_MUTANT_ACCEPT_FOREIGN CS_MUTANT_ACCEPT_TWO_ACTIVE CS_MUTANT_SKIP_INTENT_ID CS_MUTANT_ACCEPT_FORK

$(OUT)/host/test_continuity_subject: $(KDIR)/tests/test_continuity_subject.c $(CS_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -o $@ $< $(CS_HOST_SRCS)

$(OUT)/host-san/test_continuity_subject: $(KDIR)/tests/test_continuity_subject.c $(CS_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(CM_HOST_INC) -o $@ $< $(CS_HOST_SRCS)

# ALLEN-G2 on the host: the writer process provisions and commits a subject with
# one standing intent and exits; a second process reopens the same Store image,
# resolves the same subject object and finds the same intent.
.PHONY: test-continuity-subject-restart
test-continuity-subject-restart: $(OUT)/host/test_continuity_subject
	@mkdir -p $(OUT)/host-subject; img=$(OUT)/host-subject/allen.img; rm -f $$img; \
	$(OUT)/host/test_continuity_subject --write $$img > $(OUT)/host-subject/write.log || { cat $(OUT)/host-subject/write.log; exit 1; }; \
	id=$$(sed -n 's/^ALLEN subject id: //p' $(OUT)/host-subject/write.log); \
	test -n "$$id" || { echo "no subject id from the writer"; exit 1; }; \
	$(OUT)/host/test_continuity_subject --restore $$img $$id > $(OUT)/host-subject/restore.log || { cat $(OUT)/host-subject/restore.log; exit 1; }; \
	grep -h '^ALLEN' $(OUT)/host-subject/write.log $(OUT)/host-subject/restore.log; \
	echo "CK_CONTINUITY_SUBJECT_RESTART: PASS (two processes, sealed Store image $$img)"

continuity-subject-mutants: $(OUT)/host/test_continuity_subject
	@mkdir -p $(OUT)/host-mut; fail=0; \
	$(OUT)/host/test_continuity_subject > $(OUT)/host-mut/subject_base.log 2>&1 || { echo "unmutated test_continuity_subject fails"; fail=1; }; \
	for m in $(CS_MUTANTS); do \
	  b=$(OUT)/host-mut/test_continuity_subject_$$m; \
	  if ! $(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -D$$m -o $$b $(KDIR)/tests/test_continuity_subject.c $(CS_HOST_SRCS); then \
	    echo "mutant $$m does not build (FAIL)"; fail=1; continue; fi; \
	  $$b > $$b.log 2>&1; \
	  if grep -q "^test_continuity_subject: FAIL" $$b.log; then echo "mutant $$m caught"; \
	  else echo "mutant $$m NOT caught (FAIL)"; fail=1; fi; \
	  if $(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -DCK_HARDWARE_STAGING=1 -D$$m \
	      -fsyntax-only $(KDIR)/svc/continuity_subject.c 2>/dev/null; then \
	    echo "mutant flag $$m accepted under CK_HARDWARE_STAGING (FAIL)"; fail=1; \
	  else echo "mutant flag $$m refused under CK_HARDWARE_STAGING"; fi; \
	done; \
	if [ $$fail = 0 ]; then echo "CK_CONTINUITY_SUBJECT_MUTANTS: PASS"; else echo "CK_CONTINUITY_SUBJECT_MUTANTS: FAIL"; exit 1; fi

# ALLEN genesis at identity provisioning (svc/continuity_subject_provision.c;
# ARCH-0035 / OS-0018, PROPOSED): identity and genesis subject in ONE Store
# transaction, power cuts at every checkpoint and block boundary, and the
# TEST-only split-transaction mutant (MSP-1), which the test must catch. The
# mutant flag is refused under CK_HARDWARE_STAGING.
CSP_HOST_SRCS := $(KDIR)/svc/continuity_subject_provision.c $(CS_HOST_SRCS)
CSP_HOST_DEPS := $(CSP_HOST_SRCS) $(CS_HOST_DEPS)
CSP_MUTANTS := CS_MUTANT_PROVISION_SPLIT_TXN

$(OUT)/host/test_continuity_subject_provision: $(KDIR)/tests/test_continuity_subject_provision.c $(CSP_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -o $@ $< $(CSP_HOST_SRCS)

$(OUT)/host-san/test_continuity_subject_provision: $(KDIR)/tests/test_continuity_subject_provision.c $(CSP_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(CM_HOST_INC) -o $@ $< $(CSP_HOST_SRCS)

continuity-subject-provision-mutants: $(OUT)/host/test_continuity_subject_provision
	@mkdir -p $(OUT)/host-mut; fail=0; \
	$(OUT)/host/test_continuity_subject_provision > $(OUT)/host-mut/subject_provision_base.log 2>&1 || { echo "unmutated test_continuity_subject_provision fails"; fail=1; }; \
	for m in $(CSP_MUTANTS); do \
	  b=$(OUT)/host-mut/test_continuity_subject_provision_$$m; \
	  if ! $(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -D$$m -o $$b $(KDIR)/tests/test_continuity_subject_provision.c $(CSP_HOST_SRCS); then \
	    echo "mutant $$m does not build (FAIL)"; fail=1; continue; fi; \
	  $$b > $$b.log 2>&1; \
	  if grep -q "^test_continuity_subject_provision: FAIL" $$b.log; then echo "mutant $$m caught ($$(grep -c '^  FAIL ' $$b.log) checks failed)"; \
	  else echo "mutant $$m NOT caught (FAIL)"; fail=1; fi; \
	  if $(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -DCK_HARDWARE_STAGING=1 -D$$m \
	      -fsyntax-only $(KDIR)/svc/continuity_subject_provision.c 2>/dev/null; then \
	    echo "mutant flag $$m accepted under CK_HARDWARE_STAGING (FAIL)"; fail=1; \
	  else echo "mutant flag $$m refused under CK_HARDWARE_STAGING"; fi; \
	done; \
	if [ $$fail = 0 ]; then echo "CK_CONTINUITY_SUBJECT_PROVISION_MUTANTS: PASS"; else echo "CK_CONTINUITY_SUBJECT_PROVISION_MUTANTS: FAIL"; exit 1; fi

# Continuity Recovery Core (C port cut 5): host test over the REAL sealed Store in a
# file, TEST-only -D mutants, each of which must make the test print its FAIL verdict.
# Mutant flags are refused under CK_HARDWARE_STAGING (svc/continuity_recovery.h).
RC_HOST_SRCS := $(KDIR)/svc/continuity_recovery.c $(CM_HOST_SRCS)
RC_HOST_DEPS := $(RC_HOST_SRCS) $(wildcard $(KDIR)/svc/continuity_*.h) $(KDIR)/core/entropy.h \
	$(wildcard $(NATIVE)/store/*.h $(NATIVE)/m5/*.h $(NATIVE)/disk/*.h $(NATIVE)/crypto/*.h) $(KDIR)/tests/ck_test.h
# MR-1 inspection writes, MR-5 degraded mount read as Unprovisioned, MR-6 repair zeroes the
# active slot, MR-7 repair without a resolved identity, MR-9 operator provisioning writes
# source Qualification. (MR-2, MR-3, MR-4, MR-8 are the cut 3 mutants.)
RC_MUTANTS := RC_MUTANT_INSPECT_WRITES RC_MUTANT_DEGRADED_IS_UNPROVISIONED RC_MUTANT_REPAIR_ACTIVE \
	RC_MUTANT_REPAIR_NO_IDENTITY RC_MUTANT_PROVISION_QUALIFICATION

$(OUT)/host/test_continuity_recovery: $(KDIR)/tests/test_continuity_recovery.c $(RC_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -o $@ $< $(RC_HOST_SRCS)

$(OUT)/host-san/test_continuity_recovery: $(KDIR)/tests/test_continuity_recovery.c $(RC_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(CM_HOST_INC) -o $@ $< $(RC_HOST_SRCS)

# K-6 region geometry (cut 7): host test over the real sealed Store in a file; needs dev/disk_layout.h.
$(OUT)/host/test_continuity_geometry: $(KDIR)/tests/test_continuity_geometry.c $(RC_HOST_DEPS) $(KDIR)/dev/disk_layout.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -I$(KDIR)/dev -o $@ $< $(RC_HOST_SRCS)

$(OUT)/host-san/test_continuity_geometry: $(KDIR)/tests/test_continuity_geometry.c $(RC_HOST_DEPS) $(KDIR)/dev/disk_layout.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(CM_HOST_INC) -I$(KDIR)/dev -o $@ $< $(RC_HOST_SRCS)

continuity-recovery-mutants: $(OUT)/host/test_continuity_recovery
	@mkdir -p $(OUT)/host-mut; fail=0; \
	$(OUT)/host/test_continuity_recovery > $(OUT)/host-mut/recovery_base.log 2>&1 || { echo "unmutated test_continuity_recovery fails"; fail=1; }; \
	for m in $(RC_MUTANTS); do \
	  b=$(OUT)/host-mut/test_continuity_recovery_$$m; \
	  if ! $(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -D$$m -o $$b $(KDIR)/tests/test_continuity_recovery.c $(RC_HOST_SRCS); then \
	    echo "mutant $$m: does not build (FAIL)"; fail=1; continue; fi; \
	  if $$b > $$b.log 2>&1; then echo "mutant $$m: SURVIVED (FAIL)"; fail=1; \
	  elif grep -q "^test_continuity_recovery: FAIL" $$b.log; then \
	    echo "mutant $$m: killed ($$(grep -c '^  FAIL ' $$b.log) checks failed)"; \
	  else echo "mutant $$m: no FAIL verdict (crashed?) (FAIL)"; fail=1; fi; \
	done; \
	for m in $(RC_MUTANTS); do \
	  if $(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -DCK_HARDWARE_STAGING=1 -D$$m \
	      -fsyntax-only $(KDIR)/svc/continuity_recovery.c 2>/dev/null; then \
	    echo "mutant flag $$m accepted under CK_HARDWARE_STAGING (FAIL)"; fail=1; \
	  else echo "mutant flag $$m refused under CK_HARDWARE_STAGING"; fi; \
	done; \
	if [ $$fail = 0 ]; then echo "CK_CONTINUITY_RECOVERY_MUTANTS: PASS"; else echo "CK_CONTINUITY_RECOVERY_MUTANTS: FAIL"; exit 1; fi

ART_TOOL := $(OUT)/host/ck_artifact_tool
$(ART_TOOL): $(KDIR)/tools/ck_artifact_tool.c $(ART_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror $(ART_HOST_INC) -o $@ $< $(ART_HOST_SRCS)
tool: $(ART_TOOL)

# Boot-disk image tool (scripts/qemu_ck_artifact_test.sh): writes signed artifacts
# into the sealed Store on a raw NVMe image with the kernel's own Store code
# (store_boot.c, artifact_store.c). Hosted; never part of an image.
STORE_IMG_TOOL := $(OUT)/host/ck_store_image
STORE_IMG_SRCS := $(STAGE_OWN_SRCS) $(KDIR)/core/ipc.c $(STAGE_NATIVE_SRCS) $(NATIVE)/disk/disk_file.c \
	$(KDIR)/svc/tests/ck_host.c $(KDIR)/tools/ck_store_image.c
$(STORE_IMG_TOOL): $(STORE_IMG_SRCS) $(STAGE_HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(STAGE_HOST_FLAGS) $(STAGE_INC) -o $@ $(STORE_IMG_SRCS)
store-image: $(STORE_IMG_TOOL)

# N3 memory gate tool (scripts/qemu_ck_memory_test.sh, aienos#329): appends a
# foreign-bound or a corrupted record to the Cortex journal of a provisioned
# TEST-keys disk image. Hosted; never part of an image.
CORTEX_IMG_TOOL := $(OUT)/host/ck_cortex_image
CORTEX_IMG_SRCS := $(STAGE_OWN_SRCS) $(KDIR)/core/ipc.c $(STAGE_NATIVE_SRCS) $(NATIVE)/disk/disk_file.c \
	$(KDIR)/svc/tests/ck_host.c $(STAGE_CORTEX_SRCS) $(KDIR)/core/context.c $(KDIR)/tools/ck_cortex_image.c
$(CORTEX_IMG_TOOL): $(CORTEX_IMG_SRCS) $(STAGE_HDRS) $(KDIR)/core/context.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(STAGE_HOST_FLAGS) $(STAGE_INC) -o $@ $(CORTEX_IMG_SRCS)
cortex-image: $(CORTEX_IMG_TOOL)

# Continuity / Recovery Core QEMU gate tool (scripts/qemu_ck_continuity_test.sh,
# scripts/qemu_ck_recovery_test.sh): operator response, degraded-peer injection,
# AgentRoot corruption on a boot-disk image. Hosted; never part of an image.
CONT_TOOL := $(OUT)/host/ck_cont_tool
CONT_TOOL_SRCS := $(STAGE_OWN_SRCS) $(KDIR)/core/ipc.c $(STAGE_NATIVE_SRCS) $(NATIVE)/disk/disk_file.c \
	$(KDIR)/svc/tests/ck_host.c $(KDIR)/svc/continuity_resolve.c $(KDIR)/svc/continuity_codec.c \
	$(KDIR)/svc/continuity_resolve_sealed.c $(KDIR)/svc/continuity_subject.c \
	$(KDIR)/tools/ck_cont_tool.c
$(CONT_TOOL): $(CONT_TOOL_SRCS) $(STAGE_HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(STAGE_HOST_FLAGS) $(STAGE_INC) -idirafter $(KDIR)/core -o $@ $(CONT_TOOL_SRCS)
cont-tool: $(CONT_TOOL)

# GPT boot-disk image tool (QEMU gates; hosted, never part of an image).
GPT_IMG_TOOL := $(OUT)/host/ck_gpt_image
GPT_IMG_SRCS := $(KDIR)/dev/disk_part.c $(NATIVE)/disk/disk.c $(NATIVE)/disk/disk_file.c \
	$(KDIR)/tools/gpt_write.c $(KDIR)/tools/ck_gpt_image.c
$(GPT_IMG_TOOL): $(GPT_IMG_SRCS) $(KDIR)/dev/disk_part.h $(KDIR)/tools/gpt_write.h $(NATIVE)/disk/disk.h $(BOOT)/slot_format.h
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -I$(KDIR)/dev -I$(KDIR)/tools -I$(NATIVE)/disk -o $@ $(GPT_IMG_SRCS)
gpt-image: $(GPT_IMG_TOOL)

# MODEL.MAP tool (model ingest gate + the attended-boot staging; hosted, never
# part of an image). SHA-256 is the kernel's own (argus).
MODEL_MAP_TOOL := $(OUT)/host/ck_model_map
$(MODEL_MAP_TOOL): $(KDIR)/tools/ck_model_map.c $(NATIVE)/argus/sha256.c $(BOOT)/model_map.h $(NATIVE)/argus/sha256.h
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -I$(BOOT) -I$(NATIVE)/argus -o $@ $(KDIR)/tools/ck_model_map.c $(NATIVE)/argus/sha256.c
model-map: $(MODEL_MAP_TOOL)

# GSP firmware container inspector (aienos#286 cut C, host work only: inventory
# and refusal checks for the NVIDIA GSP-RM ELF container the pinned Linux
# driver loads for the GB10; docs/GB10_FIRMWARE_INVENTORY.md). Never loads
# anything. SHA-256 is the kernel's own (argus). The real file is optional:
# when absent the inspect step is NOT_RUN, the self-test still runs.
GSP_FW_TOOL := $(OUT)/host/ck_gsp_fw_inspect
GSP_FW_FILE ?= /lib/firmware/nvidia/580.173.02/gsp_ga10x.bin
GSP_FW_SHA256 := 32cb7cf3e77f97e92f6e92135939ccb3ba382748144569c0dfccf3338d43d963
$(GSP_FW_TOOL): $(KDIR)/tools/ck_gsp_fw_inspect.c $(NATIVE)/argus/sha256.c $(NATIVE)/argus/sha256.h
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -I$(NATIVE)/argus -o $@ $(KDIR)/tools/ck_gsp_fw_inspect.c $(NATIVE)/argus/sha256.c
gsp-fw-inspect: $(GSP_FW_TOOL)
gsp-fw-inspect-test: $(GSP_FW_TOOL)
	$(GSP_FW_TOOL) selftest
	@if [ -r "$(GSP_FW_FILE)" ]; then \
	  out=$$($(GSP_FW_TOOL) inspect "$(GSP_FW_FILE)" --family gb10y --expect-version 580.173.02) || { echo "$$out"; echo "CK_GSP_FW_INSPECT_PIN: FAIL (refused)"; exit 1; }; \
	  echo "$$out" | grep -E '^(fwversion|build_id|signature_section|sha256_file|RESULT)'; \
	  echo "$$out" | grep -q '^sha256_file $(GSP_FW_SHA256)$$' && echo "CK_GSP_FW_INSPECT_PIN: PASS" || { echo "CK_GSP_FW_INSPECT_PIN: FAIL (digest differs from the pin)"; exit 1; }; \
	else echo "CK_GSP_FW_INSPECT_PIN: NOT_RUN ($(GSP_FW_FILE) absent)"; fi

# ---- host encoder/decoder for the SEC2 chain-of-trust boot message (aienos#286 cut C/D host work) ----
# Byte-exact NVDM-over-MCTP packet and GSP_FMC_BOOT_PARAMS layouts from the pinned
# driver source; self-test = layouts, golden headers, round trips, every mutation refused.
# Never loads anything. docs/GB10_FIRMWARE_INVENTORY.md section 10.
GSP_COT_TOOL := $(OUT)/host/ck_gsp_cot_encode
$(GSP_COT_TOOL): $(KDIR)/tools/ck_gsp_cot_encode.c $(NATIVE)/argus/sha256.c $(NATIVE)/argus/sha256.h
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -I$(NATIVE)/argus -o $@ $(KDIR)/tools/ck_gsp_cot_encode.c $(NATIVE)/argus/sha256.c
gsp-cot-encode: $(GSP_COT_TOOL)
gsp-cot-test: $(GSP_COT_TOOL)
	$(GSP_COT_TOOL) selftest | grep -E '^CK_GSP_COT_ENCODE_SELFTEST: (PASS|FAIL)' | grep -q PASS || { $(GSP_COT_TOOL) selftest | grep -E 'FAIL|SELFTEST'; exit 1; }
	@$(GSP_COT_TOOL) selftest | tail -1

# ---- host extractor for the GB10B firmware arrays compiled into the pinned driver (aienos#286 cut C host work) ----
# Parses the two public generated files g_bindata_kgspGetBinArchive{GspRmBoot,GspRmFmcGfwProdSigned}_GB10B.c
# (MIT), cross-checks every size/flag/record, inflates the compressed descriptor with our own
# DEFLATE decoder (CRC-32 + ISIZE trailer verified), checks UCODE_HASH == SHA-384(UCODE_IMAGE)
# and the RM_RISCV_UCODE_DESC offsets, and writes the arrays as files. Never loads anything.
# The driver files are optional (fetch them from the 580.173.02 tag into GSP_BINDATA_DIR);
# when absent the pin step is NOT_RUN, the self-test still runs. docs/GB10_FIRMWARE_INVENTORY.md 3.3 and 11.
GSP_BINDATA_TOOL := $(OUT)/host/ck_gsp_bindata_extract
GSP_BINDATA_DIR ?= $(HOME)/.cache/aienos/open-gpu-kernel-modules-580.173.02
GSP_BINDATA_FMC_IMAGE_SHA256 := b13ead4b9a6b8a0d268f3094cc4f4521d6be8a9a525edbc9a8f3f397c86f1f2e
GSP_BINDATA_BOOT_PROD_SHA256 := 427a691d8453f02548d395f40ac900eb0d5b8ea864e8f14f958eef890ba400a2
$(GSP_BINDATA_TOOL): $(KDIR)/tools/ck_gsp_bindata_extract.c $(NATIVE)/argus/sha256.c $(NATIVE)/argus/sha256.h
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -I$(NATIVE)/argus -o $@ $(KDIR)/tools/ck_gsp_bindata_extract.c $(NATIVE)/argus/sha256.c
gsp-bindata-extract: $(GSP_BINDATA_TOOL)
gsp-bindata-test: $(GSP_BINDATA_TOOL)
	$(GSP_BINDATA_TOOL) selftest | grep -E '^CK_GSP_BINDATA_EXTRACT_SELFTEST: (PASS|FAIL)' | grep -q PASS || { $(GSP_BINDATA_TOOL) selftest | grep -E 'FAIL|SELFTEST'; exit 1; }
	@$(GSP_BINDATA_TOOL) selftest | tail -1
	@fmc="$(GSP_BINDATA_DIR)/g_bindata_kgspGetBinArchiveGspRmFmcGfwProdSigned_GB10B.c"; boot="$(GSP_BINDATA_DIR)/g_bindata_kgspGetBinArchiveGspRmBoot_GB10B.c"; \
	if [ -r "$$fmc" ] && [ -r "$$boot" ]; then \
	  out=$$($(GSP_BINDATA_TOOL) extract "$$fmc") || { echo "$$out"; echo "CK_GSP_BINDATA_PIN: FAIL (FMC file refused)"; exit 1; }; \
	  echo "$$out" | grep -E '^(hash384|array .* UCODE_IMAGE |RESULT)'; \
	  echo "$$out" | grep -q '^array .* UCODE_IMAGE .* size=195912 sha256=$(GSP_BINDATA_FMC_IMAGE_SHA256)$$' || { echo "CK_GSP_BINDATA_PIN: FAIL (FMC image digest differs from the pin)"; exit 1; }; \
	  out=$$($(GSP_BINDATA_TOOL) extract "$$boot") || { echo "$$out"; echo "CK_GSP_BINDATA_PIN: FAIL (boot file refused)"; exit 1; }; \
	  echo "$$out" | grep -E '^(desc UCODE_DESC_PROD|array .* UCODE_IMAGE_PROD |RESULT)'; \
	  echo "$$out" | grep -q '^array .* UCODE_IMAGE_PROD .* size=196608 sha256=$(GSP_BINDATA_BOOT_PROD_SHA256)$$' || { echo "CK_GSP_BINDATA_PIN: FAIL (boot PROD image digest differs from the pin)"; exit 1; }; \
	  echo "$$out" | grep -q '^desc UCODE_DESC_PROD version=5 manifest=0x0+0xa00 monitor_data=0xa00+0xa600 monitor_code=0xb000+0x24d00 monitor_enabled=1 ' || { echo "CK_GSP_BINDATA_PIN: FAIL (descriptor differs from the pin)"; exit 1; }; \
	  echo "CK_GSP_BINDATA_PIN: PASS"; \
	else echo "CK_GSP_BINDATA_PIN: NOT_RUN ($(GSP_BINDATA_DIR) lacks the two GB10B bindata files)"; fi

# ---- host encoder/decoder for the GSP-RM boot-argument blocks (aienos#286 cut C host work) ----
# Byte-exact GspFwWprMeta (256), libos init-argument page, log-buffer PTE prefix,
# GSP_ARGUMENTS_CACHED page, RPC shared-buffer page table and radix-3 ELF table, with
# the GB10B values traced from the pinned driver (heap 133 MiB, 7 logs + RMARGS, 129 PTEs).
# Self-test = compiler layouts, golden constants, round trips, every mutation refused.
# Never loads anything. docs/GB10_FIRMWARE_INVENTORY.md section 12.
GSP_BOOTARGS_TOOL := $(OUT)/host/ck_gsp_boot_args_encode
$(GSP_BOOTARGS_TOOL): $(KDIR)/tools/ck_gsp_boot_args_encode.c
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -o $@ $(KDIR)/tools/ck_gsp_boot_args_encode.c
gsp-bootargs-encode: $(GSP_BOOTARGS_TOOL)
gsp-bootargs-test: $(GSP_BOOTARGS_TOOL)
	$(GSP_BOOTARGS_TOOL) selftest | grep -E '^CK_GSP_BOOT_ARGS_ENCODE_SELFTEST: (PASS|FAIL)' | grep -q PASS || { $(GSP_BOOTARGS_TOOL) selftest | grep -E 'FAIL|SELFTEST'; exit 1; }
	@$(GSP_BOOTARGS_TOOL) selftest | tail -1

# ---- host encoder/decoder for the GSP-RM message queue (aienos#286 cut C host part 5) ----
# Byte-exact msgqTxHeader/msgqRxHeader, GSP_MSG_QUEUE_ELEMENT with checksum and sequence
# rules, rpc_message_header_v03_00, continuation-record plan and PACKED_REGISTRY_TABLE,
# all from the pinned driver. Self-test = compiler layouts, golden bytes, round trips,
# every mutation refused. Never touches a device. docs/GB10_FIRMWARE_INVENTORY.md section 13.
GSP_RPC_TOOL := $(OUT)/host/ck_gsp_rpc_encode
$(GSP_RPC_TOOL): $(KDIR)/tools/ck_gsp_rpc_encode.c
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -o $@ $(KDIR)/tools/ck_gsp_rpc_encode.c
gsp-rpc-encode: $(GSP_RPC_TOOL)
gsp-rpc-test: $(GSP_RPC_TOOL)
	$(GSP_RPC_TOOL) selftest | grep -E '^CK_GSP_RPC_ENCODE_SELFTEST: (PASS|FAIL)' | grep -q PASS || { $(GSP_RPC_TOOL) selftest | grep -E 'FAIL|SELFTEST'; exit 1; }
	@$(GSP_RPC_TOOL) selftest | tail -1

# ---- native image slots: host tool + freestanding check (native v1 plan P11 cut 1, gate N7) ----
# native/boot/slot_format.h + slot_select.c: the A/B slot manifest, control record and the
# loader's selection rules (bounded candidate tries, generation floor, no boot loop, an
# exhausted candidate never boots on its own authority). docs/NATIVE_IMAGE_SLOTS.md.
# ck_slot_tool builds/signs/verifies manifests and simulates the decision; its self-test
# is the format's oracle. slot-free proves slot_select.c compiles with the kernel's
# freestanding flags and needs only the image's own digest/signature primitives.
# No image code changes in this cut; the loader does not read slots yet.
SLOT_TOOL := $(OUT)/host/ck_slot_tool
SLOT_TOOL_SRCS := $(KDIR)/tools/ck_slot_tool.c $(BOOT)/slot_select.c $(BOOT)/slot_control.c $(BOOT)/slot_update.c $(NATIVE)/disk/disk.c $(NATIVE)/sig/sha512.c \
	$(NATIVE)/sig/ed25519.c $(NATIVE)/sig/ct.c $(NATIVE)/argus/sha256.c $(NATIVE)/store/torn_slot.c
$(SLOT_TOOL): $(SLOT_TOOL_SRCS) $(BOOT)/slot_format.h $(BOOT)/slot_control.h $(BOOT)/slot_update.h
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -o $@ $(SLOT_TOOL_SRCS)
slot-tool: $(SLOT_TOOL)
# P11 cut 3: the service image's slot key table (see SVC_SLOT_KEY_SRC above).
ifneq ($(SVC_SLOT_KEYS_C),)
$(SVC_SLOT_KEYS_C): $(SLOT_TOOL) FORCE
	@mkdir -p $(dir $@)
	@$(SLOT_TOOL) keys-c $(SVC_SLOT_KEY_SRC) --out $@
endif
slot-test: $(SLOT_TOOL)
	$(SLOT_TOOL) selftest | grep -E '^CK_SLOT_TOOL_SELFTEST: (PASS|FAIL)' | grep -q PASS || { $(SLOT_TOOL) selftest | grep -E 'FAIL|SELFTEST'; exit 1; }
	@$(SLOT_TOOL) selftest | tail -1
SLOT_FREE_ALLOWED_U := aienos_sha512 aienos_ed25519_verify sha256_hash _GLOBAL_OFFSET_TABLE_
slot-free: $(BOOT)/slot_select.c $(BOOT)/slot_format.h
	@mkdir -p $(OUT)/free
	$(KCC) $(KCFLAGS) -c $(BOOT)/slot_select.c -o $(OUT)/free/slot_select.o
	@bad=$$($(CROSS)nm -u $(OUT)/free/slot_select.o | awk '{print $$2}' | grep -vxF $(foreach a,$(SLOT_FREE_ALLOWED_U),-e $(a)) || true); \
	if [ -n "$$bad" ]; then echo "slot-free: FAIL unexpected undefined symbols: $$bad"; exit 1; fi; \
	echo "SLOT_FREE: PASS (undefined: $(SLOT_FREE_ALLOWED_U))"

# ---- reproducible native package (scripts/native_package.sh, P11 cut 1b) ----
# Builds the image twice from a clean tree, refuses if they differ, records
# PACKAGE.txt + SHA256SUMS, binds them into the slot manifest's provenance and
# verifies the owner signature. package-test = scripts/native_package_test.sh
# (TEST signer and TEST-FIXTURE owner files only; ~35 s; nothing booted).
package-test: $(SLOT_TOOL)
	NATIVE_PACKAGE_TOOL_OUT=$(OUT) bash $(REPO)/scripts/native_package_test.sh | grep -E '^NATIVE_PACKAGE_TEST: (PASS|FAIL)' | grep -q PASS || { NATIVE_PACKAGE_TOOL_OUT=$(OUT) bash $(REPO)/scripts/native_package_test.sh | grep -E '^FAIL|NATIVE_PACKAGE_TEST'; exit 1; }
	@echo "NATIVE_PACKAGE_TEST: PASS"

# ---- SLOTLDR.EFI: the signed A/B slot loader (native v1 plan P11 cut 2a, gate N7) ----
# native/boot/slot_loader.c: a separate UEFI application in FRONT of the unchanged
# stub + kernel image (BOOTAA64.EFI is not touched). It reads the slots partition,
# verifies both slots against the keys baked in here, applies slot_select.c, commits
# the control record before a candidate try, then LoadImage + StartImage of the
# verified bytes. Own object list: no kernel objects (checked), no runtime services,
# no UEFI variables, no ExitBootServices (checked in the source). Keys: CK_SLOT_KEYS
# or CK_TEST_SLOT_KEY=1 (see the top of this file). docs/NATIVE_IMAGE_SLOTS.md.
#   make slot-loader CK_TEST_SLOT_KEY=1        -> $(OUT)/SLOTLDR.EFI (TEST-ONLY key)
#   make slot-loader CK_SLOT_KEYS=<file>       -> $(OUT)/SLOTLDR.EFI (owner keys)
#   make slot-loader-check                      build checks + refusals (in make test)
# QEMU gate: scripts/qemu_ck_slot_loader_test.sh (AIENOS_CK_SLOT_LOADER).
SLOTLDR_DIR := $(OUT)/slotldr
SLOTLDR_ELF := $(SLOTLDR_DIR)/slotldr.elf
SLOTLDR_EFI := $(OUT)/SLOTLDR.EFI
SLOTLDR_KEYS_C := $(SLOTLDR_DIR)/slot_keys.c
SLOTLDR_C := $(BOOT)/slot_loader.c $(BOOT)/slot_select.c $(BOOT)/slot_control.c $(NATIVE)/sig/sha512.c $(NATIVE)/sig/ed25519.c \
	$(NATIVE)/sig/ct.c $(NATIVE)/argus/sha256.c $(NATIVE)/store/torn_slot.c $(KDIR)/core/libc_min.c \
	$(KDIR)/core/fmt.c
SLOTLDR_OBJS := $(patsubst $(NATIVE)/%.c,$(SLOTLDR_DIR)/obj/%.o,$(SLOTLDR_C)) \
	$(SLOTLDR_DIR)/obj/boot/efi_entry.o $(SLOTLDR_DIR)/obj/slot_keys.o
SLOTLDR_CFLAGS := $(KCFLAGS) $(ART_INC) -I$(NATIVE)/store
SLOTLDR_HDRS := $(BOOT)/slot_format.h $(BOOT)/slot_control.h $(BOOT)/efi.h $(NATIVE)/store/torn_slot.h $(KDIR)/core/fmt.h $(ART_HDRS)
SLOTLDR_KEY_SRC := $(if $(strip $(CK_TEST_SLOT_KEY)),--test-key,$(if $(strip $(CK_SLOT_KEYS)),--keys $(abspath $(CK_SLOT_KEYS)),))
$(SLOTLDR_DIR)/obj/%.o: $(NATIVE)/%.c $(SLOTLDR_HDRS)
	@mkdir -p $(dir $@)
	$(KCC) $(SLOTLDR_CFLAGS) -c -o $@ $<
$(SLOTLDR_DIR)/obj/boot/slot_loader.o: $(BOOT)/slot_loader.c $(SLOTLDR_HDRS) $(OUT)/commit.stamp
	@mkdir -p $(dir $@)
	$(KCC) $(SLOTLDR_CFLAGS) -DAIENOS_COMMIT='"$(AIENOS_COMMIT)"' -c -o $@ $<
$(SLOTLDR_DIR)/obj/boot/efi_entry.o: $(BOOT)/efi_entry.S
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) -c -o $@ $<
# Rewritten only when the key table changes (ck_slot_tool keys-c compares).
$(SLOTLDR_KEYS_C): $(SLOT_TOOL) FORCE
	@[ -n "$(SLOTLDR_KEY_SRC)" ] || { echo "slot-loader: give CK_SLOT_KEYS=<owner public keys file> or CK_TEST_SLOT_KEY=1 (TEST only)"; exit 1; }
	@mkdir -p $(dir $@)
	@$(SLOT_TOOL) keys-c $(SLOTLDR_KEY_SRC) --out $@
$(SLOTLDR_DIR)/obj/slot_keys.o: $(SLOTLDR_KEYS_C)
	@mkdir -p $(dir $@)
	$(KCC) $(SLOTLDR_CFLAGS) -c -o $@ $<
$(SLOTLDR_ELF): $(SLOTLDR_OBJS) $(BOOT)/image.ld
	@if grep -nE -- '->(RuntimeServices|ExitBootServices|SetVariable|GetVariable|SetWatchdogTimer)' $(BOOT)/slot_loader.c; then \
	  echo "slot_loader.c calls a service the slot loader must never call"; exit 1; fi
	$(call link_image,$@,$(SLOTLDR_OBJS))
	@k=$$($(KNM) $@ | grep -E ' [TtDdBbRr] (ck_kernel_entry|kmain|ck_boot_model_load|ck_printf)$$' || true); \
	if [ -n "$$k" ]; then echo "SLOTLDR links kernel objects: $$k"; rm -f $@; exit 1; fi
	@if [ "$(strip $(CK_TEST_SLOT_KEY))" = 1 ]; then \
	  grep -aqF "TEST-ONLY key" $@ || { echo "TEST-key SLOTLDR lacks its TEST-ONLY announcement"; rm -f $@; exit 1; }; \
	elif grep -aqF "TEST-ONLY" $@; then echo "owner-key SLOTLDR carries a TEST-ONLY note"; rm -f $@; exit 1; fi
$(SLOTLDR_EFI): $(SLOTLDR_ELF)
	$(call pe_image,$<,$@)
slot-loader: $(SLOTLDR_EFI)
SLOTLDR_FIXTURE_KEYS := $(KDIR)/tests/fixtures/owner/TEST-FIXTURE-owner-pubkeys.txt
slot-loader-check:
	@$(MAKE) -s --no-print-directory OUT=$(OUT)/slotldr-check-test CK_TEST_SLOT_KEY=1 slot-loader >/dev/null
	@grep -aqF "TEST-ONLY key" $(OUT)/slotldr-check-test/SLOTLDR.EFI
	@$(MAKE) -s --no-print-directory OUT=$(OUT)/slotldr-check-owner CK_SLOT_KEYS=$(SLOTLDR_FIXTURE_KEYS) slot-loader >/dev/null
	@if grep -aqF "TEST-ONLY" $(OUT)/slotldr-check-owner/SLOTLDR.EFI; then echo "SLOT_LOADER_BUILD: FAIL owner-key loader carries TEST-ONLY"; exit 1; fi
	@for c in "CK_HARDWARE_STAGING=1 CK_TEST_SLOT_KEY=1|cannot be combined with CK_HARDWARE_STAGING" \
	          "CK_TEST_SLOT_KEY=1 CK_SLOT_KEYS=$(SLOTLDR_FIXTURE_KEYS)|are exclusive" \
	          "CK_SLOT_KEYS=$(SLOTLDR_FIXTURE_KEYS:.txt=.missing)|cannot read the keys file" \
	          "|give CK_SLOT_KEYS"; do \
	  args=$${c%%|*}; want=$${c#*|}; \
	  if $(MAKE) -s --no-print-directory OUT=$(OUT)/slotldr-check-refuse $$args slot-loader >$(OUT)/slotldr-refuse.log 2>&1; then \
	    echo "SLOT_LOADER_BUILD: FAIL not refused: $$args"; exit 1; fi; \
	  grep -qF -- "$$want" $(OUT)/slotldr-refuse.log || { echo "SLOT_LOADER_BUILD: FAIL refused without '$$want': $$args"; cat $(OUT)/slotldr-refuse.log; exit 1; }; \
	  echo "slot-loader refused as required: $${args:-no key source} ($$want)"; \
	done
	@echo "SLOT_LOADER_BUILD: PASS (TEST-key and owner-key loaders built; TEST key refused with hardware staging)"

# ---- PI5DIAG.EFI: AIENOS-PI5-BOOT-0, the Raspberry Pi 5 firmware diagnostic ----
# native/boot/diag_main.c: a UEFI application that reports what the firmware shows
# (ConOut + \EFI\AIENOS\PI5BOOT0.TXT) and returns. Own object list, no kernel, no
# ExitBootServices (checked). Copy to the card as EFI/BOOT/BOOTAA64.EFI.
#   make pi5-diag     -> $(OUT)/PI5DIAG.EFI      QEMU test: scripts/qemu_ck_pi5_diag_test.sh
PI5DIAG_DIR := $(OUT)/pi5diag
PI5DIAG_ELF := $(PI5DIAG_DIR)/pi5diag.elf
PI5DIAG_EFI := $(OUT)/PI5DIAG.EFI
PI5DIAG_OBJS := $(PI5DIAG_DIR)/diag_main.o $(PI5DIAG_DIR)/efi_entry.o $(PI5DIAG_DIR)/fmt.o $(PI5DIAG_DIR)/libc_min.o
$(PI5DIAG_DIR)/diag_main.o: $(BOOT)/diag_main.c $(BOOT)/diag.h $(BOOT)/efi.h $(KDIR)/core/fmt.h
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) -c -o $@ $<
$(PI5DIAG_DIR)/efi_entry.o: $(BOOT)/efi_entry.S
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) -c -o $@ $<
$(PI5DIAG_DIR)/fmt.o: $(KDIR)/core/fmt.c $(KDIR)/core/fmt.h
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) -c -o $@ $<
$(PI5DIAG_DIR)/libc_min.o: $(KDIR)/core/libc_min.c
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) -c -o $@ $<
$(PI5DIAG_ELF): $(PI5DIAG_OBJS) $(BOOT)/image.ld
	@if grep -nE -- '->ExitBootServices' $(BOOT)/diag_main.c || grep -nE -- 'rt->' $(BOOT)/diag_main.c | grep -vE -- 'rt->ResetSystem'; then \
	  echo "diag_main.c calls a service the diagnostic must never call (only ResetSystem is allowed)"; exit 1; fi
	$(call link_image,$@,$(PI5DIAG_OBJS))
	@k=$$($(KNM) $@ | grep -E ' [TtDdBbRr] (ck_kernel_entry|kmain|ck_boot_model_load|ck_printf)$$' || true); \
	if [ -n "$$k" ]; then echo "PI5DIAG links kernel objects: $$k"; rm -f $@; exit 1; fi
$(PI5DIAG_EFI): $(PI5DIAG_ELF)
	$(call pe_image,$<,$@)
pi5-diag: $(PI5DIAG_EFI)

# ---- IMACDIAG.EFI: AIENOS-IMAC-BOOT-0, the same diagnostic for x86_64 (2017 iMac) ----
# diag_main.c + diag_x86.c (CPUID, SMBIOS identity, PCI, GOP, disks), report in
# \EFI\AIENOS\IMACBOOT.TXT, then power off. The only x86_64 image in this tree: its own
# cross toolchain and flags (-mabi=ms: every function uses the UEFI x64 convention),
# its own entry (efi_entry_x86_64.S) and PE header (image_x86_64.ld, Machine 0x8664).
# Copy to a FAT stick as EFI/BOOT/BOOTX64.EFI.
#   make imac-diag    -> $(OUT)/IMACDIAG.EFI     QEMU test: scripts/qemu_ck_imac_diag_test.sh
ifeq ($(HOST_ARCH),x86_64)
X86_CROSS ?=
else
X86_CROSS ?= x86_64-linux-gnu-
endif
X86CC := $(X86_CROSS)gcc
X86LD := $(X86_CROSS)ld
X86OBJCOPY := $(X86_CROSS)objcopy
X86NM := $(X86_CROSS)nm
X86READELF := $(X86_CROSS)readelf
X86CFLAGS := -std=gnu11 -O2 -Wall -Wextra -Werror -ffreestanding -nostdlib -fno-builtin \
	-fno-stack-protector -fno-tree-loop-distribute-patterns -mgeneral-regs-only -mno-red-zone \
	-mabi=ms -fcf-protection=none -fno-asynchronous-unwind-tables -fpie -fvisibility=hidden -fno-plt \
	-I$(KDIR)/core -I$(BOOT)
X86LDFLAGS := -nostdlib -pie --no-dynamic-linker -z norelro -z noexecstack -z max-page-size=4096 \
	--no-warn-rwx-segments -T $(BOOT)/image_x86_64.ld
IMACDIAG_DIR := $(OUT)/imacdiag
IMACDIAG_ELF := $(IMACDIAG_DIR)/imacdiag.elf
IMACDIAG_EFI := $(OUT)/IMACDIAG.EFI
IMACDIAG_OBJS := $(IMACDIAG_DIR)/diag_main.o $(IMACDIAG_DIR)/diag_x86.o $(IMACDIAG_DIR)/efi_entry_x86_64.o \
	$(IMACDIAG_DIR)/fmt.o $(IMACDIAG_DIR)/libc_min.o
$(IMACDIAG_DIR)/diag_main.o: $(BOOT)/diag_main.c $(BOOT)/diag.h $(BOOT)/efi.h $(KDIR)/core/fmt.h
$(IMACDIAG_DIR)/diag_x86.o: $(BOOT)/diag_x86.c $(BOOT)/diag.h $(BOOT)/efi.h
$(IMACDIAG_DIR)/efi_entry_x86_64.o: $(BOOT)/efi_entry_x86_64.S
$(IMACDIAG_DIR)/fmt.o: $(KDIR)/core/fmt.c $(KDIR)/core/fmt.h
$(IMACDIAG_DIR)/libc_min.o: $(KDIR)/core/libc_min.c
$(IMACDIAG_OBJS):
	@mkdir -p $(dir $@)
	$(X86CC) $(X86CFLAGS) -c -o $@ $<
$(IMACDIAG_ELF): $(IMACDIAG_OBJS) $(BOOT)/image_x86_64.ld
	@if grep -nE -- '->ExitBootServices' $(BOOT)/diag_main.c $(BOOT)/diag_x86.c || grep -nE -- 'rt->' $(BOOT)/diag_main.c $(BOOT)/diag_x86.c | grep -vE -- 'rt->ResetSystem'; then \
	  echo "the diagnostic calls a service it must never call (only ResetSystem is allowed)"; exit 1; fi
	@mkdir -p $(dir $@)
	$(X86LD) $(X86LDFLAGS) -o $@ $(IMACDIAG_OBJS)
	@u=$$($(X86NM) -u $@ | grep -v ' w ' || true); \
	if [ -n "$$u" ]; then echo "image has undefined symbols: $$u"; rm -f $@; exit 1; fi
	@bad=$$($(X86READELF) -rW $@ | grep -E '^[0-9a-f]+ ' | grep -v R_X86_64_RELATIVE || true); \
	if [ -n "$$bad" ]; then echo "image has non-RELATIVE relocations:"; echo "$$bad"; rm -f $@; exit 1; fi
	@k=$$($(X86NM) $@ | grep -E ' [TtDdBbRr] (ck_kernel_entry|kmain|ck_boot_model_load|ck_printf)$$' || true); \
	if [ -n "$$k" ]; then echo "IMACDIAG links kernel objects: $$k"; rm -f $@; exit 1; fi
$(IMACDIAG_EFI): $(IMACDIAG_ELF)
	$(X86OBJCOPY) -O binary $< $@
	@sz=$$(stat -c %s $@); pad=$$(( (4096 - sz % 4096) % 4096 )); \
	if [ $$pad -gt 0 ]; then head -c $$pad /dev/zero >> $@; fi
	@[ "$$(head -c 2 $@)" = "MZ" ] || { echo "not a PE image"; rm -f $@; exit 1; }
	@[ "$$(od -An -tx1 -j68 -N2 $@ | tr -d ' ')" = "6486" ] || { echo "PE Machine is not x86_64 (0x8664)"; rm -f $@; exit 1; }
	@echo "built $@ (commit $(AIENOS_COMMIT))"
imac-diag: $(IMACDIAG_EFI)

# ---- IMACKERN.EFI: AIENOS-IMAC-KERNEL-0, the C kernel core on x86_64 (2017 iMac) ----
# x86/efi_x86.c (stub: GOP, RSDP, memory map, ExitBootServices, CHANDOF3) + x86/kmain_x86.c
# (GDT/TSS/IDT, own page tables, guard page, HPET-timed TSC, local APIC timer, ACPI S5)
# + x86/pci_x86.c (PCI walk; AHCI via x86/ahci_x86.c and NVMe via ../disk/disk_nvme.c, both
# read-only, GPT checked by dev/disk_part.c; a look at the Ethernet chip) + x86/smp_x86.S
# (secondary cores started and parked) + x86/tg3_x86.c (BCM57766 Ethernet: link detection; no
# transmit in the default image)
# + x86/trap.S + x86/console_x86.c (COM1 when present, GOP framebuffer), on the
# arch-neutral core: fbcon, fmt, acpi, handoff_check, frames, heap. Same toolchain and PE
# header as IMACDIAG. Copy to a FAT stick as EFI/BOOT/BOOTX64.EFI.
#   make imac-kernel  -> $(OUT)/IMACKERN.EFI     QEMU test: scripts/qemu_ck_imac_kernel_test.sh
# The network report is a LAB-ONLY diagnostic, opt-in and default off:
#   make imac-kernel CK_X86_REPORT=1 -> $(OUT)/IMACKERN-LAB.EFI (own object dir)
# adds x86/report_x86.c + ../../net/aienos_net.c and tg3 transmit (-DCK_X86_REPORT=1): during the
# hold it broadcasts only allowlisted console lines (ck_x86_report_filter, never the raw console)
# as UDP to port 47031, header "AIENOS-IMAC-REPORT v=2 auth=none": UNAUTHENTICATED, never a
# receipt, evidence or a command. Host test scripts/ck_imac_report_test.sh, receiver
# tools/ck_imac_report_listen.c. The default image, and any resident or service (ALLEN) build,
# must not contain it: the link step below fails a default image that has a report symbol.
CK_X86_REPORT ?= 0
X86K := $(KDIR)/x86
ifeq ($(CK_X86_REPORT),1)
IMACKERN_DIR := $(OUT)/imackern-lab
IMACKERN_EFI := $(OUT)/IMACKERN-LAB.EFI
else ifeq ($(CK_X86_REPORT),0)
IMACKERN_DIR := $(OUT)/imackern
IMACKERN_EFI := $(OUT)/IMACKERN.EFI
else
$(error CK_X86_REPORT must be 0 (default) or 1 (lab-only network report))
endif
IMACKERN_ELF := $(IMACKERN_DIR)/imackern.elf
IMACKERN_CFLAGS := $(X86CFLAGS) -I$(KDIR)/include -I$(KDIR)/mm -I$(KDIR)/dev -I$(NATIVE)/disk -I$(NATIVE)/net
IMACKERN_OBJS := $(IMACKERN_DIR)/efi_entry_x86_64.o $(IMACKERN_DIR)/efi_x86.o $(IMACKERN_DIR)/efi_gop.o \
	$(IMACKERN_DIR)/kmain_x86.o $(IMACKERN_DIR)/console_x86.o $(IMACKERN_DIR)/trap.o \
	$(IMACKERN_DIR)/fbcon.o $(IMACKERN_DIR)/fmt.o $(IMACKERN_DIR)/acpi.o $(IMACKERN_DIR)/handoff_check.o \
	$(IMACKERN_DIR)/frames.o $(IMACKERN_DIR)/heap.o $(IMACKERN_DIR)/libc_min.o \
	$(IMACKERN_DIR)/ahci_x86.o $(IMACKERN_DIR)/disk_part.o $(IMACKERN_DIR)/disk.o \
	$(IMACKERN_DIR)/pci_x86.o $(IMACKERN_DIR)/smp_x86.o $(IMACKERN_DIR)/disk_nvme.o \
	$(IMACKERN_DIR)/tg3_x86.o
IMACKERN_REPORT_OBJS := $(IMACKERN_DIR)/report_x86.o $(IMACKERN_DIR)/aienos_net.o
# Symbols only the lab image may contain; the default image is checked for them after linking.
IMACKERN_REPORT_SYMS := ck_x86_report_hold|ck_x86_report_frame|ck_x86_report_filter|ck_x86_report_parts|ck_x86_tg3_send|ck_x86_tg3_drain|net_udp_build
ifeq ($(CK_X86_REPORT),1)
IMACKERN_OBJS += $(IMACKERN_REPORT_OBJS)
IMACKERN_CFLAGS += -DCK_X86_REPORT=1
endif
IMACKERN_HDRS := $(X86K)/x86.h $(BOOT)/handoff.h $(BOOT)/efi.h $(KDIR)/core/ck_internal.h $(KDIR)/include/ck.h
$(IMACKERN_DIR)/efi_entry_x86_64.o: $(BOOT)/efi_entry_x86_64.S
$(IMACKERN_DIR)/efi_x86.o: $(X86K)/efi_x86.c $(IMACKERN_HDRS)
$(IMACKERN_DIR)/efi_gop.o: $(BOOT)/efi_gop.c $(IMACKERN_HDRS)
$(IMACKERN_DIR)/kmain_x86.o: $(X86K)/kmain_x86.c $(IMACKERN_HDRS) $(KDIR)/core/handoff_check.h $(KDIR)/mm/frames.h $(KDIR)/mm/heap.h $(OUT)/commit.stamp
$(IMACKERN_DIR)/console_x86.o: $(X86K)/console_x86.c $(IMACKERN_HDRS) $(KDIR)/core/fbcon.h
$(IMACKERN_DIR)/trap.o: $(X86K)/trap.S
$(IMACKERN_DIR)/fbcon.o: $(KDIR)/core/fbcon.c $(KDIR)/core/fbcon.h $(KDIR)/core/font8x8.h
$(IMACKERN_DIR)/fmt.o: $(KDIR)/core/fmt.c $(KDIR)/core/fmt.h
$(IMACKERN_DIR)/acpi.o: $(KDIR)/core/acpi.c $(KDIR)/core/acpi.h
$(IMACKERN_DIR)/handoff_check.o: $(KDIR)/core/handoff_check.c $(KDIR)/core/handoff_check.h $(BOOT)/handoff.h
$(IMACKERN_DIR)/frames.o: $(KDIR)/mm/frames.c $(KDIR)/mm/frames.h
$(IMACKERN_DIR)/heap.o: $(KDIR)/mm/heap.c $(KDIR)/mm/heap.h
$(IMACKERN_DIR)/libc_min.o: $(KDIR)/core/libc_min.c
$(IMACKERN_DIR)/ahci_x86.o: $(X86K)/ahci_x86.c $(IMACKERN_HDRS) $(KDIR)/mm/frames.h $(KDIR)/dev/disk_part.h $(NATIVE)/disk/disk.h
$(IMACKERN_DIR)/disk_part.o: $(KDIR)/dev/disk_part.c $(KDIR)/dev/disk_part.h $(NATIVE)/disk/disk.h
$(IMACKERN_DIR)/disk.o: $(NATIVE)/disk/disk.c $(NATIVE)/disk/disk.h
$(IMACKERN_DIR)/pci_x86.o: $(X86K)/pci_x86.c $(IMACKERN_HDRS) $(KDIR)/mm/frames.h $(KDIR)/dev/disk_part.h $(NATIVE)/disk/disk.h $(NATIVE)/disk/disk_nvme.h
$(IMACKERN_DIR)/smp_x86.o: $(X86K)/smp_x86.S
$(IMACKERN_DIR)/disk_nvme.o: $(NATIVE)/disk/disk_nvme.c $(NATIVE)/disk/disk_nvme.h $(NATIVE)/disk/disk.h
$(IMACKERN_DIR)/tg3_x86.o: $(X86K)/tg3_x86.c $(IMACKERN_HDRS) $(KDIR)/mm/frames.h
$(IMACKERN_DIR)/report_x86.o: $(X86K)/report_x86.c $(X86K)/report_x86.h $(IMACKERN_HDRS) $(NATIVE)/net/aienos_net.h
$(IMACKERN_DIR)/aienos_net.o: $(NATIVE)/net/aienos_net.c $(NATIVE)/net/aienos_net.h
$(sort $(IMACKERN_OBJS) $(IMACKERN_REPORT_OBJS)):
	@mkdir -p $(dir $@)
	$(X86CC) $(IMACKERN_CFLAGS) -DAIENOS_COMMIT='"$(AIENOS_COMMIT)"' -c -o $@ $<
$(IMACKERN_ELF): $(IMACKERN_OBJS) $(BOOT)/image_x86_64.ld
	@if grep -nE -- 'rt->|RuntimeServices' $(X86K)/*.c; then \
	  echo "the x86 kernel calls a UEFI runtime service; it must never call one"; exit 1; fi
	@if grep -nE "define ATA_" $(X86K)/ahci_x86.c | grep -vE "ATA_(IDENTIFY 0xec|READ_DMA_EXT 0x25)$$"; then \
	  echo "ahci_x86.c defines an ATA command other than IDENTIFY and READ DMA EXT; the driver is read-only"; exit 1; fi
	@if grep -nE "nvme_(write|flush)\(" $(X86K)/*.c; then \
	  echo "the x86 kernel calls nvme_write or nvme_flush; its disks are read-only"; exit 1; fi
	@mkdir -p $(dir $@)
	$(X86LD) $(X86LDFLAGS) -o $@ $(IMACKERN_OBJS)
	@u=$$($(X86NM) -u $@ | grep -v ' w ' || true); \
	if [ -n "$$u" ]; then echo "image has undefined symbols: $$u"; rm -f $@; exit 1; fi
	@bad=$$($(X86READELF) -rW $@ | grep -E '^[0-9a-f]+ ' | grep -v R_X86_64_RELATIVE || true); \
	if [ -n "$$bad" ]; then echo "image has non-RELATIVE relocations:"; echo "$$bad"; rm -f $@; exit 1; fi
	@n=$$($(X86NM) $@ | grep -c ' t isr_common$$' || true); s=$$($(X86NM) $@ | grep ' T ck_x86_isr_stubs$$' | cut -c1-16); \
	e=$$($(X86NM) $@ | grep ' t isr_common$$' | cut -c1-16); \
	if [ "$$n" != 1 ] || [ $$((0x$$e - 0x$$s)) != 4096 ]; then echo "interrupt stubs are not 256 x 16 bytes"; rm -f $@; exit 1; fi
	@r=$$($(X86NM) $@ | grep -E ' [TtDdBbRr] ($(IMACKERN_REPORT_SYMS))$$' || true); \
	if [ "$(CK_X86_REPORT)" = 1 ]; then \
	  for s in ck_x86_report_hold ck_x86_report_filter ck_x86_report_frame; do \
	    echo "$$r" | grep -q " $$s$$" || { echo "lab image lacks $$s"; rm -f $@; exit 1; }; done; \
	elif [ -n "$$r" ]; then \
	  echo "default iMac image links the lab-only network report (build it with CK_X86_REPORT=1 only):"; \
	  echo "$$r"; rm -f $@; exit 1; fi
	@if [ "$(CK_X86_REPORT)" != 1 ] && grep -aq "AIENOS-IMAC-REPORT" $@; then \
	  echo "default iMac image carries the report header string"; rm -f $@; exit 1; fi
$(IMACKERN_EFI): $(IMACKERN_ELF)
	$(X86OBJCOPY) -O binary $< $@
	@sz=$$(stat -c %s $@); pad=$$(( (4096 - sz % 4096) % 4096 )); \
	if [ $$pad -gt 0 ]; then head -c $$pad /dev/zero >> $@; fi
	@[ "$$(head -c 2 $@)" = "MZ" ] || { echo "not a PE image"; rm -f $@; exit 1; }
	@[ "$$(od -An -tx1 -j68 -N2 $@ | tr -d ' ')" = "6486" ] || { echo "PE Machine is not x86_64 (0x8664)"; rm -f $@; exit 1; }
	@echo "built $@ (commit $(AIENOS_COMMIT))"
imac-kernel: $(IMACKERN_EFI)
# Negative test builds for W^X (#409), QEMU only and never deployed: CK_X86_WX_MUTATE=1 leaves RAM
# executable, =2 leaves the kernel's code writable, and the kernel's W^X probes must then panic
# (scripts/qemu_ck_imac_kernel_test.sh). Build them into their own OUT directory.
CK_X86_WX_MUTATE ?= 0
ifneq ($(CK_X86_WX_MUTATE),0)
IMACKERN_CFLAGS += -DCK_X86_WX_MUTATE=$(CK_X86_WX_MUTATE)
endif

# ---- NETLDR.EFI: the lab network loader for the 2017 iMac (x86_64) ----
# native/boot/net_loader.c + netboot_proto.c (wire spec netboot_proto.h). Stays on the stick as
# EFI/BOOT/BOOTX64.EFI; at every power-on it fetches a kernel from tools/ck_imac_netboot.c over
# the LAN, verifies it with the SLOTLDR verifier (ck_slot_verify: Ed25519 manifest signature,
# SHA-512 of the image) against the public keys baked in from CK_NETLDR_KEYS ("owner_root_ed25519
# <64 hex>" lines; ck_imac_netboot keygen writes one) and only then starts it. No answer for
# CK_NETLDR_FALLBACK_S seconds: it starts \EFI\AIENOS\IMACKERN.EFI from the stick instead.
#   make imac-netldr CK_NETLDR_KEYS=<file>  -> $(OUT)/NETLDR.EFI
#   make imac-netboot-tool                  -> $(OUT)/host/ck_imac_netboot (keygen, sign, serve)
# QEMU test: scripts/qemu_ck_imac_netboot_test.sh (AIENOS_IMAC_NETBOOT).
CK_NETLDR_KEYS ?=
CK_NETLDR_FALLBACK_S ?= 30
ifeq ($(shell echo '$(CK_NETLDR_FALLBACK_S)' | grep -xE '[1-9][0-9]{0,3}'),)
$(error CK_NETLDR_FALLBACK_S must be a whole number of seconds, 1..9999)
endif
NETLDR_DIR := $(OUT)/netldr
NETLDR_ELF := $(NETLDR_DIR)/netldr.elf
NETLDR_EFI := $(OUT)/NETLDR.EFI
NETLDR_KEYS_C := $(NETLDR_DIR)/netldr_keys.c
NETLDR_C := $(BOOT)/net_loader.c $(BOOT)/netboot_proto.c $(BOOT)/slot_select.c $(NATIVE)/net/aienos_net.c \
	$(NATIVE)/sig/sha512.c $(NATIVE)/sig/ed25519.c $(NATIVE)/sig/ct.c $(NATIVE)/argus/sha256.c \
	$(KDIR)/core/libc_min.c $(KDIR)/core/fmt.c
NETLDR_OBJS := $(patsubst $(NATIVE)/%.c,$(NETLDR_DIR)/obj/%.o,$(NETLDR_C)) \
	$(NETLDR_DIR)/obj/efi_entry_x86_64.o $(NETLDR_DIR)/obj/netldr_keys.o
NETLDR_CFLAGS := $(X86CFLAGS) $(ART_INC) -I$(NATIVE)/net -I$(NATIVE)/store
NETLDR_HDRS := $(BOOT)/netboot_proto.h $(BOOT)/slot_format.h $(BOOT)/efi.h $(NATIVE)/net/aienos_net.h \
	$(KDIR)/core/fmt.h $(ART_HDRS)
$(NETLDR_DIR)/obj/%.o: $(NATIVE)/%.c $(NETLDR_HDRS)
	@mkdir -p $(dir $@)
	$(X86CC) $(NETLDR_CFLAGS) -c -o $@ $<
# The fallback delay is compiled in; the stamp rebuilds the loader when it changes.
$(NETLDR_DIR)/fallback.stamp: FORCE
	@mkdir -p $(dir $@)
	@[ "$$(cat $@ 2>/dev/null)" = "$(CK_NETLDR_FALLBACK_S)" ] || echo "$(CK_NETLDR_FALLBACK_S)" > $@
$(NETLDR_DIR)/obj/boot/net_loader.o: $(BOOT)/net_loader.c $(NETLDR_HDRS) $(OUT)/commit.stamp $(NETLDR_DIR)/fallback.stamp
	@mkdir -p $(dir $@)
	$(X86CC) $(NETLDR_CFLAGS) -DAIENOS_COMMIT='"$(AIENOS_COMMIT)"' -DCK_NETLDR_FALLBACK_S=$(CK_NETLDR_FALLBACK_S)u -c -o $@ $<
$(NETLDR_DIR)/obj/efi_entry_x86_64.o: $(BOOT)/efi_entry_x86_64.S
	@mkdir -p $(dir $@)
	$(X86CC) $(X86CFLAGS) -c -o $@ $<
$(NETLDR_KEYS_C): $(SLOT_TOOL) FORCE
	@[ -n "$(strip $(CK_NETLDR_KEYS))" ] || { echo "imac-netldr: give CK_NETLDR_KEYS=<public key file> (ck_imac_netboot keygen writes one)"; exit 1; }
	@mkdir -p $(dir $@)
	@$(SLOT_TOOL) keys-c --keys $(abspath $(CK_NETLDR_KEYS)) --out $@
$(NETLDR_DIR)/obj/netldr_keys.o: $(NETLDR_KEYS_C)
	@mkdir -p $(dir $@)
	$(X86CC) $(NETLDR_CFLAGS) -c -o $@ $<
$(NETLDR_ELF): $(NETLDR_OBJS) $(BOOT)/image_x86_64.ld
	@if grep -nE -- '->(RuntimeServices|ExitBootServices|SetVariable|GetVariable)|RuntimeServices' $(BOOT)/net_loader.c; then \
	  echo "net_loader.c calls a service the network loader must never call"; exit 1; fi
	@mkdir -p $(dir $@)
	$(X86LD) $(X86LDFLAGS) -o $@ $(NETLDR_OBJS)
	@u=$$($(X86NM) -u $@ | grep -v ' w ' || true); \
	if [ -n "$$u" ]; then echo "image has undefined symbols: $$u"; rm -f $@; exit 1; fi
	@bad=$$($(X86READELF) -rW $@ | grep -E '^[0-9a-f]+ ' | grep -v R_X86_64_RELATIVE || true); \
	if [ -n "$$bad" ]; then echo "image has non-RELATIVE relocations:"; echo "$$bad"; rm -f $@; exit 1; fi
	@k=$$($(X86NM) $@ | grep -E ' [TtDdBbRr] (ck_x86_kernel_entry|kernel_main|ck_printf)$$' || true); \
	if [ -n "$$k" ]; then echo "NETLDR links kernel objects: $$k"; rm -f $@; exit 1; fi
	@if grep -aqF "TEST-ONLY" $@; then echo "NETLDR carries a TEST-ONLY key note"; rm -f $@; exit 1; fi
$(NETLDR_EFI): $(NETLDR_ELF)
	$(X86OBJCOPY) -O binary $< $@
	@sz=$$(stat -c %s $@); pad=$$(( (4096 - sz % 4096) % 4096 )); \
	if [ $$pad -gt 0 ]; then head -c $$pad /dev/zero >> $@; fi
	@[ "$$(head -c 2 $@)" = "MZ" ] || { echo "not a PE image"; rm -f $@; exit 1; }
	@[ "$$(od -An -tx1 -j68 -N2 $@ | tr -d ' ')" = "6486" ] || { echo "PE Machine is not x86_64 (0x8664)"; rm -f $@; exit 1; }
	@echo "built $@ (commit $(AIENOS_COMMIT), fallback $(CK_NETLDR_FALLBACK_S) s)"
imac-netldr: $(NETLDR_EFI)
NETBOOT_TOOL := $(OUT)/host/ck_imac_netboot
NETBOOT_TOOL_SRCS := $(KDIR)/tools/ck_imac_netboot.c $(BOOT)/netboot_proto.c $(NATIVE)/net/aienos_net.c \
	$(NATIVE)/sig/sha512.c $(NATIVE)/sig/ed25519.c $(NATIVE)/sig/ct.c
$(NETBOOT_TOOL): $(NETBOOT_TOOL_SRCS) $(BOOT)/netboot_proto.h $(NATIVE)/net/aienos_net.h $(NATIVE)/sig/aienos_sig.h
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -I$(BOOT) -I$(NATIVE)/net -I$(NATIVE)/sig -o $@ $(NETBOOT_TOOL_SRCS)
# Apple NetBoot answerer (BSDP + one-file TFTP): the iMac starts NETLDR.EFI from the Spark with N held.
BSDP_TOOL := $(OUT)/host/ck_imac_bsdp
$(BSDP_TOOL): $(KDIR)/tools/ck_imac_bsdp.c
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -o $@ $<
imac-netboot-tool: $(NETBOOT_TOOL) $(BSDP_TOOL)

# Raspberry Pi 5 board image (see CK_PI5 above): target/native-kernel-pi5/BOOTAA64.EFI
pi5-store:
	$(MAKE) CK_PI5_STORE=1 full

# PI5-8 Q1: --remap-path-prefix keeps the build directory out of the Rust panic-location strings, so the three Pi images
# that link this library are byte-identical when built from different checkout paths (scripts/ck_pi5_repro_check.sh).
PI5_INFER_LIB := $(REPO)/target/infer-kernel/aarch64-unknown-none/release/libaienos_infer_kernel.a
pi5-infer:
	RUSTFLAGS="--remap-path-prefix=$(REPO)=/aienos" CARGO_TARGET_DIR=$(REPO)/target/infer-kernel cargo build -q --release --target aarch64-unknown-none --manifest-path $(REPO)/crates/aienos-infer-kernel/Cargo.toml
	$(MAKE) CK_PI5_INFER=1 CK_INFER_LIB=$(PI5_INFER_LIB) all
pi5-unlock:
	$(MAKE) CK_PI5_UNLOCK=1 full

pi5-unlock-card:
	$(MAKE) CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 full

pi5-fact:
	$(MAKE) CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_PI5_FACT=1 full

pi5-agent:
	RUSTFLAGS="--remap-path-prefix=$(REPO)=/aienos" CARGO_TARGET_DIR=$(REPO)/target/infer-kernel cargo build -q --release --target aarch64-unknown-none --manifest-path $(REPO)/crates/aienos-infer-kernel/Cargo.toml
	$(MAKE) CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_PI5_AGENT=1 CK_INFER_LIB=$(PI5_INFER_LIB) full

pi5-lifecycle:
	RUSTFLAGS="--remap-path-prefix=$(REPO)=/aienos" CARGO_TARGET_DIR=$(REPO)/target/infer-kernel cargo build -q --release --target aarch64-unknown-none --manifest-path $(REPO)/crates/aienos-infer-kernel/Cargo.toml
	$(MAKE) CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_PI5_LIFECYCLE=1 CK_INFER_LIB=$(PI5_INFER_LIB) full

pi5-artifact:
	$(MAKE) CK_PI5_ARTIFACT=1 all

pi5:
	$(MAKE) CK_PI5=1 all

# Raspberry Pi 5 PCIe/RP1 enumerator image (see CK_PI5_PCIE above): target/native-kernel-pi5-pcie/BOOTAA64.EFI
pi5-net:
	$(MAKE) CK_PI5_NET=1 all

pi5-pcie:
	$(MAKE) CK_PI5_PCIE=1 all

# ---- host checker for the AIENOS_CK_SCREEN gate (scripts/qemu_ck_screen_test.sh) ----
FB_CHECK_TOOL := $(OUT)/host/ck_fb_check
$(FB_CHECK_TOOL): $(KDIR)/tools/ck_fb_check.c $(KDIR)/core/fbcon.c $(KDIR)/core/fbcon.h $(KDIR)/core/font8x8.h
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -o $@ $(KDIR)/tools/ck_fb_check.c $(KDIR)/core/fbcon.c
fb-check: $(FB_CHECK_TOOL)

# ---- platform xHCI discovery over dumped firmware tables (NEXT-PHASE-3 cut 2) ----
# Runs the kernel scan (core/acpi_dev.c) and IORT lookup (core/acpi.c) over
# DSDT/SSDT/IORT files read under Linux and prints the lines the kernel
# fence prints (dev/xhci_acpi_fmt.h). Hosted; never part of an image.
ACPI_SCAN_TOOL := $(OUT)/host/ck_acpi_scan
$(ACPI_SCAN_TOOL): $(KDIR)/tools/ck_acpi_scan.c $(KDIR)/core/acpi_dev.c $(KDIR)/core/acpi.c \
	$(KDIR)/core/acpi_dev.h $(KDIR)/core/acpi.h $(KDIR)/dev/xhci_acpi_fmt.h
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -I$(KDIR)/core -I$(KDIR)/dev -I$(BOOT) -o $@ \
	  $(KDIR)/tools/ck_acpi_scan.c $(KDIR)/core/acpi_dev.c $(KDIR)/core/acpi.c
acpi-scan: $(ACPI_SCAN_TOOL)

# Owner provisioning generator (hosted; never part of an image) and the
# generated header for the hardware staging image.
OWNER_GEN := $(OUT)/host/ck_owner_gen
$(OWNER_GEN): $(KDIR)/tools/ck_owner_gen.c
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -o $@ $<
owner-gen: $(OWNER_GEN)
ifneq ($(OWNER_HDR),)
$(OWNER_HDR): $(OWNER_GEN) $(OWNER_PUBKEYS_FILE) $(OWNER_MACHINE_FILE)
	@mkdir -p $(dir $@)
	$(OWNER_GEN) $(OWNER_PUBKEYS_FILE) $(OWNER_MACHINE_FILE) $@
endif

clean:
	rm -rf $(OUT)

# AIENOS-PI5 RNG200 hardware entropy source: driver logic over a mocked register block, real core/entropy.c rules.
PI5_RNG_SRCS := $(KDIR)/dev/pi5_rng.c $(KDIR)/core/entropy.c
$(OUT)/host/test_pi5_rng: $(KDIR)/tests/test_pi5_rng.c $(PI5_RNG_SRCS) $(KDIR)/tests/ck_test.h $(KDIR)/dev/pi5_rng.h $(KDIR)/core/entropy.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -DCK_RNG200_SPINS=1000 -I$(KDIR)/dev -o $@ $< $(PI5_RNG_SRCS)
test-pi5-rng: $(OUT)/host/test_pi5_rng
	$<
$(OUT)/host-san/test_pi5_rng: $(KDIR)/tests/test_pi5_rng.c $(PI5_RNG_SRCS) $(KDIR)/tests/ck_test.h $(KDIR)/dev/pi5_rng.h $(KDIR)/core/entropy.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) -DCK_RNG200_SPINS=1000 -I$(KDIR)/dev -o $@ $< $(PI5_RNG_SRCS)

FORCE:
.PHONY: uefi-vars slot-loader slot-loader-check pi5-diag imac-diag imac-kernel imac-netldr imac-netboot-tool
.PHONY: artifact-tier-pi5 artifact-tier-mutant
.PHONY: osc-receipt-mutants osc-receipt-release all full pi5 pi5-store pi5-infer pi5-unlock pi5-unlock-card pi5-fact pi5-agent pi5-lifecycle pi5-artifact artifact-card-mutant test sanitize context-mutant agent-cmd-mutant cortex-image handoff-mutant acpi-dev-mutant iort-mutants smmu-l2-mutants acpi-scan clean print-kcflags udp-echo tool store-image gpt-image cont-tool owner-gen fb-check continuity-mutants continuity-resolve-mutants FORCE

# AIENOS-PI5 step 3 marker + Pi card GPT test (hosted; a file stands in for the card, QEMU cannot model the Pi SD host).
PI5_MARKER_SRCS := $(KDIR)/core/pi5_marker.c $(KDIR)/dev/disk_part.c $(NATIVE)/disk/disk.c $(NATIVE)/disk/disk_file.c \
	$(KDIR)/tools/gpt_write.c
$(OUT)/host/test_pi5_marker: $(KDIR)/tests/test_pi5_marker.c $(PI5_MARKER_SRCS) $(KDIR)/tests/ck_test.h $(KDIR)/core/pi5_marker.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -I$(KDIR)/dev -I$(KDIR)/tools -I$(NATIVE)/disk -o $@ $< $(PI5_MARKER_SRCS)
test-pi5-marker: $(OUT)/host/test_pi5_marker
	$<
$(OUT)/host-san/test_pi5_marker: $(KDIR)/tests/test_pi5_marker.c $(PI5_MARKER_SRCS) $(KDIR)/tests/ck_test.h $(KDIR)/core/pi5_marker.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) -I$(KDIR)/dev -I$(KDIR)/tools -I$(NATIVE)/disk -o $@ $< $(PI5_MARKER_SRCS)

# AIENOS-PI5 software-only DMA confinement (ADR 0020): host test only, not linked into any image.
DMAW_SRCS := $(KDIR)/dev/dma_window.c
DMAW_DEPS := $(KDIR)/tests/test_dma_window.c $(DMAW_SRCS) $(KDIR)/tests/ck_test.h $(KDIR)/dev/dma_window.h
$(OUT)/host/test_dma_window: $(DMAW_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -I$(KDIR)/dev -o $@ $< $(DMAW_SRCS)
$(OUT)/host-san/test_dma_window: $(DMAW_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) -I$(KDIR)/dev -o $@ $< $(DMAW_SRCS)
test-dma-window: $(OUT)/host/test_dma_window
	$<
# Each mutant removes one check; the test must FAIL for every one. (The explicit "addr below base" test is not a
# mutant: with unsigned arithmetic the end check already refuses it, so it is kept as defence in depth.)
DMAW_MUTANTS := NO_END WRAP NO_ZERO NO_LATCH NO_STALE NO_ALIGN NO_FRAMECAP NO_GOT NO_INDEX
dma-window-mutants:
	@mkdir -p $(OUT)/host
	@fail=0; for m in $(DMAW_MUTANTS); do \
	  $(HOSTCC) $(HCFLAGS) -DCK_DMAW_MUTANT_$$m -I$(KDIR)/dev -o $(OUT)/host/test_dma_window_mut_$$m $(KDIR)/tests/test_dma_window.c $(DMAW_SRCS) || exit 1; \
	  if $(OUT)/host/test_dma_window_mut_$$m >/dev/null; then echo "MUTANT SURVIVED: $$m"; fail=1; else echo "mutant killed: $$m"; fi; \
	done; test $$fail -eq 0
.PHONY: test-dma-window dma-window-mutants

# AIENOS-PI5 PCIe root complex / RP1 enumerator logic over a fake register file. Not the hardware.
PI5PCIE_SRCS := $(KDIR)/dev/pi5_pcie.c
PI5PCIE_DEPS := $(KDIR)/tests/test_pi5_pcie.c $(PI5PCIE_SRCS) $(KDIR)/tests/ck_test.h $(KDIR)/dev/pi5_pcie.h
$(OUT)/host/test_pi5_pcie: $(PI5PCIE_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -I$(KDIR)/dev -o $@ $< $(PI5PCIE_SRCS)
$(OUT)/host-san/test_pi5_pcie: $(PI5PCIE_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) -I$(KDIR)/dev -o $@ $< $(PI5PCIE_SRCS)
test-pi5-pcie: $(OUT)/host/test_pi5_pcie
	$<
# Each mutant removes one decision; the test must FAIL for every one.
PI5PCIE_MUTANTS := NO_OUTSIDE NO_FULLCOVER NO_REMAP NO_INDEX NO_ALIGN NO_MERGE
pi5-pcie-mutants:
	@mkdir -p $(OUT)/host
	@fail=0; for m in $(PI5PCIE_MUTANTS); do \
	  $(HOSTCC) $(HCFLAGS) -DCK_PCIE_MUTANT_$$m -I$(KDIR)/dev -o $(OUT)/host/test_pi5_pcie_mut_$$m $(KDIR)/tests/test_pi5_pcie.c $(PI5PCIE_SRCS) || exit 1; \
	  if $(OUT)/host/test_pi5_pcie_mut_$$m >/dev/null; then echo "MUTANT SURVIVED: $$m"; fail=1; else echo "mutant killed: $$m"; fi; \
	done; test $$fail -eq 0
.PHONY: test-pi5-pcie pi5-pcie-mutants pi5-pcie

# AIENOS-PI5 network cut 2 (inbound window plan, RP1 quiesce, clocks, PHY reset, MDIO, PHY ID) over fake registers.
PI5NET_SRCS := $(KDIR)/dev/pi5_net.c $(KDIR)/dev/pi5_pcie.c
PI5NET_DEPS := $(KDIR)/tests/test_pi5_net.c $(PI5NET_SRCS) $(KDIR)/tests/ck_test.h $(KDIR)/dev/pi5_net.h $(KDIR)/dev/pi5_pcie.h
$(OUT)/host/test_pi5_net: $(PI5NET_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -I$(KDIR)/dev -o $@ $< $(PI5NET_SRCS)
$(OUT)/host-san/test_pi5_net: $(PI5NET_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) -I$(KDIR)/dev -o $@ $< $(PI5NET_SRCS)
test-pi5-net: $(OUT)/host/test_pi5_net
	$<
# Each mutant removes one decision; the test must FAIL for every one.
PI5NET_MUTANTS := NO_STRADDLE NO_REMAP_EN NO_DISABLE_FIRST NO_READBACK NO_RESTORE NO_OTHERS NO_STATUS_MASK NO_QUIESCE_CHECK OB_NO_LIMIT NO_ASSERT NO_HOLD NO_RELEASE NO_HIGH_FIRST NO_IDLE_AFTER NO_MPE TOUCH_ON_CLOCK NO_EXACT_DIV NO_CLK_VERIFY OUI_ORDER BAD_CLASS NO_BOUNDS NO_MDC_DIV PARTIAL_ANY
pi5-net-mutants:
	@mkdir -p $(OUT)/host
	@fail=0; for m in $(PI5NET_MUTANTS); do \
	  $(HOSTCC) $(HCFLAGS) -DCK_NET_MUTANT_$$m -I$(KDIR)/dev -o $(OUT)/host/test_pi5_net_mut_$$m $(KDIR)/tests/test_pi5_net.c $(PI5NET_SRCS) || exit 1; \
	  if $(OUT)/host/test_pi5_net_mut_$$m >/dev/null; then echo "MUTANT SURVIVED: $$m"; fail=1; else echo "mutant killed: $$m"; fi; \
	done; test $$fail -eq 0
.PHONY: test-pi5-net pi5-net-mutants pi5-net

# AIENOS-PI5 network cut 3 (GEM descriptors, transfer order, bus-master window, PHY loopback) over a fake GEM that checks every DMA it makes.
PI5GEM_SRCS := $(KDIR)/dev/pi5_gem.c $(KDIR)/dev/pi5_net.c $(KDIR)/dev/pi5_pcie.c $(KDIR)/dev/dma_window.c
PI5GEM_DEPS := $(KDIR)/tests/test_pi5_gem.c $(PI5GEM_SRCS) $(KDIR)/tests/ck_test.h $(KDIR)/dev/pi5_gem.h $(KDIR)/dev/pi5_net.h $(KDIR)/dev/pi5_pcie.h $(KDIR)/dev/dma_window.h
$(OUT)/host/test_pi5_gem: $(PI5GEM_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -I$(KDIR)/dev -o $@ $< $(PI5GEM_SRCS)
$(OUT)/host-san/test_pi5_gem: $(PI5GEM_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) -I$(KDIR)/dev -o $@ $< $(PI5GEM_SRCS)
test-pi5-gem: $(OUT)/host/test_pi5_gem
	$<
# Each mutant removes one decision; the test must FAIL for every one.
PI5GEM_MUTANTS := NO_VALIDATE BME_EARLY BME_LEFT_ON NO_QUIESCE_WAIT NO_RETE_OFF NO_BARRIER NO_TIEOFF NO_RXLEN_CHECK NO_TX_LAST NO_SENTINEL_USED NO_ADDR64 NO_HWWIN NOT_STICKY NO_FRAMECAP NO_SEQ NO_DIFF MDIO_OP PHYLB_BIT NO_WRAP NO_GBE NO_DRFCS NO_BME_VERIFY NO_LLB_CLEAR
pi5-gem-mutants:
	@mkdir -p $(OUT)/host
	@fail=0; for m in $(PI5GEM_MUTANTS); do \
	  $(HOSTCC) $(HCFLAGS) -DCK_GEM_MUTANT_$$m -I$(KDIR)/dev -o $(OUT)/host/test_pi5_gem_mut_$$m $(KDIR)/tests/test_pi5_gem.c $(PI5GEM_SRCS) || exit 1; \
	  if $(OUT)/host/test_pi5_gem_mut_$$m >/dev/null; then echo "MUTANT SURVIVED: $$m"; fail=1; else echo "mutant killed: $$m"; fi; \
	done; test $$fail -eq 0
.PHONY: test-pi5-gem pi5-gem-mutants
