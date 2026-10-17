/* kmain_x86.c -- AIENOS-IMAC-KERNEL-0: the C kernel core on x86_64, first
 * cut, for the 2017 iMac (iMac18,3, Core i5-7500) and QEMU q35.
 *
 * After ExitBootServices (efi_x86.c) on the firmware's page tables:
 * interrupts off, own GDT + TSS (IST1 stack for #DF, NMI, #MC) and IDT (256
 * stubs, trap.S), the CHANDOF3 record checked (core/handoff_check.c), a frame
 * allocator over the memory map (mm/frames.c), own 4-level page tables that
 * identity map [0, top) with 2 MiB pages (RAM write-back, the rest uncached,
 * the GOP framebuffer write-combining through PAT entry 1) and a 4 KiB guard
 * page under the kernel stack, CR3 switched and the stack moved. W^X (#409):
 * EFER.NXE and CR0.WP on every core; only the kernel's code is executable
 * (read-only), every other leaf is no-execute, read-only data is read-only,
 * proven by probes and an audit of every leaf. Then: the
 * screen console (core/fbcon.c), heap (mm/heap.c), the guard page proven to
 * fault and the fault contained, the TSC measured against the HPET, the
 * local APIC (xAPIC) with its timer at 100 Hz for 20 ticks, the MADT CPU
 * count, the secondary cores started and parked (smp_x86.S), the AHCI and
 * NVMe disks read-only and a look at the Ethernet chip (pci_x86.c,
 * ahci_x86.c), and the final report. It holds the screen CK_X86_HOLD_S seconds and
 * powers off through ACPI S5 (FADT PM1 control + the DSDT's \_S5 package); the lab image
 * (CK_X86_REPORT=1) restarts through the FADT reset register instead, back
 * into its network loader (native/boot/net_loader.c).
 * Scheduling on the secondary cores, disk writes, the network driver and VT-d
 * are later cuts. No runtime service
 * is called. QEMU runs of this path qualify nothing physical. */
#include "../core/ck_internal.h"
#include "../core/handoff_check.h"
#include "../mm/frames.h"
#include "../mm/heap.h"
#include "x86.h"

#ifndef AIENOS_COMMIT
#define AIENOS_COMMIT "unknown"
#endif
#ifndef CK_X86_REPORT
#define CK_X86_REPORT 0 /* 1 only in the opt-in lab image: the network report */
#endif
#ifndef CK_X86_HOLD_S
#define CK_X86_HOLD_S 60u
#endif

#define SEL_CODE 0x08
#define SEL_DATA 0x10
#define SEL_TSS 0x18
#define VEC_TIMER 0x40
#define VEC_SPURIOUS 0xff
#define STACK_BYTES (64u << 10)
#define IST_BYTES (16u << 10)
#define HEAP_PAGES 256u /* 1 MiB */
#define MAP_TOP_MAX (512ull << 30) /* one PML4 entry */

#define PTE_P 0x1ull
#define PTE_W 0x2ull
#define PTE_PWT 0x8ull
#define PTE_PCD 0x10ull
#define PTE_PS 0x80ull
#define PTE_NX (1ull << 63)
#define PTE_ADDR 0x000ffffffffff000ull
#define MSR_EFER 0xc0000080u
#define EFER_NXE (1ull << 11)
#define CR0_WP (1ull << 16)

/* CK_X86_WX_MUTATE (negative test builds only): 1 leaves RAM executable,
 * 2 leaves the kernel's code writable. The W^X probes must then FAIL. */
#ifndef CK_X86_WX_MUTATE
#define CK_X86_WX_MUTATE 0
#endif

/* Image regions (image_x86_64.ld), runtime addresses after self-relocation. */
extern char __image_base[], __text_start[], __text_end[], __ro_start[], __ro_end[], __image_end[];

const char *ck_commit(void) { return AIENOS_COMMIT; }

static struct ck_handoff *hand;
static struct ck_frames frames;
static struct ck_heap heap;
static uint64_t tramp_pa; /* secondary-core trampoline page, below 1 MiB; 0 = none */

/* ---- descriptor tables ---- */
struct __attribute__((packed)) tss64 {
    uint32_t r0;
    uint64_t rsp[3];
    uint64_t r1;
    uint64_t ist[7];
    uint64_t r2;
    uint16_t r3, iomap;
};
_Static_assert(sizeof(struct tss64) == 104, "tss64 size");
struct __attribute__((packed)) dtr {
    uint16_t limit;
    uint64_t base;
};
struct idt_gate {
    uint16_t off0, sel;
    uint8_t ist, attr;
    uint16_t off1;
    uint32_t off2, zero;
};
_Static_assert(sizeof(struct idt_gate) == 16, "idt gate size");

static uint64_t gdt[5] __attribute__((aligned(16)));
static struct tss64 tss __attribute__((aligned(16)));
static struct idt_gate idt[256] __attribute__((aligned(16)));
static uint8_t ist_stack[IST_BYTES] __attribute__((aligned(16)));
/* First page: the guard, unmapped once the kernel's tables are live. */
static uint8_t kstack[4096 + STACK_BYTES] __attribute__((aligned(4096)));

static void tables_load(void)
{
    gdt[0] = 0;
    gdt[1] = 0x00209a0000000000ull; /* 64-bit code, DPL 0 */
    gdt[2] = 0x0000920000000000ull; /* data */
    uint64_t tb = (uint64_t)(uintptr_t)&tss, tl = sizeof tss - 1;
    gdt[3] = (tl & 0xffff) | (tb & 0xffffff) << 16 | 0x89ull << 40 | ((tl >> 16) & 0xf) << 48 |
             ((tb >> 24) & 0xff) << 56;
    gdt[4] = tb >> 32;
    tss.ist[0] = (uint64_t)(uintptr_t)(ist_stack + sizeof ist_stack);
    tss.iomap = sizeof tss;
    struct dtr g = {sizeof gdt - 1, (uint64_t)(uintptr_t)gdt};
    ck_x86_load_gdt(&g, SEL_CODE, SEL_DATA, SEL_TSS);

    for (unsigned v = 0; v < 256; v++) {
        uint64_t a = (uint64_t)(uintptr_t)ck_x86_isr_stubs + (uint64_t)v * CK_X86_ISR_STRIDE;
        idt[v].off0 = (uint16_t)a;
        idt[v].sel = SEL_CODE;
        idt[v].ist = (v == 2 || v == 8 || v == 18) ? 1 : 0;
        idt[v].attr = 0x8e; /* present, DPL 0, 64-bit interrupt gate */
        idt[v].off1 = (uint16_t)(a >> 16);
        idt[v].off2 = (uint32_t)(a >> 32);
        idt[v].zero = 0;
    }
    struct dtr i = {sizeof idt - 1, (uint64_t)(uintptr_t)idt};
    __asm__ volatile("lidt %0" ::"m"(i) : "memory");
}

/* ---- power ---- */
static uint64_t tsc_hz;

static void delay_ms(uint64_t ms)
{
    if (!tsc_hz)
        return;
    uint64_t t0 = ck_rdtsc(), n = tsc_hz / 1000 * ms;
    while (ck_rdtsc() - t0 < n)
        ck_pause();
}

/* \_S5 sleep types from the DSDT: "_S5_" PackageOp PkgLength NumElements
 * then two integers (ZeroOp, OneOp, OnesOp or BytePrefix n). */
static int s5_types(const uint8_t *dsdt, uint32_t len, unsigned *a, unsigned *b)
{
    for (uint32_t i = 36; i + 12 < len; i++) {
        if (memcmp(dsdt + i, "_S5_", 4) != 0 || dsdt[i + 4] != 0x12)
            continue;
        uint32_t p = i + 5;
        p += 1u + (dsdt[p] >> 6); /* PkgLength: lead byte + follow bytes */
        p++;                      /* NumElements */
        unsigned v[2];
        for (unsigned k = 0; k < 2; k++) {
            if (p >= len)
                return -1;
            uint8_t op = dsdt[p++];
            if (op == 0x00 || op == 0x01)
                v[k] = op;
            else if (op == 0xff)
                v[k] = 0x7;
            else if (op == 0x0a && p < len)
                v[k] = dsdt[p++] & 7u;
            else
                return -1;
        }
        *a = v[0];
        *b = v[1];
        return 0;
    }
    return -1;
}

static uint32_t rd32(const void *p, unsigned off)
{
    uint32_t v;
    memcpy(&v, (const uint8_t *)p + off, 4);
    return v;
}
static uint64_t rd64(const void *p, unsigned off)
{
    uint64_t v;
    memcpy(&v, (const uint8_t *)p + off, 8);
    return v;
}

static void acpi_poweroff(void)
{
    const uint8_t *fadt = hand && hand->rsdp ? ck_acpi_lookup(hand->rsdp, "FACP") : 0;
    if (!fadt) {
        ck_puts("power: no FADT\n");
        return;
    }
    uint32_t flen = rd32(fadt, 4);
    uint64_t dsdt = flen >= 148 ? rd64(fadt, 140) : 0;
    if (!dsdt)
        dsdt = rd32(fadt, 40);
    uint32_t pm1a = rd32(fadt, 64), pm1b = rd32(fadt, 68), smi = rd32(fadt, 48);
    uint8_t enable = fadt[52];
    unsigned ta, tb;
    if (!dsdt || s5_types((const uint8_t *)(uintptr_t)dsdt, rd32((const void *)(uintptr_t)dsdt, 4), &ta, &tb)) {
        ck_puts("power: no \\_S5 package in the DSDT\n");
        return;
    }
    if (!pm1a || pm1a > 0xffff) {
        ck_printf("power: PM1a control block 0x%x is not an I/O port\n", pm1a);
        return;
    }
    if (!(ck_inw((uint16_t)pm1a) & 1) && smi && enable) { /* SCI_EN clear: ACPI mode off */
        ck_outb((uint16_t)smi, enable);
        for (unsigned i = 0; i < 300 && !(ck_inw((uint16_t)pm1a) & 1); i++)
            delay_ms(10);
    }
    ck_printf("power: off via ACPI S5 pm1a=0x%x pm1b=0x%x slp_typ=%u/%u\n", pm1a, pm1b, ta, tb);
    ck_outw((uint16_t)pm1a, (uint16_t)(ta << 10 | 1u << 13));
    if (pm1b && pm1b <= 0xffff)
        ck_outw((uint16_t)pm1b, (uint16_t)(tb << 10 | 1u << 13));
    delay_ms(2000);
    ck_puts("power: still running after the S5 write\n");
}

#if CK_X86_REPORT
/* Lab image only: restart instead of powering off, so the iMac comes back to
 * its network loader (NETLDR.EFI) for the next test without a hand on the
 * power button. The FADT reset register (ACPI 6.5 section 4.8.3.6; on the
 * iMac18,3: flags bit 10 RESET_REG_SUP set, SystemIO port 0xCF9, value 0x06,
 * read from its FACP table on 2026-10-17); without one, the same write to the
 * PCH reset control port 0xCF9 that the FADT names. */
static void acpi_reset(void)
{
    const uint8_t *fadt = hand && hand->rsdp ? ck_acpi_lookup(hand->rsdp, "FACP") : 0;
    uint16_t port = 0xCF9;
    uint8_t value = 0x06;
    if (fadt && rd32(fadt, 4) >= 129 && (rd32(fadt, 112) & (1u << 10)) && fadt[116] == 1 /* SystemIO */ &&
        rd64(fadt, 120) && rd64(fadt, 120) <= 0xffff) {
        port = (uint16_t)rd64(fadt, 120);
        value = fadt[128];
        ck_printf("power: restart via the ACPI reset register port=0x%x value=0x%x\n", port, value);
    } else {
        ck_puts("power: restart via port 0xcf9 (no usable ACPI reset register)\n");
    }
    ck_outb(port, value);
    for (volatile uint64_t i = 0; i < 100000000ull; i++)
        __asm__ volatile("pause");
    ck_puts("power: still running after the reset write\n");
}
#endif

static __attribute__((noreturn)) void finish(void)
{
    ck_cli();
    if (!tsc_hz) { /* no clock yet: keep the screen readable, never power off unseen */
#if CK_X86_REPORT
        ck_puts("power: no clock measured; lab image restarts\n");
        acpi_reset();
#endif
        ck_puts("power: halted before the clock was measured; hold the power button to turn the machine off\n");
        for (;;)
            __asm__ volatile("hlt");
    }
    if (CK_X86_HOLD_S) {
#if CK_X86_REPORT
        /* Lab build only (make imac-kernel CK_X86_REPORT=1): sends the
         * allowlisted, unauthenticated report if the network is up. */
        ck_printf("power: holding the screen %u s, then restart\n", (unsigned)CK_X86_HOLD_S);
        ck_x86_report_hold(tsc_hz, CK_X86_HOLD_S);
#else
        /* Default and resident builds: no report code is linked; nothing is sent. */
        ck_printf("power: holding the screen %u s, then ACPI S5\n", (unsigned)CK_X86_HOLD_S);
        delay_ms((uint64_t)CK_X86_HOLD_S * 1000u);
#endif
    }
#if CK_X86_REPORT
    acpi_reset();
#endif
    acpi_poweroff();
    ck_puts("power: halted; hold the power button to turn the machine off\n");
    for (;;)
        __asm__ volatile("hlt");
}

void ck_panic(const char *fmt, ...)
{
    ck_cli();
    va_list ap;
    va_start(ap, fmt);
    ck_puts("panic: ");
    ck_vprintf(fmt, ap);
    va_end(ap);
    ck_puts("\n");
    finish();
}

/* ---- traps ---- */
static struct {
    volatile int armed, hit;
    volatile uint64_t resume, cr2, err;
} probe;
static volatile uint64_t ticks, tick_tsc[32];
static volatile uint64_t stray_irqs;
static volatile uint32_t *xapic;

static const char *const exc_name[32] = {
    "#DE", "#DB", "NMI", "#BP", "#OF", "#BR", "#UD", "#NM", "#DF", "?", "#TS", "#NP", "#SS", "#GP", "#PF", "?",
    "#MF", "#AC", "#MC", "#XM", "#VE", "#CP", "?", "?", "?", "?", "?", "?", "#HV", "#VC", "#SX", "?"};

/* The local APIC in xAPIC mode (MMIO, 4 KiB at IA32_APIC_BASE): the mode
 * the iMac's firmware leaves it in and the one QEMU TCG emulates. x2APIC
 * (MSR access) waits for a test that can run it. */
static void apic_wr(unsigned reg, uint32_t v)
{
    xapic[reg / 4] = v;
}
static uint32_t apic_rd(unsigned reg)
{
    return xapic[reg / 4];
}
#define APIC_ID 0x20
#define APIC_VER 0x30
#define APIC_TPR 0x80
#define APIC_EOI 0xb0
#define APIC_SVR 0xf0
#define APIC_LVT_TIMER 0x320
#define APIC_TIMER_INIT 0x380
#define APIC_TIMER_CUR 0x390
#define APIC_TIMER_DIV 0x3e0

void ck_x86_trap(struct ck_x86_frame *f)
{
    if (f->vector == 14 && probe.armed) {
        probe.armed = 0;
        probe.hit = 1;
        probe.cr2 = ck_rd_cr2();
        probe.err = f->error;
        f->rip = probe.resume;
        return;
    }
    if (f->vector == VEC_TIMER) {
        uint64_t n = ticks;
        if (n < 32)
            tick_tsc[n] = ck_rdtsc();
        ticks = n + 1;
        apic_wr(APIC_EOI, 0);
        return;
    }
    if (f->vector == VEC_SPURIOUS)
        return;
    if (f->vector >= 32) {
        stray_irqs++;
        if (xapic)
            apic_wr(APIC_EOI, 0);
        return;
    }
    ck_panic("exception: vector %llu %s error=0x%llx rip=0x%llx rsp=0x%llx cr2=0x%llx rflags=0x%llx",
             (unsigned long long)f->vector, exc_name[f->vector], (unsigned long long)f->error,
             (unsigned long long)f->rip, (unsigned long long)f->rsp, (unsigned long long)ck_rd_cr2(),
             (unsigned long long)f->rflags);
}

/* ---- memory ---- */
struct mm {
    uint64_t root, top, pages_wb, pages_wc, pages_uc, pt_frames, fb_lo, fb_hi, pages_4k;
    int fb_ok;
};
static struct mm mm;

static uint64_t *table_new(void)
{
    uint64_t pa;
    if (ck_frames_alloc(&frames, 1, CK_PAGE, &pa))
        ck_panic("paging: out of frames for page tables");
    mm.pt_frames++;
    memset((void *)(uintptr_t)pa, 0, CK_PAGE);
    return (uint64_t *)(uintptr_t)pa;
}

/* EFI types that are RAM (write-back): everything but reserved (0), unusable
 * (8), MMIO (11, 12) and persistent memory left to later cuts. */
static int efi_ram(uint32_t type)
{
    return type <= 10 && type != 0 && type != 8;
}

static uint64_t *pds[MAP_TOP_MAX >> 30];

static int in(uint64_t p, const char *lo, const char *hi)
{
    return p >= (uint64_t)(uintptr_t)lo && p < (uint64_t)(uintptr_t)hi;
}

/* The permission of one 4 KiB page inside a split 2 MiB page: the stack
 * guard unmapped, code read-only executable, the PE header and read-only data
 * read-only no-execute, the trampoline writable executable until
 * wx_retire_trampoline(), everything else writable no-execute. */
static uint64_t leaf4k(uint64_t p, uint64_t cache, uint64_t nx)
{
    if (p == (uint64_t)(uintptr_t)kstack)
        return 0;
    if (in(p, __text_start, __text_end))
        return p | PTE_P | cache | (CK_X86_WX_MUTATE == 2 ? PTE_W : 0);
    if (in(p, __image_base, __text_start) || in(p, __ro_start, __ro_end))
        return p | PTE_P | cache | nx;
    if (tramp_pa && p == tramp_pa)
        return p | PTE_P | PTE_W | cache;
    return p | PTE_P | PTE_W | cache | nx;
}

static void split_2m(uint64_t a, uint64_t nx)
{
    uint64_t *e = &pds[a >> 30][(a >> 21) & 511];
    if (!(*e & PTE_PS))
        return; /* already split */
    uint64_t cache = *e & (PTE_PCD | PTE_PWT), *pt = table_new();
    for (uint64_t j = 0; j < 512; j++)
        pt[j] = leaf4k(a | j << 12, cache, nx);
    *e = (uint64_t)(uintptr_t)pt | PTE_P | PTE_W;
    mm.pages_4k += 512;
}

/* The 4 KiB PTE mapping `a`, or 0 when `a` sits in a 2 MiB page. */
static uint64_t *pte4k(uint64_t a)
{
    uint64_t e = pds[a >> 30][(a >> 21) & 511];
    if (!(e & PTE_P) || (e & PTE_PS))
        return 0;
    return (uint64_t *)(uintptr_t)(e & PTE_ADDR) + ((a >> 12) & 511);
}

/* The secondary cores are up (or will never start): the trampoline page
 * becomes read-only no-execute data. */
static void wx_retire_trampoline(void)
{
    uint64_t *e = tramp_pa ? pte4k(tramp_pa) : 0;
    if (!e)
        return;
    *e = (*e & ~PTE_W) | (CK_X86_WX_MUTATE == 1 ? 0 : PTE_NX);
    __asm__ volatile("invlpg (%0)" ::"r"(tramp_pa) : "memory");
}

/* Every present leaf of the identity map: writable+executable ones, and
 * executable 4 KiB units (must equal the code pages). */
static void wx_audit(uint64_t *wx, uint64_t *exec4k)
{
    *wx = *exec4k = 0;
    for (uint64_t g = 0; g < mm.top >> 30; g++)
        for (uint64_t i = 0; i < 512; i++) {
            uint64_t e = pds[g][i];
            if (!(e & PTE_P))
                continue;
            if (e & PTE_PS) {
                if (!(e & PTE_NX)) {
                    *exec4k += 512;
                    *wx += !!(e & PTE_W);
                }
                continue;
            }
            const uint64_t *pt = (const uint64_t *)(uintptr_t)(e & PTE_ADDR);
            for (uint64_t j = 0; j < 512; j++)
                if ((pt[j] & PTE_P) && !(pt[j] & PTE_NX)) {
                    (*exec4k)++;
                    *wx += !!(pt[j] & PTE_W);
                }
        }
}

static void mm_build(void)
{
    const struct ck_handoff *h = hand;
    ck_frames_init(&frames);
    if (ck_frames_from_efi(&frames, (const void *)(uintptr_t)h->memory_map, h->map_size, h->desc_size) < 0)
        ck_panic("memory: bad UEFI memory map");
    /* Page 0 stays out: a null pointer must never be a usable frame. */
    ck_frames_reserve(&frames, 0, CK_PAGE);
    /* The secondary-core trampoline needs a page below 1 MiB; take the
     * lowest free page before anything else does. */
    if (ck_frames_alloc(&frames, 1, CK_PAGE, &tramp_pa) || tramp_pa >= 0x100000)
        tramp_pa = 0;

    uint64_t top = 4ull << 30;
    for (uint64_t off = 0; off + h->desc_size <= h->map_size; off += h->desc_size) {
        const struct ck_efi_desc *d = (const void *)(uintptr_t)(h->memory_map + off);
        uint64_t end = d->phys + d->pages * CK_PAGE;
        if (end > top)
            top = end;
    }
    top = (top + (1ull << 30) - 1) & ~((1ull << 30) - 1);
    if (top > MAP_TOP_MAX)
        top = MAP_TOP_MAX;
    mm.top = top;

    /* Framebuffer: write-combining 2 MiB pages, unless one overlaps RAM. */
    if (h->fb_status == CK_HANDOFF_FB_PRESENT) {
        mm.fb_lo = h->fb_base & ~((2ull << 20) - 1);
        mm.fb_hi = (h->fb_base + h->fb_size + (2ull << 20) - 1) & ~((2ull << 20) - 1);
        mm.fb_ok = mm.fb_hi <= top;
        for (uint64_t off = 0; mm.fb_ok && off + h->desc_size <= h->map_size; off += h->desc_size) {
            const struct ck_efi_desc *d = (const void *)(uintptr_t)(h->memory_map + off);
            uint64_t lo = d->phys, hi = d->phys + d->pages * CK_PAGE;
            if (efi_ram(d->type) && lo < mm.fb_hi && hi > mm.fb_lo)
                mm.fb_ok = 0;
        }
    }

    /* Every 2 MiB page starts uncached (PCD|PWT, PAT index 3): device memory
     * (local APIC, I/O APIC, HPET, PCI BARs) whatever the MTRRs say. Pages
     * that hold RAM from the memory map become write-back (index 0), the
     * framebuffer write-combining (PWT alone, index 1, set to WC below).
     * W^X (#409): every leaf is no-execute except the kernel's code (and the
     * secondary-core trampoline while the cores start); the 2 MiB pages that
     * hold the image or the trampoline are split into 4 KiB pages below.
     * W^X separates code from data inside one privilege level; it is not
     * process isolation. Learned or generated code must never run here. */
    if (ck_rd_cr4() & (1ull << 12))
        ck_panic("paging: firmware runs 5-level paging (CR4.LA57); this kernel builds 4-level tables");
    uint32_t xr[4];
    ck_cpuid(0x80000000, 0, xr);
    if (xr[0] < 0x80000001)
        ck_panic("paging: CPU has no extended CPUID leaf for NX");
    ck_cpuid(0x80000001, 0, xr);
    if (!(xr[3] & (1u << 20)))
        ck_panic("paging: CPU has no NX (execute disable)");
    uint64_t nx = CK_X86_WX_MUTATE == 1 ? 0 : PTE_NX;
    uint64_t *pml4 = table_new(), *pdpt = table_new();
    pml4[0] = (uint64_t)(uintptr_t)pdpt | PTE_P | PTE_W;
    for (uint64_t g = 0; g < top >> 30; g++) {
        uint64_t *pd = pds[g] = table_new();
        pdpt[g] = (uint64_t)(uintptr_t)pd | PTE_P | PTE_W;
        for (uint64_t i = 0; i < 512; i++)
            pd[i] = (g << 30 | i << 21) | PTE_P | PTE_W | PTE_PS | PTE_PCD | PTE_PWT | nx;
    }
    for (uint64_t off = 0; off + h->desc_size <= h->map_size; off += h->desc_size) {
        const struct ck_efi_desc *d = (const void *)(uintptr_t)(h->memory_map + off);
        if (!efi_ram(d->type))
            continue;
        uint64_t hi = d->phys + d->pages * CK_PAGE;
        for (uint64_t a = d->phys & ~((2ull << 20) - 1); a < hi && a < top; a += 2ull << 20) {
            uint64_t *e = &pds[a >> 30][(a >> 21) & 511];
            if (*e & PTE_PS)
                *e &= ~(PTE_PCD | PTE_PWT);
        }
    }
    for (uint64_t a = mm.fb_lo; mm.fb_ok && a < mm.fb_hi; a += 2ull << 20) {
        uint64_t *e = &pds[a >> 30][(a >> 21) & 511];
        if (*e & PTE_PS)
            *e = (*e & ~PTE_PCD) | PTE_PWT;
    }
    /* 4 KiB pages where the image and the trampoline live, keeping the
     * 2 MiB page's cache type (PCD/PWT sit at the same bits in a 4 KiB PTE). */
    uint64_t img_lo = (uint64_t)(uintptr_t)__image_base, img_hi = (uint64_t)(uintptr_t)__image_end;
    for (uint64_t a = img_lo & ~((2ull << 20) - 1); a < img_hi; a += 2ull << 20)
        split_2m(a, nx);
    if (tramp_pa)
        split_2m(tramp_pa & ~((2ull << 20) - 1), nx);
    for (uint64_t g = 0; g < top >> 30; g++)
        for (uint64_t i = 0; i < 512; i++) {
            uint64_t e = pds[g][i];
            if (!(e & PTE_PS))
                continue;
            if (e & PTE_PCD)
                mm.pages_uc++;
            else if (e & PTE_PWT)
                mm.pages_wc++;
            else
                mm.pages_wb++;
        }
    mm.root = (uint64_t)(uintptr_t)pml4;

    /* IA32_PAT: the power-on value with entry 1 (PWT) changed from WT to WC. */
    uint32_t r[4];
    ck_cpuid(1, 0, r);
    if (!(r[3] & (1u << 16)))
        ck_panic("paging: CPU has no PAT");
    __asm__ volatile("wbinvd" ::: "memory");
    ck_wrmsr(0x277, 0x0007040600070106ull);
    /* NX bits are reserved (a #PF on every access) until EFER.NXE is set. */
    ck_wrmsr(MSR_EFER, ck_rdmsr(MSR_EFER) | EFER_NXE);
    ck_wr_cr3(mm.root);
    uint64_t cr0;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    __asm__ volatile("mov %0, %%cr0" ::"r"(cr0 | CR0_WP) : "memory"); /* read-only binds the kernel too */
    /* Toggling CR4.PGE drops global TLB entries the firmware's tables left. */
    uint64_t cr4 = ck_rd_cr4();
    if (cr4 & 0x80) {
        __asm__ volatile("mov %0, %%cr4" ::"r"(cr4 & ~0x80ull) : "memory");
        __asm__ volatile("mov %0, %%cr4" ::"r"(cr4) : "memory");
    }
    __asm__ volatile("wbinvd" ::: "memory");
}

/* Device registers above the identity-mapped range (a 64-bit BAR the firmware
 * placed high, as OVMF does with NVMe): 2 MiB uncached pages added to the live
 * tables on demand. 0 ok, -1 refused (wraps or beyond 46 address bits). */
static uint64_t *sub_table(uint64_t *t, unsigned i)
{
    if (!(t[i] & PTE_P))
        t[i] = (uint64_t)(uintptr_t)table_new() | PTE_P | PTE_W;
    return (uint64_t *)(uintptr_t)(t[i] & PTE_ADDR);
}

int ck_x86_map_mmio(uint64_t pa, uint64_t len)
{
    if (!len || pa + len < pa || pa + len > (1ull << 46))
        return -1;
    uint64_t *pml4 = (uint64_t *)(uintptr_t)mm.root;
    for (uint64_t a = pa & ~((2ull << 20) - 1); a < pa + len; a += 2ull << 20) {
        if (a < mm.top)
            continue;
        uint64_t *pd = sub_table(sub_table(pml4, (unsigned)(a >> 39) & 511), (unsigned)(a >> 30) & 511);
        uint64_t *e = &pd[(a >> 21) & 511];
        if (!(*e & PTE_P)) {
            *e = a | PTE_P | PTE_W | PTE_PS | PTE_PCD | PTE_PWT | PTE_NX;
            mm.pages_uc++;
        }
        __asm__ volatile("invlpg (%0)" ::"r"(a) : "memory");
    }
    return 0;
}

/* ---- time ---- */
static const char *timebase = "none";
static uint64_t hpet_period_fs;

static void tsc_measure(void)
{
    const uint8_t *t = ck_acpi_lookup(hand->rsdp, "HPET");
    if (t && rd32(t, 4) >= 56 && t[40] == 0) {
        volatile uint64_t *hp = (volatile uint64_t *)(uintptr_t)rd64(t, 44);
        uint64_t period = hp[0] >> 32; /* GCAP_ID: counter period in fs */
        if (period && period <= 100000000ull) {
            hp[2] |= 1; /* GEN_CONF.ENABLE_CNF */
            uint64_t want = 50000000000000ull / period; /* 50 ms in HPET ticks */
            /* Bounded by 2^34 TSC ticks (about 5 s at 3.4 GHz): an HPET that
             * does not count falls through to CPUID instead of hanging. */
            uint64_t c0 = hp[30], s0 = ck_rdtsc(), c1;
            do
                c1 = hp[30];
            while (c1 - c0 < want && ck_rdtsc() - s0 < (1ull << 34));
            if (c1 - c0 < want)
                goto no_hpet;
            uint64_t s1 = ck_rdtsc(), ns = (c1 - c0) * period / 1000000ull;
            if (ns) {
                tsc_hz = (s1 - s0) * 1000000000ull / ns;
                hpet_period_fs = period;
                timebase = "hpet";
                return;
            }
        }
    }
no_hpet:;
    uint32_t r[4];
    ck_cpuid(0, 0, r);
    if (r[0] >= 0x16) {
        ck_cpuid(0x16, 0, r);
        if (r[0]) {
            tsc_hz = (uint64_t)r[0] * 1000000ull;
            timebase = "cpuid16";
        }
    }
}

/* ---- interrupts ---- */
struct apic_report {
    uint32_t id, version, lapic_hz, cpus, ioapics, ioapic_lines;
    uint64_t ticks, ms, min_us, max_us, avg_us;
};

static void ioapic_mask_all(uint64_t base, uint32_t *lines)
{
    volatile uint32_t *io = (volatile uint32_t *)(uintptr_t)base;
    io[0] = 1;
    uint32_t n = ((io[4] >> 16) & 0xff) + 1;
    for (uint32_t i = 0; i < n; i++) {
        io[0] = 0x10 + 2 * i;
        io[4] |= 1u << 16;
    }
    *lines += n;
}

static void madt_walk(struct apic_report *ar)
{
    const uint8_t *m = ck_acpi_lookup(hand->rsdp, "APIC");
    if (!m)
        ck_panic("madt: no ACPI MADT");
    uint32_t len = rd32(m, 4);
    for (uint32_t off = 44; off + 2 <= len;) {
        uint8_t type = m[off], el = m[off + 1];
        if (el < 2 || off + el > len)
            ck_panic("madt: bad entry at %u", off);
        if (type == 0 && el >= 8 && (rd32(m, off + 4) & 3))
            ar->cpus++;
        else if (type == 9 && el >= 16 && (rd32(m, off + 8) & 3))
            ar->cpus++;
        else if (type == 1 && el >= 12) {
            ar->ioapics++;
            ioapic_mask_all(rd32(m, off + 4), &ar->ioapic_lines);
        }
        off += el;
    }
}

static void apic_start(struct apic_report *ar)
{
    /* Legacy 8259 PICs: every line masked. */
    ck_outb(0x21, 0xff);
    ck_outb(0xa1, 0xff);
    uint64_t base = ck_rdmsr(0x1b);
    if (base & 1u << 10) /* x2APIC on: leaving it needs a pass through disabled */
        ck_wrmsr(0x1b, base & ~(3ull << 10));
    ck_wrmsr(0x1b, (base & ~(1ull << 10)) | 1u << 11);
    xapic = (volatile uint32_t *)(uintptr_t)(base & 0xffffff000ull);
    ar->id = apic_rd(APIC_ID) >> 24;
    ar->version = apic_rd(APIC_VER);
    apic_wr(APIC_TPR, 0);
    apic_wr(APIC_SVR, 0x100 | VEC_SPURIOUS);

    /* LAPIC timer rate: divide by 16, one shot, 10 ms of TSC. */
    apic_wr(APIC_TIMER_DIV, 0x3);
    apic_wr(APIC_LVT_TIMER, 1u << 16 | VEC_TIMER);
    apic_wr(APIC_TIMER_INIT, 0xffffffffu);
    delay_ms(10);
    uint32_t left = apic_rd(APIC_TIMER_CUR);
    apic_wr(APIC_TIMER_INIT, 0);
    ar->lapic_hz = (0xffffffffu - left) * 100u;
    if (!ar->lapic_hz)
        ck_panic("apic: timer did not count");

    /* 100 Hz periodic for 20 ticks, bounded by 1 s. */
    ticks = 0;
    apic_wr(APIC_LVT_TIMER, 1u << 17 | VEC_TIMER);
    apic_wr(APIC_TIMER_INIT, ar->lapic_hz / 100u);
    uint64_t t0 = ck_rdtsc();
    ck_sti();
    while (ticks < 21 && ck_rdtsc() - t0 < tsc_hz)
        ck_pause(); /* not hlt: a timer that never fires must not hang the boot */
    ck_cli();
    apic_wr(APIC_LVT_TIMER, 1u << 16 | VEC_TIMER);
    apic_wr(APIC_TIMER_INIT, 0);
    uint64_t n = ticks < 21 ? ticks : 21;
    ar->ticks = n ? n - 1 : 0; /* intervals between the first and the last tick seen */
    ar->min_us = ~0ull;
    for (uint64_t i = 1; i < n; i++) {
        uint64_t us = (tick_tsc[i] - tick_tsc[i - 1]) * 1000000ull / tsc_hz;
        if (us < ar->min_us)
            ar->min_us = us;
        if (us > ar->max_us)
            ar->max_us = us;
    }
    if (ar->ticks) {
        uint64_t span = (tick_tsc[n - 1] - tick_tsc[0]) * 1000000ull / tsc_hz;
        ar->avg_us = span / ar->ticks;
        ar->ms = span / 1000;
    } else {
        ar->min_us = 0;
    }
}

/* ---- secondary cores ----
 * Each enabled local APIC the MADT lists (other than this core's) gets INIT,
 * SIPI, SIPI pointing at the trampoline (smp_x86.S). A started core loads the
 * kernel's GDT (no task register) and IDT, sets the same PAT, enables its
 * local APIC, records its APIC ID, checks in, and halts with interrupts off.
 * Nothing is scheduled on it yet. */
#define SMP_MAX 16u
#define AP_STACK_PAGES 4u
#define APIC_ICR_LO 0x300
#define APIC_ICR_HI 0x310
#define PAT_VALUE 0x0007040600070106ull

struct smp_report {
    unsigned listed, started, failed;
    uint32_t ids[SMP_MAX], up_ids[SMP_MAX];
    const char *why;
};
static volatile uint32_t ap_up, ap_ids[SMP_MAX];

static void delay_us(uint64_t us)
{
    uint64_t t0 = ck_rdtsc(), n = tsc_hz / 1000000 * us;
    while (ck_rdtsc() - t0 < n)
        ck_pause();
}

static void ap_entry(void *arg)
{
    uint64_t idx = (uint64_t)(uintptr_t)arg;
    struct dtr g = {sizeof gdt - 1, (uint64_t)(uintptr_t)gdt};
    ck_x86_load_gdt(&g, SEL_CODE, SEL_DATA, 0);
    struct dtr i = {sizeof idt - 1, (uint64_t)(uintptr_t)idt};
    __asm__ volatile("lidt %0" ::"m"(i) : "memory");
    ck_wrmsr(0x277, PAT_VALUE);
    uint64_t base = ck_rdmsr(0x1b);
    if (base & 1u << 10)
        ck_wrmsr(0x1b, base & ~(3ull << 10));
    ck_wrmsr(0x1b, (base & ~(1ull << 10)) | 1u << 11);
    apic_wr(APIC_TPR, 0);
    apic_wr(APIC_SVR, 0x100 | VEC_SPURIOUS);
    ap_ids[idx] = apic_rd(APIC_ID) >> 24;
    __atomic_fetch_add(&ap_up, 1, __ATOMIC_SEQ_CST);
    for (;;)
        __asm__ volatile("cli; hlt");
}

static int icr_send(uint32_t id, uint32_t lo)
{
    apic_wr(APIC_ICR_HI, id << 24);
    apic_wr(APIC_ICR_LO, lo);
    for (unsigned n = 0; n < 1000; n++) {
        if (!(apic_rd(APIC_ICR_LO) & 1u << 12))
            return 0;
        delay_us(1);
    }
    return -1;
}

static void tramp_put32(const char *sym, uint32_t v)
{
    uint64_t off = (uint64_t)(uintptr_t)(sym - ck_x86_tramp_start);
    memcpy((uint8_t *)(uintptr_t)tramp_pa + off, &v, 4);
}
static void tramp_put64(const char *sym, uint64_t v)
{
    uint64_t off = (uint64_t)(uintptr_t)(sym - ck_x86_tramp_start);
    memcpy((uint8_t *)(uintptr_t)tramp_pa + off, &v, 8);
}
static uint32_t tramp_at(const char *sym)
{
    return (uint32_t)(tramp_pa + (uint64_t)(uintptr_t)(sym - ck_x86_tramp_start));
}

static void smp_start(const struct apic_report *ar, struct smp_report *sr)
{
    const uint8_t *m = ck_acpi_lookup(hand->rsdp, "APIC");
    uint32_t len = rd32(m, 4);
    for (uint32_t off = 44; off + 2 <= len; off += m[off + 1])
        if (m[off] == 0 && m[off + 1] >= 8 && (rd32(m, off + 4) & 3) && sr->listed < SMP_MAX)
            sr->ids[sr->listed++] = m[off + 3];
    uint64_t size = (uint64_t)(uintptr_t)(ck_x86_tramp_end - ck_x86_tramp_start);
    if (!tramp_pa)
        sr->why = "no free page below 1 MiB";
    else if (mm.root >= (1ull << 32))
        sr->why = "page tables above 4 GiB";
    else if (size > CK_PAGE)
        sr->why = "trampoline larger than a page";
    if (sr->why)
        return;
    memcpy((void *)(uintptr_t)tramp_pa, ck_x86_tramp_start, size);
    tramp_put32(ck_x86_tramp_gdtr + 2, tramp_at(ck_x86_tramp_gdt));
    tramp_put32(ck_x86_tramp_far32, tramp_at(ck_x86_tramp_pm32));
    tramp_put32(ck_x86_tramp_far64, tramp_at(ck_x86_tramp_lm64));
    tramp_put32(ck_x86_tramp_cr3, (uint32_t)mm.root);
    tramp_put64(ck_x86_tramp_entry, (uint64_t)(uintptr_t)ap_entry);
    for (unsigned k = 0; k < sr->listed; k++) {
        uint32_t id = sr->ids[k];
        if (id == ar->id)
            continue;
        uint64_t st;
        if (ck_frames_alloc(&frames, AP_STACK_PAGES, CK_PAGE, &st)) {
            sr->failed++;
            continue;
        }
        unsigned before = ap_up;
        tramp_put64(ck_x86_tramp_stack, st + AP_STACK_PAGES * CK_PAGE);
        tramp_put64(ck_x86_tramp_arg, before);
        __asm__ volatile("mfence" ::: "memory");
        int bad = icr_send(id, 0x4500); /* INIT, assert */
        delay_ms(10);
        for (unsigned s = 0; s < 2 && ap_up == before; s++) {
            bad |= icr_send(id, 0x4600 | (uint32_t)(tramp_pa >> 12)); /* start-up */
            delay_us(200);
        }
        uint64_t t0 = ck_rdtsc();
        while (ap_up == before && ck_rdtsc() - t0 < tsc_hz / 10)
            ck_pause();
        if (ap_up != before && !bad)
            sr->up_ids[sr->started++] = ap_ids[before];
        else
            sr->failed++;
        if (ap_up > before + 1)
            break; /* a core checked in twice or out of turn: stop starting more */
    }
}

/* ---- W^X probes (#409) ----
 * Each probe arms the #PF catcher (ck_x86_trap), touches one address and
 * resumes at the label after the access. A store writes back the byte it
 * read, so a mutated (writable) build changes nothing. An execute probe
 * jumps to two bytes `jmp *%rax` with rax = the resume label, so code that
 * does run comes straight back and the probe sees no fault. */
static int probe_store(uint64_t a)
{
    probe.hit = 0;
    probe.armed = 1;
    __asm__ volatile("lea 1f(%%rip), %%rax\n\t"
                     "mov %%rax, %0\n\t"
                     "movb (%1), %%cl\n\t"
                     "movb %%cl, (%1)\n"
                     "1:"
                     : "=m"(probe.resume)
                     : "r"(a)
                     : "rax", "rcx", "memory");
    probe.armed = 0;
    return probe.hit && probe.cr2 == a && (probe.err & 3) == 3; /* present + write */
}

static int probe_exec(uint8_t *buf)
{
    buf[0] = 0xff; /* jmp *%rax */
    buf[1] = 0xe0;
    uint64_t a = (uint64_t)(uintptr_t)buf;
    probe.hit = 0;
    probe.armed = 1;
    __asm__ volatile("lea 1f(%%rip), %%rax\n\t"
                     "mov %%rax, %0\n\t"
                     "jmp *%1\n"
                     "1:"
                     : "=m"(probe.resume)
                     : "r"(a)
                     : "rax", "memory");
    probe.armed = 0;
    return probe.hit && probe.cr2 == a && (probe.err & 0x11) == 0x11; /* present + instruction fetch */
}

static void wx_probes(void)
{
    uint64_t efer = ck_rdmsr(MSR_EFER), cr0;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    uint8_t *hb = ck_heap_alloc(&heap, 16);
    volatile uint8_t sb[16];
    if (!hb)
        ck_panic("wx: no heap for the execute probe");
    int tw = probe_store((uint64_t)(uintptr_t)__text_start);
    int rw = probe_store((uint64_t)(uintptr_t)__ro_start);
    int hx = probe_exec(hb);
    int sx = probe_exec((uint8_t *)sb);
    ck_heap_free(&heap, hb);
    const char *f = "fault", *n = "ALLOWED";
    if (!(efer & EFER_NXE) || !(cr0 & CR0_WP) || !tw || !rw || !hx || !sx)
        ck_panic("wx: FAIL nx=%s wp=%s text_write=%s ro_write=%s heap_exec=%s stack_exec=%s",
                 efer & EFER_NXE ? "on" : "off", cr0 & CR0_WP ? "on" : "off", tw ? f : n, rw ? f : n,
                 hx ? f : n, sx ? f : n);
    ck_puts("wx: ok nx=on wp=on text=rx ro=r data=rw-nx text_write=fault ro_write=fault heap_exec=fault "
            "stack_exec=fault\n");
}

/* ---- the kernel ---- */
static void cpu_line(void)
{
    uint32_t r[4];
    char vendor[13], brand[49];
    ck_cpuid(0, 0, r);
    memcpy(vendor, &r[1], 4);
    memcpy(vendor + 4, &r[3], 4);
    memcpy(vendor + 8, &r[2], 4);
    vendor[12] = 0;
    brand[0] = 0;
    ck_cpuid(0x80000000, 0, r);
    if (r[0] >= 0x80000004) {
        for (uint32_t i = 0; i < 3; i++) {
            ck_cpuid(0x80000002 + i, 0, r);
            memcpy(brand + 16 * i, r, 16);
        }
        brand[48] = 0;
    }
    const char *b = brand;
    while (*b == ' ')
        b++;
    ck_printf("cpu: %s %s\n", vendor, b);
}

static __attribute__((noreturn)) void kernel_main(void *arg)
{
    (void)arg;
    const struct ck_handoff *h = hand;
    if (h->fb_status == CK_HANDOFF_FB_PRESENT && mm.fb_ok) {
        uint32_t scale, cols, rows;
        if (ck_x86_console_fb_on((volatile void *)(uintptr_t)h->fb_base, h->fb_width, h->fb_height,
                                 h->fb_pitch, h->fb_format, &scale, &cols, &rows) == 0)
            ck_printf("screen: gop %ux%u pitch=%u format=%s base=0x%llx map=wc scale=%u grid=%ux%u\n",
                      h->fb_width, h->fb_height, h->fb_pitch, h->fb_format ? "bgrx" : "rgbx",
                      (unsigned long long)h->fb_base, scale, cols, rows);
        else
            ck_puts("screen: refused (unusable geometry)\n");
    } else if (h->fb_status == CK_HANDOFF_FB_PRESENT) {
        ck_puts("screen: refused (framebuffer overlaps RAM or lies above the mapped range)\n");
    } else {
        ck_puts("screen: none\n");
    }
    uint64_t cr3 = ck_rd_cr3() & PTE_ADDR;
    ck_printf("paging: root=0x%llx firmware_cr3=0x%llx switched=%s top_gib=%llu pages_2m_wb=%llu "
              "pages_2m_wc=%llu pages_2m_uc=%llu pt_frames=%llu fb=%s pat1=wc\n",
              (unsigned long long)cr3, (unsigned long long)(h->firmware_ttbr0 & PTE_ADDR),
              cr3 == mm.root && cr3 != (h->firmware_ttbr0 & PTE_ADDR) ? "yes" : "no",
              (unsigned long long)(mm.top >> 30), (unsigned long long)mm.pages_wb, (unsigned long long)mm.pages_wc, (unsigned long long)mm.pages_uc,
              (unsigned long long)mm.pt_frames, mm.fb_ok ? "wc" : "unmapped");

    uint64_t hp;
    if (ck_frames_alloc(&frames, HEAP_PAGES, CK_PAGE, &hp) ||
        ck_heap_init(&heap, (void *)(uintptr_t)hp, HEAP_PAGES * CK_PAGE))
        ck_panic("heap: no region");
    void *a = ck_heap_alloc(&heap, 100), *b = ck_heap_alloc(&heap, 5000);
    if (!a || !b || ck_heap_free(&heap, a) || ck_heap_free(&heap, b) || ck_heap_check(&heap))
        ck_panic("heap: smoke test failed");
    ck_printf("memory: frame_ranges=%u free_bytes=%llu heap=0x%llx+%u heap_test=ok\n", frames.n,
              (unsigned long long)ck_frames_free_bytes(&frames), (unsigned long long)hp,
              (unsigned)(HEAP_PAGES * CK_PAGE));
    ck_printf("stack: 0x%llx-0x%llx guard=0x%llx ist1=0x%llx\n",
              (unsigned long long)(uintptr_t)(kstack + 4096),
              (unsigned long long)(uintptr_t)(kstack + sizeof kstack), (unsigned long long)(uintptr_t)kstack,
              (unsigned long long)(uintptr_t)(ist_stack + sizeof ist_stack));

    /* The guard page faults, and the fault is contained. */
    uint64_t g = (uint64_t)(uintptr_t)kstack;
    probe.hit = 0;
    probe.armed = 1;
    __asm__ volatile("lea 1f(%%rip), %%rax\n\t"
                     "mov %%rax, %0\n\t"
                     "movb (%1), %%al\n"
                     "1:"
                     : "=m"(probe.resume)
                     : "r"(g)
                     : "rax", "memory");
    probe.armed = 0;
    if (probe.hit && probe.cr2 == g && !(probe.err & 1))
        ck_printf("guard_page: ok fault=contained (#PF cr2=0x%llx error=0x%llx, not present)\n",
                  (unsigned long long)probe.cr2, (unsigned long long)probe.err);
    else
        ck_panic("guard_page: FAIL hit=%d cr2=0x%llx error=0x%llx", probe.hit, (unsigned long long)probe.cr2,
                 (unsigned long long)probe.err);

    wx_probes();

    tsc_measure();
    if (!tsc_hz)
        ck_panic("timebase: no HPET and no CPUID leaf 0x16 frequency");
    ck_printf("timebase: %s period_fs=%llu tsc_hz=%llu\n", timebase, (unsigned long long)hpet_period_fs,
              (unsigned long long)tsc_hz);

    struct apic_report ar = {0};
    madt_walk(&ar);
    apic_start(&ar);
    ck_printf("apic: mode=%s id=%u version=0x%x timer_hz=%u\n", "xapic", ar.id,
              ar.version, ar.lapic_hz);
    ck_printf("madt: cpus=%u ioapics=%u ioapic_lines_masked=%u\n", ar.cpus, ar.ioapics, ar.ioapic_lines);
    ck_printf("timer_irq: %llu ticks in %llu ms\n", (unsigned long long)ar.ticks, (unsigned long long)ar.ms);
    ck_printf("timer_stats: vector=0x%x period_us=10000 min_us=%llu avg_us=%llu max_us=%llu stray_irqs=%llu\n",
              VEC_TIMER, (unsigned long long)ar.min_us, (unsigned long long)ar.avg_us,
              (unsigned long long)ar.max_us, (unsigned long long)stray_irqs);
    if (ar.ticks < 20)
        ck_panic("timer: only %llu ticks", (unsigned long long)ar.ticks);

    struct smp_report sr = {0};
    smp_start(&ar, &sr);
    wx_retire_trampoline();
    uint64_t wx, exec4k, text4k = (uint64_t)(__text_end - __text_start) >> 12;
    wx_audit(&wx, &exec4k);
    if (wx || exec4k != text4k)
        ck_panic("wx_audit: FAIL wx_leaves=%llu exec_pages=%llu text_pages=%llu", (unsigned long long)wx,
                 (unsigned long long)exec4k, (unsigned long long)text4k);
    ck_printf("wx_audit: ok wx_leaves=0 exec_pages=%llu text_pages=%llu pages_4k=%llu trampoline=retired\n",
              (unsigned long long)exec4k, (unsigned long long)text4k, (unsigned long long)mm.pages_4k);
    if (sr.why) {
        ck_printf("smp: cpus=%u started=0 (%s)\n", sr.listed, sr.why);
    } else {
        char ids[SMP_MAX * 4 + 1];
        unsigned n = 0;
        for (unsigned k = 0; k < sr.started; k++)
            n += (unsigned)ck_snprintf(ids + n, sizeof ids - n, k ? ",%u" : "%u", sr.up_ids[k]);
        ids[n] = 0;
        ck_printf("smp: cpus=%u started=%u failed=%u bsp_id=%u ap_ids=%s trampoline=0x%llx state=halted\n",
                  sr.listed, sr.started, sr.failed, ar.id, sr.started ? ids : "none",
                  (unsigned long long)tramp_pa);
    }

    const struct ck_x86_storage_result *st = ck_x86_storage(h->rsdp, &frames, tsc_hz, mm.top);
    ck_puts("kernel: alive\n");
    ck_printf("summary: cores=%u/%u timer=ok sata_disks=%u nvme_disks=%u gpt_valid=%u writes=none net=%s\n",
              sr.started + 1, sr.listed, st->ahci_disks, st->nvme_disks, st->gpt_valid,
              !st->net_found          ? "none"
              : st->net_driver == 2   ? "driver-failed"
              : st->net_link == 1     ? "link-up"
              : st->net_link == 2     ? "link-down"
                                      : "seen");
    ck_puts("AIENOS-IMAC-KERNEL-0 DONE\n");
    ck_puts("note: QEMU qualifies nothing physical\n");
    finish();
}

void ck_x86_kernel_entry(struct ck_handoff *h)
{
    ck_cli();
    hand = h;
    tables_load();
    ck_puts("\nreport_kind: kernel\n");
    if (CK_X86_WX_MUTATE)
        ck_printf("wx: MUTATED TEST BUILD (CK_X86_WX_MUTATE=%u): W^X deliberately broken, never deploy\n",
                  (unsigned)CK_X86_WX_MUTATE);
    ck_printf("exit_boot_services: ok attempts=%u\n", h->exit_attempts);
    cpu_line();
    ck_puts("descriptors: gdt=5 tss=yes ist1=df,nmi,mc idt=256\n");
    const char *why;
    if (ck_handoff_check(h, &why) != 0)
        ck_panic("handoff: %s", why);
    ck_puts("handoff: CHANDOF3 ok\n");
    mm_build();
    ck_x86_call_on_stack(kernel_main, 0, (uint64_t)(uintptr_t)(kstack + sizeof kstack));
}
