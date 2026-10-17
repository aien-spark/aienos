/* x86.h -- x86_64 machine access for the AIENOS-IMAC-KERNEL-0 kernel
 * (native/kernel/x86): port and MSR I/O, CPUID, TSC, control registers,
 * the trap frame trap.S builds, and the entry points between the files.
 * Everything is compiled -mabi=ms (UEFI calling convention, like the stub),
 * so trap.S passes the first argument in rcx. */
#ifndef AIENOS_CK_X86_H
#define AIENOS_CK_X86_H
#include <stddef.h>
#include <stdint.h>

static inline void ck_outb(uint16_t p, uint8_t v) { __asm__ volatile("outb %0, %1" ::"a"(v), "Nd"(p)); }
static inline void ck_outw(uint16_t p, uint16_t v) { __asm__ volatile("outw %0, %1" ::"a"(v), "Nd"(p)); }
static inline uint8_t ck_inb(uint16_t p)
{
    uint8_t v;
    __asm__ volatile("inb %1, %0" : "=a"(v) : "Nd"(p));
    return v;
}
static inline uint16_t ck_inw(uint16_t p)
{
    uint16_t v;
    __asm__ volatile("inw %1, %0" : "=a"(v) : "Nd"(p));
    return v;
}
static inline uint64_t ck_rdmsr(uint32_t m)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(m));
    return (uint64_t)hi << 32 | lo;
}
static inline void ck_wrmsr(uint32_t m, uint64_t v)
{
    __asm__ volatile("wrmsr" ::"c"(m), "a"((uint32_t)v), "d"((uint32_t)(v >> 32)) : "memory");
}
static inline void ck_cpuid(uint32_t leaf, uint32_t sub, uint32_t r[4])
{
    __asm__ volatile("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3]) : "a"(leaf), "c"(sub));
}
static inline uint64_t ck_rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (uint64_t)hi << 32 | lo;
}
#define CK_RD_CR(n)                                                                                \
    static inline uint64_t ck_rd_cr##n(void)                                                       \
    {                                                                                              \
        uint64_t v;                                                                                \
        __asm__ volatile("mov %%cr" #n ", %0" : "=r"(v));                                         \
        return v;                                                                                  \
    }
CK_RD_CR(0)
CK_RD_CR(2)
CK_RD_CR(3)
CK_RD_CR(4)
#undef CK_RD_CR
static inline void ck_wr_cr3(uint64_t v) { __asm__ volatile("mov %0, %%cr3" ::"r"(v) : "memory"); }
static inline void ck_cli(void) { __asm__ volatile("cli" ::: "memory"); }
static inline void ck_sti(void) { __asm__ volatile("sti" ::: "memory"); }
static inline void ck_pause(void) { __asm__ volatile("pause"); }

/* What trap.S pushes, lowest address first: the general registers, the
 * vector and error code (0 for vectors without one), then the CPU frame. */
struct ck_x86_frame {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8, rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t vector, error;
    uint64_t rip, cs, rflags, rsp, ss;
};
_Static_assert(sizeof(struct ck_x86_frame) == 22 * 8, "ck_x86_frame size");

/* trap.S */
extern char ck_x86_isr_stubs[]; /* 256 stubs, 16 bytes apart */
#define CK_X86_ISR_STRIDE 16u
void ck_x86_load_gdt(const void *gdtr, uint16_t code_sel, uint16_t data_sel, uint16_t tss_sel);
__attribute__((noreturn)) void ck_x86_call_on_stack(void (*fn)(void *), void *arg, uint64_t sp);
void ck_x86_trap(struct ck_x86_frame *f); /* kmain.c, called by every stub */

/* console_x86.c: COM1 if a 16550 answers there, the GOP framebuffer once
 * the kernel turned it on, and a RAM copy of everything written so far that
 * is replayed onto the screen when it comes on. */
int ck_x86_com1_probe(void);
int ck_x86_console_fb_on(volatile void *base, uint32_t width, uint32_t height, uint32_t pitch,
                         uint32_t format, uint32_t *scale, uint32_t *cols, uint32_t *rows);

/* console_x86.c: the RAM copy of everything written so far (the first
 * 16 KiB); in the lab image, the input the network report filters. */
const char *ck_x86_console_log(size_t *len);

/* pci_x86.c: PCI walk over the MCFG ECAM window; every AHCI and NVMe disk
 * read-only (identify, read, GPT check), a look at the Ethernet chip. */
struct ck_frames;
struct ck_x86_storage_result {
    unsigned pci_functions, ahci_ctrls, ahci_disks, nvme_ctrls, nvme_disks, gpt_valid;
    unsigned net_found, net_link; /* net_link: 0 not read, 1 up, 2 down */
    unsigned net_driver;          /* 0 not tried, 1 running, 2 failed */
};
const struct ck_x86_storage_result *ck_x86_storage(uint64_t rsdp, struct ck_frames *fr, uint64_t tsc_hz,
                                                   uint64_t map_top);
/* kmain_x86.c: maps [pa, pa + len) uncached when it lies above the identity map. */
int ck_x86_map_mmio(uint64_t pa, uint64_t len);
/* ahci_x86.c: one AHCI controller at abar, polled, read-only. */
void ck_x86_ahci_start(unsigned ctrl, uint64_t abar, struct ck_frames *fr, uint64_t tsc_hz);
unsigned ck_x86_ahci_disks(void);

/* tg3_x86.c: the Broadcom BCM57766 Ethernet chip, transmit only, polled.
 * start: regs = BAR0 (mapped), cfg = its ECAM config space; 0 when the chip
 * is up (the link may still be negotiating). The rest report on or use it. */
int ck_x86_tg3_start(volatile uint8_t *regs, volatile uint8_t *cfg, struct ck_frames *fr, uint64_t tsc_hz);
int ck_x86_tg3_ready(void);
int ck_x86_tg3_link(void);
void ck_x86_tg3_mac(uint8_t mac[6]);
#if defined(CK_X86_REPORT) && CK_X86_REPORT
/* Lab image only (make imac-kernel CK_X86_REPORT=1); absent from the default
 * and any resident or service build. */
int ck_x86_tg3_send(const uint8_t *frame, size_t len);
int ck_x86_tg3_drain(unsigned ms);
/* report_x86.c (lab only): holds `seconds`, sending the allowlisted console
 * lines as unauthenticated UDP broadcasts every 2 s while the link is up;
 * returns the rounds sent. */
unsigned ck_x86_report_hold(uint64_t tsc_hz, unsigned seconds);
#endif

/* smp_x86.S: the secondary-core trampoline, copied below 1 MiB and patched. */
extern char ck_x86_tramp_start[], ck_x86_tramp_end[], ck_x86_tramp_gdt[], ck_x86_tramp_pm32[],
    ck_x86_tramp_lm64[], ck_x86_tramp_gdtr[], ck_x86_tramp_far32[], ck_x86_tramp_far64[], ck_x86_tramp_cr3[],
    ck_x86_tramp_stack[], ck_x86_tramp_entry[], ck_x86_tramp_arg[];

#endif
