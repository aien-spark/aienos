/* smp_x86.S -- the start-up trampoline for the secondary cores of
 * AIENOS-IMAC-KERNEL-1 (native/kernel/x86).
 *
 * kmain_x86.c copies ck_x86_tramp_start..ck_x86_tramp_end to a page below
 * 1 MiB, fills the patch slots (GDTR base, the two far-jump targets, CR3,
 * stack, entry, argument) with absolute addresses for that page, and sends
 * INIT, SIPI, SIPI with the page number as the vector. A core then starts
 * here in real mode at CS = page >> 4, IP = 0, and walks: 16-bit -> 32-bit
 * protected mode (the trampoline's own flat GDT) -> PAE + the kernel's page
 * tables + EFER.LME/NXE + paging and CR0.WP -> 64-bit, then calls entry(arg) on its own
 * stack (-mabi=ms: the argument in rcx, 32 bytes of shadow space). If entry
 * returns, the core halts with interrupts off. */

    .text
    .globl ck_x86_tramp_start, ck_x86_tramp_end
    .globl ck_x86_tramp_gdtr, ck_x86_tramp_far32, ck_x86_tramp_far64
    .globl ck_x86_tramp_cr3, ck_x86_tramp_stack, ck_x86_tramp_entry, ck_x86_tramp_arg
    .p2align 12
    .code16
ck_x86_tramp_start:
    cli
    cld
    mov %cs, %ax
    mov %ax, %ds
    xor %ebx, %ebx
    mov %cs, %bx
    shl $4, %ebx                       /* ebx = linear address of the page */
    lgdtl ck_x86_tramp_gdtr - ck_x86_tramp_start
    mov %cr0, %eax
    or $1, %eax
    mov %eax, %cr0
    ljmpl *(ck_x86_tramp_far32 - ck_x86_tramp_start)

    .code32
tramp_pm32:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov %cr4, %eax
    or $0x20, %eax                     /* PAE */
    mov %eax, %cr4
    mov (ck_x86_tramp_cr3 - ck_x86_tramp_start)(%ebx), %eax
    mov %eax, %cr3
    mov $0xc0000080, %ecx              /* EFER */
    rdmsr
    or $0x900, %eax                    /* LME + NXE: the kernel's tables carry NX bits */
    wrmsr
    mov %cr0, %eax
    or $0x80010000, %eax               /* PG + WP: read-only pages bind this core too */
    mov %eax, %cr0
    ljmpl *(ck_x86_tramp_far64 - ck_x86_tramp_start)(%ebx)

    .code64
tramp_lm64:
    mov %ebx, %ebx                     /* zero the upper half */
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov (ck_x86_tramp_stack - ck_x86_tramp_start)(%rbx), %rsp
    mov (ck_x86_tramp_arg - ck_x86_tramp_start)(%rbx), %rcx
    mov (ck_x86_tramp_entry - ck_x86_tramp_start)(%rbx), %rax
    sub $32, %rsp
    call *%rax
1:  cli
    hlt
    jmp 1b

    .p2align 3
tramp_gdt:
    .quad 0
    .quad 0x00cf9a000000ffff           /* 0x08: 32-bit code */
    .quad 0x00cf92000000ffff           /* 0x10: data */
    .quad 0x00209a0000000000           /* 0x18: 64-bit code */
ck_x86_tramp_gdtr:
    .word 31
    .long 0                            /* page + (tramp_gdt - start) */
    .p2align 2
ck_x86_tramp_far32:
    .long 0                            /* page + (tramp_pm32 - start) */
    .word 0x08
    .p2align 2
ck_x86_tramp_far64:
    .long 0                            /* page + (tramp_lm64 - start) */
    .word 0x18
    .p2align 2
ck_x86_tramp_cr3:
    .long 0
    .p2align 3
ck_x86_tramp_stack:
    .quad 0
ck_x86_tramp_entry:
    .quad 0
ck_x86_tramp_arg:
    .quad 0
    .globl ck_x86_tramp_gdt, ck_x86_tramp_pm32, ck_x86_tramp_lm64
    .set ck_x86_tramp_gdt, tramp_gdt
    .set ck_x86_tramp_pm32, tramp_pm32
    .set ck_x86_tramp_lm64, tramp_lm64
ck_x86_tramp_end:
