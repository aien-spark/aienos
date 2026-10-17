/* tg3_x86.c -- the 2017 iMac's Broadcom BCM57766 Ethernet chip (PCI
 * 14e4:1686), polled, received frames never read. The default image uses
 * it for link detection only; frame transmit (ck_x86_tg3_send,
 * ck_x86_tg3_drain) is compiled only into the opt-in lab image
 * (CK_X86_REPORT=1), for the lab-only network report.
 *
 * Written from Broadcom's register layout as the Linux tg3 driver documents
 * it (no code taken from it); the order of every step follows tg3's
 * bring-up for this chip family (57765 class, PCIe, CPMU, no NVRAM, no
 * management firmware), resolved to the one chip on this machine. QEMU has
 * no model of it, so the steps print what they found and the first one that
 * fails stops the driver with its name on the screen.
 *
 * Bring-up: register access set up through config space; the station
 * address read from what Apple's firmware left (the bootcode's SRAM mailbox,
 * else MAC_ADDR_0) and never printed; PHY reset; every engine stopped and a
 * core reset (no BAR access for 240 us around it); bootcode handshake (a
 * timeout is allowed, as tg3 allows it); then buffer manager, rings, host
 * coalescing, DMA engines and MAC enabled in tg3's order, all pointing at
 * memory this driver owns; autonegotiation started (10/100/1000).
 *
 * Interrupts stay masked (MISC_HOST_CTRL MASK_PCI_INT, every interrupt
 * mailbox 1, no MSI). Receive is set up only because the chip expects valid
 * receive rings; nothing reads them, so incoming frames are dropped once the
 * 64 receive buffers are used. Transmit: one 16-byte descriptor per frame,
 * frames copied into one of 32 driver buffers, completion read from the
 * status block (forced with HOSTCC "now"). */
#include "../core/ck_internal.h"
#include "../mm/frames.h"
#include "x86.h"

/* PCI config space (ECAM) */
#define CFG_MISC_HOST_CTRL 0x68
#define CFG_PCISTATE 0x70
#define CFG_REG_BASE 0x78
#define CFG_MEM_WIN_BASE 0x7c
#define CFG_PRODID_ASICREV 0xfc
#define MHC_VALUE 0x29au /* MASK_PCI_INT | WORD_SWAP | PCISTATE_RW | INDIR_ACCESS | TAGGED_STATUS */

/* BAR0 registers */
#define MEM_WIN_BASE 0x7c
#define MEM_WIN_DATA 0x84
#define MBOX_INT0 0x204
#define MBOX_RX_STD_PROD 0x26c
#define MBOX_RX_JMB_PROD 0x274
#define MBOX_RX_RET_CONS0 0x284
#define MBOX_TX_PROD0 0x304
#define MAC_MODE 0x400
#define MAC_STATUS 0x404
#define MAC_EVENT 0x408
#define MAC_LED_CTRL 0x40c
#define MAC_ADDR0_HI 0x410
#define MAC_ADDR0_LO 0x414
#define MAC_TX_BACKOFF 0x438
#define MAC_RX_MTU 0x43c
#define MAC_MI_COM 0x44c
#define MAC_MI_STAT 0x450
#define MAC_MI_MODE 0x454
#define MAC_TX_MODE 0x45c
#define MAC_TX_STATUS 0x460
#define MAC_TX_LENGTHS 0x464
#define MAC_RX_MODE 0x468
#define MAC_HASH0 0x470
#define MAC_RCV_RULE0 0x480
#define MAC_RCV_RULE_CFG 0x500
#define MAC_LOW_WMARK_MAX_RX 0x504
#define SNDDATAI_MODE 0x0c00
#define SNDDATAI_STATSCTRL 0x0c08
#define SNDDATAI_STATSENAB 0x0c0c
#define SNDDATAC_MODE 0x1000
#define SNDBDS_MODE 0x1400
#define SNDBDI_MODE 0x1800
#define SNDBDC_MODE 0x1c00
#define RCVLPC_MODE 0x2000
#define RCVLPC_CONFIG 0x2010
#define RCVLPC_STATSCTRL 0x2014
#define RCVLPC_STATS_ENABLE 0x2018
#define RCVDBDI_MODE 0x2400
#define RCVDBDI_JUMBO_FLAGS 0x2448
#define RCVDBDI_STD_BD 0x2450
#define RCVDCC_MODE 0x2800
#define RCVBDI_MODE 0x2c00
#define RCVBDI_STD_THRESH 0x2c18
#define RCVBDI_JUMBO_THRESH 0x2c1c
#define STD_REPLENISH_LWM 0x2d00
#define JMB_REPLENISH_LWM 0x2d04
#define RCVCC_MODE 0x3000
#define CPMU_LSPD_10MB_CLK 0x3604
#define CPMU_PADRNG_CTL 0x3668
#define HOSTCC_MODE 0x3c00
#define HOSTCC_STATUS 0x3c04
#define HOSTCC_RXCOL_TICKS 0x3c08
#define HOSTCC_TXCOL_TICKS 0x3c0c
#define HOSTCC_RXMAX_FRAMES 0x3c10
#define HOSTCC_TXMAX_FRAMES 0x3c14
#define HOSTCC_RXCOAL_MAXF_INT 0x3c20
#define HOSTCC_TXCOAL_MAXF_INT 0x3c24
#define HOSTCC_STATUS_BLK 0x3c38
#define HOSTCC_VEC1 0x3d80
#define MEMARB_MODE 0x4000
#define BUFMGR_MODE 0x4400
#define BUFMGR_STATUS 0x4404
#define BUFMGR_MB_RDMA_LOW 0x4410
#define BUFMGR_MB_MACRX_LOW 0x4414
#define BUFMGR_MB_HIGH 0x4418
#define BUFMGR_DMA_LOW 0x4434
#define BUFMGR_DMA_HIGH 0x4438
#define RDMAC_MODE 0x4800
#define RDMAC_STATUS 0x4804
#define RDMA_RSRVCTRL 0x4900
#define WDMAC_MODE 0x4c00
#define WDMAC_STATUS 0x4c04
#define FTQ_RESET 0x5c00
#define DMA_RW_CTRL 0x6c
#define GRC_MODE 0x6800
#define GRC_MISC_CFG 0x6804
#define GRC_LOCAL_CTRL 0x6808
#define GRC_FASTBOOT_PC 0x6894
#define NVRAM_SWARB 0x7020
#define PCIE_DL_FTSMAX 0x7c0c

/* NIC SRAM (through the memory window) */
#define SRAM_SEND_RCB 0x100
#define SRAM_RET_RCB 0x200
#define SRAM_FW_MBOX 0xb50
#define SRAM_DATA_SIG 0xb54
#define SRAM_DATA_CFG 0xb58
#define SRAM_MAC_HI 0xc14
#define SRAM_MAC_LO 0xc18
#define SRAM_RX_STD_BDCACHE 0x6000
#define FW_MAGIC 0x4b657654u

/* MII registers of the BCM57765 PHY (MDIO address 1) */
#define PHY_ADDR 1
#define MII_BMCR 0
#define MII_BMSR 1
#define MII_ADVERTISE 4
#define MII_CTRL1000 9
#define PHY_DSP_FIFO 0x10
#define PHY_AUXCTL 0x18
#define PHY_AUX_STAT 0x19
#define PHY_ISTAT 0x1a
#define PHY_IMASK 0x1b
#define PHY_SHADOW 0x1c

#define TX_RING 512u
#define RX_STD 512u
#define RX_RET 1024u
#define RX_POSTED 64u
#define TX_BUFS 32u
#define BUF_SZ 2048u
#define RX_BUF_SZ 1536u

/* Driver memory, one allocation, below 4 GiB: */
#define OFF_STATUS 0x0000u                          /* 1 page */
#define OFF_TX_RING 0x1000u                         /* 512 x 16 = 2 pages */
#define OFF_RX_STD 0x3000u                          /* 512 x 32 = 4 pages */
#define OFF_RX_RET 0x7000u                          /* 1024 x 32 = 8 pages */
#define OFF_RX_BUF 0xf000u                          /* 64 x 2 KiB = 32 pages */
#define OFF_TX_BUF (OFF_RX_BUF + RX_POSTED * BUF_SZ) /* 32 x 2 KiB = 16 pages */
#define DMA_BYTES (OFF_TX_BUF + TX_BUFS * BUF_SZ)
#define DMA_PAGES (DMA_BYTES / CK_PAGE)

static volatile uint8_t *regs, *cfg;
static uint64_t hz, dma;
static uint8_t mac[6];
static int ready, link_up;
static unsigned tx_prod, pcie_cap;
static uint32_t mac_mode;

static void udelay(uint64_t us)
{
    uint64_t t0 = ck_rdtsc(), n = hz / 1000000 * us + 1;
    while (ck_rdtsc() - t0 < n)
        ck_pause();
}
static uint32_t rd(uint32_t off) { return *(volatile uint32_t *)(regs + off); }
static void wr(uint32_t off, uint32_t v) { *(volatile uint32_t *)(regs + off) = v; }
static void wrf(uint32_t off, uint32_t v)
{
    wr(off, v);
    (void)rd(off);
}
static uint32_t cr32(uint32_t off) { return *(volatile uint32_t *)(cfg + off); }
static uint16_t cr16(uint32_t off) { return *(volatile uint16_t *)(cfg + off); }
static void cw32(uint32_t off, uint32_t v) { *(volatile uint32_t *)(cfg + off) = v; }
static void cw16(uint32_t off, uint16_t v) { *(volatile uint16_t *)(cfg + off) = v; }

static void sram_w(uint32_t a, uint32_t v)
{
    wrf(MEM_WIN_BASE, a);
    wrf(MEM_WIN_DATA, v);
    wrf(MEM_WIN_BASE, 0);
}
static uint32_t sram_r(uint32_t a)
{
    wrf(MEM_WIN_BASE, a);
    uint32_t v = rd(MEM_WIN_DATA);
    wrf(MEM_WIN_BASE, 0);
    return v;
}

/* Clears `bit` and waits for it to read 0 (1000 x 100 us). 0 on success. */
static int stop_block(uint32_t off, uint32_t bit)
{
    wrf(off, rd(off) & ~bit);
    for (unsigned i = 0; i < 1000; i++) {
        if (!(rd(off) & bit))
            return 0;
        udelay(100);
    }
    return -1;
}

static int mi_wait(uint32_t *v)
{
    udelay(10);
    for (unsigned i = 0; i < 5000; i++) {
        uint32_t c = rd(MAC_MI_COM);
        if (!(c & 0x20000000)) {
            udelay(5);
            *v = rd(MAC_MI_COM);
            return 0;
        }
        udelay(10);
    }
    return -1;
}
static int phy_r(unsigned reg, uint16_t *out)
{
    uint32_t v;
    wrf(MAC_MI_COM, (uint32_t)PHY_ADDR << 21 | (reg & 0x1f) << 16 | 0x08000000 | 0x20000000);
    if (mi_wait(&v))
        return -1;
    *out = (uint16_t)v;
    return 0;
}
static int phy_w(unsigned reg, uint16_t val)
{
    uint32_t v;
    wrf(MAC_MI_COM, (uint32_t)PHY_ADDR << 21 | (reg & 0x1f) << 16 | val | 0x04000000 | 0x20000000);
    return mi_wait(&v);
}
static int auxctl_r(uint16_t sel, uint16_t *v)
{
    return phy_w(PHY_AUXCTL, (uint16_t)(sel << 12 | 0x7)) || phy_r(PHY_AUXCTL, v);
}
static int auxctl_w(uint16_t sel, uint16_t v)
{
    return phy_w(PHY_AUXCTL, (uint16_t)(v | sel | (sel == 0x7 ? 0x8000 : 0)));
}

/* tg3_phy_reset for this PHY: BMCR reset, power-down timers, extended
 * packet length, FIFO elasticity, auto-MDIX, wirespeed. */
static int phy_reset(void)
{
    uint16_t v;
    if (phy_r(MII_BMSR, &v) || phy_r(MII_BMSR, &v) || phy_w(MII_BMCR, 0x8000))
        return -1;
    unsigned i = 0;
    for (; i < 5000; i++) {
        if (phy_r(MII_BMCR, &v))
            return -1;
        if (!(v & 0x8000))
            break;
        udelay(10);
    }
    if (i == 5000)
        return -1;
    udelay(40);
    if (phy_w(PHY_SHADOW, 0x941f) || phy_w(PHY_SHADOW, 0xa801))
        return -1;
    if (auxctl_r(0x0, &v) || auxctl_w(0x0, v | 0x4000))
        return -1;
    if (phy_r(PHY_DSP_FIFO, &v) || phy_w(PHY_DSP_FIFO, v | 0x0001))
        return -1;
    if (auxctl_r(0x7, &v) || auxctl_w(0x7, v | 0x0200))
        return -1;
    if (auxctl_r(0x7, &v) || auxctl_w(0x7, v | 0x0010))
        return -1;
    return 0;
}

static const char *read_mac(void)
{
    uint32_t hi = sram_r(SRAM_MAC_HI), lo;
    const char *from = "sram";
    if (hi >> 16 == 0x484b) {
        lo = sram_r(SRAM_MAC_LO);
    } else {
        hi = rd(MAC_ADDR0_HI);
        lo = rd(MAC_ADDR0_LO);
        from = "registers";
    }
    mac[0] = (uint8_t)(hi >> 8);
    mac[1] = (uint8_t)hi;
    mac[2] = (uint8_t)(lo >> 24);
    mac[3] = (uint8_t)(lo >> 16);
    mac[4] = (uint8_t)(lo >> 8);
    mac[5] = (uint8_t)lo;
    unsigned any = 0;
    for (unsigned i = 0; i < 6; i++)
        any |= mac[i];
    if (any && !(mac[0] & 1) && !(mac[0] == 0xff && mac[1] == 0xff))
        return from;
    /* None left by the firmware: a locally administered address. */
    uint64_t t = ck_rdtsc();
    mac[0] = 0x02;
    for (unsigned i = 1; i < 6; i++, t >>= 8)
        mac[i] = (uint8_t)t;
    return "generated";
}

static void fail(const char *stage)
{
    ck_printf("net_tg3: stopped at %s; no network report this run\n", stage);
}

int ck_x86_tg3_start(volatile uint8_t *r, volatile uint8_t *c, struct ck_frames *fr, uint64_t tsc_hz)
{
    regs = r;
    cfg = c;
    hz = tsc_hz;
    ready = link_up = 0;

    /* A: register access, identity, management firmware, station address. */
    if (cr32(0) != 0x168614e4u) {
        fail("identity (not 14e4:1686)");
        return -1;
    }
    for (unsigned p = cr32(0x34) & 0xfc, n = 0; p && n < 48; n++) {
        uint32_t h = cr32(p);
        if ((h & 0xff) == 0x10) {
            pcie_cap = p;
            break;
        }
        p = (h >> 8) & 0xfc;
    }
    if (!pcie_cap) {
        fail("PCIe capability");
        return -1;
    }
    cw16(4, (uint16_t)(cr16(4) | 0x6));
    cw32(CFG_MISC_HOST_CTRL, MHC_VALUE);
    uint32_t asic = cr32(CFG_PRODID_ASICREV) >> 12;
    if (asic != 0x57766) {
        ck_printf("net_tg3: asic_rev=0x%x, only the 57766 is driven\n", asic);
        return -1;
    }
    wr(MEMARB_MODE, rd(MEMARB_MODE) | 0x2);
    wr(GRC_MODE, (rd(GRC_MODE) & 0x00010000) | 0x34);
    cw32(CFG_MEM_WIN_BASE, 0);
    cw32(CFG_REG_BASE, 0);
    uint32_t sig = sram_r(SRAM_DATA_SIG), ncfg = sig == FW_MAGIC ? sram_r(SRAM_DATA_CFG) : 0;
    if (ncfg & (0x80 | 0x00200000)) {
        ck_printf("net_tg3: management firmware enabled (cfg=0x%x); left alone\n", ncfg);
        return -1;
    }
    const char *mac_from = read_mac();
    wrf(MAC_MI_MODE, 0x00008000);
    udelay(80);

    /* B: interrupts masked, bootcode signature, PHY reset, engines stopped,
     * core reset. */
    for (unsigned i = 0; i < 5; i++) {
        wr(MBOX_INT0 + 8 * i, 1);
        (void)rd(MBOX_INT0 + 8 * i);
    }
    sram_w(SRAM_FW_MBOX, FW_MAGIC);
    if (phy_reset()) {
        fail("PHY reset (MDIO)");
        return -1;
    }
    unsigned stuck = 0;
    wrf(MAC_RX_MODE, rd(MAC_RX_MODE) & ~0x2u);
    udelay(10);
    static const uint16_t blocks[] = {0x2c00, 0x2000, 0x2400, 0x2800, 0x3000, 0x1400,
                                      0x1800, 0x0c00, 0x4800, 0x1000, 0x1c00};
    for (unsigned i = 0; i < sizeof blocks / sizeof blocks[0]; i++)
        stuck += stop_block(blocks[i], 0x2) != 0;
    wrf(MAC_MODE, rd(MAC_MODE) & ~0x00200000u);
    udelay(40);
    stuck += stop_block(MAC_TX_MODE, 0x2) != 0;
    stuck += stop_block(HOSTCC_MODE, 0x2) != 0;
    stuck += stop_block(WDMAC_MODE, 0x2) != 0;
    wr(FTQ_RESET, 0xffffffffu);
    wr(FTQ_RESET, 0);

    wr(NVRAM_SWARB, 0x2);
    unsigned g = 0;
    for (; g < 8000 && !(rd(NVRAM_SWARB) & 0x200); g++)
        udelay(20);
    if (g == 8000)
        wr(NVRAM_SWARB, 0x20);
    uint16_t pci_cmd = cr16(4);
    wr(GRC_FASTBOOT_PC, 0);
    wr(GRC_MISC_CFG, 1u << 29);
    wr(GRC_MISC_CFG, (1u << 29) | 1u); /* core clock reset: no BAR access until restored */
    udelay(120);
    (void)cr16(4);
    udelay(120);
    uint16_t devctl = cr16(pcie_cap + 8);
    cw16(pcie_cap + 8, (uint16_t)(devctl & ~(0x0010 | 0x0800)));
    cw16(pcie_cap + 0xa, 0x000f);
    cw32(CFG_MISC_HOST_CTRL, MHC_VALUE);
    cw32(CFG_PCISTATE, 0x60);
    cw16(4, pci_cmd);
    wr(MEMARB_MODE, 0x2);
    unsigned fw_ok = 0;
    for (unsigned i = 0; i < 100000; i++) {
        if (sram_r(SRAM_FW_MBOX) == ~FW_MAGIC) {
            fw_ok = 1;
            break;
        }
        udelay(10);
    }
    wr(GRC_MODE, 0x34);
    wrf(MAC_MODE, 0);
    udelay(40);
    wrf(MAC_MI_MODE, 0x00008000);
    udelay(80);
    if (rd(CFG_MISC_HOST_CTRL) == 0xffffffffu) {
        fail("core reset (registers read all-ones)");
        return -1;
    }
    cw32(CFG_MISC_HOST_CTRL, MHC_VALUE);
    cw32(CFG_MEM_WIN_BASE, 0);

    /* D: tg3_reset_hw for the 57766. */
    wr(CPMU_PADRNG_CTL, rd(CPMU_PADRNG_CTL) | 0x00040000);
    uint32_t grc = rd(GRC_MODE);
    wr(GRC_MODE, (grc & ~(0x00400000u | 0x20000000u)) | 0x20000000u);
    wr(PCIE_DL_FTSMAX, (rd(PCIE_DL_FTSMAX) & ~0xffu) | 0x2c);
    wr(GRC_MODE, grc);
    wr(CPMU_LSPD_10MB_CLK, (rd(CPMU_LSPD_10MB_CLK) & ~0x001f0000u) | 0x00130000u);

    if (!dma) {
        uint64_t pa;
        if (ck_frames_alloc(fr, DMA_PAGES, CK_PAGE, &pa) || pa + DMA_BYTES > 0x100000000ull) {
            fail("DMA memory below 4 GiB");
            return -1;
        }
        dma = pa;
    }
    memset((void *)(uintptr_t)dma, 0, DMA_BYTES);
    volatile uint32_t *std = (volatile uint32_t *)(uintptr_t)(dma + OFF_RX_STD);
    for (unsigned i = 0; i < RX_STD; i++) {
        uint64_t b = dma + OFF_RX_BUF + (uint64_t)i * BUF_SZ;
        std[i * 8 + 0] = i < RX_POSTED ? (uint32_t)(b >> 32) : 0;
        std[i * 8 + 1] = i < RX_POSTED ? (uint32_t)b : 0;
        std[i * 8 + 2] = RX_BUF_SZ;
        std[i * 8 + 3] = 0x4;
        std[i * 8 + 7] = 0x10000u | i;
    }
    __asm__ volatile("sfence" ::: "memory");

    wr(DMA_RW_CTRL, rd(DMA_RW_CTRL) | 0x1);
    wr(GRC_MODE, 0x00120034u | 0x04000000u | 0x00010000u);
    wr(GRC_MISC_CFG, (rd(GRC_MISC_CFG) & ~0xffu) | (65u << 1));
    wr(BUFMGR_MB_RDMA_LOW, 0x00);
    wr(BUFMGR_MB_MACRX_LOW, 0x2a);
    wr(BUFMGR_MB_HIGH, 0xa0);
    wr(BUFMGR_DMA_LOW, 0x05);
    wr(BUFMGR_DMA_HIGH, 0x0a);
    wr(BUFMGR_MODE, 0x2 | 0x4);
    unsigned b = 0;
    for (; b < 2000 && !(rd(BUFMGR_MODE) & 0x2); b++)
        udelay(10);
    if (b == 2000) {
        fail("buffer manager enable");
        return -1;
    }
    wr(RCVBDI_STD_THRESH, RX_POSTED / 8);
    wr(STD_REPLENISH_LWM, 128);
    wr(RCVBDI_JUMBO_THRESH, 12);
    wr(JMB_REPLENISH_LWM, 64);
    wr(RCVDBDI_STD_BD + 0x0, (uint32_t)((dma + OFF_RX_STD) >> 32));
    wr(RCVDBDI_STD_BD + 0x4, (uint32_t)(dma + OFF_RX_STD));
    wr(RCVDBDI_STD_BD + 0xc, SRAM_RX_STD_BDCACHE);
    wr(RCVDBDI_JUMBO_FLAGS, 0x2);
    wr(RCVDBDI_STD_BD + 0x8, RX_STD << 16 | RX_BUF_SZ << 2);
    wr(MBOX_RX_STD_PROD, RX_POSTED);
    wr(MBOX_RX_JMB_PROD, 0);

    sram_w(SRAM_SEND_RCB + 0x10 + 0x8, 0x2);
    for (unsigned k = 1; k < 4; k++)
        sram_w(SRAM_RET_RCB + 0x10 * k + 0x8, 0x2);
    for (unsigned i = 0; i < 5; i++) {
        wr(MBOX_INT0 + 8 * i, 1);
        (void)rd(MBOX_INT0 + 8 * i);
    }
    for (unsigned i = 0; i < 4; i++)
        wr(MBOX_RX_RET_CONS0 + 8 * i, 0);
    wr(MBOX_TX_PROD0, 0);
    tx_prod = 0;
    wr(HOSTCC_STATUS_BLK, (uint32_t)((dma + OFF_STATUS) >> 32));
    wr(HOSTCC_STATUS_BLK + 4, (uint32_t)(dma + OFF_STATUS));
    sram_w(SRAM_SEND_RCB + 0x0, (uint32_t)((dma + OFF_TX_RING) >> 32));
    sram_w(SRAM_SEND_RCB + 0x4, (uint32_t)(dma + OFF_TX_RING));
    sram_w(SRAM_SEND_RCB + 0x8, TX_RING << 16);
    sram_w(SRAM_RET_RCB + 0x0, (uint32_t)((dma + OFF_RX_RET) >> 32));
    sram_w(SRAM_RET_RCB + 0x4, (uint32_t)(dma + OFF_RX_RET));
    sram_w(SRAM_RET_RCB + 0x8, RX_RET << 16);

    uint32_t mhi = (uint32_t)mac[0] << 8 | mac[1];
    uint32_t mlo = (uint32_t)mac[2] << 24 | (uint32_t)mac[3] << 16 | (uint32_t)mac[4] << 8 | mac[5];
    for (unsigned n = 0; n < 4; n++) {
        wr(MAC_ADDR0_HI + 8 * n, mhi);
        wr(MAC_ADDR0_LO + 8 * n, mlo);
    }
    wr(MAC_TX_BACKOFF, (uint32_t)(mac[0] + mac[1] + mac[2] + mac[3] + mac[4] + mac[5]) & 0x3ff);
    wr(MAC_RX_MTU, 1522);
    wr(MAC_TX_LENGTHS, 0x2620);
    wr(MAC_RCV_RULE_CFG, 0x8);
    wr(RCVLPC_CONFIG, 0x181);
    wr(RDMA_RSRVCTRL, rd(RDMA_RSRVCTRL) | 0x4);
    wr(RCVLPC_STATS_ENABLE, rd(RCVLPC_STATS_ENABLE) & ~0x00040000u);
    wr(RCVLPC_STATSCTRL, 0x1);
    wr(SNDDATAI_STATSENAB, 0xffffff);
    wr(SNDDATAI_STATSCTRL, 0x1 | 0x2);

    wr(HOSTCC_MODE, 0);
    for (b = 0; b < 2000 && (rd(HOSTCC_MODE) & 0x2); b++)
        udelay(10);
    wr(HOSTCC_TXCOL_TICKS, 0x48);
    wr(HOSTCC_TXMAX_FRAMES, 0x35);
    wr(HOSTCC_TXCOAL_MAXF_INT, 0x05);
    wr(HOSTCC_RXCOL_TICKS, 0x14);
    wr(HOSTCC_RXMAX_FRAMES, 0x05);
    wr(HOSTCC_RXCOAL_MAXF_INT, 0x05);
    for (unsigned i = 0; i < 4; i++)
        for (unsigned o = 0; o < 0x18; o += 4)
            wr(HOSTCC_VEC1 + 0x18 * i + o, 0);
    wr(HOSTCC_MODE, 0x702);
    wr(RCVCC_MODE, 0x2 | 0x4);
    wr(RCVLPC_MODE, 0x2);

    mac_mode = 0x00e04800u;
    wrf(MAC_MODE, mac_mode | 0x1000 | 0x8000);
    udelay(40);
    uint32_t gpio_mask = 0x0001f800u;
    wrf(GRC_LOCAL_CTRL, (0x01009018u & ~gpio_mask) | (rd(GRC_LOCAL_CTRL) & gpio_mask) | 0x1000 | 0x8000);
    udelay(100);
    wrf(WDMAC_MODE, 0x200003feu);
    udelay(40);
    wrf(RDMAC_MODE, 0x188303feu);
    udelay(40);
    wr(RCVDCC_MODE, 0x2 | 0x4);
    wr(SNDDATAC_MODE, 0x2);
    wr(SNDBDC_MODE, 0x2 | 0x4);
    wr(RCVBDI_MODE, 0x2 | 0x4);
    wr(RCVDBDI_MODE, 0x2 | 0x10);
    wr(SNDDATAI_MODE, 0x2);
    wr(SNDDATAI_MODE, 0x2 | 0x8);
    wr(SNDBDI_MODE, 0x2 | 0x4);
    wr(SNDBDS_MODE, 0x2 | 0x4);
    wrf(MAC_TX_MODE, 0x102);
    udelay(100);
    wrf(MAC_RX_MODE, 0x01000002u);
    udelay(10);
    wr(MAC_LED_CTRL, 0x800);
    wr(MAC_MI_STAT, 0x1);
    wrf(MAC_RX_MODE, 0x01000002u);
    udelay(10);
    wrf(MAC_LOW_WMARK_MAX_RX, 1);

    /* E: copper PHY, autonegotiation (tg3_setup_copper_phy, link-down path). */
    uint16_t v;
    wr(MAC_EVENT, 0);
    wrf(MAC_STATUS, 0x10 | 0x8 | 0x00400000 | 0x1000);
    udelay(40);
    if (auxctl_w(0x2, 0) || phy_r(PHY_ISTAT, &v) || phy_r(PHY_ISTAT, &v) || phy_w(PHY_IMASK, 0xffff) ||
        phy_w(MII_ADVERTISE, 0x05e1) || phy_w(MII_CTRL1000, 0x0300) || phy_w(MII_BMCR, 0x1200)) {
        fail("PHY autonegotiation setup (MDIO)");
        return -1;
    }
    mac_mode = (mac_mode & ~0xeu) | 0x8; /* GMII until the link says otherwise */
    wrf(MAC_MODE, mac_mode);
    udelay(40);
    wrf(MAC_EVENT, 0x1000);
    udelay(40);

    for (unsigned i = 0; i < 4; i++)
        wr(MAC_HASH0 + 4 * i, 0);
    wrf(MAC_RX_MODE, 0x01000002u);
    wr(MAC_RCV_RULE0, 0x42000000u);
    wr(MAC_RCV_RULE0 + 4, 0x7fffffffu);
    wr(MAC_RCV_RULE0 + 8, 0x06000004u);
    wr(MAC_RCV_RULE0 + 0xc, 0x7fffffffu);
    for (unsigned o = 0x4a0; o < 0x4c0; o += 4)
        wr(o, 0);

    ready = 1;
    ck_printf("net_tg3: chip=57766 mac_from=%s bootcode=%s engines_stuck=%u bufmgr=ok dma=0x%llx "
              "autoneg=started\n",
              mac_from, fw_ok ? "ready" : "silent", stuck, (unsigned long long)dma);
    return 0;
}

int ck_x86_tg3_ready(void) { return ready; }

void ck_x86_tg3_mac(uint8_t out[6]) { memcpy(out, mac, 6); }

/* Link check (polled tg3_setup_copper_phy): on the first link-up, the MAC
 * port mode and duplex follow the PHY's resolved speed. */
int ck_x86_tg3_link(void)
{
    uint16_t bmsr, aux = 0;
    if (!ready || phy_r(MII_BMSR, &bmsr) || phy_r(MII_BMSR, &bmsr))
        return 0;
    if (!(bmsr & 0x4)) {
        if (link_up)
            ck_puts("net_tg3: link down\n");
        return link_up = 0;
    }
    if (link_up)
        return 1;
    for (unsigned i = 0; i < 2000; i++) {
        if (phy_r(PHY_AUX_STAT, &aux))
            return 0;
        if (aux)
            break;
        udelay(10);
    }
    unsigned sd = (aux >> 8) & 7, speed = sd >= 6 ? 1000 : sd >= 3 ? 100 : 10;
    int full = sd == 2 || sd == 5 || sd == 7;
    mac_mode = (mac_mode & ~0xeu) | (speed == 1000 ? 0x8 : 0x4) | (full ? 0 : 0x2);
    wrf(MAC_MODE, mac_mode);
    udelay(40);
    wr(MAC_TX_LENGTHS, 0x2600 | (speed == 1000 && !full ? 0xff : 32));
    wrf(MAC_EVENT, 0x1000);
    udelay(40);
    link_up = 1;
    ck_printf("net_tg3: link up %u Mb/s %s duplex\n", speed, full ? "full" : "half");
    return 1;
}

#if defined(CK_X86_REPORT) && CK_X86_REPORT
/* Transmit exists only in the opt-in lab image, for the network report
 * (report_x86.c). The default image has no way to send a frame. */
static int stalled_shown;

static unsigned tx_cons(void)
{
    __asm__ volatile("" ::: "memory");
    return *(volatile uint16_t *)(uintptr_t)(dma + OFF_STATUS + 0x12) & (TX_RING - 1);
}

int ck_x86_tg3_send(const uint8_t *frame, size_t len)
{
    if (!ready || !link_up || !frame || len > 1514 || len < 14)
        return -1;
    /* Room: fewer than TX_BUFS frames in flight (each frame is one BD). */
    unsigned waited = 0;
    while (((tx_prod - tx_cons()) & (TX_RING - 1)) >= TX_BUFS - 1) {
        wr(HOSTCC_MODE, 0x702 | 0x8);
        udelay(100);
        if (++waited > 500) { /* 50 ms */
            if (!stalled_shown++)
                ck_printf("net_tg3: transmit stalled prod=%u cons=%u sndbds=0x%x sndbdi=0x%x rdmac=0x%x "
                          "wdmac=0x%x bufmgr=0x%x hostcc=0x%x mac_tx=0x%x\n",
                          tx_prod, tx_cons(), rd(SNDBDS_MODE + 4), rd(SNDBDI_MODE + 4), rd(RDMAC_STATUS),
                          rd(WDMAC_STATUS), rd(BUFMGR_STATUS), rd(HOSTCC_STATUS), rd(MAC_TX_STATUS));
            return -1;
        }
    }
    uint64_t buf = dma + OFF_TX_BUF + (uint64_t)(tx_prod % TX_BUFS) * BUF_SZ;
    size_t n = len < 60 ? 60 : len;
    memcpy((void *)(uintptr_t)buf, frame, len);
    if (n > len)
        memset((void *)(uintptr_t)(buf + len), 0, n - len);
    volatile uint32_t *bd = (volatile uint32_t *)(uintptr_t)(dma + OFF_TX_RING + (uint64_t)tx_prod * 16);
    bd[0] = (uint32_t)(buf >> 32);
    bd[1] = (uint32_t)buf;
    bd[2] = (uint32_t)n << 16 | 0x4;
    bd[3] = 0;
    __asm__ volatile("sfence" ::: "memory");
    tx_prod = (tx_prod + 1) & (TX_RING - 1);
    wr(MBOX_TX_PROD0, tx_prod);
    return 0;
}

/* Waits up to `ms` for every queued frame to be sent. 0 when all are. */
int ck_x86_tg3_drain(unsigned ms)
{
    if (!ready)
        return -1;
    for (unsigned i = 0; i < ms * 10; i++) {
        if (tx_cons() == tx_prod)
            return 0;
        wr(HOSTCC_MODE, 0x702 | 0x8);
        udelay(100);
    }
    return -1;
}
#endif /* CK_X86_REPORT */
