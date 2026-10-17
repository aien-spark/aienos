/* net_loader.c -- NETLDR.EFI: the AIENOS lab network loader for the 2017 iMac
 * (x86_64 UEFI application; wire format netboot_proto.h).
 *
 * Lives on the USB stick as EFI/BOOT/BOOTX64.EFI so the stick never has to
 * move again. At every power-on it asks the LAN for a kernel, verifies it and
 * starts it:
 *   1. Network: the firmware's Simple Network Protocol (UEFI 2.10 section
 *      24.1), opened EXCLUSIVE so the firmware's own network stack lets go of
 *      the receive queue. No SNP handle: ConnectController on every handle
 *      once, then look again. Every handle is tried (the iMac also has a Wi-Fi
 *      SNP that looks like Ethernet): the first with its cable link up wins;
 *      with none reporting a link, each gets a 10 s turn before the fallback.
 *   2. HELLO every second. WAIT: the server is there with nothing queued; ask
 *      again after the seconds it names. OFFER: fetch the object (signed slot
 *      manifest + image) in NB_WINDOW-chunk windows, re-asking for gaps.
 *   3. ck_slot_verify (slot_select.c, the SLOTLDR verifier): Ed25519 manifest
 *      signature by a key baked in at build time (CK_NETLDR_KEYS), SHA-512 of
 *      the image, image_len == the bytes received. Refused: DONE status 1 with
 *      the reason, nothing runs, back to step 2.
 *   4. Verified: DONE status 0, SNP Shutdown + Stop + CloseProtocol (no
 *      firmware DMA into memory the kernel will own), LoadImage from the
 *      verified buffer, StartImage.
 *   No answer at all for CK_NETLDR_FALLBACK_S seconds: start the kernel on the
 *   stick itself (\EFI\AIENOS\IMACKERN.EFI on this loader's volume), so the
 *   iMac still runs AIENOS with the Spark disconnected. That file is trusted
 *   as the stick is: whoever can write the stick can replace this loader too.
 *
 * The UEFI watchdog is re-armed to NETLDR_WATCHDOG_S on every server answer
 * and before StartImage, so a hung loader or kernel (before ExitBootServices)
 * resets the machine instead of waiting for a hand on the power button.
 * Never: UEFI variables, runtime services, ExitBootServices, disk writes.
 * Freestanding C with the x86 kernel's flags; no kernel objects are linked. */
#include <stdarg.h>
#include "efi.h"
#include "slot_format.h"
#include "netboot_proto.h"
#include "aienos_net.h"
#include "../kernel/core/fmt.h"

#ifndef AIENOS_COMMIT
#define AIENOS_COMMIT "unknown"
#endif
#ifndef CK_NETLDR_FALLBACK_S
#define CK_NETLDR_FALLBACK_S 30u
#endif
#define NETLDR_WATCHDOG_S 600u
#define LOCAL_KERNEL u"\\EFI\\AIENOS\\IMACKERN.EFI"
#define LOCAL_MAX (16ull << 20)
#define PAGE 4096ull

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);

/* Generated at build time (native/kernel/Makefile, ck_slot_tool keys-c). */
extern const uint8_t ck_slot_loader_keys[][32];
extern const unsigned ck_slot_loader_nkeys;

#define EFI_LOAD_ERROR EFI_ERR(1)
#define EFI_NOT_READY EFI_ERR(6)
#define EFI_ALREADY_STARTED EFI_ERR(20)

/* ---- Simple Network Protocol (UEFI 2.10 section 24.1; r-efi 6.0.0
 * protocols/simple_network.rs) ---- */
#define SNP_GUID_INIT { 0xa19832b9, 0xac25, 0x11d3, { 0x9a, 0x2d, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } }
#define LOADED_IMAGE_DEVICE_PATH_GUID_INIT \
    { 0xbc62157e, 0x3e33, 0x4fec, { 0x99, 0x20, 0x2d, 0x3b, 0x36, 0xd7, 0x50, 0xdf } }
enum { SNP_STOPPED, SNP_STARTED, SNP_INITIALIZED };
#define SNP_RX_UNICAST 1u
#define SNP_RX_BROADCAST 4u
#define OPEN_BY_HANDLE 0x1u
#define OPEN_EXCLUSIVE 0x20u

typedef struct { uint8_t addr[32]; } EFI_MAC_ADDRESS;
typedef struct {
    uint32_t State, HwAddressSize, MediaHeaderSize, MaxPacketSize, NvRamSize, NvRamAccessSize;
    uint32_t ReceiveFilterMask, ReceiveFilterSetting, MaxMCastFilterCount, MCastFilterCount;
    EFI_MAC_ADDRESS MCastFilter[16];
    EFI_MAC_ADDRESS CurrentAddress, BroadcastAddress, PermanentAddress;
    uint8_t IfType, MacAddressChangeable, MultipleTxSupported, MediaPresentSupported, MediaPresent;
} SNP_MODE;
_Static_assert(offsetof(SNP_MODE, CurrentAddress) == 552, "SNP_MODE CurrentAddress");
_Static_assert(offsetof(SNP_MODE, MediaPresent) == 652, "SNP_MODE MediaPresent");

typedef struct SNP {
    uint64_t Revision;
    EFI_STATUS (*Start)(struct SNP *);
    EFI_STATUS (*Stop)(struct SNP *);
    EFI_STATUS (*Initialize)(struct SNP *, uint64_t extra_rx, uint64_t extra_tx);
    EFI_STATUS (*Reset)(struct SNP *, uint8_t extended);
    EFI_STATUS (*Shutdown)(struct SNP *);
    EFI_STATUS (*ReceiveFilters)(struct SNP *, uint32_t enable, uint32_t disable, uint8_t reset_mcast,
                                 uint64_t mcast_count, EFI_MAC_ADDRESS *mcast);
    void *StationAddress, *Statistics, *MCastIpToMac, *NvData;
    EFI_STATUS (*GetStatus)(struct SNP *, uint32_t *irq, void **tx_buf);
    EFI_STATUS (*Transmit)(struct SNP *, uint64_t header_size, uint64_t size, void *buf, EFI_MAC_ADDRESS *src,
                           EFI_MAC_ADDRESS *dst, uint16_t *proto);
    EFI_STATUS (*Receive)(struct SNP *, uint64_t *header_size, uint64_t *size, void *buf, EFI_MAC_ADDRESS *src,
                          EFI_MAC_ADDRESS *dst, uint16_t *proto);
    void *WaitForPacket;
    SNP_MODE *Mode;
} SNP;
_Static_assert(offsetof(SNP, GetStatus) == 0x58, "SNP GetStatus");
_Static_assert(offsetof(SNP, Receive) == 0x68, "SNP Receive");
_Static_assert(offsetof(SNP, Mode) == 0x78, "SNP Mode");

/* Boot-services members efi.h keeps as placeholders (UEFI 2.10 section 7). */
typedef EFI_STATUS (*load_image_fn)(uint8_t boot_policy, EFI_HANDLE parent, void *device_path, void *source,
                                    uint64_t source_size, EFI_HANDLE *out);
typedef EFI_STATUS (*start_image_fn)(EFI_HANDLE image, uint64_t *exit_data_size, CHAR16 **exit_data);
typedef EFI_STATUS (*connect_fn)(EFI_HANDLE controller, EFI_HANDLE *driver, void *remaining, uint8_t recursive);
typedef EFI_STATUS (*open_protocol_fn)(EFI_HANDLE handle, const EFI_GUID *protocol, void **iface, EFI_HANDLE agent,
                                       EFI_HANDLE controller, uint32_t attributes);
typedef EFI_STATUS (*close_protocol_fn)(EFI_HANDLE handle, const EFI_GUID *protocol, EFI_HANDLE agent,
                                        EFI_HANDLE controller);
_Static_assert(offsetof(EFI_BOOT_SERVICES, LoadImage) == 0xc8, "LoadImage");
_Static_assert(offsetof(EFI_BOOT_SERVICES, ConnectController) == 0x108, "ConnectController");
_Static_assert(offsetof(EFI_BOOT_SERVICES, OpenProtocol) == 0x118, "OpenProtocol");

static const EFI_GUID snp_guid = SNP_GUID_INIT;
static EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *conout;
static EFI_BOOT_SERVICES *bs;
static EFI_HANDLE self;
static SNP *snp;
static EFI_HANDLE snp_handle;
static int snp_exclusive;
static uint8_t mac[6];
static uint8_t tx[1600], rx[2048];
static uint8_t have[NB_OBJECT_MAX / NB_CHUNK / 8];
static uint64_t tsc_per_ms;

/* ---- console -------------------------------------------------------------- */
struct line {
    char b[256];
    size_t n;
};

static void line_emit(void *ctx, char c)
{
    struct line *l = ctx;
    if (l->n < sizeof l->b - 1)
        l->b[l->n++] = c;
}

static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void say(const char *fmt, ...)
{
    struct line l;
    CHAR16 w[2 * sizeof l.b + 1];
    size_t k = 0;
    va_list ap;
    l.n = 0;
    va_start(ap, fmt);
    ck_vformat(line_emit, &l, fmt, ap);
    va_end(ap);
    for (size_t i = 0; i < l.n; i++) {
        if (l.b[i] == '\n')
            w[k++] = '\r';
        w[k++] = (uint8_t)l.b[i];
    }
    w[k] = 0;
    if (conout)
        conout->OutputString(conout, w);
}

/* ---- time ------------------------------------------------------------------- */
static uint64_t rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (uint64_t)hi << 32 | lo;
}

static uint64_t now_ms(void) { return rdtsc() / tsc_per_ms; }

static void watchdog(uint64_t seconds) { bs->SetWatchdogTimer(seconds, 0x10000, 0, 0); }

/* ---- network ---------------------------------------------------------------- */
static void net_close(void)
{
    if (!snp)
        return;
    snp->Shutdown(snp);
    snp->Stop(snp);
    if (snp_exclusive)
        ((close_protocol_fn)bs->CloseProtocol)(snp_handle, &snp_guid, self, 0);
    snp = 0;
}

/* Every SNP handle, in firmware order. The iMac firmware carries a Wi-Fi driver (Internet
 * Recovery) beside the wired one, and an 802.11 SNP reports IfType 1 like Ethernet, so the
 * first handle is not necessarily the cable. */
#define NIC_MAX 8
static EFI_HANDLE nics[NIC_MAX];
static unsigned n_nics, nic_tries = 1;

static int find_nics(void)
{
    EFI_HANDLE *h = 0;
    uint64_t n = 0;
    if (bs->LocateHandleBuffer(ByProtocol, &snp_guid, 0, &n, &h) != EFI_SUCCESS || n == 0) {
        EFI_HANDLE *all = 0;
        uint64_t na = 0;
        say("netldr: no network interface yet; connecting firmware drivers\n");
        if (bs->LocateHandleBuffer(AllHandles, 0, 0, &na, &all) == EFI_SUCCESS) {
            for (uint64_t i = 0; i < na; i++)
                ((connect_fn)bs->ConnectController)(all[i], 0, 0, 1);
            bs->FreePool(all);
        }
        if (bs->LocateHandleBuffer(ByProtocol, &snp_guid, 0, &n, &h) != EFI_SUCCESS || n == 0) {
            say("netldr: no network interface (Simple Network Protocol) in this firmware\n");
            return -1;
        }
    }
    n_nics = n < NIC_MAX ? (unsigned)n : NIC_MAX;
    for (unsigned i = 0; i < n_nics; i++)
        nics[i] = h[i];
    bs->FreePool(h);
    return 0;
}

enum { LINK_UNUSABLE = -1, LINK_DOWN, LINK_UNKNOWN, LINK_UP };

/* Open nics[i] (exclusive if the firmware lets go), bring it to Initialized with unicast +
 * broadcast receive, wait up to 10 s for the cable link. Leaves it open as snp unless
 * LINK_UNUSABLE; the caller closes the ones it does not keep. */
static int use_nic(unsigned i, int quiet)
{
    EFI_STATUS s;
    SNP *p = 0;
    int ex = 1;
    if (((open_protocol_fn)bs->OpenProtocol)(nics[i], &snp_guid, (void **)&p, self, 0, OPEN_EXCLUSIVE) !=
        EFI_SUCCESS) {
        ex = 0;
        if (bs->HandleProtocol(nics[i], &snp_guid, (void **)&p) != EFI_SUCCESS)
            p = 0;
    }
    if (!p || !p->Mode) {
        say("netldr: nic %u unusable (no protocol)\n", i);
        return LINK_UNUSABLE;
    }
    SNP_MODE *m = p->Mode;
    if (!quiet)
        say("netldr: nic %u of %u mac=%02x:%02x:%02x:%02x:%02x:%02x type=%u state=%u open=%s\n", i, n_nics,
            m->CurrentAddress.addr[0], m->CurrentAddress.addr[1], m->CurrentAddress.addr[2], m->CurrentAddress.addr[3],
            m->CurrentAddress.addr[4], m->CurrentAddress.addr[5], m->IfType, m->State, ex ? "exclusive" : "shared");
    snp = p;
    snp_handle = nics[i];
    snp_exclusive = ex;
    if (m->IfType != 1 || m->HwAddressSize != 6) {
        net_close();
        return LINK_UNUSABLE;
    }
    memcpy(mac, m->CurrentAddress.addr, 6);
    if (m->State == SNP_STOPPED && (s = p->Start(p)) != EFI_SUCCESS && s != EFI_ALREADY_STARTED) {
        say("netldr: nic %u Start status=0x%llx\n", i, (unsigned long long)s);
        net_close();
        return LINK_UNUSABLE;
    }
    if (m->State == SNP_STARTED && (s = p->Initialize(p, 0, 0)) != EFI_SUCCESS) {
        say("netldr: nic %u Initialize status=0x%llx\n", i, (unsigned long long)s);
        net_close();
        return LINK_UNUSABLE;
    }
    uint32_t want = (SNP_RX_UNICAST | SNP_RX_BROADCAST) & m->ReceiveFilterMask;
    if (!(want & SNP_RX_BROADCAST) || (s = p->ReceiveFilters(p, want, 0, 0, 0, 0)) != EFI_SUCCESS) {
        say("netldr: nic %u cannot receive broadcasts (mask=0x%x status=0x%llx)\n", i, m->ReceiveFilterMask,
            (unsigned long long)(want & SNP_RX_BROADCAST ? s : EFI_ERR(3)));
        net_close();
        return LINK_UNUSABLE;
    }
    if (!m->MediaPresentSupported) {
        if (!quiet)
            say("netldr: nic %u link: not reported\n", i);
        return LINK_UNKNOWN;
    }
    for (uint64_t t = now_ms() + 10000; !m->MediaPresent && now_ms() < t;) {
        uint32_t irq;
        p->GetStatus(p, &irq, 0);
        bs->Stall(100000);
    }
    if (!quiet)
        say("netldr: nic %u link %s\n", i, m->MediaPresent ? "up" : "down");
    return m->MediaPresent ? LINK_UP : LINK_DOWN;
}

/* Keep the first interface with its cable link up. With none up, round number `round` picks
 * among the rest (link not reported first, then link down), so a caller that moves to the
 * next round after a silent window tries each in turn; nic_tries says how many there are. */
static int net_open(unsigned round)
{
    unsigned cand[2 * NIC_MAX], nc = 0, down[NIC_MAX], nd = 0;
    if (find_nics() != 0)
        return -1;
    for (unsigned i = 0; i < n_nics; i++) {
        int r = use_nic(i, round != 0);
        if (r == LINK_UP) {
            nic_tries = 1;
            return 0;
        }
        if (r == LINK_UNUSABLE)
            continue;
        net_close();
        if (r == LINK_UNKNOWN)
            cand[nc++] = i;
        else
            down[nd++] = i;
    }
    for (unsigned k = 0; k < nd; k++)
        cand[nc++] = down[k];
    if (nc == 0) {
        say("netldr: no usable network interface\n");
        return -1;
    }
    nic_tries = nc;
    unsigned pick = cand[round % nc];
    say("netldr: no interface reports a cable link; trying nic %u (%u of %u)\n", pick, round % nc + 1, nc);
    return use_nic(pick, 1) == LINK_UNUSABLE ? -1 : 0;
}

/* Why the last net_send failed (for the DONE report). */
static const char *tx_why;
static EFI_STATUS tx_status;

static int net_send(const struct nb_msg *m)
{
    static uint8_t msg[NB_MSG_MAX], udp[8 + NB_MSG_MAX], ip[20 + sizeof udp];
    const net_ipv4 any = {{0, 0, 0, 0}}, bcast = {{255, 255, 255, 255}};
    net_udp_header uh = {NB_PORT_LOADER, NB_PORT_SERVER};
    net_ipv4_header ih = {0, 0, 1, NET_IPPROTO_UDP, any, bcast};
    net_eth_frame e;
    size_t n = nb_build(m, msg, sizeof msg), uw = 0, iw = 0, ew = 0;
    tx_why = "frame build";
    if (!n || net_udp_build(&uh, msg, n, any, bcast, udp, sizeof udp, &uw) != NET_OK ||
        net_ipv4_build(&ih, udp, uw, ip, sizeof ip, &iw) != NET_OK)
        return -1;
    memset(e.destination.b, 0xff, 6);
    memcpy(e.source.b, mac, 6);
    e.ethertype = NET_ETHERTYPE_IPV4;
    e.payload = ip;
    e.payload_len = iw;
    if (net_eth_build(&e, tx, sizeof tx, &ew) != NET_OK)
        return -1;
    tx_why = "Transmit";
    if ((tx_status = snp->Transmit(snp, 0, ew, tx, 0, 0, 0)) != EFI_SUCCESS)
        return -1;
    /* The frame buffer is the firmware's until GetStatus hands it back. A driver that never
     * reports the completion still sent the frame: go on and listen (the next frame is built
     * a second or more later), and say so if nothing ever answers. */
    for (uint64_t t = now_ms() + 100; now_ms() < t;) {
        uint32_t irq;
        void *done = 0;
        if (snp->GetStatus(snp, &irq, &done) == EFI_SUCCESS && done) {
            tx_why = "frames sent, nothing came back";
            return 0;
        }
    }
    tx_why = "frames handed to the card, completion never reported";
    return 0;
}

/* Next netboot message with our nonce before deadline (ms). 0 or -1. */
static int net_recv(const uint8_t nonce[16], uint64_t deadline, struct nb_msg *out)
{
    do {
        uint64_t size = sizeof rx;
        EFI_STATUS s = snp->Receive(snp, 0, &size, rx, 0, 0, 0);
        if (s == EFI_NOT_READY)
            continue;
        if (s != EFI_SUCCESS || size > sizeof rx)
            continue;
        net_eth_frame e;
        net_ipv4_header ih;
        net_udp_header uh;
        const uint8_t *ipp, *up;
        size_t ipn, un;
        if (net_eth_parse(rx, size, &e) != NET_OK || e.ethertype != NET_ETHERTYPE_IPV4 ||
            net_ipv4_parse(e.payload, e.payload_len, &ih, &ipp, &ipn) != NET_OK || ih.protocol != NET_IPPROTO_UDP ||
            net_udp_parse(ipp, ipn, ih.source, ih.destination, &uh, &up, &un) != NET_OK ||
            uh.destination_port != NB_PORT_LOADER || uh.source_port != NB_PORT_SERVER)
            continue;
        if (nb_parse(up, un, out) != 0 || memcmp(out->nonce, nonce, 16) != 0)
            continue;
        return 0;
    } while (now_ms() < deadline);
    return -1;
}

/* ---- starting a kernel ------------------------------------------------------ */
static void start_image(const char *what, void *buf, uint64_t len)
{
    static const EFI_GUID lidp_guid = LOADED_IMAGE_DEVICE_PATH_GUID_INIT;
    void *dp = 0;
    EFI_HANDLE child = 0;
    bs->HandleProtocol(self, &lidp_guid, &dp);
    EFI_STATUS s = ((load_image_fn)bs->LoadImage)(0, self, dp, buf, len, &child);
    if (s != EFI_SUCCESS) {
        say("netldr: LoadImage of the %s kernel status=0x%llx: not started\n", what, (unsigned long long)s);
        return;
    }
    say("netldr: starting the %s kernel (%llu bytes)\n", what, (unsigned long long)len);
    watchdog(300);
    s = ((start_image_fn)bs->StartImage)(child, 0, 0);
    say("netldr: the %s kernel returned status=0x%llx\n", what, (unsigned long long)s);
}

/* The kernel on the stick itself, for when no server answers. */
static void start_local(void)
{
    static const EFI_GUID li_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID_INIT;
    static const EFI_GUID sfs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID_INIT;
    EFI_LOADED_IMAGE_PROTOCOL *li = 0;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = 0;
    EFI_FILE_PROTOCOL *root = 0, *f = 0;
    uint64_t pa = 0, got = 0;
    if (bs->HandleProtocol(self, &li_guid, (void **)&li) != EFI_SUCCESS || !li ||
        bs->HandleProtocol(li->DeviceHandle, &sfs_guid, (void **)&fs) != EFI_SUCCESS || !fs ||
        fs->OpenVolume(fs, &root) != EFI_SUCCESS) {
        say("netldr: cannot open this stick's volume: no local kernel\n");
        return;
    }
    if (root->Open(root, &f, (CHAR16 *)LOCAL_KERNEL, 1 /* read */, 0) != EFI_SUCCESS) {
        say("netldr: no \\EFI\\AIENOS\\IMACKERN.EFI on this stick\n");
        root->Close(root);
        return;
    }
    if (bs->AllocatePages(AllocateAnyPages, EfiLoaderData, LOCAL_MAX / PAGE, &pa) != EFI_SUCCESS) {
        say("netldr: no memory for the local kernel\n");
    } else {
        for (;;) {
            uint64_t n = LOCAL_MAX - got;
            if (n == 0 || f->Read(f, &n, (uint8_t *)(uintptr_t)pa + got) != EFI_SUCCESS || n == 0)
                break;
            got += n;
        }
    }
    f->Close(f);
    root->Close(root);
    if (pa && got > 0 && got < LOCAL_MAX)
        start_image("local", (void *)(uintptr_t)pa, got);
    else if (pa)
        say("netldr: local kernel unreadable or larger than %llu bytes\n", (unsigned long long)LOCAL_MAX);
    if (pa)
        bs->FreePages(pa, LOCAL_MAX / PAGE);
}

/* ---- one netboot exchange --------------------------------------------------- */
enum { R_SILENT, R_ANSWERED, R_BOOT };

static void new_nonce(uint8_t nonce[16])
{
    static uint64_t ctr;
    uint64_t a = rdtsc() ^ (++ctr << 48), b = a * 0x9e3779b97f4a7c15ull ^ ((uint64_t)mac[5] << 8 | mac[4]);
    memcpy(nonce, &a, 8);
    memcpy(nonce + 8, &b, 8);
}

static void done(const uint8_t nonce[16], uint8_t status, const char *text)
{
    struct nb_msg m = {0};
    size_t n = 0;
    while (text[n] && n < NB_TEXT_MAX)
        n++;
    m.type = NB_DONE;
    memcpy(m.nonce, nonce, 16);
    m.status = status;
    m.len = (uint16_t)n;
    m.data = (const uint8_t *)text;
    int sent = 0;
    for (int i = 0; i < 3; i++)
        sent += net_send(&m) == 0;
    if (sent)
        say("netldr: told the Spark: %s (%d/3 sent)\n", text, sent);
    else
        say("netldr: could not tell the Spark (%s, status 0x%llx)\n", tx_why, (unsigned long long)tx_status);
}

/* Fetch total bytes into obj. 0 complete, -1 gave up. */
static int fetch(const uint8_t nonce[16], uint8_t *obj, uint32_t total)
{
    uint32_t chunks = nb_chunks(total), got = 0, next = 0, strikes = 0, shown = 0;
    memset(have, 0, (chunks + 7) / 8);
    while (got < chunks) {
        while (have[next / 8] & (1u << (next % 8)))
            next++;
        struct nb_msg g = {0}, d;
        g.type = NB_GET;
        memcpy(g.nonce, nonce, 16);
        g.offset = next * NB_CHUNK;
        g.count = (uint16_t)(chunks - next < NB_WINDOW ? chunks - next : NB_WINDOW);
        uint32_t before = got;
        if (net_send(&g) == 0) {
            uint64_t deadline = now_ms() + 300;
            while (net_recv(nonce, deadline, &d) == 0) {
                if (d.type != NB_DATA)
                    continue;
                uint32_t c = d.offset / NB_CHUNK;
                uint32_t want = total - d.offset < NB_CHUNK ? total - d.offset : NB_CHUNK;
                if (d.offset >= total || d.len != want || (have[c / 8] & (1u << (c % 8))))
                    continue;
                memcpy(obj + d.offset, d.data, d.len);
                have[c / 8] |= (uint8_t)(1u << (c % 8));
                got++;
                deadline = now_ms() + 300;
                if (got == chunks || c == next + g.count - 1u)
                    break;
            }
        }
        if (got == before) {
            if (++strikes >= 20) {
                say("netldr: transfer stalled at %u of %u pieces; starting over\n", got, chunks);
                return -1;
            }
        } else {
            strikes = 0;
            watchdog(NETLDR_WATCHDOG_S);
        }
        if (got * 10 / chunks > shown) {
            shown = got * 10 / chunks;
            say("netldr: received %u%%\n", shown * 10);
        }
    }
    return 0;
}

static int exchange(void)
{
    static unsigned last_wait;
    uint8_t nonce[16];
    struct nb_msg h = {0}, r;
    new_nonce(nonce);
    h.type = NB_HELLO;
    memcpy(h.nonce, nonce, 16);
    memcpy(h.mac, mac, 6);
    if (net_send(&h) != 0 || net_recv(nonce, now_ms() + 1000, &r) != 0)
        return R_SILENT;
    if (r.type != NB_WAIT && r.type != NB_OFFER)
        return R_SILENT;
    watchdog(NETLDR_WATCHDOG_S);
    if (r.type == NB_WAIT) {
        if (last_wait != r.seconds)
            say("netldr: the Spark answered: nothing queued; asking again every %u s\n", r.seconds);
        last_wait = r.seconds;
        bs->Stall((uint64_t)r.seconds * 1000000u);
        return R_ANSWERED;
    }
    last_wait = 0;
    uint32_t total = r.total;
    uint64_t pages = (total + PAGE - 1) / PAGE, pa = 0;
    say("netldr: the Spark offers a kernel: %u bytes\n", total);
    if (bs->AllocatePages(AllocateAnyPages, EfiLoaderData, pages, &pa) != EFI_SUCCESS) {
        say("netldr: no memory for %u bytes\n", total);
        done(nonce, 1, "loader out of memory");
        return R_ANSWERED;
    }
    uint8_t *obj = (uint8_t *)(uintptr_t)pa;
    if (fetch(nonce, obj, total) != 0) {
        bs->FreePages(pa, pages);
        return R_ANSWERED;
    }
    const struct ck_slot_manifest *m = (const struct ck_slot_manifest *)obj;
    struct ck_slot_eval ev;
    ck_slot_verify(m, obj + CK_SLOT_UNIT, total - CK_SLOT_UNIT, ck_slot_loader_keys, ck_slot_loader_nkeys, &ev);
    if (ev.valid && m->image_len != total - CK_SLOT_UNIT) {
        ev.valid = 0;
        ev.why = "image_len differs from the bytes received";
    }
    if (!ev.valid) {
        say("netldr: REFUSED the network kernel (%s): nothing was started\n", ev.why ? ev.why : "invalid");
        done(nonce, 1, ev.why ? ev.why : "invalid");
        bs->FreePages(pa, pages);
        bs->Stall(5000000);
        return R_ANSWERED;
    }
    char commit[13];
    memcpy(commit, m->commit, 12);
    commit[12] = 0;
    say("netldr: signature and SHA-512 verified: gen=%llu commit=%s len=%llu\n",
        (unsigned long long)m->generation, commit, (unsigned long long)m->image_len);
    done(nonce, 0, "verified, starting");
    bs->Stall(200000); /* let the last frames leave before the NIC is stopped */
    net_close();
    start_image("network", obj + CK_SLOT_UNIT, m->image_len);
    bs->FreePages(pa, pages);
    return R_BOOT;
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    conout = st->ConOut;
    bs = st->BootServices;
    self = image;
    say("netldr: AIENOS NETLDR v1 commit=%s keys=%u fallback=%us\n", AIENOS_COMMIT, ck_slot_loader_nkeys,
        (unsigned)CK_NETLDR_FALLBACK_S);
    uint64_t t0 = rdtsc();
    bs->Stall(20000);
    tsc_per_ms = (rdtsc() - t0) / 20;
    if (!tsc_per_ms)
        tsc_per_ms = 1;
    watchdog(NETLDR_WATCHDOG_S);
    unsigned round = 0;
    for (;;) {
        if (ck_slot_loader_nkeys == 0 || net_open(round) != 0) {
            say("netldr: %s; starting the kernel on this stick in 10 s\n",
                ck_slot_loader_nkeys == 0 ? "no trusted keys built in" : "no usable network");
            bs->Stall(10000000); /* time to read (or photograph) the lines above */
            start_local();
            say("netldr: nothing started; trying again in 10 s\n");
            bs->Stall(10000000);
            continue;
        }
        /* With several candidate interfaces and no cable link reported, each gets a share. */
        uint64_t window = (uint64_t)(nic_tries > 1 ? 10u : CK_NETLDR_FALLBACK_S) * 1000u;
        say("netldr: asking the Spark for a kernel from %02x:%02x:%02x:%02x:%02x:%02x (ports %u/%u)\n", mac[0],
            mac[1], mac[2], mac[3], mac[4], mac[5], NB_PORT_SERVER, NB_PORT_LOADER);
        uint64_t last = now_ms();
        int r = R_SILENT;
        while (snp && now_ms() - last < window) {
            r = exchange();
            if (r == R_BOOT)
                break;
            if (r == R_ANSWERED)
                last = now_ms();
        }
        if (r == R_BOOT) { /* the network kernel returned: open the network again */
            round = 0;
            continue;
        }
        net_close();
        if (++round < nic_tries) {
            say("netldr: no answer on this interface; trying the next one\n");
            continue;
        }
        round = 0;
        say("netldr: no answer from the Spark (%s); starting the kernel on this stick in 10 s\n",
            tx_why ? tx_why : "frames sent");
        bs->Stall(10000000); /* time to read (or photograph) the lines above */
        start_local();
        say("netldr: back from the local kernel; asking the network again\n");
    }
}
