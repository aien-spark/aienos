/* netboot_proto.h -- the AIENOS lab netboot wire format (NETLDR.EFI <-> host
 * tools/ck_imac_netboot.c). Freestanding C, no heap, no I/O; the same object
 * is linked into the UEFI loader and the host server.
 *
 * Purpose: put a new test kernel on the iMac without touching the USB stick.
 * NETLDR.EFI stays on the stick as EFI/BOOT/BOOTX64.EFI, asks the LAN for a
 * kernel, verifies it (ck_slot_verify: Ed25519 manifest signature by a key
 * baked in at build time, SHA-512 of the image) and only then starts it.
 * Nothing in these messages is trusted: the transfer only moves bytes, the
 * signature decides. Anyone on the LAN can read the transfer (the kernels are
 * open source) or disturb it (a denial of service, never a takeover).
 *
 * Transport: UDP over IPv4, Ethernet broadcast both ways, so neither side
 * needs an address, ARP or DHCP. The loader sends from 0.0.0.0:NB_PORT_LOADER
 * to 255.255.255.255:NB_PORT_SERVER; the server answers to the subnet
 * broadcast address, port NB_PORT_LOADER. TTL 1: this network only.
 *
 * Message (all integers big-endian), NB_HDR + 8 fixed body bytes minimum:
 *   0 magic "ANB1"  4 type u8  5 reserved[3] = 0  8 nonce[16]
 *   HELLO 1 L->S  24 mac[6] 30 reserved[2]                       (32 bytes)
 *   OFFER 2 S->L  24 total u32 28 chunk u16 = NB_CHUNK 30 rsvd u16  (32)
 *   WAIT  3 S->L  24 seconds u16 (1..NB_WAIT_MAX) 26 reserved[6]   (32)
 *   GET   4 L->S  24 offset u32 28 count u16 (1..NB_WINDOW) 30 rsvd (32)
 *   DATA  5 S->L  24 offset u32 28 len u16 30 rsvd u16 32 data[len] (32 + len)
 *   DONE  6 L->S  24 status u8 (0 verified, booting; 1 refused) 25 rsvd[7]
 *                 32 text[n], n <= NB_TEXT_MAX printable ASCII     (32 + n)
 * The nonce is chosen by the loader for each attempt and echoed by the server;
 * it pairs replies with requests and is not a secret.
 * The object served is a signed slot manifest (CK_SLOT_UNIT bytes,
 * slot_format.h) followed by the image: total = CK_SLOT_UNIT + image_len.
 * DATA offsets are multiples of NB_CHUNK; every chunk but the last is full. */
#ifndef AIENOS_NETBOOT_PROTO_H
#define AIENOS_NETBOOT_PROTO_H
#include <stddef.h>
#include <stdint.h>

#define NB_MAGIC "ANB1"
#define NB_PORT_SERVER 47032u
#define NB_PORT_LOADER 47033u
#define NB_HDR 24u
#define NB_MIN 32u
#define NB_CHUNK 1024u
#define NB_WINDOW 16u
#define NB_WAIT_MAX 60u
#define NB_TEXT_MAX 96u
#define NB_OBJECT_MIN (4096u + 1u)
#define NB_OBJECT_MAX (64u << 20)
#define NB_MSG_MAX (NB_MIN + NB_CHUNK)

enum nb_type { NB_HELLO = 1, NB_OFFER, NB_WAIT, NB_GET, NB_DATA, NB_DONE };

struct nb_msg {
    uint8_t type;
    uint8_t nonce[16];
    uint8_t mac[6];         /* HELLO */
    uint32_t total;         /* OFFER */
    uint16_t seconds;       /* WAIT */
    uint32_t offset;        /* GET, DATA */
    uint16_t count;         /* GET */
    uint16_t len;           /* DATA bytes, DONE text bytes */
    uint8_t status;         /* DONE */
    const uint8_t *data;    /* DATA payload or DONE text: a view into the parsed buffer, or the bytes to send */
};

/* Encode m into out. Returns the message length, or 0 if m breaks a rule
 * above or cap is too small. */
size_t nb_build(const struct nb_msg *m, uint8_t *out, size_t cap);
/* Decode and check one message. Returns 0 and fills *m, or -1 for anything
 * malformed (wrong magic, nonzero reserved bytes, unknown type, wrong length,
 * out-of-range field, unprintable text). */
int nb_parse(const uint8_t *b, size_t len, struct nb_msg *m);
/* Number of NB_CHUNK pieces in an object of total bytes. */
static inline uint32_t nb_chunks(uint32_t total) { return (total + NB_CHUNK - 1u) / NB_CHUNK; }

#endif /* AIENOS_NETBOOT_PROTO_H */
