/* netboot_proto.c -- encode and check AIENOS lab netboot messages
 * (netboot_proto.h is the wire spec). Freestanding: no heap, no I/O. */
#include "netboot_proto.h"

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static int zero(const uint8_t *p, size_t n)
{
    uint8_t a = 0;
    for (size_t i = 0; i < n; i++)
        a |= p[i];
    return a == 0;
}

static int printable(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p[i] < 0x20 || p[i] > 0x7e)
            return 0;
    return 1;
}

/* The field rules shared by build and parse. */
static int fields_ok(const struct nb_msg *m)
{
    switch (m->type) {
    case NB_HELLO:
        return 1;
    case NB_OFFER:
        return m->total >= NB_OBJECT_MIN && m->total <= NB_OBJECT_MAX;
    case NB_WAIT:
        return m->seconds >= 1 && m->seconds <= NB_WAIT_MAX;
    case NB_GET:
        return m->count >= 1 && m->count <= NB_WINDOW && m->offset % NB_CHUNK == 0 && m->offset < NB_OBJECT_MAX;
    case NB_DATA:
        return m->len >= 1 && m->len <= NB_CHUNK && m->offset % NB_CHUNK == 0 && m->offset < NB_OBJECT_MAX &&
               (m->data != 0);
    case NB_DONE:
        return m->status <= 1 && m->len <= NB_TEXT_MAX && (m->len == 0 || (m->data && printable(m->data, m->len)));
    default:
        return 0;
    }
}

size_t nb_build(const struct nb_msg *m, uint8_t *out, size_t cap)
{
    size_t n = NB_MIN + (m && (m->type == NB_DATA || m->type == NB_DONE) ? m->len : 0);
    if (!m || !out || !fields_ok(m) || cap < n)
        return 0;
    for (size_t i = 0; i < NB_MIN; i++)
        out[i] = 0;
    for (size_t i = 0; i < 4; i++)
        out[i] = (uint8_t)NB_MAGIC[i];
    out[4] = m->type;
    for (size_t i = 0; i < 16; i++)
        out[8 + i] = m->nonce[i];
    switch (m->type) {
    case NB_HELLO:
        for (size_t i = 0; i < 6; i++)
            out[24 + i] = m->mac[i];
        break;
    case NB_OFFER:
        put32(out + 24, m->total);
        put16(out + 28, NB_CHUNK);
        break;
    case NB_WAIT:
        put16(out + 24, m->seconds);
        break;
    case NB_GET:
        put32(out + 24, m->offset);
        put16(out + 28, m->count);
        break;
    case NB_DATA:
        put32(out + 24, m->offset);
        put16(out + 28, m->len);
        break;
    case NB_DONE:
        out[24] = m->status;
        break;
    }
    for (size_t i = 0; i < n - NB_MIN; i++)
        out[NB_MIN + i] = m->data[i];
    return n;
}

int nb_parse(const uint8_t *b, size_t len, struct nb_msg *m)
{
    if (!b || !m || len < NB_MIN || len > NB_MSG_MAX)
        return -1;
    for (size_t i = 0; i < 4; i++)
        if (b[i] != (uint8_t)NB_MAGIC[i])
            return -1;
    if (!zero(b + 5, 3))
        return -1;
    *m = (struct nb_msg){0};
    m->type = b[4];
    for (size_t i = 0; i < 16; i++)
        m->nonce[i] = b[8 + i];
    switch (m->type) {
    case NB_HELLO:
        if (len != NB_MIN || !zero(b + 30, 2))
            return -1;
        for (size_t i = 0; i < 6; i++)
            m->mac[i] = b[24 + i];
        break;
    case NB_OFFER:
        if (len != NB_MIN || get16(b + 28) != NB_CHUNK || !zero(b + 30, 2))
            return -1;
        m->total = get32(b + 24);
        break;
    case NB_WAIT:
        if (len != NB_MIN || !zero(b + 26, 6))
            return -1;
        m->seconds = get16(b + 24);
        break;
    case NB_GET:
        if (len != NB_MIN || !zero(b + 30, 2))
            return -1;
        m->offset = get32(b + 24);
        m->count = get16(b + 28);
        break;
    case NB_DATA:
        if (!zero(b + 30, 2))
            return -1;
        m->offset = get32(b + 24);
        m->len = get16(b + 28);
        if (len != NB_MIN + (size_t)m->len)
            return -1;
        m->data = b + NB_MIN;
        break;
    case NB_DONE:
        if (!zero(b + 25, 7))
            return -1;
        m->status = b[24];
        m->len = (uint16_t)(len - NB_MIN);
        m->data = b + NB_MIN;
        break;
    default:
        return -1;
    }
    return fields_ok(m) ? 0 : -1;
}
