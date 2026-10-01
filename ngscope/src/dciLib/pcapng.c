#include "ngscope/hdr/dciLib/pcapng.h"

#include <string.h>

/* pcapng block types, PCAP Next Generation Dump File Format section 4. */
#define BLK_SHB 0x0A0D0D0A
#define BLK_IDB 0x00000001
#define BLK_EPB 0x00000006

#define SHB_BYTE_ORDER_MAGIC 0x1A2B3C4D

/* Option codes. 0 terminates every option list that has at least one entry. */
#define OPT_ENDOFOPT 0
#define OPT_COMMENT 1
#define OPT_SHB_USERAPPL 4
#define OPT_IF_NAME 2
#define OPT_IF_DESCRIPTION 3
#define OPT_IF_TSRESOL 9

/* Everything in a pcapng block is 32-bit aligned: option values are padded, packet data is
 * padded, and the block total length is therefore always a multiple of 4. */
#define PAD4(n) (((uint32_t)(n) + 3u) & ~3u)

/* Written natively; the SHB byte-order magic tells the reader which endianness that was, so
 * no swapping is needed on either side. */
static inline void put_u16(uint8_t* p, uint16_t v)
{
    memcpy(p, &v, 2);
}
static inline void put_u32(uint8_t* p, uint32_t v)
{
    memcpy(p, &v, 4);
}
static inline void put_u64(uint8_t* p, uint64_t v)
{
    memcpy(p, &v, 8);
}

/* Append one option: u16 code, u16 length (unpadded), value, zero padding to 4 bytes. */
static uint32_t put_option(uint8_t* buf, uint32_t off, uint16_t code, const void* val, uint16_t len)
{
    put_u16(buf + off, code);
    put_u16(buf + off + 2, len);
    off += 4;
    if (len > 0) {
        memcpy(buf + off, val, len);
        uint32_t padded = PAD4(len);
        memset(buf + off + len, 0, padded - len);
        off += padded;
    }
    return off;
}

static uint32_t put_option_end(uint8_t* buf, uint32_t off)
{
    put_u16(buf + off, OPT_ENDOFOPT);
    put_u16(buf + off + 2, 0);
    return off + 4;
}

/* Stamp the trailing block-total-length and write the block out. A pcapng reader walks the
 * file backwards using that trailer, and Wireshark rejects a block whose two length fields
 * disagree, so both are set from the same value here. Caller holds the mutex. */
static int emit_block(ngscope_pcapng_t* q, uint8_t* buf, uint32_t total)
{
    put_u32(buf + 4, total);
    put_u32(buf + total - 4, total);
    if (fwrite(buf, 1, total, q->fd) != total) {
        return -1;
    }
    q->nof_blocks++;
    q->nof_bytes += total;
    if (++q->nof_since_flush >= NGSCOPE_PCAPNG_FLUSH_BLOCKS) {
        fflush(q->fd);
        q->nof_since_flush = 0;
    }
    return 0;
}

int ngscope_pcapng_open(ngscope_pcapng_t* q,
                        const char*       path,
                        uint16_t          linktype,
                        const char*       if_name,
                        const char*       if_desc,
                        uint64_t          max_bytes)
{
    if (q == NULL || path == NULL) {
        return -1;
    }
    memset(q, 0, sizeof(ngscope_pcapng_t));
    pthread_mutex_init(&q->mutex, NULL);
    snprintf(q->path, sizeof(q->path), "%s", path);
    q->max_bytes = max_bytes;

    q->fd = fopen(path, "wb");
    if (q->fd == NULL) {
        printf("pcapng: failed to open \"%s\" for writing\n", path);
        return -1;
    }
    /* A real buffer matters: this is written from the decode threads, one record per decoded
     * transport block. */
    setvbuf(q->fd, NULL, _IOFBF, 64 * 1024);

    uint8_t  buf[NGSCOPE_PCAPNG_MAX_BLOCK];
    uint32_t off;

    /* ---- Section Header Block ---- */
    put_u32(buf + 0, BLK_SHB);
    put_u32(buf + 8, SHB_BYTE_ORDER_MAGIC);
    put_u16(buf + 12, 1); /* version major */
    put_u16(buf + 14, 0); /* version minor */
    /* Section length unknown: -1 as a signed 64-bit value. */
    put_u64(buf + 16, 0xFFFFFFFFFFFFFFFFULL);
    off = 24;
    static const char userappl[] = "NG-Scope";
    off = put_option(buf, off, OPT_SHB_USERAPPL, userappl, (uint16_t)strlen(userappl));
    off = put_option_end(buf, off);
    off += 4; /* trailing block total length */
    if (emit_block(q, buf, off) != 0) {
        fclose(q->fd);
        q->fd = NULL;
        return -1;
    }

    /* ---- Interface Description Block ---- */
    put_u32(buf + 0, BLK_IDB);
    put_u16(buf + 8, linktype);
    put_u16(buf + 10, 0);      /* reserved */
    put_u32(buf + 12, 65535);  /* snaplen */
    off = 16;
    if (if_name != NULL && if_name[0] != '\0') {
        off = put_option(buf, off, OPT_IF_NAME, if_name, (uint16_t)strlen(if_name));
    }
    if (if_desc != NULL && if_desc[0] != '\0') {
        off = put_option(buf, off, OPT_IF_DESCRIPTION, if_desc, (uint16_t)strlen(if_desc));
    }
    /* if_tsresol = 6: timestamps are microseconds since the Unix epoch, which is exactly what
     * ngscope's timestamp_us() produces, so no conversion is needed on write. */
    const uint8_t tsresol = 6;
    off                   = put_option(buf, off, OPT_IF_TSRESOL, &tsresol, 1);
    off                   = put_option_end(buf, off);
    off += 4;
    if (emit_block(q, buf, off) != 0) {
        fclose(q->fd);
        q->fd = NULL;
        return -1;
    }

    fflush(q->fd);
    q->nof_since_flush = 0;
    q->is_open         = true;
    return 0;
}

int ngscope_pcapng_write(ngscope_pcapng_t* q,
                         uint32_t          if_id,
                         uint64_t          ts_us,
                         const uint8_t*    data,
                         uint32_t          len,
                         const char*       comment)
{
    if (q == NULL || !q->is_open || data == NULL || len == 0) {
        return -1;
    }

    uint32_t clen = (comment != NULL) ? (uint32_t)strlen(comment) : 0;
    if (clen > 1024) {
        clen = 1024; /* truncate rather than drop the record */
    }

    /* 8 header + 20 fixed EPB fields + padded payload + optional comment + endofopt + trailer */
    uint32_t total = 8 + 20 + PAD4(len) + (clen ? 4 + PAD4(clen) : 0) + 4 + 4;
    if (total > NGSCOPE_PCAPNG_MAX_BLOCK) {
        pthread_mutex_lock(&q->mutex);
        q->nof_dropped++;
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }

    /* Serialised on the caller's stack, so the lock below covers only the write. */
    uint8_t  buf[NGSCOPE_PCAPNG_MAX_BLOCK];
    uint32_t off;

    put_u32(buf + 0, BLK_EPB);
    put_u32(buf + 8, if_id);
    put_u32(buf + 12, (uint32_t)(ts_us >> 32));         /* timestamp high */
    put_u32(buf + 16, (uint32_t)(ts_us & 0xFFFFFFFFU)); /* timestamp low  */
    put_u32(buf + 20, len);                             /* captured length */
    put_u32(buf + 24, len);                             /* original length */
    off = 28;
    memcpy(buf + off, data, len);
    memset(buf + off + len, 0, PAD4(len) - len);
    off += PAD4(len);
    if (clen) {
        off = put_option(buf, off, OPT_COMMENT, comment, (uint16_t)clen);
    }
    off = put_option_end(buf, off);
    off += 4;

    int ret;
    pthread_mutex_lock(&q->mutex);
    if (q->max_bytes > 0 && q->nof_bytes + total > q->max_bytes) {
        if (!q->capped) {
            q->capped = true;
            printf("pcapng: \"%s\" reached its %llu MB cap after %llu records; no more will be "
                   "written\n",
                   q->path,
                   (unsigned long long)(q->max_bytes / (1024 * 1024)),
                   (unsigned long long)q->nof_blocks);
        }
        q->nof_dropped++;
        ret = -1;
    } else {
        ret = emit_block(q, buf, off);
    }
    pthread_mutex_unlock(&q->mutex);
    return ret;
}

void ngscope_pcapng_close(ngscope_pcapng_t* q)
{
    if (q == NULL || !q->is_open) {
        return;
    }
    pthread_mutex_lock(&q->mutex);
    if (q->fd != NULL) {
        fflush(q->fd);
        fclose(q->fd);
        q->fd = NULL;
    }
    q->is_open = false;
    pthread_mutex_unlock(&q->mutex);

    /* nof_blocks counts the SHB and IDB as well, so subtract them for the record count. */
    unsigned long long records = (q->nof_blocks >= 2) ? (unsigned long long)(q->nof_blocks - 2) : 0;
    printf("pcapng: %s -- %llu records, %.1f MB",
           q->path,
           records,
           (double)q->nof_bytes / (1024.0 * 1024.0));
    if (q->nof_dropped > 0) {
        printf(", %llu dropped", (unsigned long long)q->nof_dropped);
    }
    printf("\n       records are in decode-completion order, not TTI order -- run "
           "`reordercap %s sorted.pcapng` before RLC/PDCP analysis\n",
           q->path);

    pthread_mutex_destroy(&q->mutex);
}
