#ifndef _NGSCOPE_PCAPNG_H_
#define _NGSCOPE_PCAPNG_H_

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Minimal pcapng writer: one Section Header Block, one Interface Description Block, then an
 * Enhanced Packet Block per record, each carrying an optional per-packet comment.
 *
 * srsRAN ships a classic-pcap writer (lib/src/common/pcap.c) and it is reused here for the
 * mac-lte pseudo-header, but not for the file itself, for two reasons: classic pcap has no
 * per-packet comment, and LTE_PCAP_MAC_WritePDU() stamps gettimeofday() at write time rather
 * than the subframe's own timestamp.
 *
 * Records are written in completion order. Decoder threads run different subframes
 * concurrently, so timestamps are not monotonic; pcapng permits that, but Wireshark's
 * rlc-lte/pdcp-lte reassembly is order-dependent, so run `reordercap` before analysis. The
 * reordering window is unbounded (task_scheduler.c parks subframes in a tmp buffer), which is
 * why sorting is not attempted here. */

/* Max LTE transport block is 9422 bytes; plus the 22-byte mac-lte context, a bounded comment
 * and block overhead. 16 KB leaves ample margin and keeps the whole block on the stack. */
#define NGSCOPE_PCAPNG_MAX_BLOCK 16384

/* Bytes buffered before fflush(). Bounds what an abnormal exit can lose; pcapng degrades
 * gracefully, since a reader consumes every complete block and stops at a truncated one. */
#define NGSCOPE_PCAPNG_FLUSH_BLOCKS 256

typedef struct {
    FILE*           fd;
    pthread_mutex_t mutex;
    char            path[1024];
    uint64_t        nof_blocks;
    uint64_t        nof_bytes;
    uint64_t        nof_dropped;   /* oversized, or past max_bytes */
    uint64_t        nof_since_flush;
    uint64_t        max_bytes;     /* 0 = unlimited */
    bool            capped;        /* max_bytes reached; warned once */
    bool            is_open;
} ngscope_pcapng_t;

/* Create the file and write the SHB and one IDB. linktype is a libpcap DLT (147 = DLT_USER0,
 * which Wireshark must be told to dissect as mac-lte-framed). Returns 0 on success. */
int ngscope_pcapng_open(ngscope_pcapng_t* q,
                        const char*       path,
                        uint16_t          linktype,
                        const char*       if_name,
                        const char*       if_desc,
                        uint64_t          max_bytes);

/* Append one Enhanced Packet Block. ts_us is microseconds since the Unix epoch, matching the
 * if_tsresol=6 written by open(). comment may be NULL. Thread-safe: the block is serialised
 * on the caller's stack and only the write is serialised against other threads.
 * Returns 0 if the record was written. */
int ngscope_pcapng_write(ngscope_pcapng_t* q,
                         uint32_t          if_id,
                         uint64_t          ts_us,
                         const uint8_t*    data,
                         uint32_t          len,
                         const char*       comment);

/* Flush and close. Safe to call on a handle that was never opened. */
void ngscope_pcapng_close(ngscope_pcapng_t* q);

#ifdef __cplusplus
}
#endif

#endif
