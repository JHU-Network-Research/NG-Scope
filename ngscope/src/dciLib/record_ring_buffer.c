#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#include "ngscope/hdr/dciLib/record_ring_buffer.h"

extern bool debug;

const uint64_t BUF_FLUSH_THRESHOLD = 2147483648; // flush every 2 GB

int record_ring_buffer_init(record_ring_buffer_t *buf, uint64_t capacity, const char *path){

    buf->buf = (uint8_t*) malloc(capacity);
    buf->capacity = capacity;
    buf->fp = fopen(path,"wb");
    buf->head = 0;
    buf->tail = 0;
    buf->size = 0;
    buf->nof_dropped_inserts = 0;
    buf->nof_dropped_bytes   = 0;
    pthread_mutex_init(&buf->mutex, NULL);
    pthread_cond_init(&buf->cond, NULL);
    buf->flush = false;

    if (debug)
        printf("FLUSH: Created buffer with capacity %ld\n", buf->capacity);

    return 0;
}


int record_ring_buffer_destroy(record_ring_buffer_t *buf){
    free(buf->buf);
    fclose(buf->fp);
    pthread_mutex_destroy(&buf->mutex);
    pthread_cond_destroy(&buf->cond);
    return 0;
}


int record_ring_buffer_insert(record_ring_buffer_t *buf, void *data, size_t size){

    if (debug)
        printf("DEBUG: Writing %ld bytes to buffer of size %ld with capacity %ld\n", size, buf->size, buf->capacity);

    pthread_mutex_lock(&buf->mutex);

    if (size + buf->size> buf->capacity){
        if (debug)
            printf("DEBUG: buffer capacity is not large enough\n");
        // request write exceeds capacity of the buffer
        buf->nof_dropped_inserts++;
        buf->nof_dropped_bytes += size;
        pthread_mutex_unlock(&buf->mutex);
        if (debug)
            printf("FLUSH: Want to write %ld bytes to a buffer of size %ld with capacity %ld, buffer is not large enough\n", size, buf->size, buf->capacity);
        return -1;
    }

    // Check if tail would be overwritten
    // if (buf->head < buf->tail){

    // }else if (buf->head > buf->tail){

    // }


    if (buf->head + size > buf->capacity){
        // has to be split up
        if (debug)
            printf("DEBUG: write to buffer will wrap around\n");
        uint64_t diff = buf->capacity - buf->head;
        memcpy(buf->buf+buf->head, data, diff);
        memcpy(buf->buf, data + diff, size - diff);
        buf->head = size-diff;
        // printf("DEBUG: wrote %d bytes, new buffer size: %d\n", size, buf->size);
    }else{
        // fits in one write
        if (debug)
            printf("DEBUG: Write does not wrap around\n");
        memcpy(buf->buf+buf->head, data, size);

        buf->head += size;
    }
    if (debug)
        printf("FLUSH: old buf size: %ld, wrote %ld bytes, new size: %ld, threshold: %ld\n", buf->size, size, buf->size + size, BUF_FLUSH_THRESHOLD);
    buf->size += size;

    // if (debug)
    //     printf("FLUSH: wrote %ld bytes, new buffer size: %ld\n", size, buf->size);

    if (buf->size > BUF_FLUSH_THRESHOLD){
        buf->flush = true;
        if (debug)
            printf("FLUSH: buffer size %ld over threshold %ld, signaling to flush\n", buf->size, BUF_FLUSH_THRESHOLD);
        pthread_cond_signal(&buf->cond);
    }
    pthread_mutex_unlock(&buf->mutex);

    
    return size;
}


/* Write everything currently buffered to disk.
 *
 * The disk write runs with the mutex RELEASED. It used to hold it for the whole fwrite, and
 * since insert() needs the same mutex, the receive thread stalled for every flush: 2 GB to
 * disk at a time, every ~11.7 s at 10 MHz x 2 channels, long enough for the radio to overflow.
 * Measured on the ny_87_broadway captures as a ~0.5 s sample gap every ~12 s -- the 2 GB
 * threshold divided by the 184 MB/s write rate -- that fragmented into many shorter gaps once
 * kernel writeback throttling set in.
 *
 * Unlocked writing is safe because the region [tail, tail+size) is never touched by insert():
 * it only advances head, and it refuses any write that would push size past capacity -- and
 * size still counts these bytes until they are written. Only this function moves tail, and
 * it has a single caller thread (flush_record and its cleanup handler).
 *
 * size, not head == tail, decides emptiness: a completely full buffer also has head == tail,
 * and the old test skipped flushing it. */
int64_t record_ring_buffer_flush(record_ring_buffer_t *buf){

    pthread_mutex_lock(&buf->mutex);
    uint64_t tail = buf->tail;
    uint64_t size = buf->size;
    pthread_mutex_unlock(&buf->mutex);

    if (debug)
        printf("FLUSH: flushing %ld bytes from buffer\n", size);

    if (size == 0)
        return 0;

    uint64_t first_chunk = buf->capacity - tail;
    if (first_chunk > size)
        first_chunk = size;

    size_t nwritten = fwrite(buf->buf + tail, 1, first_chunk, buf->fp);
    if (nwritten == first_chunk && size > first_chunk)
        nwritten += fwrite(buf->buf, 1, size - first_chunk, buf->fp);
    fflush(buf->fp);

    if (nwritten != size)
        fprintf(stderr, "RECORD: ERROR: wrote %zu of %lu buffered bytes to the recording\n",
                nwritten, (unsigned long)size);

    pthread_mutex_lock(&buf->mutex);
    buf->tail = (tail + nwritten) % buf->capacity;
    buf->size -= nwritten;
    /* Data inserted while the write ran may already be over the threshold again; leaving
     * flush set makes the flush thread go straight round instead of waiting for a signal. */
    if (buf->size < BUF_FLUSH_THRESHOLD)
        buf->flush = false;
    pthread_mutex_unlock(&buf->mutex);

    if (debug)
        printf("FLUSH: done flushing buffer!\n");
    return (int64_t)nwritten;

}
