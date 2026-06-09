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

extern bool rx_debug;


int record_ring_buffer_init(record_ring_buffer_t *buf, uint64_t capacity, const char *path){

    buf->buf = (uint8_t*) malloc(capacity);
    buf->capacity = capacity;
    buf->fp = fopen(path,"wb");
    buf->head = 0;
    buf->tail = 0;
    pthread_mutex_init(&buf->mutex, NULL);
    pthread_cond_init(&buf->cond, NULL);
    buf->flush = false;


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

    if (rx_debug)
        printf("DEBUG: Writing %ld bytes to buffer of size %ld with capacity %ld\n", size, buf->size, buf->capacity);

    pthread_mutex_lock(&buf->mutex);

    if (size + buf->size> buf->capacity){
        if (rx_debug)
            printf("DEBUG: buffer capacity is not large enough\n");
        // request write exceeds capacity of the buffer
        pthread_mutex_unlock(&buf->mutex);
        printf("FLUSH: Want to write %ld bytes to a buffer of size %ld with capacity %ld, buffer is not large enough\n", size, buf->size, buf->capacity);
        return -1;
    }

    // Check if tail would be overwritten
    // if (buf->head < buf->tail){

    // }else if (buf->head > buf->tail){

    // }


    if (buf->head + size > buf->capacity){
        // has to be split up
        if (rx_debug)
            printf("DEBUG: write to buffer will wrap around\n");
        uint64_t diff = buf->capacity - buf->head;
        memcpy(buf->buf+buf->head, data, diff);
        memcpy(buf->buf, data + diff, size - diff);
        buf->head = size-diff;
        // printf("DEBUG: wrote %d bytes, new buffer size: %d\n", size, buf->size);
    }else{
        // fits in one write
        if (rx_debug)
            printf("DEBUG: Write does not wrap around\n");
        memcpy(buf->buf+buf->head, data, size);

        buf->head += size;
    }

    printf("FLUSH: old buf size: %ld, wrote %ld bytes, new size: %ld, threshold: %d\n", buf->size, size, buf->size + size, BUF_FLUSH_THRESHOLD);
    buf->size += size;

    // if (rx_debug)
    //     printf("FLUSH: wrote %ld bytes, new buffer size: %ld\n", size, buf->size);

    if (buf->size > BUF_FLUSH_THRESHOLD){
        buf->flush = true;
        if (rx_debug)
            printf("FLUSH: buffer size %ld over threshold %d, signaling to flush\n", buf->size, BUF_FLUSH_THRESHOLD);
        pthread_cond_signal(&buf->cond);
    }
    pthread_mutex_unlock(&buf->mutex);

    
    return size;
}


int record_ring_buffer_flush(record_ring_buffer_t *buf){

    if (rx_debug)
        printf("FLUSH: flushing %ld bytes from buffer\n", buf->size);

    if (buf->head == buf->tail){
        if (rx_debug){
            printf("FLUSH: Buffer head and tail in same position, nothing to write\n");
        }
        return 0;
    }

    int nwritten;
    if (buf->head > buf->tail){
        if (rx_debug)
            printf("FLUSH: flush does not wrap around\n");

        nwritten = fwrite(buf->buf+buf->tail, 1, buf->head-buf->tail, buf->fp);
        buf->tail += nwritten*1;
        buf->size -= (nwritten*1);
    }else if (buf->head < buf->tail){
        if (rx_debug)
            printf("FLUSH: flush does wrap around\n");
        // nwritten = fwrite(buf->buf+buf->tail, 1, buf->capacity-buf->tail, buf->fp);
        // nwritten += fwrite(buf->buf, 1, buf->head, buf->fp);
        // buf->size -= (nwritten*1);
        // buf->tail += (nwritten*1);
        // buf->tail %= buf->capacity;

        uint64_t first_chunk = buf->capacity - buf->tail;
        int n1 = fwrite(buf->buf + buf->tail, 1, first_chunk, buf->fp);
        int n2 = fwrite(buf->buf, 1, buf->head, buf->fp);
        nwritten = n1 + n2;
        buf->size -= nwritten;
        buf->tail = (n1 == first_chunk) ? n2 : buf->tail + n1;
        buf->tail %= buf->capacity;
    }
    fflush(buf->fp);

    if (buf->size < BUF_FLUSH_THRESHOLD)
        buf->flush = false;

    if (rx_debug)
        printf("FLUSH: done flushing buffer!\n");
    return nwritten;

}
