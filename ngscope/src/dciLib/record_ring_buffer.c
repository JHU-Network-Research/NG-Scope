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
// #include "ngscope/hdr/dciLib/ngscope_rx.h"

extern bool debug;


int record_ring_buffer_init(record_ring_buffer_t *buf, uint64_t capacity, const char *path){

    buf->buf = (uint8_t*) malloc(capacity);
    buf->capacity = capacity;
    buf->fp = fopen(path,"wb");
    buf->head = 0;
    buf->tail = 0;
    pthread_mutex_init(&buf->mutex, NULL);
    pthread_cond_init(&buf->cond, NULL);
    // buf->mutex = PTHREAD_MUTEX_INITIALIZER;
    // buf->cond = PTHREAD_COND_INITIALIZER;
    buf->flush = false;

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

    if(size == 24){
        printf("DEBUG: writing header\n");
        uint64_t nof_samples_check;
        uint64_t ts_full_check;
        double ts_frac_check;
        memcpy(&nof_samples_check, data, sizeof(uint64_t));
        memcpy(&ts_full_check, data+sizeof(uint64_t), sizeof(uint64_t));
        memcpy(&ts_frac_check, data+sizeof(uint64_t)+sizeof(uint64_t), sizeof(double));
        printf("DEBUG: writing frame header with nof_samples=%ld, tv_sec: %ld, tv_frac=%.f\n", nof_samples_check,ts_full_check, ts_frac_check);
        if (nof_samples_check != 11520){
            printf("DEBUG: ERROR header has incorrect number of samples: %ld\n", nof_samples_check);
        }
    }

    if (debug)
        printf("DEBUG: Writing %ld bytes to buffer of size %ld with capacity %ld\n", size, buf->size, buf->capacity);

    pthread_mutex_lock(&buf->mutex);

    if (size > buf->capacity){
        if (debug)
            printf("DEBUG: buffer capacity is not large enough\n");
        // request write exceeds capacity of the buffer
        pthread_mutex_unlock(&buf->mutex);
        return -1;
    }

    // Check if tail would be overwritten
    if (buf->head < buf->tail){

    }else if (buf->head > buf->tail){

    }


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


        if(size == 24){
            printf("DEBUG: wrote header\n");
            uint64_t nof_samples_check;
            uint64_t ts_full_check;
            double ts_frac_check;
            memcpy(&nof_samples_check, buf->buf+buf->head, sizeof(uint64_t));
            memcpy(&ts_full_check, buf->buf+buf->head+sizeof(uint64_t), sizeof(uint64_t));
            memcpy(&ts_frac_check, buf->buf+buf->head+sizeof(uint64_t)+sizeof(uint64_t), sizeof(double));
            printf("DEBUG: wrote frame header with nof_samples=%ld, tv_sec: %ld, tv_frac=%.f\n", nof_samples_check,ts_full_check, ts_frac_check);
            if (nof_samples_check != 11520){
                printf("DEBUG: ERROR header has incorrect number of samples: %ld\n", nof_samples_check);
            }
        }
        
        buf->head += size;
    }

    buf->size += size;

    pthread_mutex_unlock(&buf->mutex);
    if (debug)
        printf("DEBUG: wrote %ld bytes, new buffer size: %ld\n", size, buf->size);

    if (buf->size > BUF_FLUSH_THRESHOLD){
        buf->flush = true;
        if (debug)
            printf("DEBUG: buffer size %ld over threshold %d, signaling to flush\n", buf->size, BUF_FLUSH_THRESHOLD);
        pthread_cond_signal(&buf->cond);
    }

    
    return size;
}


int record_ring_buffer_flush(record_ring_buffer_t *buf){

    // pthread_mutex_lock(&buf->mutex);
    // if (debug)
    printf("DEBUG: flushing %ld bytes from buffer\n", buf->size);

    if (buf->head == buf->tail){
        // pthread_mutex_unlock(&buf->mutex);
        return 0;
    }

    int nwritten;
    if (buf->head > buf->tail){
        if (debug)
            printf("DEBUG: flush does not wrap around\n");

        // debug block
        uint64_t nof_samples_check;
        uint64_t ts_full_check;
        double ts_frac_check;
        memcpy(&nof_samples_check, buf->buf+buf->tail, sizeof(uint64_t));
        memcpy(&ts_full_check, buf->buf+buf->tail+sizeof(uint64_t), sizeof(uint64_t));
        memcpy(&ts_frac_check, buf->buf+buf->tail+sizeof(uint64_t)+sizeof(uint64_t), sizeof(double));
        printf("DEBUG: initial frame header has nof_samples=%ld, tv_sec: %ld, tv_frac=%.f\n", nof_samples_check,ts_full_check, ts_frac_check);
        if (nof_samples_check != 11520){
            printf("DEBUG: ERROR header has incorrect number of samples: %ld\n", nof_samples_check);
        }


        nwritten = fwrite(buf->buf+buf->tail, 1, buf->head-buf->tail, buf->fp);
        buf->tail += nwritten*1;
        buf->size -= (nwritten*1);
    }else if (buf->head < buf->tail){
        if (debug)
            printf("DEBUG: flush does wrap around\n");
        nwritten = fwrite(buf->buf+buf->tail, 1, buf->capacity-buf->tail, buf->fp);
        nwritten += fwrite(buf->buf, 1, buf->head, buf->fp);
        buf->size -= (nwritten*1);
        buf->tail += (nwritten*1);
        buf->tail %= buf->capacity;
    }
    fflush(buf->fp);

    if (buf->size < BUF_FLUSH_THRESHOLD)
        buf->flush = false;

    if (debug)
        printf("DEBUG: done flushing buffer!\n");
    // pthread_mutex_unlock(&buf->mutex);
    return nwritten;

}
