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

#include "srsran/srsran.h"

#define BUF_FLUSH_THRESHOLD 8*1024*1024 // flush every 8 mb

typedef struct {
    FILE *fp;
    uint64_t capacity;
    uint64_t size;
    uint64_t head;
    uint64_t tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool flush;
    uint8_t *buf;

}record_ring_buffer_t;



int record_ring_buffer_init(record_ring_buffer_t *buf, uint64_t capacity, const char *path);
int record_ring_buffer_destroy(record_ring_buffer_t *buf);

int record_ring_buffer_insert(record_ring_buffer_t *buf, void *data, size_t size);
int record_ring_buffer_flush(record_ring_buffer_t *buf);