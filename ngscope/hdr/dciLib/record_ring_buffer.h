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

    /* Inserts refused because the buffer was full: the disk fell more than `capacity` behind.
     * Each one is samples (or a frame header) missing from the file, so it is reported at
     * teardown rather than dropped silently. */
    uint64_t nof_dropped_inserts;
    uint64_t nof_dropped_bytes;

}record_ring_buffer_t;



int record_ring_buffer_init(record_ring_buffer_t *buf, uint64_t capacity, const char *path);
int record_ring_buffer_destroy(record_ring_buffer_t *buf);

int record_ring_buffer_insert(record_ring_buffer_t *buf, void *data, size_t size);
/* Call WITHOUT holding buf->mutex: it takes the lock only to snapshot and to advance tail,
 * and does the disk write unlocked so insert() never waits on the disk. Single flusher only. */
int64_t record_ring_buffer_flush(record_ring_buffer_t *buf);