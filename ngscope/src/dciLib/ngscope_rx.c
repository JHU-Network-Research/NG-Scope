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
#include <execinfo.h>
#include <errno.h>

#include "srsran/srsran.h"

#include "ngscope/hdr/dciLib/ngscope_rx.h"
#include "ngscope/hdr/dciLib/load_config.h"
#include "ngscope/hdr/dciLib/record_ring_buffer.h"

const uint64_t RECORD_BUF_CAP = 1024*1024*80;
// const uint64_t flush_thresh = 1024*1024*8;
// static uint8_t record_buf[RECORD_BUF_CAP];
// static uint64_t rb_in_pos = 0;
// static uint64_t rb_out_pos = 0;
// pthread_mutex_t rb_mutex = PTHREAD_MUTEX_INITIALIZER;
// pthread_cond_t rb_cond = PTHREAD_COND_INITIALIZER;

record_ring_buffer_t record_buf;

/* ue_sync does not always ask for exactly one subframe: while re-acquiring PSS or applying a
 * timing correction it requests a longer block, and the recorder faithfully stores frames of
 * that size. The buffer therefore has to cover the largest read the task scheduler can ask
 * for, which is 3 * SRSRAN_SF_LEN_PRB(cell.nof_prb) (see task_scheduler.c:506). Sizing this
 * for a single 100-PRB subframe used to overflow it on the first oversized frame. */
#define REPLAY_BUF_NOF_SAMPLES (3 * SRSRAN_SF_LEN_MAX)

pthread_t flush_thread;

const char *record_path;
const char *replay_path;

uint64_t read_ctr = 0;

ngscope_mode_t  mode       = NORMAL;
// static uint64_t total_bytes_fetched = 0;
// static struct timespec last_rx_time  = {0, 0};
static FILE*    replay_fh  = NULL;  // used only for REPLAY
// static FILE*    outfp = NULL;
/* Channels present in the stream: what a recording's header says it holds, or what the SDR
 * was opened with. Distinct from rx_nof_rx_ant below, which is what the decoder asked for.
 * Conflating the two is what made a mismatch corrupt the stream instead of degrading it. */
static uint32_t sdr_nof_ports = SRSRAN_MAX_PORTS;

/* Channels the decoder allocated buffers for, i.e. nof_rx_ant.
 *
 * It bounds every write through ptr[]. `ptr[i] != NULL` is NOT a valid test for "this channel
 * has a buffer": the array behind it is not always SRSRAN_MAX_PORTS long -- cell search
 * passes a shorter one -- so reading past the end returns garbage that is not NULL, and
 * writing through it smashes the caller's stack. */
static uint32_t rx_nof_rx_ant = 1;

void ngscope_rx_set_nof_rx_ant(uint32_t n)
{
  rx_nof_rx_ant = (n >= 1 && n <= SRSRAN_MAX_PORTS) ? n : 1;
}

static uint64_t         last_replay_ts_full = 0;
static double           last_replay_ts_frac = 0.0;
static struct timespec  last_replay_return  = {0, 0};
static uint64_t frame_count = 0;
static uint64_t nreplayed = 0;
static uint64_t nrecorded = 0;
static bool     warned_short_stream = false;

bool __attribute__((weak)) go_exit = false;
bool __attribute__((weak)) debug = false;


bool init_record(const char* path, uint32_t buf_size_gb, uint32_t nof_ports, double rf_freq)
{
  record_path = path;
  mode = RECORD;
  sdr_nof_ports = nof_ports;
  uint64_t buf_size = (uint64_t) ONE_GB*buf_size_gb;
  if (debug)
    printf("FLUSH: ONE_GB: %d, requested capacity GB: %d, TOTAL SIZE: %ld\n", ONE_GB, buf_size_gb, buf_size);

  record_ring_buffer_init(&record_buf, buf_size, path);

  struct timespec ts;

  if ( clock_gettime( CLOCK_REALTIME, &ts ) < 0 ) {
    perror( "clock_gettime" );
    exit( 1 );
  }

  uint64_t ct = ts.tv_sec * 1000000000 + ts.tv_nsec;

  rx_record_header_t hdr;
  hdr.nof_rx_antenna = nof_ports;
  hdr.rf_freq = rf_freq;
  hdr.record_start_ns = ct;

  hdr.pci = 0;
  hdr.prb = 0;
  hdr.record_duration_ns = 0;
  hdr.frame_type = 0;
  hdr.nof_cell_ports = 0;
  hdr.cp = 0;
  hdr.phich_length = 0;
  hdr.phich_resources = 0;
  hdr.decoded_frames = 0;
  hdr.desynced_frames = 0;
  hdr.skipped_frames = 0;
  hdr.first_sync_frame = 0;
  memset(hdr.comment,0,1024);
  memset(hdr.location,0,1024);


  record_ring_buffer_insert(&record_buf, &hdr, sizeof(hdr));

//   outfp = fopen(path, "wb");

  pthread_create(&flush_thread, NULL, (void*)flush_record, &record_buf);

  return true;
}

/* ------------------------------------------------------------ compressed replay
 *
 * A recording may be handed over compressed. The replay reads strictly forward -- a header,
 * then its payload, and the only seek is a forward skip over a payload it has decided not
 * to use -- so a decompression stream serves it as well as a file, provided the skip is
 * implemented by reading and discarding rather than by fseek().
 *
 * Decompression runs in a subprocess rather than in-process, and that is a throughput
 * decision, not a convenience one. Measured on this machine over 300 MB of IQ:
 *
 *     bzip2  -dc   34 MB/s     (single-threaded; what linking libbz2 would give)
 *     lbzip2 -dc  400 MB/s     (16 threads)
 *     replay consumes ~97 MB/s
 *
 * So the obvious implementation -- link libbz2 and decode inline -- would have made every
 * replay about three times slower, while a parallel decompressor leaves fourfold headroom.
 * A slow source cannot corrupt a measurement, because the replay scheduler blocks on a busy
 * decoder rather than discarding subframes, but it does cost wall time on every run.
 *
 * The parallel tool is preferred and the serial one is the fallback, so this works on a host
 * that has only the latter -- just slower, and it says so. gzip and xz are listed too: the
 * mechanism is identical and leaving them out would be an arbitrary limitation.
 *
 * IQ compresses poorly -- bzip2 gets a recording to about 46% of its original size -- so
 * this trades a lot of CPU for a moderate saving. Worth it for archived captures, rarely
 * worth it for one being iterated on. */

static bool     replay_is_pipe   = false;
static uint32_t rs_hdr_prb       = 0;     /* the recording header's PRB, 0 if none */
/* Time spent blocked reading the recording, against wall time. The question "is the
 * decompressor the bottleneck?" has no general answer -- it depends on the cell's sample
 * rate and on how much work the decode settings ask for -- so it is measured rather than
 * predicted. Single-threaded and per device, like replay_fh itself. */
static uint64_t replay_read_ns   = 0;
static uint64_t replay_bytes     = 0;
static uint64_t replay_start_ns  = 0;

static uint64_t replay_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* fread() on the recording, timed. */
static size_t replay_fread(void* dst, size_t size, size_t nmemb)
{
    const uint64_t t0 = replay_now_ns();
    const size_t   n  = fread(dst, size, nmemb, replay_fh);
    replay_read_ns += replay_now_ns() - t0;
    replay_bytes   += n * size;
    return n;
}

static const struct {
    const char* ext;
    const char* cmds[3]; /* preferred first; NULL-terminated */
} REPLAY_CODECS[] = {
    {".bz2", {"lbzip2", "bzip2", NULL}},
    {".gz",  {"pigz",   "gzip",  NULL}},
    {".xz",  {"xz",     NULL,    NULL}},
};

/* PATH lookup without spawning anything: popen() would report a missing decompressor only
 * as an empty stream, which is indistinguishable here from an empty recording. */
static bool replay_have_cmd(const char* cmd)
{
    const char* path = getenv("PATH");
    if (path == NULL) {
        return false;
    }
    char buf[4096];
    snprintf(buf, sizeof(buf), "%s", path);
    for (char* dir = strtok(buf, ":"); dir != NULL; dir = strtok(NULL, ":")) {
        char full[4352];
        snprintf(full, sizeof(full), "%s/%s", dir, cmd);
        if (access(full, X_OK) == 0) {
            return true;
        }
    }
    return false;
}

static bool replay_ends_with(const char* s, const char* suffix)
{
    const size_t ls = strlen(s), lx = strlen(suffix);
    return ls >= lx && strcasecmp(s + ls - lx, suffix) == 0;
}

static bool replay_stream_init(void);

bool init_replay(const char* path, rx_record_header_t* hdr, uint32_t nof_ports)
{
    replay_path     = path;
    mode            = REPLAY;
    replay_is_pipe  = false;
    replay_fh       = NULL;
    replay_read_ns  = 0;
    replay_bytes    = 0;
    replay_start_ns = replay_now_ns();

    const char* cmd = NULL;
    for (size_t i = 0; i < sizeof(REPLAY_CODECS) / sizeof(REPLAY_CODECS[0]); i++) {
        if (!replay_ends_with(path, REPLAY_CODECS[i].ext)) {
            continue;
        }
        for (int c = 0; REPLAY_CODECS[i].cmds[c] != NULL; c++) {
            if (replay_have_cmd(REPLAY_CODECS[i].cmds[c])) {
                cmd = REPLAY_CODECS[i].cmds[c];
                if (c > 0) {
                    /* Whether single-threaded decompression actually limits the run depends
                     * on the cell's sample rate and how hard the decoder is working, which
                     * this cannot know in advance. So say what was picked and let the
                     * teardown report which side was the limiter. */
                    printf("REPLAY: %s not found; using %s (single-threaded). The teardown "
                           "reports whether it limited the run.\n",
                           REPLAY_CODECS[i].cmds[0], cmd);
                }
                break;
            }
        }
        if (cmd == NULL) {
            fprintf(stderr, "REPLAY: ERROR: %s is compressed but no decompressor for '%s' "
                            "is on PATH (looked for %s)\n",
                    path, REPLAY_CODECS[i].ext, REPLAY_CODECS[i].cmds[0]);
            return false;
        }
        break;
    }

    if (cmd == NULL) {
        replay_fh = fopen(path, "rb");
        if (replay_fh == NULL) {
            fprintf(stderr, "REPLAY: ERROR: cannot open %s: %s\n", path, strerror(errno));
            return false;
        }

    }else {
        /* Single-quote the path and escape any embedded quote, so a filename with a space or a
         * shell metacharacter cannot turn into a command. */
        char quoted[2048];
        size_t q = 0;
        quoted[q++] = '\'';
        for (const char* c = path; *c != '\0' && q + 4 < sizeof(quoted); c++) {
            if (*c == '\'') {
                q += (size_t)snprintf(quoted + q, sizeof(quoted) - q, "'\\''");
            } else {
                quoted[q++] = *c;
            }
        }
        quoted[q++] = '\'';
        quoted[q]   = '\0';

        char argv[2304];
        snprintf(argv, sizeof(argv), "%s -dc -- %s", cmd, quoted);
        replay_fh = popen(argv, "r");
        if (replay_fh == NULL) {
            fprintf(stderr, "REPLAY: ERROR: cannot start '%s': %s\n", argv, strerror(errno));
            return false;
        }
        replay_is_pipe = true;
        printf("REPLAY: decompressing %s through %s\n", path, cmd);
    }

    if (hdr != NULL){

        int n = fread(hdr, sizeof(rx_record_header_t), 1, replay_fh);
        printf("Size of header: %ld\n", sizeof(rx_record_header_t));
        printf("Read replay header with result %d\n", n);
        printf("\tnof_rx_antenna:\t%d\n", hdr->nof_rx_antenna);
        printf("\trf_freq:\t%f\n",hdr->rf_freq);

        if (n != 1){
            if (n < 1)
                fprintf(stderr, "ERROR: cannot read record file header\n");
            else if (n > 1)
                fprintf(stderr, "ERROR: read too large for recording header: %d", n);
            return false;
        }

        if (hdr->nof_rx_antenna < 1 || hdr->nof_rx_antenna > SRSRAN_MAX_PORTS){
            fprintf(stderr, "ERROR: Invalid # rx antenna: %d", hdr->nof_rx_antenna);
            return false;
        }

        printf("Replaying file: %s\n", path);
        printf("\tnof_rx_antenna: %d\n",hdr->nof_rx_antenna);
        printf("\trf_freq: %.02f\n", hdr->rf_freq);
        printf("\trecord start (us): %ld\n", hdr->record_start_ns);
        printf("\trecord duration (us): %ld\n", hdr->record_duration_ns);
        printf("\tnof decoded frames:\t%d\n",hdr->decoded_frames);
        printf("\tnof desynced frames:\t%d\n", hdr->desynced_frames);
        printf("\tnof skipped frames:\t%d\n", hdr->skipped_frames);
        printf("\tfirst synced frame:\t%d\n", hdr->first_sync_frame);
        printf("\tCell info:\n");
        printf("\t\tpci:\t%d\n",hdr->pci);
        printf("\t\tprb:\t%d\n",hdr->prb);
        printf("\t\tnof_ports:\t%d\n", hdr->nof_cell_ports);
        printf("\t\tframe type:\t%s\n",hdr->frame_type == SRSRAN_FDD ? "FDD" : "TDD");
        printf("\t\tcp:\t%s\n",srsran_cp_string(hdr->cp));
        printf("\t\tphich length:\t%s\n",hdr->phich_length == SRSRAN_PHICH_EXT ? "Extended" : "Normal");
        printf("\t\tphich resources:\t");
        switch (hdr->phich_resources) {
          case SRSRAN_PHICH_R_1_6:
            printf("1/6\n");
            break;
          case SRSRAN_PHICH_R_1_2:
            printf("1/2\n");
            break;
          case SRSRAN_PHICH_R_1:
            printf("1\n");
            break;
          case SRSRAN_PHICH_R_2:
            printf("2\n");
            break;
        }
        printf("\tlocation:\t%s\n",hdr->location);
        printf("\tcomment:\t%s\n",hdr->comment);



        sdr_nof_ports = hdr->nof_rx_antenna;
        rs_hdr_prb    = hdr->prb;
    }else{
        /* No header, so the file cannot say how many channels it holds -- and guessing the
         * configured nof_rx_ant, which is what this used to do, is the one guess that can
         * corrupt the stream: the read loop would consume a second channel's worth of bytes
         * per frame from a single-channel file, land the next header read inside the IQ, and
         * never resynchronise. It surfaced as "Could not find any cell in this frequency",
         * which reads as weak signal.
         *
         * Every headerless recording predates multi-channel record, so it holds exactly one
         * channel. Take that, and let the mismatch handling below zero-fill the rest. */
        sdr_nof_ports = 1;
        if (nof_ports != 1) {
            printf("REPLAY: no recording header, so assuming 1 channel in the file (%u "
                   "requested; the extra will be zero-filled)\n", nof_ports);
        }
    }

    return replay_stream_init();
}

/* Forward skip over a payload the caller has decided not to use. fseek() cannot do this on
 * a pipe, and silently doing nothing there would leave the next header read landing inside
 * the IQ samples, from which the stream never recovers. */
static void replay_skip(long nbytes)
{
    if (nbytes <= 0 || replay_fh == NULL) {
        return;
    }
    if (!replay_is_pipe) {
        fseek(replay_fh, nbytes, SEEK_CUR);
        return;
    }
    char   scratch[64 * 1024];
    size_t left = (size_t)nbytes;
    while (left > 0) {
        const size_t want = left < sizeof(scratch) ? left : sizeof(scratch);
        const size_t got  = fread(scratch, 1, want, replay_fh);
        if (got == 0) {
            return; /* EOF or error; the caller's next read reports it */
        }
        left -= got;
    }
}

/* ===================================================================== continuous replay
 *
 * Replay serves the recording as ONE continuous sample stream, cut to whatever size the
 * synchronizer asks for -- not in the chunks the recorder happened to read.
 *
 * It used to hand back recorded chunks verbatim and skip any chunk whose size differed from
 * the request. Every step of re-acquiring a cell needs an odd-sized read (the realign after a
 * PSS is found, each timing correction), so a replay could never re-sync where the recorder
 * had not: it inherited every recording-time sync failure. Measured on
 * ny_87_broadway/buffer/earfcn-9820/2026_10_11_13_21_02: PSS present in all 180 s, the
 * recorder lost sync at 38.1 s for good, and the replay decoded 3 s of it.
 *
 * The recorder writes every read with its radio timestamp, so the file is the radio's sample
 * stream minus whatever the radio itself dropped -- and the timestamps say exactly where:
 *
 * Radio timestamps are exact sample ticks, so anything beyond half a sample is real.
 *
 *   gap       the next chunk starts later than this one ends. Zero-filled for its duration,
 *             so timing stays continuous and tracking can survive it (a splice would shift the
 *             timing by an arbitrary amount). Capped at REPLAY_GAP_CAP_S per gap.
 *   overlap   the next chunk starts before this one ends. The overlap is dropped.
 *   rate      the cell search runs at 1.92 Msps and the cell at its own rate, so the stream
 *             changes rate once. Recognised as chunk spacing that matches a different standard
 *             LTE rate exactly; allowed once, and only upward. It is only visible once the
 *             chunk after the switch arrives, so reads inside the first cell-rate chunk are
 *             timestamped at the old rate -- about 1 ms, while the synchronizer is still in
 *             FIND and nothing is decoded.
 *
 * Every one of these is counted and reported by stop_replay(). */

#define REPLAY_GAP_CAP_S 2.0

static cf_t*              rs_buf[SRSRAN_MAX_PORTS]; /* one recorded chunk, per channel */
static uint64_t           rs_chunk_n   = 0;
static uint64_t           rs_pos       = 0;
static srsran_timestamp_t rs_chunk_ts;
static bool               rs_have_chunk = false;
static double             rs_rate      = 0.0;      /* samples/s; 0 until the 2nd chunk */
static uint64_t           rs_zero_left = 0;        /* zero-fill pending before rs_pos */
static srsran_timestamp_t rs_zero_ts;
static bool               rs_eof       = false;

static uint64_t rs_nof_chunks = 0, rs_nof_reads = 0, rs_nof_spanning = 0;
static uint64_t rs_nof_gaps = 0, rs_gap_samples = 0, rs_nof_capped = 0;
static double   rs_gap_max_s = 0.0, rs_gap_total_s = 0.0;
static uint64_t rs_nof_overlaps = 0, rs_overlap_samples = 0;
static uint64_t rs_nof_rate_changes = 0, rs_nof_oversized = 0;
static double   rs_rate_first = 0.0;

static const double LTE_RATES[] = {1.92e6, 3.84e6, 5.76e6, 11.52e6, 15.36e6, 23.04e6, 30.72e6};

/* The standard LTE rate within `tol` (relative) of r, or 0. */
static double rs_std_rate(double r, double tol)
{
    for (size_t i = 0; i < sizeof(LTE_RATES) / sizeof(LTE_RATES[0]); i++) {
        if (fabs(r - LTE_RATES[i]) <= tol * LTE_RATES[i]) {
            return LTE_RATES[i];
        }
    }
    return 0.0;
}

static double rs_ts_diff(const srsran_timestamp_t* a, const srsran_timestamp_t* b)
{
    return (double)(a->full_secs - b->full_secs) + (a->frac_secs - b->frac_secs);
}

/* Rate used to place samples in time. Before it is known (inside the very first chunk) the
 * stream can only be the cell search, which srsRAN always runs at 1.92 Msps. */
static double rs_rate_or_default(void)
{
    return rs_rate > 0 ? rs_rate : 1.92e6;
}

/* The cell's sample rate must match the rate the recording was made at, or nothing in it can be
 * decoded. Replay never sets a rate: the stream is served exactly as recorded, so a cell the
 * decoder believes is wider than the recording reads several recorded milliseconds per
 * subframe, never synchronises, and used to run to the end of the file in silence -- then hang
 * at shutdown, since no thread ever produced a DCI. Measured on
 * replay-test/vzw-66636-recorded-samples.bin.bz2: the recorder decoded the MIB as 15 PRB and
 * recorded at 3.84 Msps; the MIB in that same recording says 100 PRB (23.04 Msps here), and the
 * spectrum is flat across the whole capture, i.e. it holds only the centre of a 20 MHz cell.
 *
 * The recording's cell rate is the one rate change the stream makes (cell search -> cell), so
 * the check runs when both are known: at once if the change has already been seen, otherwise
 * when it is. A 6-PRB cell runs at the cell-search rate, so for it any change is the mismatch. */
static double   rs_expected_rate = 0.0; /* the decoded cell's rate; 0 until it is known */
static uint32_t rs_expected_prb  = 0;

static uint32_t rs_prb_for_rate(double rate)
{
    static const uint32_t PRBS[] = {6, 15, 25, 50, 75, 100};
    for (size_t i = 0; i < sizeof(PRBS) / sizeof(PRBS[0]); i++) {
        if (fabs((double)srsran_sampling_freq_hz(PRBS[i]) - rate) < 1.0) {
            return PRBS[i];
        }
    }
    return 0;
}

static void rs_check_rate(double recorded)
{
    if (rs_expected_rate <= 0.0 || fabs(recorded - rs_expected_rate) < 1.0) {
        return;
    }
    const uint32_t rec_prb = rs_prb_for_rate(recorded);
    fprintf(stderr,
            "REPLAY: ERROR: the recording was made at %.2f Msps (the rate for %u PRB), but the "
            "cell's MIB says %u PRB, which needs %.2f Msps. The recording cannot be decoded as "
            "this cell: %s.",
            recorded / 1e6, rec_prb, rs_expected_prb, rs_expected_rate / 1e6,
            recorded < rs_expected_rate ? "it holds only the centre of the cell's band, and the control "
                                          "channel spans all of it"
                                        : "every subframe would be read at the wrong rate");
    if (rs_hdr_prb != 0) {
        fprintf(stderr, " The recording header says %u PRB%s.", rs_hdr_prb,
                rs_hdr_prb == rec_prb ? ", so the recorder itself used the wrong cell configuration" : "");
    }
    fprintf(stderr, " Re-record this cell. Aborting.\n");
    exit(EXIT_FAILURE);
}

void ngscope_replay_check_cell_rate(const srsran_cell_t* cell)
{
    const int rate = srsran_sampling_freq_hz(cell->nof_prb);
    if (rate <= 0) {
        return;
    }
    rs_expected_rate = (double)rate;
    rs_expected_prb  = cell->nof_prb;
    if (rs_nof_rate_changes > 0) {
        rs_check_rate(rs_rate);
    }
}

bool ngscope_replay_past_cell_search(void)
{
    return rs_nof_rate_changes > 0;
}

static bool replay_stream_init(void)
{
    for (uint32_t i = 0; i < SRSRAN_MAX_PORTS; i++) {
        rs_buf[i] = NULL;
    }
    for (uint32_t i = 0; i < sdr_nof_ports && i < SRSRAN_MAX_PORTS; i++) {
        rs_buf[i] = srsran_vec_cf_malloc(REPLAY_BUF_NOF_SAMPLES);
        if (rs_buf[i] == NULL) {
            fprintf(stderr, "REPLAY: ERROR: cannot allocate the replay stream buffer\n");
            return false;
        }
    }
    rs_chunk_n = rs_pos = rs_zero_left = 0;
    rs_have_chunk = rs_eof = false;
    rs_rate = 0.0;
    return true;
}

/* Load the next recorded chunk and decide how it joins the previous one. Returns false at
 * end of stream. */
static bool replay_stream_load(void)
{
    rx_frame_header_t hdr;
    if (replay_fread(&hdr, sizeof(hdr), 1) != 1) {
        return false;
    }
    nreplayed += sizeof(hdr);
    srsran_timestamp_t ts;
    srsran_timestamp_init(&ts, (time_t)hdr.timestamp_full_secs, hdr.timestamp_frac_secs);

    const bool oversized = hdr.nof_samples > REPLAY_BUF_NOF_SAMPLES;
    if (oversized) {
        /* Cannot be staged. Keep its duration as zeros so the timing after it is still right. */
        rs_nof_oversized++;
        replay_skip((long)(hdr.nof_samples * sizeof(cf_t) * sdr_nof_ports));
    } else {
        for (uint32_t i = 0; i < sdr_nof_ports; i++) {
            const size_t got = replay_fread(rs_buf[i], sizeof(cf_t), hdr.nof_samples);
            nreplayed += got * sizeof(cf_t);
            if (got != hdr.nof_samples) {
                return false; /* truncated final chunk: end of stream */
            }
        }
    }
    rs_nof_chunks++;

    /* NGSCOPE_REPLAY_LEVELS=<csv path>: per second of recording time, per antenna, the RMS,
     * the peak and the fraction of I/Q components at or above 0.99 of full scale. Says
     * whether a stretch of bad decoding is clipping in the recording. Diagnostic. */
    if (!oversized) {
        static int    lv_state = -1;
        static FILE*  lv_fd    = NULL;
        static double lv_t0 = -1, lv_sec = -1;
        static double lv_pow[SRSRAN_MAX_PORTS], lv_peak[SRSRAN_MAX_PORTS];
        static uint64_t lv_clip[SRSRAN_MAX_PORTS], lv_n;
        if (lv_state < 0) {
            const char* p = getenv("NGSCOPE_REPLAY_LEVELS");
            lv_state      = 0;
            if (p && *p && (lv_fd = fopen(p, "w"))) {
                fprintf(lv_fd, "sec,ant,rms_db,peak,clip_frac\n");
                lv_state = 1;
            }
        }
        if (lv_state == 1) {
            const double t = (double)hdr.timestamp_full_secs + hdr.timestamp_frac_secs;
            if (lv_t0 < 0) {
                lv_t0 = t;
            }
            const double sec = floor(t - lv_t0);
            if (sec != lv_sec && lv_n > 0) {
                for (uint32_t i = 0; i < sdr_nof_ports; i++) {
                    fprintf(lv_fd, "%.0f,%u,%.2f,%.3f,%.3e\n", lv_sec, i, 10 * log10(lv_pow[i] / lv_n + 1e-30),
                            lv_peak[i], (double)lv_clip[i] / (2.0 * lv_n));
                    lv_pow[i] = lv_peak[i] = 0;
                    lv_clip[i]             = 0;
                }
                lv_n = 0;
                fflush(lv_fd);
            }
            lv_sec = sec;
            for (uint32_t i = 0; i < sdr_nof_ports; i++) {
                const float* f = (const float*)rs_buf[i];
                for (uint32_t k = 0; k < 2 * hdr.nof_samples; k++) {
                    const float a = fabsf(f[k]);
                    lv_pow[i] += (double)a * a;
                    if (a > lv_peak[i]) {
                        lv_peak[i] = a;
                    }
                    lv_clip[i] += a >= 0.99f;
                }
            }
            lv_n += hdr.nof_samples;
        }
    }

    uint64_t drop = 0;
    if (rs_have_chunk) {
        const double span = rs_ts_diff(&ts, &rs_chunk_ts);
        if (rs_rate == 0.0) {
            /* First join: the spacing of the first two chunks gives the starting rate. */
            rs_rate = rs_std_rate((double)rs_chunk_n / span, 0.03);
            if (rs_rate == 0.0) {
                rs_rate = 1.92e6;
            }
            rs_rate_first = rs_rate;
        }
        const double implied  = span > 0 ? (double)rs_chunk_n / span : 0.0;
        const double std_impl = rs_std_rate(implied, 0.005);
        const double dt       = span - (double)rs_chunk_n / rs_rate;

        if (std_impl > rs_rate && rs_nof_rate_changes == 0) {
            /* The chunk just finished ran at a higher standard rate: the switch from cell
             * search to the cell's own rate. Its spacing says so exactly; no samples move. */
            rs_rate = std_impl;
            rs_nof_rate_changes++;
            rs_check_rate(rs_rate);
        } else if (dt > 0.5 / rs_rate) {
            double fill_s = dt;
            if (fill_s > REPLAY_GAP_CAP_S) {
                fill_s = REPLAY_GAP_CAP_S;
                rs_nof_capped++;
            }
            rs_zero_left = (uint64_t)llround(fill_s * rs_rate);
            rs_zero_ts   = rs_chunk_ts;
            srsran_timestamp_add(&rs_zero_ts, 0, (double)rs_chunk_n / rs_rate);
            rs_nof_gaps++;
            rs_gap_samples += rs_zero_left;
            rs_gap_total_s += dt;
            if (dt > rs_gap_max_s) {
                rs_gap_max_s = dt;
            }
        } else if (dt < -0.5 / rs_rate) {
            drop = (uint64_t)llround(-dt * rs_rate);
            rs_nof_overlaps++;
            rs_overlap_samples += drop;
        }
    }

    rs_chunk_ts   = ts;
    rs_chunk_n    = hdr.nof_samples;
    rs_have_chunk = true;
    if (oversized) {
        /* Its whole duration becomes zeros, served after any gap fill already pending. */
        rs_zero_left += rs_chunk_n;
        if (rs_zero_left == rs_chunk_n) {
            rs_zero_ts = ts;
        }
        rs_pos = rs_chunk_n;
    } else {
        rs_pos = drop < rs_chunk_n ? drop : rs_chunk_n;
    }
    return true;
}

/* Fill ptr[] with exactly nsamples from the stream, timestamped at the first sample.
 * Returns the number served; fewer only at end of stream. */
static int replay_stream_read(void* ptr[SRSRAN_MAX_PORTS], uint32_t nsamples, srsran_timestamp_t* t)
{
    const uint32_t nof_copy = sdr_nof_ports < rx_nof_rx_ant ? sdr_nof_ports : rx_nof_rx_ant;
    uint32_t served = 0;
    int      pieces = 0;

    while (served < nsamples) {
        if (rs_zero_left > 0) {
            const uint32_t k = (uint32_t)((uint64_t)(nsamples - served) < rs_zero_left
                                              ? (uint64_t)(nsamples - served) : rs_zero_left);
            if (served == 0) {
                *t = rs_zero_ts;
            }
            for (uint32_t i = 0; i < rx_nof_rx_ant; i++) {
                memset((cf_t*)ptr[i] + served, 0, (size_t)k * sizeof(cf_t));
            }
            srsran_timestamp_add(&rs_zero_ts, 0, (double)k / rs_rate_or_default());
            rs_zero_left -= k;
            served += k;
            pieces++;
            continue;
        }
        if (rs_pos >= rs_chunk_n) {
            if (rs_eof || !replay_stream_load()) {
                rs_eof = true;
                break;
            }
            continue;
        }
        const uint32_t k = (uint32_t)((uint64_t)(nsamples - served) < rs_chunk_n - rs_pos
                                          ? (uint64_t)(nsamples - served) : rs_chunk_n - rs_pos);
        if (served == 0) {
            *t = rs_chunk_ts;
            srsran_timestamp_add(t, 0, (double)rs_pos / rs_rate_or_default());
        }
        for (uint32_t i = 0; i < nof_copy; i++) {
            memcpy((cf_t*)ptr[i] + served, rs_buf[i] + rs_pos, (size_t)k * sizeof(cf_t));
        }
        /* Fewer channels in the file than the decoder expects: zero the rest. A zero channel
         * estimate contributes zero to both sides of every MRC sum, so the result is exactly
         * the lower-antenna one -- a missing antenna, not a corrupt one. */
        for (uint32_t i = nof_copy; i < rx_nof_rx_ant; i++) {
            memset((cf_t*)ptr[i] + served, 0, (size_t)k * sizeof(cf_t));
        }
        rs_pos += k;
        served += k;
        pieces++;
    }

    rs_nof_reads++;
    if (pieces > 1) {
        rs_nof_spanning++;
    }
    if (served < nsamples) {
        for (uint32_t i = 0; i < rx_nof_rx_ant; i++) {
            memset((cf_t*)ptr[i] + served, 0, (size_t)(nsamples - served) * sizeof(cf_t));
        }
    }
    return (int)served;
}

static void replay_stream_report(void)
{
    printf("REPLAY STREAM: %llu recorded chunks served as %llu reads (%llu spanned more than one "
           "piece); starting rate %.2f Msps, %llu rate change%s (cell search -> cell)\n",
           (unsigned long long)rs_nof_chunks, (unsigned long long)rs_nof_reads,
           (unsigned long long)rs_nof_spanning, rs_rate_first / 1e6,
           (unsigned long long)rs_nof_rate_changes, rs_nof_rate_changes == 1 ? "" : "s");
    printf("REPLAY STREAM: %llu gap%s the radio dropped, %.3f s in total (largest %.3f s), "
           "zero-filled as %llu samples; %llu capped at %.0f s; %llu overlap%s (%llu samples "
           "dropped); %llu oversized chunk%s zero-filled\n",
           (unsigned long long)rs_nof_gaps, rs_nof_gaps == 1 ? "" : "s", rs_gap_total_s,
           rs_gap_max_s, (unsigned long long)rs_gap_samples, (unsigned long long)rs_nof_capped,
           REPLAY_GAP_CAP_S, (unsigned long long)rs_nof_overlaps,
           rs_nof_overlaps == 1 ? "" : "s", (unsigned long long)rs_overlap_samples,
           (unsigned long long)rs_nof_oversized, rs_nof_oversized == 1 ? "" : "s");
}

// int srsran_rf_recv_wrapper(void* h, cf_t* data_[SRSRAN_MAX_PORTS], uint32_t nsamples, srsran_timestamp_t* t)
int ngscope_recv_samples_wrapper(void* h, cf_t* data_[SRSRAN_MAX_PORTS], uint32_t nsamples, srsran_timestamp_t* t){

    // int nof_channels = 1;
    if (debug)
        printf("DEBUG: ngscope_rx receive %d samples\n", nsamples);
    /* ue_sync passes NULL for its discard reads -- the positive timing-offset correction
     * (ue_sync.c track_peak_ok) and the FIND no-space realign. These used to return 0 without
     * reading, so those corrections were never applied, live or recorded: the samples they
     * were meant to discard stayed in the stream. Read them into a local timestamp instead. */
    srsran_timestamp_t t_discard;
    if (!t){
        t = &t_discard;
    }

    // fprintf(stdout, "[AGC] retrieving normal sample\n");
    read_ctr++;
    DEBUG(" ----  Receive %d samples  ----", nsamples);
    /* Fan out only as far as the caller actually has buffers.
     *
     * This used to copy all SRSRAN_MAX_PORTS entries, but data_[] is not always that long --
     * cell search passes a shorter array -- so the surplus reads ran past its end. What came
     * back was uninitialised stack, which is not NULL, so nothing downstream could tell the
     * difference; writing through one of those pointers is a stack smash. Bounding the
     * fan-out and nulling the rest makes the array say what it means. */
    void* ptr[SRSRAN_MAX_PORTS];
    for (uint32_t i = 0; i < SRSRAN_MAX_PORTS; i++) {
        ptr[i] = (i < rx_nof_rx_ant) ? data_[i] : NULL;
    }
    int n = 0;
    if (mode == NORMAL || mode == RECORD){
        if (debug)
            printf("DEBUG: MODE is normal or record\n");
        n = srsran_rf_recv_with_time_multi(h, ptr, nsamples, true, &t->full_secs, &t->frac_secs);
        // return n;
        if (debug)
            printf("DEBUG: got %d samples\n", n);
        if (n != nsamples){
            if (debug)
                printf("DEBUG: Got mismatch in number of samples: actual=%d, expected=%d\n", n, nsamples);
        }

        if (n < 0) {
            if (debug)
                fprintf(stderr, "Error retrieving samples: recv returned %d\n", n);
            return n;
        }
        if (mode == RECORD && n > 0){
            if (debug)
                printf("DEBUG: Recording %d samples\n", n);

            rx_frame_header_t hdr;
            memset(&hdr,0,sizeof(rx_frame_header_t));
            /* n, not nsamples: the payload written below is n samples, and a header that
             * claimed more would misalign every later chunk in the file. */
            hdr.nof_samples         = (uint64_t)n;
            hdr.timestamp_full_secs = (uint64_t) t->full_secs;
            hdr.timestamp_frac_secs = t->frac_secs;
            if (debug)
                printf("DEBUG: size of hdr: %ld, size of uint32_t: %ld, size of uint64_t: %ld, size of double: %ld\n", sizeof(rx_frame_header_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(double));
            // uint64_t frame_size = sizeof(hdr) + hdr.nof_samples * sizeof(cf_t);


            record_ring_buffer_insert(&record_buf, &hdr, sizeof(hdr));
            nrecorded += (sizeof(hdr));
            for (int i = 0; i < sdr_nof_ports; i++){
                record_ring_buffer_insert(&record_buf, ptr[i], sizeof(cf_t)*n);
                nrecorded += (sizeof(cf_t)*n);
            }


            if (debug)
                printf("RECORD: Written %ld bytes to the buffer\n", nrecorded);

            if (debug)
                printf("Done recording %d samples\n", n);
        }
    }else if (mode == REPLAY){
        if (!replay_fh){
            fprintf(stderr, "ERROR: replay file is not open. Please ensure the file exists and is readable\n");
            return 0;
        }

        n = replay_stream_read(ptr, nsamples, t);
        if (n == 0) {
            if (debug)
                printf("REPLAY: reached end of replay file\n");
            sleep(1); // let decoding finish
            raise(SIGINT);
            return 0;
        }

        /* Pace to the recording: never deliver faster than the radio did. Driven by each
         * read's own timestamp, so a zero-filled gap costs its real duration too. */
        if (last_replay_return.tv_sec == 0){
            clock_gettime(CLOCK_MONOTONIC, &last_replay_return);
        }
        const double recorded_delta = (double)((uint64_t)t->full_secs - last_replay_ts_full)
                                      + (t->frac_secs - last_replay_ts_frac);
        struct timespec spin_now;
        double system_elapsed;
        do {
          clock_gettime(CLOCK_MONOTONIC, &spin_now);
          system_elapsed = (spin_now.tv_sec  - last_replay_return.tv_sec)
                         + (spin_now.tv_nsec - last_replay_return.tv_nsec) * 1e-9;
        } while (last_replay_ts_full != 0 && system_elapsed < recorded_delta);

        last_replay_ts_full = (uint64_t)t->full_secs;
        last_replay_ts_frac = t->frac_secs;

        if (sdr_nof_ports < rx_nof_rx_ant && !warned_short_stream) {
            warned_short_stream = true;
            printf("REPLAY: recording holds %u channel%s but nof_rx_ant is %u; the missing "
                   "channels are zero-filled, so this run measures %u antenna%s of diversity, "
                   "not %u\n",
                   sdr_nof_ports, sdr_nof_ports == 1 ? "" : "s", rx_nof_rx_ant,
                   sdr_nof_ports, sdr_nof_ports == 1 ? "" : "s", rx_nof_rx_ant);
        }
        clock_gettime(CLOCK_MONOTONIC, &last_replay_return);
    }
    if (debug)
        printf("DEBUG: returning %d samples\n", n);
    if (debug)

        printf("FRAME %lu: mode=%d nsamples=%d n=%d\n", frame_count, mode, nsamples, n);
    frame_count++;
    return n;
}

int stop_record(){

    if (debug)
        printf("DEBUG: closing record files\n");

    // pthread_cancel(flush_thread);

    // pthread_join(flush_thread, NULL);

    // record_ring_buffer_destroy(&record_buf);
    pthread_mutex_lock(&record_buf.mutex);
    pthread_cond_signal(&record_buf.cond);
    pthread_mutex_unlock(&record_buf.mutex);
    pthread_join(flush_thread, NULL);  // no cancel needed
    if (debug)
        printf("DEBUG: final flush done\n");
    /* Always printed, zero included: a recording with no refused inserts should say so. */
    printf("RECORD: %lu inserts (%.1f MB) refused because the buffer was full -- the disk fell "
           "%.0f GB behind%s\n",
           (unsigned long)record_buf.nof_dropped_inserts,
           record_buf.nof_dropped_bytes / 1e6, record_buf.capacity / 1e9,
           record_buf.nof_dropped_inserts ? "; the file is missing data at those points" : "");
    record_ring_buffer_destroy(&record_buf);

    return 0;
}

int stop_replay(){

    if (debug)
        printf("DEBUG: closing replay files\n");

    if (replay_fh){
        /* pclose() on a popen() stream: fclose() would leak the decompressor as a zombie. */
        const int rc = replay_is_pipe ? pclose(replay_fh) : fclose(replay_fh);
        replay_fh = NULL;
        if (rc < 0)
            return -1;
    }
    if (replay_start_ns != 0 && replay_bytes > 0) {
        const double wall    = (double)(replay_now_ns() - replay_start_ns) / 1e9;
        const double blocked = (double)replay_read_ns / 1e9;
        const double gb      = (double)replay_bytes / 1e9;
        printf("\nREPLAY SOURCE: %.2f GB in %.1f s wall; %.1f s (%.0f%%) blocked reading the\n",
               gb, wall, blocked, wall > 0 ? 100.0 * blocked / wall : 0.0);
        printf("               recording, i.e. %.0f MB/s from the source.\n",
               blocked > 0 ? gb * 1000.0 / blocked : 0.0);
        if (replay_is_pipe) {
            /* The decompressor runs concurrently with the decoder, so it only costs wall
             * time when the decoder is left waiting on it. That is what this fraction is. */
            printf("               %s\n",
                   (wall > 0 && blocked / wall > 0.25)
                       ? "The decompressor was the limiter -- a parallel one (lbzip2) would be faster."
                       : "Decompression kept up: the decoder, not the source, set the pace.");
        }
    }
    replay_stream_report();
    for (uint32_t i = 0; i < SRSRAN_MAX_PORTS; i++) {
        if (rs_buf[i]) {
            free(rs_buf[i]);
            rs_buf[i] = NULL;
        }
    }
    printf("DEBUG: file read %ld times\n", frame_count);
    fflush(stdout);
    return 0;
}


void flush_record(void *arg){
    record_ring_buffer_t *buf = (record_ring_buffer_t *) arg;

    pthread_cleanup_push(flush_thread_cleanup, (void*)buf);

    while(!go_exit){

        pthread_mutex_lock(&buf->mutex);

        while (!buf->flush && !go_exit){
            pthread_cond_wait(&buf->cond,&buf->mutex);
        }
        // printf("[FLUSH] out of wait\n");
        /* Released before flushing: the flush takes the lock itself only around its
         * bookkeeping, so the receive thread can keep inserting while the disk write runs. */
        pthread_mutex_unlock(&buf->mutex);

        record_ring_buffer_flush(buf);

    }
    pthread_cleanup_pop((void*)buf);

}

void flush_thread_cleanup(void *arg){

    if (debug)
        printf("RECORD: flushing the buffer for cleanup\n");

    record_ring_buffer_t *buf = (record_ring_buffer_t *) arg;

    record_ring_buffer_flush(buf);
    // pthread_mutex_unlock(&buf->mutex);

}

void update_record_header(rx_record_header_t *hdr){


    rx_record_header_t to_update;

    FILE *f = fopen(record_path,"rb+");
    printf("Opened file %s (%d)\n", record_path, f != NULL);
    if (fread(&to_update,sizeof(rx_record_header_t),1,f) < 1){
        fprintf(stderr,"Error reading record file header from %s\n", record_path);
        return;
    }
    if (fseek(f,0,SEEK_SET) != 0){
        fprintf(stderr,"Error setting file pointer\n");
        fclose(f);
        return;
    } // reset file pointer

    struct timespec ts;

    if ( clock_gettime( CLOCK_REALTIME, &ts ) < 0 ) {
      perror( "clock_gettime" );
      fclose(f);
      exit( 1 );
    }

    uint64_t ct = ts.tv_sec * 1000000000 + ts.tv_nsec;

    to_update.pci = hdr->pci;
    to_update.prb = hdr->prb;
    to_update.record_duration_ns = ct - hdr->record_start_ns;
    to_update.frame_type = hdr->frame_type;

    to_update.nof_cell_ports = hdr->nof_cell_ports;
    to_update.phich_length = hdr->phich_length;
    to_update.phich_resources = hdr->phich_resources;
    to_update.cp = hdr->cp;

    to_update.min_gain_db = hdr->min_gain_db;
    to_update.max_gain_db = hdr->max_gain_db;
    to_update.init_gain_db = hdr->init_gain_db;

    to_update.decoded_frames = hdr->decoded_frames;
    to_update.desynced_frames = hdr->desynced_frames;
    to_update.skipped_frames = hdr->skipped_frames;
    to_update.first_sync_frame = hdr->first_sync_frame;

    strcpy(to_update.comment, hdr->comment);
    strcpy(to_update.location, hdr->location);


    printf("Writing updated header to file: %s\n", record_path);
    printf("\tnof_rx_antenna: %d\n",to_update.nof_rx_antenna);
    printf("\trf_freq: %.02f\n", to_update.rf_freq);
    printf("\trecord start (us): %ld\n", to_update.record_start_ns);
    printf("\trecord duration (us): %ld\n", to_update.record_duration_ns);
    printf("\tmin gain db: %.02f\n", to_update.min_gain_db);
    printf("\tmax gain db: %.02f\n", to_update.max_gain_db);
    printf("\tinit gain db: %.02f\n", to_update.init_gain_db);
    printf("\tnof decoded frames:\t%d\n",to_update.decoded_frames);
    printf("\tnof desynced frames:\t%d\n", to_update.desynced_frames);
    printf("\tnof skipped frames:\t%d\n", to_update.skipped_frames);
    printf("\tfirst synced frame:\t%d\n", to_update.first_sync_frame);
    printf("\tCell info:\n");
    printf("\t\tpci:\t%d\n",to_update.pci);
    printf("\t\tprb:\t%d\n",to_update.prb);
    printf("\t\tnof_ports:\t%d\n", to_update.nof_cell_ports);
    printf("\t\tframe type:\t%s\n",to_update.frame_type == SRSRAN_FDD ? "FDD" : "TDD");
    printf("\t\tcp:\t%s\n",srsran_cp_string(to_update.cp));
    printf("\t\tphich length:\t%s\n",to_update.phich_length == SRSRAN_PHICH_EXT ? "Extended" : "Normal");
    printf("\t\tphich resources:\t");
    switch (to_update.phich_resources) {
      case SRSRAN_PHICH_R_1_6:
        printf("1/6\n");
        break;
      case SRSRAN_PHICH_R_1_2:
        printf("1/2\n");
        break;
      case SRSRAN_PHICH_R_1:
        printf("1\n");
        break;
      case SRSRAN_PHICH_R_2:
        printf("2\n");
        break;
    }
    printf("\tlocation:\t%s\n",to_update.location);
    printf("\tcomment:\t%s\n",to_update.comment);

    int n = fwrite(&to_update,sizeof(rx_record_header_t),1,f);
    if (n < 0){
        fprintf(stderr,"ERROR: Updating record header\n");
    }else if (n != 1){
        fprintf(stderr, "ERROR: Wrote incorrect number of bytes to recording file (%d)\n",n);
    }else{
        printf("Updated header with result %d\n",n);
    }
    fflush(f);
    fclose(f);
}


uint32_t get_rx_read_ctr(){
    return read_ctr;
}
