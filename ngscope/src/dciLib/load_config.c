#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <libconfig.h>
#include "ngscope/hdr/dciLib/load_config.h"

/* libconfig backend for the schema declared in load_config.h.
 *
 * Nothing here enumerates settings by hand: every lookup below is generated from
 * NGSCOPE_TOP_LEVEL_KEYS / NGSCOPE_RF_DEV_KEYS / NGSCOPE_LOG_KEYS. To add a setting, add a
 * row to the table and a field to the struct -- no lookup code needs touching, and a second
 * backend can walk the same tables instead of duplicating the key list. */

static int nof_missing_required = 0;

/* Shared with the other backends via ngscope_config_report_missing(). */
void ngscope_config_report_missing(const char* path)
{
    printf("config: ERROR: required key '%s' is missing\n", path);
    nof_missing_required++;
}

/******************** per-type readers ********************/

static void cfg_read_INT(config_t* cfg, const char* path, int* dst, int dflt, bool required)
{
    if (config_lookup_int(cfg, path, dst)) {
        printf("config: %s = %d\n", path, *dst);
        return;
    }
    *dst = dflt;
    if (required) {
        ngscope_config_report_missing(path);
        return;
    }
    printf("config: %s = %d (default)\n", path, *dst);
}

static void cfg_read_INT64(config_t* cfg, const char* path, long long* dst, long long dflt, bool required)
{
    if (config_lookup_int64(cfg, path, dst)) {
        printf("config: %s = %lld\n", path, *dst);
        return;
    }
    *dst = dflt;
    if (required) {
        ngscope_config_report_missing(path);
        return;
    }
    printf("config: %s = %lld (default)\n", path, *dst);
}

static void cfg_read_BOOL(config_t* cfg, const char* path, int* dst, int dflt, bool required)
{
    if (config_lookup_bool(cfg, path, dst)) {
        printf("config: %s = %s\n", path, *dst ? "true" : "false");
        return;
    }
    *dst = dflt;
    if (required) {
        ngscope_config_report_missing(path);
        return;
    }
    printf("config: %s = %s (default)\n", path, *dst ? "true" : "false");
}

/* Copies into a fixed-size field. The previous code used an unbounded strcpy(), so an
 * rf_args longer than the 100 byte field overflowed it. */
static void cfg_read_STRBUF(config_t* cfg, const char* path, char* dst, size_t cap, const char* dflt, bool required)
{
    const char* val = NULL;
    if (config_lookup_string(cfg, path, &val) && val != NULL) {
        if (strlen(val) >= cap) {
            printf("config: ERROR: '%s' is %zu bytes but the field holds %zu -- truncated\n",
                   path,
                   strlen(val),
                   cap - 1);
        }
        snprintf(dst, cap, "%s", val);
        printf("config: %s = \"%s\"\n", path, dst);
        return;
    }
    snprintf(dst, cap, "%s", dflt ? dflt : "");
    if (required) {
        ngscope_config_report_missing(path);
        return;
    }
    printf("config: %s = \"%s\" (default)\n", path, dst);
}

/* Borrows the string owned by the libconfig tree, so it stays valid only while that tree
 * lives -- which is why the tree is deliberately never destroyed below. */
static void cfg_read_STRPTR(config_t* cfg, const char* path, const char** dst, const char* dflt, bool required)
{
    if (config_lookup_string(cfg, path, dst) && *dst != NULL) {
        printf("config: %s = \"%s\"\n", path, *dst);
        return;
    }
    *dst = dflt;
    if (required) {
        ngscope_config_report_missing(path);
        return;
    }
    printf("config: %s = %s (default)\n", path, *dst ? *dst : "none");
}

/* One dispatch macro per TYPE token used in the schema. `lv` is the destination lvalue.
 * INT/BOOL cast so that enum-typed fields (rf_config[i].mode) work without a special case. */
#define CFG_READ_INT(cfg, path, lv, dflt, req)    cfg_read_INT(cfg, path, (int*)&(lv), (int)(dflt), req)
#define CFG_READ_INT64(cfg, path, lv, dflt, req)  cfg_read_INT64(cfg, path, &(lv), (long long)(dflt), req)
#define CFG_READ_BOOL(cfg, path, lv, dflt, req)   cfg_read_BOOL(cfg, path, (int*)&(lv), (int)(dflt), req)
#define CFG_READ_STRBUF(cfg, path, lv, dflt, req) cfg_read_STRBUF(cfg, path, (lv), sizeof(lv), dflt, req)
#define CFG_READ_STRPTR(cfg, path, lv, dflt, req) cfg_read_STRPTR(cfg, path, &(lv), dflt, req)

#define CFG_READ(type, cfg, path, lv, dflt, req) CFG_READ_##type(cfg, path, lv, dflt, req)

/******************** helpers ********************/

int compar(const void* a, const void* b)
{
    return (*(long long*)a - *(long long*)b);
}

bool containsDuplicate(long long* nums, int numsSize)
{
    int i, j;
    qsort(nums, numsSize, sizeof(long long), compar);
    for (i = 0, j = 1; j < numsSize; i++, j++) {
        if (nums[i] == nums[j]) {
            return true;
        }
    }
    return false;
}

/*********************************************
 * Function name: ngscope_read_config
 * Return value type: int
 * Description: load configuration from the
 *     config file.
 * Author: PAWS (https://paws.princeton.edu/)
*********************************************/
static int ngscope_read_config_libconfig(ngscope_config_t* config, char* path)
{
    /* Deliberately not destroyed: STRPTR fields (replay_fname) point into this tree and are
     * read later during startup. */
    config_t* cfg = (config_t*)malloc(sizeof(config_t));
    config_init(cfg);

    if (!config_read_file(cfg, path)) {
        fprintf(stderr, "%s:%d - %s\n", config_error_file(cfg), config_error_line(cfg), config_error_text(cfg));
        config_destroy(cfg);
        free(cfg);
        exit(EXIT_FAILURE);
    }

    /************************ top level ************************/
#define X(type, key, field, dflt, req) CFG_READ(type, cfg, key, config->field, dflt, req);
    NGSCOPE_TOP_LEVEL_KEYS(X)
#undef X

    ngscope_config_check_nof_rf_dev(config);

    /************************ per RF device ************************/
    for (int i = 0; i < config->nof_rf_dev; i++) {
        char p[128];

#define X(type, key, field, dflt, req)                                                                                 \
    snprintf(p, sizeof(p), "rf_config%d.%s", i, key);                                                                  \
    CFG_READ(type, cfg, p, config->rf_config[i].field, dflt, req);
        NGSCOPE_RF_DEV_KEYS(X)
#undef X

    }

    /************************ logging ************************/
    config->dci_log_config.nof_cell = config->nof_rf_dev;

    /* Which .dciLog files get written is set per device by rf_config<N>.log_dl / log_ul /
     * log_phich, applied in fill_dci_log_config(). */
#define X(type, key, field, dflt, req) CFG_READ(type, cfg, "dci_log_config." key, config->dci_log_config.field, dflt, req);
    NGSCOPE_LOG_KEYS(X)
#undef X

    ngscope_config_finalize(config, path);
    return 0;
}

bool ngscope_config_check_log(ngscope_config_t* config)
{
    for (int i = 0; i < config->nof_rf_dev; i++) {
        if (config->rf_config[i].log_dl || config->rf_config[i].log_ul) {
            return true;
        }
    }
    return false;
}

/******************** shared across config backends ********************/

void ngscope_config_reset_missing(void)
{
    nof_missing_required = 0;
}

void ngscope_config_check_nof_rf_dev(ngscope_config_t* config)
{
    /* Guards every rf_config[] index; the array has MAX_NOF_RF_DEV entries. */
    if (config->nof_rf_dev < 1 || config->nof_rf_dev > MAX_NOF_RF_DEV) {
        printf("config: ERROR: nof_rf_dev=%d is outside 1..%d\n", config->nof_rf_dev, MAX_NOF_RF_DEV);
        exit(EXIT_FAILURE);
    }
}

/* Recover the carrier frequency of a recording from the files sitting beside it.
 *
 * The samples themselves cannot supply it. Downconversion removed the carrier, and
 * rx_frame_header_t (ngscope_rx.h) carries only a sample count and a timestamp -- so there is
 * nothing in the .bin to read, and no amount of analysis will produce one.
 *
 * What is available is the run directory the recording was written into:
 *
 *   1. cell_type.json, written beside recorded-samples.bin by every run, carries rf_freq.
 *      Preferred, and exact.
 *   2. Older recordings predate that field, but the same directory holds
 *      dci_output/dci_raw_log_dl_freq_<hz>_<stamp>.dciLog -- the frequency is in the name.
 *
 * Returns 0 when neither is available, which is not fatal: in replay rf_freq only labels
 * output filenames, since radio.c tunes nothing when mode == REPLAY.
 *
 * Both files are ours and have a fixed shape, so they are scanned rather than parsed. */
static long long replay_freq_from_run_dir(const char* replay_fname)
{
    if (replay_fname == NULL) {
        return 0;
    }
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s", replay_fname);
    char* slash = strrchr(dir, '/');
    if (slash == NULL) {
        return 0;   /* a bare filename: the run directory is not knowable */
    }
    *slash = '\0';

    /* 1. cell_type.json */
    char path[1152];
    snprintf(path, sizeof(path), "%s/cell_type.json", dir);
    FILE* f = fopen(path, "r");
    if (f != NULL) {
        char buf[2048];
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = '\0';
        const char* key = strstr(buf, "\"rf_freq\"");
        if (key != NULL) {
            const char* colon = strchr(key, ':');
            long long   hz    = 0;
            if (colon != NULL && sscanf(colon + 1, " \"%lld\"", &hz) == 1 && hz > 0) {
                return hz;
            }
        }
    }

    /* 2. the DCI log filename from the run that made the recording */
    snprintf(path, sizeof(path), "%s/dci_output", dir);
    DIR* d = opendir(path);
    if (d != NULL) {
        const char*    prefix = "dci_raw_log_dl_freq_";
        long long      hz     = 0;
        struct dirent* ent;
        while ((ent = readdir(d)) != NULL) {
            const char* p = strstr(ent->d_name, prefix);
            if (p != NULL && sscanf(p + strlen(prefix), "%lld", &hz) == 1 && hz > 0) {
                closedir(d);
                return hz;
            }
        }
        closedir(d);
    }
    return 0;
}

/* Rules that hold no matter which file format the settings came from. Every backend fills
 * ngscope_config_t and then calls this. */
void ngscope_config_finalize(ngscope_config_t* config, const char* path)
{
    config->dci_log_config.nof_cell = config->nof_rf_dev;

    if (config->rach_filter_only && !config->decode_RAR) {
        printf("config: WARNING: rach_filter_only needs decode_RAR to populate the RNTI set; "
               "with decode_RAR off every UE DCI would be dropped. Forcing decode_RAR on.\n");
        config->decode_RAR = true;
    }

    if (config->mark_security_phase && !config->decode_RAR) {
        printf("config: WARNING: mark_security_phase anchors each UE's security boundary on the "
               "RAR that assigned its RNTI; with decode_RAR off there are no anchors and every "
               "DCI would be labelled unknown. Forcing decode_RAR on.\n");
        config->decode_RAR = true;
    }

    /* rlc_reassembly and qam_retry are replay-only by construction (task_scheduler.c ANDs them
     * with mode == REPLAY), so say so rather than letting a live run look as though it had
     * them. Not an error: they default on, so every live config would otherwise trip it. */
    if (config->rlc_reassembly || config->qam_retry) {
        bool any_replay = false;
        for (int i = 0; i < config->nof_rf_dev; i++) {
            if (config->rf_config[i].mode == REPLAY) {
                any_replay = true;
                break;
            }
        }
        if (!any_replay) {
            printf("config: note: rlc_reassembly and qam_retry apply to replay only; no "
                   "rf_config is in mode=2, so both are inert this run\n");
        }
    }

    for (int i = 0; i < config->nof_rf_dev; i++) {
        /* srsran_ue_dl_init() and the sync buffers are sized from this, and
         * srsran_rf_open_devname() asks the driver for exactly this many channels. */
        if (config->rf_config[i].nof_rx_ant < 1 || config->rf_config[i].nof_rx_ant > SRSRAN_MAX_PORTS) {
            printf("config: ERROR: rf_config%d nof_rx_ant=%d is outside 1..%d\n",
                   i, config->rf_config[i].nof_rx_ant, SRSRAN_MAX_PORTS);
            nof_missing_required++;
        }

        /* nof_thread indexes sf_buffer[][], dci_decoder[] and dci_thd[] in task_scheduler.c,
         * all of which are MAX_NOF_DCI_DECODER wide. Unchecked, a larger value walks off the
         * end of each and segfaults inside srsran_ue_dl_init() with no hint of the cause. */
        if (config->rf_config[i].nof_thread < 1 ||
            config->rf_config[i].nof_thread > MAX_NOF_DCI_DECODER) {
            printf("config: ERROR: rf_config%d nof_thread=%d is outside 1..%d\n",
                   i, config->rf_config[i].nof_thread, MAX_NOF_DCI_DECODER);
            nof_missing_required++;
        }
    }

    for (int i = 0; i < config->nof_rf_dev; i++) {
        /* The recorder writes channel 0 only (ngscope_rx.c) and rx_frame_header_t has no
         * channel count, so a two-antenna recording would be silently truncated to one and
         * the resulting file would look perfectly valid. Refuse rather than lose the capture. */
        if (config->rf_config[i].mode == RECORD && config->rf_config[i].nof_rx_ant > 1) {
            printf("config: ERROR: rf_config%d has nof_rx_ant=%d with mode=1 (record), but the IQ "
                   "recorder only stores channel 0 -- the recording would silently lose the "
                   "other %d channel(s). Record with nof_rx_ant=1, or capture live.\n",
                   i, config->rf_config[i].nof_rx_ant, config->rf_config[i].nof_rx_ant - 1);
            nof_missing_required++;
        }

        if (config->rf_config[i].mode == REPLAY && config->rf_config[i].replay_fname == NULL) {
            printf("config: ERROR: rf_config%d mode=2 (replay) requires replay_fname\n", i);
            nof_missing_required++;
        }
    }

    /* rf_freq in replay: learn it from the recording rather than trusting the config.
     *
     * Nothing tunes in replay -- radio.c only calls srsran_rf_set_rx_freq() when
     * mode != REPLAY -- so a configured frequency is not a receiver setting there, it is only
     * a label on the output filenames. A wrong one silently mislabels a capture, which is
     * worse than having none, so the recording's own record of what it was recorded at wins
     * over whatever the config says. */
    for (int i = 0; i < config->nof_rf_dev; i++) {
        if (config->rf_config[i].mode != REPLAY) {
            /* Live and record genuinely tune, so there the setting really is required. It is
             * not marked required in the schema table because replay must be allowed to omit
             * it; this is where that distinction is enforced. */
            if (config->rf_config[i].rf_freq <= 0) {
                printf("config: ERROR: rf_config%d rf_freq is required unless mode=2 (replay), "
                       "where it is read from the recording instead\n", i);
                nof_missing_required++;
            }
            continue;
        }

        const long long learned = replay_freq_from_run_dir(config->rf_config[i].replay_fname);
        const long long stated  = config->rf_config[i].rf_freq;

        if (learned > 0) {
            config->rf_config[i].rf_freq = learned;
            if (stated > 0 && stated != learned) {
                printf("config: rf_config%d rf_freq: using %lld Hz from the recording, "
                       "ignoring the configured %lld Hz\n", i, learned, stated);
            } else {
                printf("config: rf_config%d rf_freq = %lld (learned from the recording)\n",
                       i, learned);
            }
        } else if (stated > 0) {
            printf("config: rf_config%d rf_freq: the recording does not say what it was "
                   "recorded at, keeping the configured %lld Hz\n", i, stated);
        } else {
            printf("config: rf_config%d rf_freq: unknown -- neither the recording nor the "
                   "config says. Output filenames will read freq_0; nothing else is affected, "
                   "since replay tunes nothing.\n", i);
        }
    }

    /* Only frequencies that actually name something. Two replays whose recordings do not say
     * what they were recorded at are both 0, and that is not a collision: neither is tuning a
     * receiver, and this check exists to stop two USRPs fighting over one cell. */
    long long freq_vec[MAX_NOF_RF_DEV];
    int       nof_freq = 0;
    for (int i = 0; i < config->nof_rf_dev; i++) {
        if (config->rf_config[i].rf_freq > 0) {
            freq_vec[nof_freq++] = config->rf_config[i].rf_freq;
        }
    }
    if (containsDuplicate(freq_vec, nof_freq)) {
        printf("Two USRP is listening to the same base station (with the same frequency), which results in "
               "unpredictable behavior when logging the DCI messages. \n \
		So, we currently doesn't support it! Please check your configuration files to fix it.\n");
        exit(0);
    }

    if (nof_missing_required > 0) {
        printf("config: %d required setting(s) missing from %s -- refusing to run with fabricated values.\n",
               nof_missing_required,
               path);
        exit(EXIT_FAILURE);
    }
}

/* Public entry point. Picks the backend from the file extension so both formats can coexist
 * in one tree during the migration: *.toml uses the TOML reader, anything else libconfig. */
int ngscope_read_config(ngscope_config_t* config, char* path)
{
    ngscope_config_reset_missing();

    size_t n = strlen(path);
    if (n > 5 && strcmp(path + n - 5, ".toml") == 0) {
        printf("config: reading %s (TOML)\n", path);
        return ngscope_read_config_toml(config, path);
    }

    printf("config: reading %s (libconfig)\n", path);
    return ngscope_read_config_libconfig(config, path);
}
