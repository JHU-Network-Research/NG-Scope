#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
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

    for (int i = 0; i < config->nof_rf_dev; i++) {
        /* srsran_ue_dl_init() and the sync buffers are sized from this, and
         * srsran_rf_open_devname() asks the driver for exactly this many channels. */
        if (config->rf_config[i].nof_rx_ant < 1 || config->rf_config[i].nof_rx_ant > SRSRAN_MAX_PORTS) {
            printf("config: ERROR: rf_config%d nof_rx_ant=%d is outside 1..%d\n",
                   i, config->rf_config[i].nof_rx_ant, SRSRAN_MAX_PORTS);
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

    long long freq_vec[MAX_NOF_RF_DEV];
    for (int i = 0; i < config->nof_rf_dev; i++) {
        freq_vec[i] = config->rf_config[i].rf_freq;
    }
    if (containsDuplicate(freq_vec, config->nof_rf_dev)) {
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
