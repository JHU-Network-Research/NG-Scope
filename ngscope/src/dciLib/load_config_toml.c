#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ngscope/hdr/dciLib/load_config.h"
#include "toml.h"

/* TOML backend for the schema declared in load_config.h.
 *
 * Like the libconfig backend, every lookup here is generated from NGSCOPE_TOP_LEVEL_KEYS /
 * NGSCOPE_RF_DEV_KEYS / NGSCOPE_LOG_KEYS -- the key list is not duplicated. Adding a setting
 * to the schema makes it available in both formats at once.
 *
 * The one deliberate difference from the .cfg layout is that RF devices are an array of
 * tables, which is how TOML expresses a repeated section:
 *
 *     [[rf_config]]        instead of   rf_config0 = { ... };
 *     rf_freq = 2680000000
 *
 * `nof_rf_dev` is therefore derived from the array length rather than being declared. */

/******************** per-type readers ********************/
/* `disp` is the display path used in messages; `key` is the bare key within `t`. */

static void toml_read_INT(const toml_table_t* t, const char* disp, const char* key, int* dst, int dflt, bool required)
{
    toml_datum_t d = toml_int_in(t, key);
    if (d.ok) {
        *dst = (int)d.u.i;
        printf("config: %s = %d\n", disp, *dst);
        return;
    }
    *dst = dflt;
    if (required) {
        ngscope_config_report_missing(disp);
        return;
    }
    printf("config: %s = %d (default)\n", disp, *dst);
}

static void toml_read_INT64(const toml_table_t* t,
                            const char*         disp,
                            const char*         key,
                            long long*          dst,
                            long long           dflt,
                            bool                required)
{
    toml_datum_t d = toml_int_in(t, key);
    if (d.ok) {
        *dst = (long long)d.u.i;
        printf("config: %s = %lld\n", disp, *dst);
        return;
    }
    *dst = dflt;
    if (required) {
        ngscope_config_report_missing(disp);
        return;
    }
    printf("config: %s = %lld (default)\n", disp, *dst);
}

static void toml_read_BOOL(const toml_table_t* t, const char* disp, const char* key, int* dst, int dflt, bool required)
{
    toml_datum_t d = toml_bool_in(t, key);
    if (d.ok) {
        *dst = d.u.b ? 1 : 0;
        printf("config: %s = %s\n", disp, *dst ? "true" : "false");
        return;
    }
    *dst = dflt;
    if (required) {
        ngscope_config_report_missing(disp);
        return;
    }
    printf("config: %s = %s (default)\n", disp, *dst ? "true" : "false");
}

/* toml_string_in() hands back a malloc'd copy, so this frees it after copying in. */
static void toml_read_STRBUF(const toml_table_t* t,
                             const char*         disp,
                             const char*         key,
                             char*               dst,
                             size_t              cap,
                             const char*         dflt,
                             bool                required)
{
    toml_datum_t d = toml_string_in(t, key);
    if (d.ok) {
        if (strlen(d.u.s) >= cap) {
            printf("config: ERROR: '%s' is %zu bytes but the field holds %zu -- truncated\n",
                   disp,
                   strlen(d.u.s),
                   cap - 1);
        }
        snprintf(dst, cap, "%s", d.u.s);
        free(d.u.s);
        printf("config: %s = \"%s\"\n", disp, dst);
        return;
    }
    snprintf(dst, cap, "%s", dflt ? dflt : "");
    if (required) {
        ngscope_config_report_missing(disp);
        return;
    }
    printf("config: %s = \"%s\" (default)\n", disp, dst);
}

/* The struct field is a borrowed `const char*` that outlives the parse, so the malloc'd
 * string is handed over rather than freed. This mirrors the libconfig backend, which keeps
 * its whole config tree alive for the same reason. */
static void toml_read_STRPTR(const toml_table_t* t,
                             const char*         disp,
                             const char*         key,
                             const char**        dst,
                             const char*         dflt,
                             bool                required)
{
    toml_datum_t d = toml_string_in(t, key);
    if (d.ok) {
        *dst = d.u.s; /* ownership transferred to config */
        printf("config: %s = \"%s\"\n", disp, *dst);
        return;
    }
    *dst = dflt;
    if (required) {
        ngscope_config_report_missing(disp);
        return;
    }
    printf("config: %s = %s (default)\n", disp, *dst ? *dst : "none");
}

#define TOML_READ_INT(t, disp, key, lv, dflt, req)    toml_read_INT(t, disp, key, (int*)&(lv), (int)(dflt), req)
#define TOML_READ_INT64(t, disp, key, lv, dflt, req)  toml_read_INT64(t, disp, key, &(lv), (long long)(dflt), req)
#define TOML_READ_BOOL(t, disp, key, lv, dflt, req)   toml_read_BOOL(t, disp, key, (int*)&(lv), (int)(dflt), req)
#define TOML_READ_STRBUF(t, disp, key, lv, dflt, req) toml_read_STRBUF(t, disp, key, (lv), sizeof(lv), dflt, req)
#define TOML_READ_STRPTR(t, disp, key, lv, dflt, req) toml_read_STRPTR(t, disp, key, &(lv), dflt, req)

#define TOML_READ(type, t, disp, key, lv, dflt, req) TOML_READ_##type(t, disp, key, lv, dflt, req)

/******************** entry point ********************/

int ngscope_read_config_toml(ngscope_config_t* config, char* path)
{
    FILE* fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "config: cannot open %s\n", path);
        exit(EXIT_FAILURE);
    }

    char          errbuf[256] = {0};
    toml_table_t* root        = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);

    if (root == NULL) {
        fprintf(stderr, "config: %s: %s\n", path, errbuf);
        exit(EXIT_FAILURE);
    }

    /************************ top level ************************/
    /* nof_rf_dev is skipped: in TOML the device count is the length of the [[rf_config]]
     * array, set just below. It stays in the shared schema because the .cfg format, which
     * has no array syntax, does need it declared. */
#define X(type, key, field, dflt, req)                                                                                 \
    if (strcmp(key, "nof_rf_dev") != 0) {                                                                              \
        TOML_READ(type, root, key, key, config->field, dflt, req);                                                     \
    }
    NGSCOPE_TOP_LEVEL_KEYS(X)
#undef X

    /************************ per RF device ************************/
    /* The [[rf_config]] array is authoritative for how many devices there are; nof_rf_dev is
     * accepted only so the two formats declare the same set of keys. */
    toml_array_t* rf = toml_array_in(root, "rf_config");
    if (rf == NULL) {
        printf("config: ERROR: no [[rf_config]] table in %s\n", path);
        toml_free(root);
        exit(EXIT_FAILURE);
    }

    int nof_dev        = toml_array_nelem(rf);
    config->nof_rf_dev = nof_dev;
    printf("config: nof_rf_dev = %d (from %d [[rf_config]] table%s)\n", nof_dev, nof_dev, nof_dev == 1 ? "" : "s");
    ngscope_config_check_nof_rf_dev(config);

    for (int i = 0; i < config->nof_rf_dev; i++) {
        toml_table_t* dev = toml_table_at(rf, i);
        if (dev == NULL) {
            printf("config: ERROR: [[rf_config]] entry %d is not a table\n", i);
            toml_free(root);
            exit(EXIT_FAILURE);
        }
        char disp[128];

#define X(type, key, field, dflt, req)                                                                                 \
    snprintf(disp, sizeof(disp), "rf_config[%d].%s", i, key);                                                          \
    TOML_READ(type, dev, disp, key, config->rf_config[i].field, dflt, req);
        NGSCOPE_RF_DEV_KEYS(X)
#undef X
    }

    /************************ logging ************************/
    /* An absent [dci_log_config] table is fine: every key in it is optional, and passing a
     * NULL table to the readers below would crash, so substitute an empty one. */
    toml_table_t* logtab = toml_table_in(root, "dci_log_config");
    if (logtab == NULL) {
        static char  empty[] = "";
        static char  eb[64];
        logtab = toml_parse(empty, eb, sizeof(eb));
    }

#define X(type, key, field, dflt, req)                                                                                 \
    TOML_READ(type, logtab, "dci_log_config." key, key, config->dci_log_config.field, dflt, req);
    NGSCOPE_LOG_KEYS(X)
#undef X

    /* Not freed: STRPTR fields (replay_fname) hold strings handed over from the parse. The
     * table itself could be freed, but the strings must not be, and toml_free() would take
     * them with it. */
    ngscope_config_finalize(config, path);
    return 0;
}
