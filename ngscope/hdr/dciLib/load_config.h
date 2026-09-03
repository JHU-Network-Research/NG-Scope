#ifndef _CONFIG_H_
#define _CONFIG_H_
#include <stdio.h>
#include "task_scheduler.h"

typedef enum { NORMAL, RECORD, REPLAY } ngscope_mode_t;

typedef struct{
    long long   rf_freq;
    int         N_id_2;
    char        rf_args[100];
    int         nof_thread;
    int         nof_rx_ant;
    int         disable_plot;
	int 		log_dl;
	int			log_ul;
    int         log_phich;

    ngscope_mode_t      mode; // operating mode (0=NORMAL, 1=RECORD, 2=REPLAY)
    const char *        replay_fname; // record/replay filename
    int         debug;
    int         silent;
    int         decode_pdcch;
}rf_dev_config_t;

typedef struct{
    int     nof_cell;

	// Any value larger than 0 indicates the log files will be separated into multiple files
	int 	log_interval; // in seconds
}dci_log_config_t;


typedef struct{
    int                 nof_rf_dev;
    int                 remote_enable;
	int 				decode_SIB;
	int 				decode_RAR;
	int 				rar_seed_tracker;
	int 				rach_filter_only;
	int 				mark_security_phase;
	int 				enable_256qam;
	int 				pcap_mac;
	int 				pcap_max_mb;
	/* Replay-only decode aid: inert in live capture, where spending a second PDSCH decode
	 * per failure would be paid for in discarded subframes. See security_rrc.h. */
	int 				qam_retry;
	/* Replay-only measurement instrument: probe every blind-search DCI against the DL-SCH
	 * CRC and record whether it is real, split by RACH confirmation. See security_rrc.h. */
	int 				probe_blind_dci;
    const char *        dci_logs_path;
    const char *        sib_logs_path;
    const char *        out_path;

    dci_log_config_t    dci_log_config;
    rf_dev_config_t     rf_config[MAX_NOF_RF_DEV];
}ngscope_config_t;

/****************************************************************************
 * Configuration schema
 *
 * These three tables are the single source of truth for what NG-Scope accepts. Adding a
 * setting is one line here plus the struct field it writes to -- the parser is generated
 * from the table, so no lookup code has to be touched, and any additional config backend
 * (e.g. TOML) can walk the same tables rather than duplicating the key list.
 *
 * Columns:  X(TYPE, "key", struct_field, default, required)
 *
 *   TYPE     INT | INT64 | BOOL | STRBUF (fixed char[]) | STRPTR (borrowed const char*)
 *   required true means there is no sane default: if the key is absent NG-Scope reports
 *            it and exits rather than running with a fabricated value.
 *
 * Every optional key MUST have a usable default. ngscope_config_t is a stack local in
 * main(), so a key with no default and no value leaves the field holding garbage.
 *
 * These tables are mirrored in gui/ngscope_gui/schema.py, which is what the GUI renders
 * its form and writes its TOML from. Adding a setting here means adding the matching line
 * there, or the GUI will not be able to set it.
 ****************************************************************************/

/* Top-level keys, written to ngscope_config_t */
#define NGSCOPE_TOP_LEVEL_KEYS(X)                                                          \
    X(INT,    "nof_rf_dev",        nof_rf_dev,         1,      false)                      \
    X(BOOL,   "remote_enable",     remote_enable,      false,  false)                      \
    X(BOOL,   "decode_SIB",        decode_SIB,         false,  false)                      \
    X(BOOL,   "decode_RAR",        decode_RAR,         false,  false)                      \
    X(BOOL,   "rar_seed_tracker",  rar_seed_tracker,   false,  false)                      \
    X(BOOL,   "rach_filter_only",  rach_filter_only,   false,  false)                      \
    X(BOOL,   "mark_security_phase", mark_security_phase, false, false)                    \
    X(BOOL,   "enable_256qam",     enable_256qam,      true,   false)                      \
    X(BOOL,   "pcap_mac",          pcap_mac,           false,  false)                      \
    X(INT,    "pcap_max_mb",       pcap_max_mb,        0,      false)                      \
    X(BOOL,   "qam_retry",         qam_retry,          true,   false)                      \
    X(BOOL,   "probe_blind_dci",   probe_blind_dci,    false,  false)

/* Per-device keys, written to ngscope_config_t.rf_config[i], read from "rf_config<i>.<key>" */
#define NGSCOPE_RF_DEV_KEYS(X)                                                             \
    /* Not marked required: replay learns it from the recording, and
     * ngscope_config_finalize() enforces it for the modes that actually tune. */          \
    X(INT64,  "rf_freq",           rf_freq,            0,      false)                      \
    X(INT,    "N_id_2",            N_id_2,             -1,     false)                      \
    X(INT,    "nof_thread",        nof_thread,         4,      false)                      \
    X(INT,    "nof_rx_ant",        nof_rx_ant,         1,      false)                      \
    X(STRBUF, "rf_args",           rf_args,            "",     false)                      \
    X(BOOL,   "disable_plot",      disable_plot,       true,   false)                      \
    X(BOOL,   "log_dl",            log_dl,             true,   false)                      \
    X(BOOL,   "log_ul",            log_ul,             true,   false)                      \
    X(BOOL,   "log_phich",         log_phich,          false,  false)                      \
    X(INT,    "mode",              mode,               0,      false)                      \
    X(STRPTR, "replay_fname",      replay_fname,       NULL,   false)                      \
    X(BOOL,   "debug",             debug,              false,  false)                      \
    X(BOOL,   "silent",            silent,             false,  false)                      \
    X(BOOL,   "decode_pdcch",      decode_pdcch,       true,   false)

/* Logging keys, written to ngscope_config_t.dci_log_config, read from "dci_log_config.<key>" */
#define NGSCOPE_LOG_KEYS(X)                                                                \
    X(INT,    "log_interval",      log_interval,       -1,     false)

/* Reads `path` into `config`. The backend is chosen by extension: *.toml is parsed as TOML,
 * anything else as libconfig. Both fill the same struct from the same schema above. */
int ngscope_read_config(ngscope_config_t* config, char * path);

/* TOML backend (load_config_toml.c). Call ngscope_read_config() instead. */
int ngscope_read_config_toml(ngscope_config_t* config, char * path);

/* Shared by every backend: a required key was absent. */
void ngscope_config_report_missing(const char* path);
void ngscope_config_reset_missing(void);

/* Shared validation. check_nof_rf_dev() must run before any rf_config[] indexing;
 * finalize() applies the cross-key rules and exits if a required key was missing. */
void ngscope_config_check_nof_rf_dev(ngscope_config_t* config);
void ngscope_config_finalize(ngscope_config_t* config, const char* path);

bool ngscope_config_check_log(ngscope_config_t* config);
#endif
