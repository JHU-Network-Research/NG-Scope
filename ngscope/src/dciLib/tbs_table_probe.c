#include "ngscope/hdr/dciLib/tbs_table_probe.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

/* Real schedulers stay below this; 3GPP turbo coding tops out around 0.93 after rate
 * matching. Between here and 1.0 is "implausible"; above 1.0 is impossible. */
#define TBS_PROBE_MAX_PLAUSIBLE_RATE 0.93f

typedef struct {
    uint64_t nof_grants;
    uint64_t nof_impossible; /* code rate > 1.0   */
    uint64_t nof_implausible;/* code rate > 0.93  */
    double   sum_rate;
} tbs_probe_table_t;

/* [confidence][table]: table 0 = 64QAM, 1 = 256QAM.
 *
 * Two populations, because the natural hook point sees every candidate whose PDCCH CRC
 * descrambled to something, and most of those are later pruned as false alarms. A false
 * candidate carries an arbitrary MCS and PRB count, so it produces impossible code rates
 * under BOTH tables and buries the signal. Requiring a high re-encode correlation selects
 * candidates that are very likely real, and it is that population the verdict reads. */
#define TBS_PROBE_ALL 0
#define TBS_PROBE_CONFIDENT 1
#define TBS_PROBE_MIN_CORR 0.8f

static tbs_probe_table_t probe[2][2];
static uint64_t          nof_skipped;
static pthread_mutex_t   probe_mutex = PTHREAD_MUTEX_INITIALIZER;

static void account(tbs_probe_table_t* t, int tbs, uint32_t nof_bits)
{
    t->nof_grants++;
    const double rate = (double)tbs / (double)nof_bits;
    t->sum_rate += rate;
    if (rate > 1.0) {
        t->nof_impossible++;
    }
    if (rate > TBS_PROBE_MAX_PLAUSIBLE_RATE) {
        t->nof_implausible++;
    }
}

void ngscope_tbs_probe_add(const srsran_pdsch_grant_t* grant,
                           const srsran_dci_dl_t*      dci,
                           bool                        configured_alt,
                           float                       corr)
{
    if (grant == NULL || dci == NULL) {
        return;
    }
    /* srsRAN forces the 64QAM table for Format1A and for non-user RNTIs (ra_dl.c), so those
     * grants carry no information about which table the cell configured. Excluding them keeps
     * the two populations comparable. */
    if (dci->format == SRSRAN_DCI_FORMAT1A || !SRSRAN_RNTI_ISUSER(dci->rnti)) {
        return;
    }

    for (int tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
        if (!grant->tb[tb].enabled || grant->tb[tb].tbs <= 0 || grant->nof_re == 0 ||
            grant->tb[tb].nof_bits == 0) {
            continue;
        }

        /* The configured table's numbers are already on the grant. Recompute the same grant
         * under the other table: nof_prb and nof_re are unchanged, only the MCS->TBS-index
         * mapping and the modulation order differ. */
        const uint32_t     mcs       = grant->tb[tb].mcs_idx;
        const bool         other_alt = !configured_alt;
        const int          i_tbs     = srsran_ra_tbs_idx_from_mcs(mcs, other_alt, false);
        const int          other_tbs = (i_tbs < 0) ? -1 : srsran_ra_tbs_from_idx((uint32_t)i_tbs, grant->nof_prb);
        const srsran_mod_t other_mod = srsran_ra_dl_mod_from_mcs(mcs, other_alt);
        const uint32_t     other_bits = grant->nof_re * srsran_mod_bits_x_symbol(other_mod);

        const int cfg_i   = configured_alt ? 1 : 0;
        const int other_i = other_alt ? 1 : 0;
        const bool confident = (corr >= TBS_PROBE_MIN_CORR);

        pthread_mutex_lock(&probe_mutex);
        account(&probe[TBS_PROBE_ALL][cfg_i], grant->tb[tb].tbs, grant->tb[tb].nof_bits);
        if (confident) {
            account(&probe[TBS_PROBE_CONFIDENT][cfg_i], grant->tb[tb].tbs, grant->tb[tb].nof_bits);
        }
        if (other_tbs > 0 && other_bits > 0) {
            account(&probe[TBS_PROBE_ALL][other_i], other_tbs, other_bits);
            if (confident) {
                account(&probe[TBS_PROBE_CONFIDENT][other_i], other_tbs, other_bits);
            }
        } else {
            /* Reserved MCS under the other table: no comparable number, so record the gap
             * rather than silently biasing one population. */
            nof_skipped++;
        }
        pthread_mutex_unlock(&probe_mutex);
    }
}

static void report_one(const char* name, const tbs_probe_table_t* t)
{
    if (t->nof_grants == 0) {
        printf("TBS table probe:   %-13s no grants\n", name);
        return;
    }
    printf("TBS table probe:   %-13s %8llu grants, mean rate %.3f, %llu implausible (>%.2f, %.2f%%), "
           "%llu IMPOSSIBLE (>1.0, %.2f%%)\n",
           name,
           (unsigned long long)t->nof_grants,
           t->sum_rate / (double)t->nof_grants,
           (unsigned long long)t->nof_implausible,
           TBS_PROBE_MAX_PLAUSIBLE_RATE,
           100.0 * (double)t->nof_implausible / (double)t->nof_grants,
           (unsigned long long)t->nof_impossible,
           100.0 * (double)t->nof_impossible / (double)t->nof_grants);
}

static void verdict(const char* pop, const tbs_probe_table_t* t64, const tbs_probe_table_t* t256)
{
    if (t64->nof_grants == 0) {
        return;
    }
    const bool bad64  = t64->nof_impossible > 0;
    const bool bad256 = t256->nof_impossible > 0;

    if (bad64 != bad256) {
        printf("TBS table probe: VERDICT (%s) -- this cell uses the %s table. Set enable_256qam = %s\n",
               pop, bad64 ? "256QAM" : "64QAM", bad64 ? "true" : "false");
        return;
    }
    if (!bad64 && !bad256) {
        printf("TBS table probe: VERDICT (%s) -- neither table is contradicted; the lower mean "
               "code rate (%s) is the likelier one.\n",
               pop, (t64->sum_rate / t64->nof_grants <= t256->sum_rate / t256->nof_grants) ? "64QAM" : "256QAM");
        return;
    }
    /* Both show impossible rates. Some of that is false-positive DCIs, which corrupt both
     * tables equally, so the ratio between them still carries the signal. */
    const double r64  = (double)t64->nof_impossible / (double)t64->nof_grants;
    const double r256 = (double)t256->nof_impossible / (double)t256->nof_grants;
    const double lo   = (r64 < r256) ? r64 : r256;
    const double hi   = (r64 < r256) ? r256 : r64;
    const char*  best = (r64 < r256) ? "64QAM" : "256QAM";
    if (lo > 0.0 && hi / lo >= 2.0) {
        printf("TBS table probe: VERDICT (%s) -- both tables show impossible rates (false-positive "
               "DCIs do that), but %s is %.1fx cleaner, so it is the likelier one. Set "
               "enable_256qam = %s\n",
               pop, best, hi / lo, (r64 < r256) ? "false" : "true");
    } else {
        printf("TBS table probe: VERDICT (%s) -- inconclusive: %.2f%% vs %.2f%% impossible, too "
               "close to separate. Suspect the DCIs rather than the table.\n",
               pop, 100.0 * r64, 100.0 * r256);
    }
}

void ngscope_tbs_probe_report(void)
{
    pthread_mutex_lock(&probe_mutex);
    tbs_probe_table_t snap[2][2];
    memcpy(snap, probe, sizeof(snap));
    uint64_t skipped = nof_skipped;
    pthread_mutex_unlock(&probe_mutex);

    if (snap[TBS_PROBE_ALL][0].nof_grants == 0) {
        return; /* nothing to say rather than a guess */
    }

    printf("TBS table probe: which MCS->TBS table is this cell using?\n");
    printf("TBS table probe:  -- all PDCCH candidates (includes unpruned false alarms) --\n");
    report_one("64QAM", &snap[TBS_PROBE_ALL][0]);
    report_one("256QAM", &snap[TBS_PROBE_ALL][1]);
    printf("TBS table probe:  -- re-encode correlation >= %.2f (very likely real) --\n",
           TBS_PROBE_MIN_CORR);
    report_one("64QAM", &snap[TBS_PROBE_CONFIDENT][0]);
    report_one("256QAM", &snap[TBS_PROBE_CONFIDENT][1]);
    if (skipped > 0) {
        printf("TBS table probe:   %llu grants skipped (reserved MCS)\n", (unsigned long long)skipped);
    }

    verdict("all", &snap[TBS_PROBE_ALL][0], &snap[TBS_PROBE_ALL][1]);
    verdict("confident", &snap[TBS_PROBE_CONFIDENT][0], &snap[TBS_PROBE_CONFIDENT][1]);
    printf("TBS table probe: read the 'confident' verdict; the 'all' line is context.\n");
}
