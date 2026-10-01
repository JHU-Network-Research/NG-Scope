# Replay measurement harness

Scripts and config templates for A/B-ing a decoder change against a fixed IQ recording.
Replay is the right instrument because the scheduler *blocks* on a busy decoder rather than
discarding the subframe, so two runs over the same file see identical input and a yield figure
means something. Live capture drops instead, silently.

Run outputs are gitignored — they run to hundreds of megabytes each.

## Scripts

| script | does |
|---|---|
| `run.sh <config> <label>` | one replay, then extracts DCI counts, distinct RNTIs, the `rach_ok` split, the DCI format distribution and every teardown report into `results/<label>.metrics` |
| `analyse_pcap.sh <file.pcapng>` | cross-tabulates RRC/NAS message type against joined security phase |

`run.sh` is written for the **build container**, which is where its paths resolve — it
hard-codes `/src/measurements/results` and `/src/build-docker/ngscope/src/ngscope`:

```bash
docker run --rm -v "$PWD":/src -w /src amarder89/ng-scope:gui \
  bash -lc 'measurements/run.sh /src/measurements/sec_60s.toml mylabel'
```

On a host that can build natively there is no container and those paths do not exist. Until the
script is parameterised, either edit the two paths or run the binary directly:

```bash
build/ngscope/src/ngscope -c measurements/sec_60s.toml -o out/
```

`analyse_pcap.sh` takes a file argument and has no container assumptions, so it runs either way
— it needs `tshark` and `capinfos`, which are on the host rather than in the image.

## Configs

These are templates, not portable configs: `replay_fname` is an absolute `/src/...` path as
seen from inside the container, and `rf_freq` is set for the reference capture (EARFCN 5035,
band 12, 731.5 MHz). Edit both for your own recording.

`rf_freq` is required but **unused in replay** — `radio.c` only tunes when `mode != REPLAY`, so
it just labels the `.dciLog` filenames. Set it to 0 for a capture whose frequency you do not
know rather than inventing a plausible-looking number. `nof_thread` must be 1–8.

| config | for |
|---|---|
| `base.toml` | RACH-gated baseline |
| `sec_60s.toml` / `sec_full.toml` | security tracking + pcap, the usual measurement |
| `pcap.toml` | pcap without security tracking |
| `a3off.toml` | blind mode, for comparing against RACH-gated |
| `smoke.toml` | 10 s prefix, for checking a build runs at all |

The `*_60s` variants point at a 60-second prefix. Cutting one keeps iteration fast — a full
300 s capture takes about 7 minutes to replay under emulation:

```python
# frames are [nof_samples:u64][full_secs:u64][frac_secs:f64][nof_samples * cf_t],
# and nof_samples varies, so the chain has to be walked rather than strided.
```

See `docs/security-implementation.md` §9 for the regression gates worth running.
