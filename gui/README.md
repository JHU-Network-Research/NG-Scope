# NG-Scope GUI

A desktop front end for `ngscope`: edit the configuration, pick where captures go, run it,
and watch its output live. Settings are remembered between sessions.

## Run

```bash
./gui/ngscope-gui
```

That is the whole thing — from any directory. The first run creates `gui/.venv` and
installs the one dependency (pywebview); later runs start straight away.

Build ngscope first: the GUI looks for the binary in `build/ngscope/src/ngscope`, then on
`PATH`, then `/usr/local/bin/ngscope`, and you can override the path under **Advanced**.

### System packages

pywebview renders through WebKitGTK, whose backend imports the system `gi` (PyGObject)
module, so on Debian/Ubuntu you need:

```bash
sudo apt install python3-gi gir1.2-webkit2-4.1
```

The launcher checks for `gi` and says so if it is missing.

### Doing it by hand

```bash
cd gui
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m ngscope_gui          # must be run from gui/
```

`--system-site-packages` is **required**: a plain venv hides the system `gi` and the app
cannot open a window. If you hit that, delete `gui/.venv` and re-run the launcher.

## What it does

* **Configuration** — every key in the schema
  (`ngscope/hdr/dciLib/load_config.h`) is editable, grouped into Cells (up to 4
  `[[rf_config]]` devices), Decoding, and Logging. A `config.toml` is regenerated at each
  launch as `<output directory>/ngscope-gui-run.toml`, so the exact configuration that
  produced a capture sits beside it.
* **Record / replay** — Record writes IQ to
  `<output directory>/<timestamp>/recorded-samples.bin`; that path is fixed by
  `ngscope_main.c:113`, so the GUI lets you choose the *directory* rather than pretending
  the filename is settable. Replay takes an explicit file, chosen with a native dialog.
* **EARFCN sweep** — cycle cell 1 through a list of channels. ngscope has no scanning mode,
  so each channel is a separate run with its own `<timestamp>/` folder and its own
  `ngscope-gui-sweep-<earfcn>.toml`. The list takes EARFCNs separated by commas or spaces,
  plus ranges with an optional step (`5230-5240:5`).

  Each channel has two phases. **Listen** is timed from cell lock, so a channel whose cell
  search took four seconds still gets its full listening time; **Give up after** bounds the
  search, because a channel with nothing on it would otherwise retry forever. A pass
  therefore takes between `n × listen` and `n × (listen + giveup)`, which the UI quotes.

  Results build up in a table as it goes — band, frequency, PCI, PRB, time to lock, and
  time spent listening — so a pass tells you which channels had a cell and how quickly it
  locked. `Repeat` keeps cycling until you press Stop.

  Output is grouped by channel, with one summary per sweep:

  ```
  <output directory>/
  ├── sweep-summary-2026_08_17_10_16_02.csv     stamped when the sweep started
  ├── earfcn-66636/
  │   ├── ngscope-gui-sweep-66636.toml          the config this channel ran with
  │   ├── 2026_08_17_10_16_02/                  one ngscope run per visit
  │   └── 2026_08_17_10_16_13/
  └── earfcn-2850/
      └── …
  ```

  The summary has a row per channel visit, appended as each finishes so an interrupted
  sweep still leaves its results: `pass, earfcn, band, freq_hz, locked, pci, prb, lock_s,
  listen_s, total_s, exit_code, run_dir`. `run_dir` points at the capture, so the CSV is
  the index from channel to data. One `Repeat` cycle bumps `pass`; a second sweep into the
  same directory gets its own summary rather than overwriting.
* **Plots** — the two series srsGUI draws, rendered in this window instead of its own:
  **PDCCH — Equalized Symbols** and **Channel Response — Magnitude**, with the same axis
  scales `status_plot.c` gives srsGUI (±3 for the constellation, −40..40 dB for the
  response). Streaming is opt-in and invisible to anyone else: the GUI sets
  `NGSCOPE_PLOT_SOCK` to a unix socket when it launches ngscope, and with the variable
  unset — running ngscope from a terminal — srsGUI opens its windows exactly as before.
  Requires a build with `ENABLE_GUI` and a cell with `disable_plot` off.
* **Console** — ngscope's stdout and stderr, live. The process is given a pty so its
  `printf` output stays line-buffered instead of arriving in 4 KB blocks. Filter, wrap,
  follow, save to file, and a shortcut to the run folder once ngscope announces it.
* **Validation** — the rules in `ngscope_config_finalize()` (missing RNTI, replay without
  a file, two cells on one frequency, thread and buffer limits) are checked before launch,
  so they surface inline instead of as a process that exits immediately.
* **Persistence** — everything lands in `~/.config/ngscope-gui/state.json` and is restored
  on next open. `Load .toml` / `Save as…` import and export named config files.

Start with Ctrl+Enter, stop with Escape. Stop sends SIGINT, which sets `go_exit` and lets
ngscope flush its logs; it escalates to SIGTERM after 10s and SIGKILL after a further 5s.

## Keeping in sync with the C side

`ngscope_gui/schema.py` mirrors the X-macro tables in `ngscope/hdr/dciLib/load_config.h`.
Adding a setting means one line in each — the form, the TOML writer, and the reader are all
driven from the schema, so no widget code has to change. A key that no group in `app.js`
names still appears, under "More options".
