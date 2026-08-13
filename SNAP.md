# NG-Scope snap

A strictly-confined snap of `ngscope` with its srsGUI plot window and UHD
support for USRP B200/B210 (USB 3.0) and X300/X310/X410 (Ethernet).

This replaces the manual build described in the
[upstream wiki](https://github.com/PrincetonUniversity/NG-Scope/wiki/2.-Build-Instructions),
including the `sudo make install` of srsGUI, which is not in the Ubuntu archive.

---

## Install

```sh
sudo snap install --dangerous ngscope_<version>_amd64.snap
```

`--dangerous` means "unasserted" (no store signature to verify). It does **not**
mean unconfined — strict confinement is fully in force either way.

Then connect the interfaces that are not auto-connected:

```sh
sudo snap connect ngscope:raw-usb            # B200/B210 only
sudo snap connect ngscope:removable-media    # only to write captures to an external drive
```

`home`, `network`, `network-bind`, `opengl`, `x11` and `wayland` connect
automatically from snapd's base declaration. Check with `snap connections ngscope`.

### USB radios need a host udev rule

The `raw-usb` interface lets the sandboxed process reach `/dev/bus/usb`, but
snapd cannot change the ownership or mode of host device nodes. Without a rule,
opening a B200/B210 fails with `LIBUSB_ERROR_ACCESS` even with the interface
connected. Normally `uhd-host` installs this rule; a snap user has no `uhd-host`
on the host, so install the shipped copy once:

```sh
sudo cp /snap/ngscope/current/etc/udev/rules.d/uhd-usrp.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Then unplug and replug the USRP. The rule sets `MODE:="0666"`, so no group
membership is needed. Ethernet USRPs do not need this at all.

---

## First run

```sh
ngscope.uhd-find                     # confirm the radio is visible
mkdir -p ~/captures && cd ~/captures
ngscope                              # writes a starter config, then uses it
```

The first run copies a documented starter configuration to
`~/snap/ngscope/common/config.cfg`. Edit at least `rf_freq` and `rf_args`:

| Radio | `rf_args` |
|---|---|
| B200 / B210 / B205mini | `"type=b200"`, or `"serial=3292BBF"` to pin one of several |
| X300 / X310 | `"type=x300,addr=192.168.40.2"` |
| X410 | `"type=x4xx,addr=192.168.40.2"` |

The whole b2xx family shares `type=b200`, and the bundled FPGA images cover
B200, B210, B200mini and B205mini.

Then run it explicitly:

```sh
cd ~/captures
ngscope -c ~/snap/ngscope/common/config.cfg
```

**Run from a directory under `$HOME`.** `ngscope` writes all of its output
relative to the current directory — `dci_output/*.dciLog`, `decoded_sibs/`,
`rsrp.txt`, `cellcfg.txt`, `cell_status.txt` and friends. The `home` interface
covers non-hidden paths under `$HOME`; anywhere else the launcher falls back to
`~/snap/ngscope/common` and says so.

### Commands

| Command | Purpose |
|---|---|
| `ngscope` | the sniffer |
| `ngscope.uhd-find` | `uhd_find_devices` — run this first when the radio can't be opened |
| `ngscope.remote-client` | connect to the DCI sink server |
| `ngscope.remote-server` | DCI sink server |

---

## Known limitations

### UHD version is coupled to your FPGA image

The snap bundles **UHD 4.1.0.5**, the version in the Ubuntu 22.04 archive
(`libuhd-dev` + `uhd-host`). X310 and X410 hold their FPGA image on the device,
and UHD refuses to open one built for a different version. If your radio is
flashed for a newer UHD you will see a version-mismatch error and must run
`uhd_image_loader` to bring the FPGA in line.

B200/B210 are unaffected — their images ship inside the snap and are downloaded
at build time from the same UHD version.

`ppa:ettusresearch/uhd` is deliberately **not** used. It publishes only the
newest `libuhd-dev` (4.10.0.0, with no versioned dev packages), and UHD's
headers became C++17-only somewhere after 4.6 — `uhd/utils/cast.hpp` uses
`std::is_same_v` and `if constexpr`, `uhd/rfnoc/actions.hpp` uses
`std::optional`. srsRAN pins `-std=c++14` at `CMakeLists.txt:392`, so
`lib/src/phy/rf/rf_uhd_imp.cc` will not compile against them. Raising the whole
project to C++17 to accommodate a newer UHD is possible but untested.

### FPGA images beyond b2xx are not bundled

The `uhd-host` deb ships the downloader, not the images (the full set is
~690 MB). Only the b2xx set (14 MB) is bundled — B200, B210, B200mini and
B205mini, which cannot enumerate without their FPGA and firmware images.
X300/X310/X410 do not need host-side images for normal streaming, only for
`uhd_image_loader`.

To add them, run the downloader **on the host** and copy the result in:

```sh
uhd_images_downloader --types x3xx        # or x4xx
cp -r /usr/share/uhd/images/. ~/snap/ngscope/common/uhd-images/
```

There is no `ngscope.uhd-images` app: `uhd_images_downloader` is a Python
script, and snapcraft stages uhd-host's Python libraries without the `python3`
interpreter, so it cannot run inside the snap.

**How the images directory is chosen.** `uhd::get_images_dir()` resolves
`UHD_IMAGES_DIR` to a *single* directory and only accepts one that exists — it
does not search a `:`-separated list. So `uhd_setup_images_dir()` in
`bin/uhd-env.sh` picks one: the read-only bundled set by default, switching to
`~/snap/ngscope/common/uhd-images` as soon as that directory is non-empty. Copy
the bundled b2xx images in alongside your own if you use both a B2xx and an
X-series radio, since the chosen directory is used exclusively.

### `/tmp` is not writable

IQ record/replay (`mode = 1` or `2`) writes to `rr_fname`. The upstream sample
config points that at `/tmp/ngscope_iq.bin`, which the sandbox cannot write.
Use a path under `$HOME` or a bare filename, which resolves against the CWD.

### 10 GbE tuning is a host concern

A snap cannot set host sysctls. For X310/X410 at high sample rates you still
need, on the host:

```sh
sudo sysctl -w net.core.rmem_max=33554432
sudo sysctl -w net.core.wmem_max=33554432
```

plus jumbo frames (`sudo ip link set <iface> mtu 9000`) on the interface facing
the radio.

### amd64 only

The snap is built with `-DGCC_ARCH=x86-64-v3` — AVX2 + FMA, i.e. Intel Haswell
(2013) and AMD Excavator or newer. This is deliberate: NG-Scope's CMake defaults
to `-march=native` and run-detects AVX-512 from the *build* machine
(`CMakeLists.txt:113-120`, `cmake/modules/FindSSE.cmake`), which would produce a
snap that crashes with `SIGILL` on any other CPU. An arm64 build would need
`-DGCC_ARCH=armv8-a` and is untested.

---

## Building

```sh
sudo snap install snapcraft --classic
sudo snap install lxd && sudo lxd init --auto
sudo adduser "$USER" lxd && newgrp lxd

cd /path/to/NG-Scope
snapcraft --use-lxd
```

The build compiles all of srsRAN plus srsGUI, so expect 20–40 minutes on a first
run. Subsequent builds reuse the LXD instance; `snapcraft clean srsgui` (or any
part name) forces just that part to rebuild.

Tagged pushes build and publish automatically via `.github/workflows/snap.yml`.

### Layout

| Path | Role |
|---|---|
| `snap/snapcraft.yaml` | the recipe |
| `snap/local/uhd-env.sh` | shared helper: library paths and images-directory selection, sourced by both launchers |
| `snap/local/ngscope-launch` | seeds the starter config, checks the CWD is writable, defaults `-c` |
| `snap/local/uhd-find-launch` | wraps `uhd_find_devices` |
| `snap/local/config.cfg` | starter config, seeded to `$SNAP_USER_COMMON` on first run |
| `snap/local/uhd-usrp.rules` | host udev rule for USB radios |

### Notes for maintainers

Four gotchas the recipe works around, each commented at its site in
`snapcraft.yaml`:

1. `libconfig` is an undeclared dependency — `ngscope/src/dciLib/CMakeLists.txt:9`
   links the bare name `config` with no `find_package`.
2. `remote_client` and `remote_server` are built but never installed
   (`ngscope/src/CMakeLists.txt:38-39`), so the recipe installs them explicitly.
3. Jammy builds UHD with the Python API, so `libuhd.so.4.1.0` has a `NEEDED`
   entry for `libpython3.10.so.1.0`. Never prune it from `prime:` — doing so
   breaks `uhd_find_devices` and the `dlopen` of the RF plugin.
4. `-DAUTO_DETECT_ISA=OFF` is **not** the way to pin the ISA — it leaves
   `HAVE_SSE` unset and trips `FATAL_ERROR "no SIMD instructions found"` at
   `CMakeLists.txt:503-505`. Use `-DGCC_ARCH=` plus `-DENABLE_AVX512=OFF`.

To trim roughly 25 MB (compressed), replace the `uhd-host` stage-package with
`libuhd4.1.0`; this drops Python and with it the `uhd-find` and `uhd-images`
apps.

### Moving to the Snap Store later

The artifact is identical — the migration is
`snapcraft login && snapcraft upload --release=stable ngscope_*.snap`, which
gains auto-updates and delta downloads. Two things keep that door open:

- **Reserve the name** at <https://snapcraft.io/register-snap>. Free, and does
  not oblige you to publish.
- Keep `grade: stable` and monotonic versions (already handled by `adopt-info`).

`raw-usb` will still need a manual `snap connect` after publishing, unless you
separately request an auto-connect declaration during store review.
