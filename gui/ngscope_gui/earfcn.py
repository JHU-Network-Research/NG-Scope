"""LTE EARFCN <-> downlink centre frequency.

The band table is transcribed from srsRAN's own `lte_bands[]`
(lib/src/phy/common/phy_common.c), and the lookup mirrors `srsran_band_fd()` /
`srsran_band_get_band()` there, so the frequency this module computes is the one ngscope
would associate with the EARFCN. It was generated from that array rather than typed by
hand; regenerate it the same way if srsRAN's table changes.

Each row is (band, fd_low_mhz, dl_earfcn_offset), and within a band:

    F_DL = fd_low_mhz + 0.1 * (dl_earfcn - dl_earfcn_offset)   [MHz]

Like srsRAN, this does not verify that an EARFCN lies inside its band's actual channel
width -- the table's offsets partition the EARFCN space, so any value in range maps to
some band.
"""

# (band, fd_low_mhz, dl_earfcn_offset) -- ordered by dl_earfcn_offset.
LTE_BANDS = [
    (  1,     2110,      0),
    (  2,     1930,    600),
    (  3,     1805,   1200),
    (  4,     2110,   1950),
    (  5,      869,   2400),
    (  6,      875,   2650),
    (  7,     2620,   2750),
    (  8,      925,   3450),
    (  9,   1844.9,   3800),
    ( 10,     2110,   4150),
    ( 11,   1475.9,   4750),
    ( 12,      729,   5010),
    ( 13,      746,   5180),
    ( 14,      758,   5280),
    ( 17,      734,   5730),
    ( 18,      860,   5850),
    ( 19,      875,   6000),
    ( 20,      791,   6150),
    ( 21,   1495.9,   6450),
    ( 22,     3500,   6600),
    ( 23,     2180,   7500),
    ( 24,     1525,   7700),
    ( 25,     1930,   8040),
    ( 26,      859,   8690),
    ( 27,      852,   9040),
    ( 28,      758,   9210),
    ( 29,      717,   9660),
    ( 30,     2350,   9770),
    ( 31,    462.5,   9870),
    ( 32,     1452,   9920),
    ( 33,     1900,  36000),
    ( 34,     2010,  36200),
    ( 35,     1850,  36350),
    ( 36,     1930,  36950),
    ( 37,     1910,  37550),
    ( 38,     2570,  37750),
    ( 39,     1880,  38250),
    ( 40,     2300,  38650),
    ( 41,     2496,  39650),
    ( 42,     3400,  41590),
    ( 43,     3600,  43590),
    ( 44,      703,  45590),
    ( 45,     1447,  46590),
    ( 46,     5150,  46790),
    ( 47,     5855,  54540),
    ( 48,     3550,  55240),
    ( 49,     3550,  56740),
    ( 50,     1432,  58240),
    ( 51,     1427,  59090),
    ( 52,     3300,  59140),
    ( 64,        0,  60140),
    ( 65,     2110,  65536),
    ( 66,     2110,  66436),
    ( 67,      738,  67336),
    ( 68,      753,  67536),
    ( 69,     2570,  67836),
    ( 70,     1995,  68336),
    ( 71,      617,  68586),
    ( 72,        0,  68936),
]

# The last row is a terminator (band 72, fd_low 0) marking the end of the EARFCN space;
# srsran_band_get_band() never returns it, matching the exclusion here.
MAX_DL_EARFCN = LTE_BANDS[-1][2]

# Sanity bounds for a downlink centre frequency, used to catch unit mistakes such as
# entering MHz into a field that wants Hz.
MIN_SANE_HZ = 100_000_000
MAX_SANE_HZ = 8_000_000_000


def _band_row(earfcn):
    """Mirror of srsran_band_get_band(): the last row whose offset is <= earfcn,
    excluding the terminator."""
    if earfcn < 0 or earfcn > MAX_DL_EARFCN:
        return None
    match = None
    for row in LTE_BANDS[:-1]:
        if row[2] <= earfcn:
            match = row
        else:
            break
    return match


def earfcn_to_freq(earfcn):
    """(freq_hz, band) for a downlink EARFCN, or None if out of range."""
    row = _band_row(earfcn)
    if row is None:
        return None
    band, fd_low_mhz, offset = row
    mhz = fd_low_mhz + 0.1 * (earfcn - offset)
    # 0.1 MHz raster -> round to the nearest 100 kHz to keep float error out of the Hz.
    return int(round(mhz * 10) * 100_000), band


def freq_to_earfcns(freq_hz):
    """Every downlink EARFCN that maps to this frequency, as [(earfcn, band), ...].

    Deliberately a list, not a single value: bands overlap in frequency -- 2130 MHz is a
    valid centre in bands 1, 4 and 66 -- so one frequency can have several EARFCNs, and
    guessing one would silently pick the wrong band. Empty if the frequency does not land
    on any band's 100 kHz raster.
    """
    if not freq_hz or freq_hz < MIN_SANE_HZ or freq_hz > MAX_SANE_HZ:
        return []
    mhz = freq_hz / 1_000_000
    out = []
    for i, (band, fd_low_mhz, offset) in enumerate(LTE_BANDS[:-1]):
        span = LTE_BANDS[i + 1][2] - offset          # EARFCNs belonging to this band
        earfcn = offset + int(round((mhz - fd_low_mhz) * 10))
        if offset <= earfcn < offset + span:
            back = earfcn_to_freq(earfcn)
            if back and back[0] == freq_hz:
                out.append((earfcn, band))
    return out


def describe(earfcn):
    """Human-readable summary for the UI, or None if the EARFCN is invalid."""
    result = earfcn_to_freq(earfcn)
    if result is None:
        return None
    freq_hz, band = result
    return {"freq_hz": freq_hz, "band": band, "mhz": freq_hz / 1_000_000}
