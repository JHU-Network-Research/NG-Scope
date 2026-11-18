"""Rule-based cell classification (replaces the random forest).

A cell is judged by the fraction of the UEs seen in the listening window that were observed to
authenticate (`frac_auth_total` from compile_replays.py: a UE counts if a security-mode command or
a data-radio-bearer frame was seen for its RNTI).

    fraction >= threshold  ->  "legitimate"
    fraction <  threshold  ->  "unknown"   (could be an IMSI catcher; not enough authentication)

Optional sufficiency checks (each off by default) guard against judging a cell on too little
traffic. If an enabled check fails the window is "insufficient" and no verdict is made.
"""

TOLERANCE_S = 5  # a window counts as a full listen if its duration is within this of `listen`

DEFAULT_RULES = {
    "auth_threshold_pct": 30.0,
    "min_ues_on": False, "min_ues": 10,
    "min_dcis_on": False, "min_dcis_per_rnti": 50.0,
    "min_tbs_on": False, "min_total_tbs": 1_000_000,
}
DEFAULT_LISTEN_S = 120

FEATURES = [
    "ue_count", "count_auth_total", "frac_auth_total",
    "count_auth_drb", "frac_auth_drb", "count_auth_secmode", "frac_auth_secmode",
    "auth_msg_count", "dcis_per_ue", "total_tbs_per_ue", "total_tbs", "duration",
]


def normalize(rules):
    r = dict(DEFAULT_RULES)
    r.update({k: v for k, v in (rules or {}).items() if k in DEFAULT_RULES})
    r["auth_threshold_pct"] = float(r["auth_threshold_pct"])
    if not 0 <= r["auth_threshold_pct"] <= 100:
        raise ValueError("Authentication threshold must be between 0 and 100 %.")
    for k in ("min_ues", "min_dcis_per_rnti", "min_total_tbs"):
        r[k] = float(r[k])
        if r[k] < 0:
            raise ValueError(f"{k} cannot be negative.")
    for k in ("min_ues_on", "min_dcis_on", "min_tbs_on"):
        r[k] = bool(r[k])
    return r


def features_of(row):
    ue = float(row["ue_count"])
    per_ue = float(row["total_tbs_per_ue"])
    f = {k: float(row[k]) for k in FEATURES if k in row and k != "total_tbs"}
    f["total_tbs"] = per_ue * ue
    return {k: round(f[k], 4) for k in FEATURES if k in f}


def evaluate(feat, rules):
    """Apply the rules to one feature vector. Returns (label, checks)."""
    checks = []
    failed = False
    if rules["min_ues_on"]:
        ok = feat["ue_count"] >= rules["min_ues"]
        checks.append({"name": "UEs seen", "value": feat["ue_count"],
                       "need": f">= {rules['min_ues']:g}", "ok": ok})
        failed |= not ok
    if rules["min_dcis_on"]:
        ok = feat["dcis_per_ue"] >= rules["min_dcis_per_rnti"]
        checks.append({"name": "DCIs per RNTI", "value": round(feat["dcis_per_ue"], 1),
                       "need": f">= {rules['min_dcis_per_rnti']:g}", "ok": ok})
        failed |= not ok
    if rules["min_tbs_on"]:
        ok = feat["total_tbs"] >= rules["min_total_tbs"]
        checks.append({"name": "Total TBS", "value": round(feat["total_tbs"]),
                       "need": f">= {rules['min_total_tbs']:g}", "ok": ok})
        failed |= not ok
    if failed:
        return "insufficient", checks
    pct = feat["frac_auth_total"] * 100
    ok = pct >= rules["auth_threshold_pct"]
    checks.append({"name": "UEs authenticated", "value": f"{pct:.1f} %",
                   "need": f">= {rules['auth_threshold_pct']:g} %", "ok": ok})
    return ("legitimate" if ok else "unknown"), checks


def classify(celldf, rules, listen=DEFAULT_LISTEN_S):
    """Classify every window of a compile_replays celldf built with interval=`listen`."""
    rules = normalize(rules)
    need = ["ue_count", "frac_auth_total", "dcis_per_ue", "total_tbs_per_ue", "duration"]
    missing = [c for c in need if c not in celldf]
    if missing:
        raise ValueError(f"celldf is missing columns: {missing}")
    df = celldf.sort_values([c for c in ("window_start", "window_index") if c in celldf])
    full = df[(df.duration - listen).abs() <= TOLERANCE_S]
    partial = full.empty
    use = df if partial else full
    out = []
    for _, row in use.iterrows():
        feat = features_of(row)
        label, checks = evaluate(feat, rules)
        out.append({
            "cell_id": int(row.get("cell_id", -1)), "earfcn": int(row.get("earfcn", -1)),
            "duration": round(float(row["duration"]), 1), "ue_count": int(row["ue_count"]),
            "auth_frac": round(float(row["frac_auth_total"]), 4),
            "label": label, "checks": checks, "partial": bool(partial), "features": feat,
        })
    return out


def summarize(windows):
    """One verdict per recording: the first window, i.e. the first `listen` seconds."""
    if not windows:
        return {"label": "insufficient", "auth_frac": None}
    first = windows[0]
    return {"label": first["label"], "auth_frac": first["auth_frac"]}
