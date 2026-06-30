"""
Per-source-IP reclassification

Measurements:
    INTENSITY  high if peak_rpm >= HIGH_PEAK_RPM OR total_events >= HIGH_VOLUME
    INTENT     amplification if amp_intent_fraction >= AMP_INTENT_FRACTION

Labels:
    scanner   known research-scanner prefix OR (>=3 distinct query types AND low intensity)
    attacker  high intensity , amplification intent
    flooder   high intensity , benign intent
    prober    low  intensity , amplification intent
    noise     low  intensity , benign intent

Outputs: classified_sources_tiered.csv
         classification_axes_summary.csv
         classification_confusion_matrix.csv
"""

import duckdb
import pandas as pd
from common import PARQUET_PATH, DNS_AMP_TYPES, NTP_AMP_MODES, SSDP_IS_AMP, PROBE_LABEL_SQL

OUTPUT_LABELS    = "data/classified_sources_tiered.csv"
OUTPUT_AXES      = "data/classification_axes_summary.csv"
OUTPUT_CONFUSION = "data/classification_confusion_matrix.csv"

HIGH_PEAK_RPM = 100
HIGH_VOLUME   = 3400          # p99 total events per IP (very high ails)
AMP_INTENT_FRACTION = 0.50

SCANNER_MIN_QTYPES = 3
KNOWN_SCANNER_PREFIXES = (
    "66.240.", "71.6.", "216.239.",
    "198.108.66.", "162.142.", "167.94.",
    "192.35.168.", "141.212.",
)


def print_diagnostics(con):
    for svc, field in [("dns", "QueryType"), ("ntp", "Mode"), ("ssdp", "QueryType")]:
        print(f"{svc.upper()} {field}\n\n")
        print(con.execute(f"""
            SELECT {field}, COUNT(*) AS events
            FROM read_parquet(?) WHERE ServiceName = '{svc}'
            GROUP BY {field} ORDER BY events DESC
        """, [PARQUET_PATH]).df().to_string(index=False))


def compute_features(con):
    dns_types = ", ".join(f"'{t}'" for t in DNS_AMP_TYPES)
    ntp_modes = ", ".join(f"'{m}'" for m in NTP_AMP_MODES)
    ssdp_amp  = "1" if SSDP_IS_AMP else "0"
    return con.execute(f"""
        WITH per_minute AS (
            SELECT SourceIP,
                   DATE_TRUNC('minute', TRY_CAST(Timestamp AS TIMESTAMP)) AS minute,
                   COUNT(*) AS rpm
            FROM read_parquet('{PARQUET_PATH}')
            WHERE SourceIP IS NOT NULL GROUP BY 1, 2
        ),
        peak AS (SELECT SourceIP, MAX(rpm) AS peak_rpm FROM per_minute GROUP BY SourceIP),
        base AS (
            SELECT SourceIP,
                   COUNT(*) AS total_events,
                   COUNT(DISTINCT ServiceName) AS services_targeted,
                   COUNT(DISTINCT QueryType)   AS distinct_query_types,
                   ROUND(AVG(AmplificationFactor), 4) AS mean_amplification,
                   ROUND(AVG(CASE
                       WHEN ServiceName='dns'  AND QueryType IN ({dns_types}) THEN 1
                       WHEN ServiceName='ntp'  AND CAST(Mode AS VARCHAR) IN ({ntp_modes}) THEN 1
                       WHEN ServiceName='ssdp' THEN {ssdp_amp}
                       ELSE 0 END), 4) AS amp_intent_fraction
            FROM read_parquet('{PARQUET_PATH}')
            WHERE SourceIP IS NOT NULL GROUP BY SourceIP
        )
        SELECT base.*, peak.peak_rpm FROM base JOIN peak USING (SourceIP)
    """).df()


def label_row(r):
    intensity = "high" if (r.peak_rpm >= HIGH_PEAK_RPM or r.total_events >= HIGH_VOLUME) else "low"
    intent = "amplification" if r.amp_intent_fraction >= AMP_INTENT_FRACTION else "benign"
    if any(r.SourceIP.startswith(p) for p in KNOWN_SCANNER_PREFIXES):
        return intensity, intent, "scanner"
    if r.distinct_query_types >= SCANNER_MIN_QTYPES and intensity == "low":
        return intensity, intent, "scanner"
    if intensity == "high" and intent == "amplification": 
        label = "attacker"
    elif intensity == "high":
        label = "flooder"
    elif intent == "amplification":                        
        label = "prober"
    else:                                                  
        label = "noise"
    return intensity, intent, label


def original_label_per_ip(con):
    return con.execute(f"""
        WITH labelled AS (
            SELECT SourceIP, {PROBE_LABEL_SQL} AS orig, COUNT(*) c
            FROM read_parquet('{PARQUET_PATH}')
            WHERE SourceIP IS NOT NULL AND {PROBE_LABEL_SQL} IS NOT NULL
            GROUP BY 1, 2),
        ranked AS (
            SELECT SourceIP, orig,
                   ROW_NUMBER() OVER (PARTITION BY SourceIP ORDER BY c DESC) rn
            FROM labelled)
        SELECT SourceIP, orig AS original_label FROM ranked WHERE rn = 1
    """).df()


def main():
    con = duckdb.connect()
    print_diagnostics(con)
    print("\n(Verify intent rules above match common settings.)\n")

    feats = compute_features(con)
    print(f"{len(feats):,} source IPs")
    axes = feats.apply(label_row, axis=1, result_type="expand")
    axes.columns = ["intensity", "intent", "new_label"]
    feats = pd.concat([feats, axes], axis=1)

    merged = feats.merge(original_label_per_ip(con), on="SourceIP", how="left")
    merged.to_csv(OUTPUT_LABELS, index=False)

    print("\n New label distribution")
    print(merged["new_label"].value_counts().to_string())

    axes_summary = merged.groupby(["intensity", "intent"]).agg(
        ip_count=("SourceIP", "count"),
        avg_total_events=("total_events", "mean"),
        avg_peak_rpm=("peak_rpm", "mean"),
        avg_amplification=("mean_amplification", "mean")).round(2).reset_index()
    axes_summary.to_csv(OUTPUT_AXES, index=False)
    print("Intensity / Intent")
    print(axes_summary.to_string(index=False))

    pd.crosstab(merged["original_label"], merged["new_label"]).to_csv(OUTPUT_CONFUSION)
    print("\n Confusion (original -> new)")
    new_labels = sorted(merged["new_label"].dropna().unique())
    for orig in sorted(merged["original_label"].dropna().unique()):
        row = merged[merged["original_label"] == orig]
        parts = [f"{l}={int((row['new_label']==l).sum())}" for l in new_labels]
        print(f"  original={orig:8} (n={len(row):>6}) -> " + ", ".join(parts))

    oa = merged[merged["original_label"] == "attacker"]
    if len(oa):
        print(f"\n  Of {len(oa):,} honeypot 'attacker' IPs, "
              f"{(oa['new_label']!='attacker').mean()*100:.1f}% reclassified downward.")

if __name__ == "__main__":
    main()