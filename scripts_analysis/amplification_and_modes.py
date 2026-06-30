"""
Calculates per-protocol amp statistics and a histogram of amp factors.
Splits ip llabels to a per protocol count with unique and event counts + avg amp
Reads the labels from classify.py.

Output: amplification_stats.csv
        amplification_histo.csv
        behavioral_modes.csv
"""

import duckdb
import pandas as pd
from common import PARQUET_PATH, PROBE_LABEL_SQL

LABELS_CSV  = "data/classified_sources_tiered.csv"
OUTPUT_STATS   = "data/amplification_stats.csv"
OUTPUT_BUCKETS = "data/amplification_histo.csv"
OUTPUT_MODES   = "data/behavioral_modes.csv"


def main():
    con = duckdb.connect()

    stats = con.execute(f"""
        SELECT ServiceName,
               {PROBE_LABEL_SQL} AS orig_probe_type,
               COUNT(*) AS event_count,
               ROUND(AVG(AmplificationFactor), 4)            AS amp_mean,
               ROUND(MEDIAN(AmplificationFactor), 4)         AS amp_median,
               ROUND(QUANTILE_CONT(AmplificationFactor,0.99),4) AS amp_p99,
               ROUND(MAX(AmplificationFactor), 4)            AS amp_max
        FROM read_parquet('{PARQUET_PATH}')
        WHERE AmplificationFactor IS NOT NULL AND ServiceName IS NOT NULL
        GROUP BY ServiceName, {PROBE_LABEL_SQL}
        ORDER BY ServiceName, orig_probe_type
    """).df()
    stats.to_csv(OUTPUT_STATS, index=False)
    print("Amplification stats")
    print(stats.to_string(index=False))

    buckets = con.execute(f"""
        SELECT ServiceName,
               FLOOR(AmplificationFactor / 5) * 5 AS bucket_floor,
               COUNT(*) AS event_count
        FROM read_parquet('{PARQUET_PATH}')
        WHERE AmplificationFactor IS NOT NULL AND ServiceName IS NOT NULL
        GROUP BY ServiceName, FLOOR(AmplificationFactor / 5) * 5
        ORDER BY ServiceName, bucket_floor
    """).df()
    buckets.to_csv(OUTPUT_BUCKETS, index=False)
    print(f"\nSaved amplification buckets to {OUTPUT_BUCKETS}")

    labels = pd.read_csv(LABELS_CSV)[["SourceIP", "new_label"]]
    con.register("labels", labels)
    modes = con.execute(f"""
        SELECT l.new_label,
               p.ServiceName,
               COUNT(DISTINCT p.SourceIP) AS unique_sources,
               COUNT(*)                   AS events,
               ROUND(AVG(p.AmplificationFactor), 4) AS avg_amplification
        FROM read_parquet('{PARQUET_PATH}') p
        JOIN labels l USING (SourceIP)
        WHERE p.ServiceName IS NOT NULL
        GROUP BY l.new_label, p.ServiceName
        ORDER BY l.new_label, events DESC
    """).df()
    modes.to_csv(OUTPUT_MODES, index=False)
    print("Behavioral modes by protocol")
    print(modes.to_string(index=False))


if __name__ == "__main__":
    main()