"""

Splits traffic by Minimal vs Amplified
calculates per variant: 
    event count, distinct src IPs, distinct dest IPs, avg resp size, avg amp, and events per IP

Also gives source IP overlap between A/B.

Rest of scripts read opts from this

Output: ab_var_overview.csv
        ab_source_overlap.csv
"""

import duckdb
from common import PARQUET_PATH, ARM_CASE_SQL, MINIMAL_IN, AMPLIFIED_IN

OUTPUT_OVERVIEW = "data/ab_var_overview.csv"
OUTPUT_OVERLAP  = "data/ab_source_overlap.csv"


def main():
    con = duckdb.connect()

    overview = con.execute(f"""
        SELECT {ARM_CASE_SQL} AS arm,
               COUNT(*)                          AS events,
               COUNT(DISTINCT SourceIP)          AS unique_sources,
               COUNT(DISTINCT DestinationIP)     AS unique_dests,
               ROUND(AVG(ResponseSizeBytes), 1)  AS avg_response_bytes,
               ROUND(AVG(AmplificationFactor), 4) AS avg_amplification,
               ROUND(COUNT(*)::DOUBLE / NULLIF(COUNT(DISTINCT SourceIP), 0), 1)
                   AS events_per_source
        FROM read_parquet('{PARQUET_PATH}')
        GROUP BY arm ORDER BY events DESC
    """).df()
    overview.to_csv(OUTPUT_OVERVIEW, index=False)
    print("VAR overview")
    print(overview.to_string(index=False))

    overlap = con.execute(f"""
        WITH a AS (SELECT DISTINCT SourceIP FROM read_parquet('{PARQUET_PATH}')
                   WHERE DestinationIP IN {MINIMAL_IN}),
             b AS (SELECT DISTINCT SourceIP FROM read_parquet('{PARQUET_PATH}')
                   WHERE DestinationIP IN {AMPLIFIED_IN})
        SELECT
            (SELECT COUNT(*) FROM a) AS sources_minimal,
            (SELECT COUNT(*) FROM b) AS sources_amplified,
            (SELECT COUNT(*) FROM (SELECT * FROM a INTERSECT SELECT * FROM b)) AS in_both,
            (SELECT COUNT(*) FROM (SELECT * FROM a EXCEPT SELECT * FROM b)) AS minimal_only,
            (SELECT COUNT(*) FROM (SELECT * FROM b EXCEPT SELECT * FROM a)) AS amplified_only
    """).df()
    overlap.to_csv(OUTPUT_OVERLAP, index=False)
    print("Source overlap")
    print(overlap.to_string(index=False))


if __name__ == "__main__":
    main()
