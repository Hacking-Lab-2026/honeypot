"""
SQ3: resp size and amp factor between the 2 variants:  resp size + amp  split by ARM / PROTOCOL
     ignores zero-byte throttled events from the amplification stats so it shows served
     returns the zero-byte separately

SQ4: rate-limiter suppression per-protocol: total requests, % throttled,

Output: sq3_amp_by_arm_protocol.csv
        sq4_rate_limiter_effect.csv
"""

import duckdb
from common import PARQUET_PATH, ARM_CASE_SQL

OUT_SQ3 = "data/sq3_amp_by_arm_protocol.csv"
OUT_SQ4 = "data/sq4_rate_limiter_effect.csv"


def main():
    con = duckdb.connect()

    sq3 = con.execute(f"""
        SELECT
            {ARM_CASE_SQL}                                   AS arm,
            ServiceName                                      AS protocol,
            COUNT(*)                                         AS events,
            ROUND(AVG(ResponseSizeBytes), 1)                 AS avg_resp_bytes,
            ROUND(AVG(ResponseSizeBytes)
                  FILTER (WHERE ResponseSizeBytes > 0), 1)   AS avg_resp_bytes_served,
            ROUND(AVG(AmplificationFactor)
                  FILTER (WHERE ResponseSizeBytes > 0), 3)   AS avg_amp_served,
            ROUND(MAX(AmplificationFactor), 1)               AS max_amp
        FROM read_parquet('{PARQUET_PATH}')
        WHERE {ARM_CASE_SQL} <> 'other'
        GROUP BY arm, protocol
        ORDER BY protocol, arm
    """).df()
    sq3.to_csv(OUT_SQ3, index=False)
    print("SQ3")
    print(sq3.to_string(index=False))

    sq4 = con.execute(f"""
        WITH med AS (
            SELECT ServiceName,
                   MEDIAN(ResponseSizeBytes) FILTER (WHERE ResponseSizeBytes > 0)
                       AS median_served_bytes
            FROM read_parquet('{PARQUET_PATH}')
            GROUP BY ServiceName
        )
        SELECT
            p.ServiceName                                              AS protocol,
            COUNT(*)                                                   AS total_requests,
            SUM(CASE WHEN p.ResponseSizeBytes = 0 THEN 1 ELSE 0 END)   AS zero_byte_requests,
            ROUND(100.0 * SUM(CASE WHEN p.ResponseSizeBytes = 0 THEN 1 ELSE 0 END)
                  / COUNT(*), 2)                                       AS pct_suppressed,
            ROUND(SUM(p.ResponseSizeBytes) / 1e9, 3)                   AS gb_sent,
            ROUND(MAX(m.median_served_bytes) * COUNT(*) / 1e9, 3)      AS gb_if_unthrottled_est
        FROM read_parquet('{PARQUET_PATH}') p
        JOIN med m USING (ServiceName)
        GROUP BY p.ServiceName
        ORDER BY total_requests DESC
    """).df()
    sq4.to_csv(OUT_SQ4, index=False)
    print("SQ4")
    print(sq4.to_string(index=False))


if __name__ == "__main__":
    main()
