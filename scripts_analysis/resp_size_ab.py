"""
Calculates the volume and size of interactions by variant

see dual_arm_direction.py for skew measurements 

Output: within_attacker.csv
"""

import duckdb
from common import PARQUET_PATH, MINIMAL_IN, AMPLIFIED_IN, DUAL_ARM

OUTPUT_WITHIN = "data/within_attacker.csv"


def main():
    con = duckdb.connect()

    within = con.execute(f"""
        {DUAL_ARM}
        SELECT
            CASE WHEN DestinationIP IN {MINIMAL_IN} THEN 'A_minimal' ELSE 'B_amplified' END AS arm,
            COUNT(DISTINCT SourceIP)         AS dual_arm_attackers,
            COUNT(*)                         AS events,
            ROUND(AVG(ResponseSizeBytes), 1) AS avg_response_bytes
        FROM read_parquet('{PARQUET_PATH}')
        WHERE SourceIP IN (SELECT SourceIP FROM dual_arm)
          AND (DestinationIP IN {MINIMAL_IN} OR DestinationIP IN {AMPLIFIED_IN})
        GROUP BY arm ORDER BY arm
    """).df()
    within.to_csv(OUTPUT_WITHIN, index=False)
    print("=== SQ1 within-attacker (IPs that hit both arms) ===")
    print(within.to_string(index=False))


if __name__ == "__main__":
    main()
