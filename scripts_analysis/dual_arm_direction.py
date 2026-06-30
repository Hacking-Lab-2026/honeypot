"""
Check distribution for IPs that hit both arms, shows high volume on few IPs skew towards minimal

Output: dual_arm_direction.csv
"""

import duckdb
from common import PARQUET_PATH, MINIMAL_IN, AMPLIFIED_IN, DUAL_ARM

OUTPUT = "data/dual_arm_direction.csv"


def main():
    con = duckdb.connect()

    per_ip = con.execute(f"""
        {DUAL_ARM}
        SELECT
            SourceIP,
            SUM(CASE WHEN DestinationIP IN {MINIMAL_IN}   THEN 1 ELSE 0 END) AS events_minimal,
            SUM(CASE WHEN DestinationIP IN {AMPLIFIED_IN} THEN 1 ELSE 0 END) AS events_amplified
        FROM read_parquet('{PARQUET_PATH}')
        WHERE SourceIP IN (SELECT SourceIP FROM dual_arm)
          AND (DestinationIP IN {MINIMAL_IN} OR DestinationIP IN {AMPLIFIED_IN})
        GROUP BY SourceIP
    """).df()

    per_ip["diff"] = per_ip["events_amplified"] - per_ip["events_minimal"]
    per_ip["prefers"] = per_ip["diff"].apply(
        lambda d: "amplified" if d > 0 else ("minimal" if d < 0 else "tie"))
    per_ip = per_ip.sort_values("diff", ascending=False)
    per_ip.to_csv(OUTPUT, index=False)

    print(f"Dual-arm IPs: {len(per_ip)}")
    print("Per-IP preference")
    print(per_ip["prefers"].value_counts().to_string())

    tot_min = per_ip["events_minimal"].sum()
    tot_amp = per_ip["events_amplified"].sum()
    print(f"\n  aggregate events minimal:   {tot_min:,}")
    print(f"  aggregate events amplified: {tot_amp:,}")
    top5 = per_ip.nlargest(5, "events_minimal")["events_minimal"].sum()
    print(f"  top-5 minimal senders = {top5/tot_min*100:.1f}% of minimal-arm events")


if __name__ == "__main__":
    main()
