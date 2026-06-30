"""
Shared config
A/B deployment:
    Arm A "Minimal"   -> 145.220.231.112 .. .119  (small responses)
    Arm B "Amplified" -> 145.220.231.120 .. .127  (padded/large responses)
"""

import os
PARQUET_PATH = os.environ.get("HONEYPOT_PARQUET", "data/honeypot_clean.parquet")

MINIMAL_IPS   = [f"145.220.231.{n}" for n in range(112, 120)]
AMPLIFIED_IPS = [f"145.220.231.{n}" for n in range(120, 128)]


def _sql_in(ips):
    return "(" + ", ".join(f"'{ip}'" for ip in ips) + ")"


MINIMAL_IN   = _sql_in(MINIMAL_IPS)
AMPLIFIED_IN = _sql_in(AMPLIFIED_IPS)

# Tags each row with its experimental variant by IP
ARM_CASE_SQL = f"""
    CASE
        WHEN DestinationIP IN {MINIMAL_IN}   THEN 'A_minimal'
        WHEN DestinationIP IN {AMPLIFIED_IN} THEN 'B_amplified'
        ELSE 'other'
    END
"""

# Labelling issue normalization
PROBE_LABEL_SQL = "COALESCE(probe_type, ProbeType)"

# Intersect helper
DUAL_ARM = f"""
    WITH dual_arm AS (
        SELECT SourceIP FROM read_parquet('{PARQUET_PATH}') WHERE DestinationIP IN {MINIMAL_IN}
        INTERSECT
        SELECT SourceIP FROM read_parquet('{PARQUET_PATH}') WHERE DestinationIP IN {AMPLIFIED_IN}
    )
"""

# Amplification intent modes
DNS_AMP_TYPES = ("ANY", "TXT", "TYPE48")
NTP_AMP_MODES = ("7",)      # monlist
SSDP_IS_AMP   = True        # honeypot only answers to M-SEARCH