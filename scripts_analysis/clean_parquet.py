import duckdb
import time

RAW_JSONL    = "/srv/storage/honeypot_events.jsonl.old"
FULL_PARQUET = "/srv/storage/honeypot.parquet"
CLEAN_PARQUET = "/srv/storage/honeypot_clean.parquet"
CUTOFF = "2026-06-11 11:53:03.509025695"


def main():
    con = duckdb.connect()

    t0 = time.time()
    con.execute(f"""
        COPY (
            SELECT * EXCLUDE (ResponsePayload)
            FROM read_ndjson_auto('{RAW_JSONL}', ignore_errors=true)
        ) TO '{FULL_PARQUET}' (FORMAT PARQUET, COMPRESSION ZSTD)
    """)
    print(f"  done in {(time.time()-t0)/60:.1f} min")

    t0 = time.time()
    con.execute(f"""
        COPY (
            SELECT *
            FROM '{FULL_PARQUET}'
            WHERE TRY_CAST(Timestamp AS TIMESTAMP) > TIMESTAMP '{CUTOFF}'
        ) TO '{CLEAN_PARQUET}' (FORMAT PARQUET, COMPRESSION ZSTD)
    """)
    print(f"  done in {(time.time()-t0)/60:.1f} min")

    n_full = con.execute(f"SELECT COUNT(*) FROM '{FULL_PARQUET}'").fetchone()[0]
    n_clean = con.execute(f"SELECT COUNT(*) FROM '{CLEAN_PARQUET}'").fetchone()[0]
    print(f"\nFull:  {n_full:,} events")
    print(f"Clean: {n_clean:,} events  ({n_full - n_clean:,})")


if __name__ == "__main__":
    main()