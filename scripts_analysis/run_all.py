"""
export HONEYPOT_PARQUET=/path/to/honeypot_clean.parquet # or change path
python run_all.py                  
python run_all.py --build-parquet  # rebuild parquet from dataset (takes a while)

Scripts run in order, do not changge, sequential input -> output
"""

import subprocess, sys, time
from pathlib import Path

ANALYSIS = [
    ("classify.py",                    "Tiered per-IP classifier"),
    ("ab_var_overview.py",             "Per variant population + overlap"),
    ("resp_size_ab.py",                "Within-source comparison"),
    ("dual_arm_direction.py",          "Skew check"),
    ("amplification_and_modes.py",     "Amp by protocol + modes"),
    ("sq3_sq4_tables.py",              "SQ3 arm / protocol + SQ4 limiter"),
]

def run(base, fn, desc):
    p = base / fn
    if not p.exists():
        print(f"[SKIP] {fn} not found"); return
    print(f"\n{'='*60}\n{fn}  --  {desc}\n{'='*60}")
    t = time.time()
    r = subprocess.run([sys.executable, str(p)], cwd=str(base))
    if r.returncode == 0:
        print(f"[OK] {fn} ({time.time()-t:.1f}s)")
    else:
        print(f"[FAILED] {fn} exited {r.returncode}"); sys.exit(r.returncode)

def main():
    base = Path(__file__).parent
    (base / "data").mkdir(exist_ok=True)
    if "--build-parquet" in sys.argv:
        run(base, "clean_parquet.py", "Build parquet from raw JSONL")
    for fn, desc in ANALYSIS:
        run(base, fn, desc)
    print(f"\nDONE: check {base/'data'}/")

if __name__ == "__main__":
    main()
