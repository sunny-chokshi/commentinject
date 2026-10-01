"""
TRANSFERABILITY ANALYSIS

Computes, for each ordered pair (source -> target):
  transfer rate = P(target fooled | source fooled)
i.e. among adversarial cases where the SOURCE model was fooled, how often was
the TARGET model also fooled by the identical comment.

Also computes:
  - per-model fooled rate (how often each model is fooled overall)
  - average transfer rate (overall transferability)
  - a transfer matrix

Usage: python3 analyze_transfer.py
"""
import csv
from collections import defaultdict
from itertools import product

def load():
    with open("results/raw_results_transfer.csv") as f:
        return list(csv.DictReader(f))
def tb(s): return str(s).strip().lower() == "true"

def main():
    rows = load()
    models = sorted(set(r["model"] for r in rows))

    # index fooled status by (sample_id, strategy, model)
    fooled = {}
    for r in rows:
        fooled[(r["sample_id"], r["strategy"], r["model"])] = tb(r["fooled"])

    # unique adversarial cases
    cases = sorted(set((r["sample_id"], r["strategy"]) for r in rows))

    print("="*60)
    print("TRANSFERABILITY RESULTS")
    print("="*60)

    # per-model fooled rate
    print("\nPER-MODEL FOOLED RATE (attack success against each model alone):")
    for m in models:
        n = sum(1 for c in cases if (c[0], c[1], m) in fooled)
        f = sum(1 for c in cases if fooled.get((c[0], c[1], m), False))
        print(f"  {m:22s}: {100*f/n:5.1f}%  ({f}/{n})")

    # transfer matrix: rows = source, cols = target
    print("\nTRANSFER MATRIX  P(target fooled | source fooled):")
    header = "  source \\ target      " + "  ".join(f"{m.split(':')[0][:10]:>10s}" for m in models)
    print(header)
    transfer = {}
    for src in models:
        # cases where source was fooled
        src_fooled_cases = [c for c in cases if fooled.get((c[0], c[1], src), False)]
        row = f"  {src.split(':')[0][:18]:18s}  "
        for tgt in models:
            if not src_fooled_cases:
                rate = 0.0
            else:
                also = sum(1 for c in src_fooled_cases if fooled.get((c[0], c[1], tgt), False))
                rate = 100 * also / len(src_fooled_cases)
            transfer[(src, tgt)] = rate
            row += f"{rate:9.1f}%  "
        print(row)

    # average off-diagonal transfer (true cross-model transfer, excluding self)
    off = [transfer[(s, t)] for s, t in product(models, models) if s != t]
    avg_transfer = sum(off) / len(off) if off else 0
    print(f"\nAVERAGE CROSS-MODEL TRANSFER RATE (off-diagonal): {avg_transfer:.1f}%")

    # interpretation helper
    print("\nINTERPRETATION:")
    if avg_transfer >= 70:
        print("  HIGH transferability: comments that fool one model largely fool others.")
        print("  An attacker can craft against one model and reuse broadly.")
    elif avg_transfer >= 40:
        print("  MODERATE transferability: substantial but partial transfer.")
    else:
        print("  LOW transferability: attacks are largely model-specific.")

    with open("results/transfer_report.txt", "w") as f:
        f.write("TRANSFERABILITY RESULTS\n")
        f.write("="*60 + "\n\n")
        f.write(f"Models: {', '.join(models)}\n\n")
        f.write("PER-MODEL FOOLED RATE:\n")
        for m in models:
            n = sum(1 for c in cases if (c[0], c[1], m) in fooled)
            fl = sum(1 for c in cases if fooled.get((c[0], c[1], m), False))
            f.write(f"  {m}: {100*fl/n:.1f}% ({fl}/{n})\n")
        f.write("\nTRANSFER MATRIX P(target fooled | source fooled):\n")
        f.write("  source \\ target: " + ", ".join(m.split(':')[0] for m in models) + "\n")
        for src in models:
            f.write(f"  {src}: " + ", ".join(f"{transfer[(src,t)]:.1f}%" for t in models) + "\n")
        f.write(f"\nAVERAGE CROSS-MODEL TRANSFER RATE: {avg_transfer:.1f}%\n")
    print("\nSaved results/transfer_report.txt")

if __name__ == "__main__":
    main()
