#!/usr/bin/env python3
"""Reproduce the headline numbers of all four CommentInject studies.

Usage:  python3 scripts/analyze.py
Reads results/study*.csv, prints every headline number, and writes
results/summary_study1.csv ... summary_study4.csv. Wilson 95% intervals.
Standard library only.
"""
import csv, math, os, collections

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "..", "results")
B = lambda v: str(v).strip().lower() in ("true", "1")

def load(name):
    return list(csv.DictReader(open(os.path.join(RES, name))))

def wilson(k, n, z=1.96):
    if n == 0:
        return float("nan"), float("nan"), float("nan")
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return 100 * p, 100 * max(0, c - h), 100 * min(1, c + h)

def chi2_independence(table):
    rs = [sum(r) for r in table]; cs = [sum(c) for c in zip(*table)]; n = sum(rs)
    return sum((table[i][j] - rs[i] * cs[j] / n) ** 2 / (rs[i] * cs[j] / n)
               for i in range(len(table)) for j in range(len(cs)))

def write(name, rows):
    with open(os.path.join(RES, name), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)

def fmt(k, n):
    p, lo, hi = wilson(k, n)
    return f"{p:5.1f}% [{lo:.1f}, {hi:.1f}] ({k}/{n})"

# Study 1: attack ranking, 12 strategies x 30 samples x 2 models (+ clean)
s1 = load("study1_attack_ranking.csv")
print("STUDY 1  attack ranking (Cyber-AI 2026, paper 9090)")
clean = [B(r["detected"]) for r in s1 if r["condition"] == "clean"]
print("  clean detection          ", fmt(sum(clean), len(clean)))
by = collections.defaultdict(list)
for r in s1:
    if r["condition"] == "adversarial":
        by[r["strategy"]].append(B(r["detected"]))
rows, table = [], []
for s, v in sorted(by.items(), key=lambda x: (sum(x[1]) / len(x[1]), x[0])):
    p, lo, hi = wilson(sum(v), len(v))
    rows.append({"strategy": s, "detected": sum(v), "n": len(v), "detect_pct": round(p, 1), "ci_lo": round(lo, 1), "ci_hi": round(hi, 1)})
    table.append([sum(v), len(v) - sum(v)])
    print(f"  {s:24s} {fmt(sum(v), len(v))}")
print(f"  chi-square across strategies = {chi2_independence(table):.2f}, dof = {len(table) - 1}")
write("summary_study1.csv", rows)

# Study 2: comment-stripping defense, 8 strategies, clean / adversarial / defended
s2 = load("study2_defense.csv")
print("\nSTUDY 2  comment-stripped defense (Cyber-AI 2026, paper 9091)")
rows = []
for c in ("clean", "adversarial", "defended"):
    v = [B(r["detected"]) for r in s2 if r["condition"] == c]
    p, lo, hi = wilson(sum(v), len(v))
    rows.append({"condition": c, "detected": sum(v), "n": len(v), "detect_pct": round(p, 1), "ci_lo": round(lo, 1), "ci_hi": round(hi, 1)})
    print(f"  {c:12s} {fmt(sum(v), len(v))}")
key = lambda r: (r["model"], r["sample_id"], r["strategy"])
adv = {key(r): B(r["detected"]) for r in s2 if r["condition"] == "adversarial"}
dfd = {key(r): B(r["detected"]) for r in s2 if r["condition"] == "defended"}
b = sum(1 for k in adv if not adv[k] and dfd[k]); c = sum(1 for k in adv if adv[k] and not dfd[k])
print(f"  McNemar (continuity-corrected): b = {b}, c = {c}, chi-square = {(abs(b - c) - 1) ** 2 / (b + c):.2f}")
write("summary_study2.csv", rows)

# Study 3: cross-model, 4 models x 4 strategies (+ clean)
s3 = load("study3_cross_model.csv")
print("\nSTUDY 3  cross-model comparison (IEEE CRESS 2026 submission)")
rows, table = [], []
for m in sorted({r["model"] for r in s3}):
    cl = [B(r["detected"]) for r in s3 if r["model"] == m and r["condition"] == "clean"]
    ad = [B(r["detected"]) for r in s3 if r["model"] == m and r["condition"] == "adversarial"]
    pc = wilson(sum(cl), len(cl)); pa = wilson(sum(ad), len(ad))
    rows.append({"model": m, "clean_pct": round(pc[0], 1), "adversarial_pct": round(pa[0], 1), "adv_ci_lo": round(pa[1], 1), "adv_ci_hi": round(pa[2], 1), "n_adversarial": len(ad)})
    table.append([sum(ad), len(ad) - sum(ad)])
    print(f"  {m:22s} clean {pc[0]:5.1f}%   adversarial {fmt(sum(ad), len(ad))}")
print(f"  chi-square across models = {chi2_independence(table):.2f}, dof = {len(table) - 1}")
write("summary_study3.csv", rows)

# Study 4: transferability, same 240 adversarial cases shown to 4 models
s4 = load("study4_transferability.csv")
print("\nSTUDY 4  cross-model transferability (ICon INDIA 2026, paper 317)")
models = sorted({r["model"] for r in s4})
fooled = {(r["model"], r["sample_id"], r["strategy"]): B(r["fooled"]) for r in s4}
cases = sorted({(r["sample_id"], r["strategy"]) for r in s4})
for m in models:
    v = [fooled[(m,) + k] for k in cases]
    print(f"  fooled {m:22s} {fmt(sum(v), len(v))}")
rows, cross = [], []
for s in models:
    src = [k for k in cases if fooled[(s,) + k]]
    for t in models:
        k = sum(fooled[(t,) + c] for c in src); p, lo, hi = wilson(k, len(src))
        rows.append({"source": s, "target": t, "target_fooled": k, "source_fooled": len(src), "transfer_pct": round(p, 1), "ci_lo": round(lo, 1), "ci_hi": round(hi, 1)})
        if s != t:
            cross.append(p)
all4 = sum(all(fooled[(m,) + k] for m in models) for k in cases)
print(f"  mean cross-model transfer rate = {sum(cross) / len(cross):.1f}%")
print(f"  cases fooling all four models  = {100 * all4 / len(cases):.1f}% ({all4}/{len(cases)})")
write("summary_study4.csv", rows)
