"""
EXPANDED PAPER 9 ANALYSIS - Attack Strategy Effectiveness
Ranks the 8 adversarial strategies by effectiveness and tests whether the
differences between strategies are statistically significant.

Usage:
    python3 analyze_p9strong.py
"""

import csv, math
from collections import defaultdict

def load():
    with open("results/raw_results_p9_12strat.csv") as f:
        return list(csv.DictReader(f))

def tb(s): return str(s).strip().lower() == "true"

def chi_square(detected_counts, total_counts):
    keys = list(detected_counts.keys())
    det = [detected_counts[k] for k in keys]
    tot = [total_counts[k] for k in keys]
    grand = sum(tot); td = sum(det); tm = grand - td
    chi2 = 0.0
    for i, k in enumerate(keys):
        ed = td*tot[i]/grand if grand else 0
        em = tm*tot[i]/grand if grand else 0
        if ed > 0: chi2 += (det[i]-ed)**2/ed
        if em > 0: chi2 += ((tot[i]-det[i])-em)**2/em
    dof = len(keys) - 1
    # p-value approx
    if dof > 0 and chi2 > 0:
        x = chi2/dof
        z = (x**(1.0/3) - (1 - 2.0/(9*dof))) / math.sqrt(2.0/(9*dof))
        p = 0.5*math.erfc(z/math.sqrt(2))
    else:
        p = 1.0
    return chi2, dof, p

def wilson(k, n, z=1.96):
    if n == 0: return (0, 0)
    p = k/n; d = 1 + z*z/n
    c = (p + z*z/(2*n))/d
    h = (z*math.sqrt(p*(1-p)/n + z*z/(4*n*n)))/d
    return (max(0, c-h)*100, min(1, c+h)*100)

def main():
    rows = load()
    models = sorted(set(r["model"] for r in rows))
    strategies = [s for s in [
        "authority_claim","false_reassurance","misleading_context","security_camouflage",
        "fake_review_approval","deadline_pressure","false_test_coverage","distraction_comment",
        "scope_limitation","compliance_claim","formal_verification","authorial_confidence"
    ] if s in set(r["strategy"] for r in rows)]

    adv = [r for r in rows if r["condition"] == "adversarial"]
    clean = [r for r in rows if r["condition"] == "clean"]

    def pct(d, t): return 100*d/t if t else 0

    # Clean baseline (across models)
    cd = sum(1 for r in clean if tb(r["detected"]))
    print("="*60)
    print("EXPANDED PAPER 9 RESULTS: ATTACK STRATEGY EFFECTIVENESS")
    print("="*60)
    print(f"Clean baseline (all models): {pct(cd, len(clean)):.1f}% ({cd}/{len(clean)})")
    print()

    # Per-strategy detection (aggregated across both models)
    strat_stats = {}
    for s in strategies:
        srows = [r for r in adv if r["strategy"] == s]
        sd = sum(1 for r in srows if tb(r["detected"]))
        strat_stats[s] = (sd, len(srows))

    print("STRATEGY EFFECTIVENESS (ranked, hardest to detect first):")
    print("-"*60)
    ranked = sorted(strategies, key=lambda s: strat_stats[s][0]/max(strat_stats[s][1],1))
    for s in ranked:
        d, t = strat_stats[s]
        lo, hi = wilson(d, t)
        print(f"  {s:22s}: {pct(d,t):5.1f}% detected  95% CI [{lo:.1f}, {hi:.1f}]  ({d}/{t})")

    # Significance: do strategies differ?
    det_counts = {s: strat_stats[s][0] for s in strategies}
    tot_counts = {s: strat_stats[s][1] for s in strategies}
    chi2, dof, p = chi_square(det_counts, tot_counts)
    print()
    print("STATISTICAL TEST (do strategies differ in effectiveness?):")
    print("-"*60)
    print(f"  Chi-square = {chi2:.2f}, dof = {dof}, p approx = {p:.5f}")
    print("  " + ("SIGNIFICANT (p<0.05): strategies differ in effectiveness."
                  if p < 0.05 else "Not significant at p<0.05."))
    print()

    # Per model per strategy
    print("PER-MODEL BREAKDOWN:")
    print("-"*60)
    hdr = f"{'strategy':22s}" + "".join(f"{m.split(':')[0][:12]:>14s}" for m in models)
    print(hdr)
    for s in strategies:
        line = f"{s:22s}"
        for m in models:
            mr = [r for r in adv if r["strategy"] == s and r["model"] == m]
            md = sum(1 for r in mr if tb(r["detected"]))
            line += f"{pct(md,len(mr)):>13.1f}%"
        print(line)

    # Save reports
    with open("results/p9_12strat_report.txt", "w") as f:
        f.write("EXPANDED PAPER 9: ATTACK STRATEGY EFFECTIVENESS\n")
        f.write("="*60 + "\n\n")
        f.write(f"Models: {', '.join(models)}\n")
        f.write(f"8 strategies, 30 samples, {len(rows)} total trials\n\n")
        f.write(f"Clean baseline: {pct(cd,len(clean)):.1f}%\n\n")
        f.write("STRATEGY EFFECTIVENESS (ranked hardest to detect first):\n")
        for s in ranked:
            d, t = strat_stats[s]; lo, hi = wilson(d, t)
            f.write(f"  {s:22s}: {pct(d,t):5.1f}%  95% CI [{lo:.1f}, {hi:.1f}]  ({d}/{t})\n")
        f.write(f"\nChi-square = {chi2:.2f}, dof = {dof}, p approx = {p:.5f}\n")
        f.write("SIGNIFICANT\n" if p < 0.05 else "Not significant\n")
        f.write("\nPER-MODEL BREAKDOWN:\n")
        f.write(hdr + "\n")
        for s in strategies:
            line = f"{s:22s}"
            for m in models:
                mr = [r for r in adv if r["strategy"] == s and r["model"] == m]
                md = sum(1 for r in mr if tb(r["detected"]))
                line += f"{pct(md,len(mr)):>13.1f}%"
            f.write(line + "\n")

    with open("results/p9_12strat_table.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Strategy", "Detection Rate", "95% CI Low", "95% CI High", "Missed/Total"])
        for s in ranked:
            d, t = strat_stats[s]; lo, hi = wilson(d, t)
            w.writerow([s, f"{pct(d,t):.1f}%", f"{lo:.1f}", f"{hi:.1f}", f"{t-d}/{t}"])

    print()
    print("Saved: results/p9_12strat_report.txt, results/p9_12strat_table.csv")

if __name__ == "__main__":
    main()
