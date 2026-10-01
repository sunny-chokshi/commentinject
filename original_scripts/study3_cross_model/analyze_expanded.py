"""
EXPANDED ANALYSIS WITH STATISTICAL TESTING
Produces the comparison tables plus statistical significance tests that a
competitive conference reviewer will expect.

Adds:
- Per-model, per-strategy detection rates (30 samples each)
- Chi-square test for whether model choice significantly affects detection
- Per-CWE difficulty analysis (which vulnerability types are hardest)

Uses only Python standard library plus scipy if available. If scipy is not
installed, it computes the chi-square statistic manually.

Usage:
    python3 analyze_expanded.py
"""

import csv
from collections import defaultdict
import math


def load():
    with open("results/raw_results_expanded.csv") as f:
        return list(csv.DictReader(f))


def to_bool(s):
    return str(s).strip().lower() == "true"


def chi_square_2xN(detected_counts, total_counts):
    """
    Manual chi-square test of independence.
    Rows: detected vs missed. Columns: models.
    Returns (chi2, dof, approx_p).
    """
    models = list(detected_counts.keys())
    k = len(models)
    detected = [detected_counts[m] for m in models]
    missed = [total_counts[m] - detected_counts[m] for m in models]
    grand = sum(total_counts.values())
    total_detected = sum(detected)
    total_missed = sum(missed)

    chi2 = 0.0
    for i, m in enumerate(models):
        col_total = total_counts[m]
        exp_det = total_detected * col_total / grand if grand else 0
        exp_mis = total_missed * col_total / grand if grand else 0
        if exp_det > 0:
            chi2 += (detected[i] - exp_det) ** 2 / exp_det
        if exp_mis > 0:
            chi2 += (missed[i] - exp_mis) ** 2 / exp_mis
    dof = k - 1

    # Approximate p-value via survival function of chi-square.
    try:
        from scipy.stats import chi2 as chi2dist
        p = float(chi2dist.sf(chi2, dof))
    except Exception:
        # Wilson-Hilferty approximation for p-value without scipy
        if dof > 0 and chi2 > 0:
            x = chi2 / dof
            z = (x ** (1.0/3) - (1 - 2.0/(9*dof))) / math.sqrt(2.0/(9*dof))
            # standard normal survival
            p = 0.5 * math.erfc(z / math.sqrt(2))
        else:
            p = 1.0
    return chi2, dof, p


def main():
    rows = load()
    models = sorted(set(r["model"] for r in rows))
    strategies = sorted(set(r["strategy"] for r in rows if r["condition"] == "adversarial"))

    def pct(d, t):
        return 100 * d / t if t else 0

    # Per model stats
    stats = {}
    for m in models:
        mrows = [r for r in rows if r["model"] == m]
        clean = [r for r in mrows if r["condition"] == "clean"]
        adv = [r for r in mrows if r["condition"] == "adversarial"]
        cd = sum(1 for r in clean if to_bool(r["detected"]))
        ad = sum(1 for r in adv if to_bool(r["detected"]))
        per_strat = {}
        for s in strategies:
            srows = [r for r in adv if r["strategy"] == s]
            sd = sum(1 for r in srows if to_bool(r["detected"]))
            per_strat[s] = (sd, len(srows))
        stats[m] = {"clean": (cd, len(clean)), "adv": (ad, len(adv)), "per_strat": per_strat}

    # Comparison table
    with open("results/comparison_expanded.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Condition"] + models)
        w.writerow(["Clean baseline"] + [f"{pct(*stats[m]['clean']):.1f}%" for m in models])
        for s in strategies:
            w.writerow([s] + [f"{pct(*stats[m]['per_strat'][s]):.1f}%" for m in models])
        w.writerow(["All adversarial"] + [f"{pct(*stats[m]['adv']):.1f}%" for m in models])

    # Chi-square: does model choice affect adversarial detection?
    adv_detected = {m: stats[m]["adv"][0] for m in models}
    adv_total = {m: stats[m]["adv"][1] for m in models}
    chi2, dof, pval = chi_square_2xN(adv_detected, adv_total)

    # Per-CWE difficulty (adversarial only, across all models)
    cwe_stats = defaultdict(lambda: [0, 0])
    for r in rows:
        if r["condition"] == "adversarial":
            cwe_stats[r["cwe"]][1] += 1
            if to_bool(r["detected"]):
                cwe_stats[r["cwe"]][0] += 1

    with open("results/expanded_report.txt", "w") as f:
        f.write("EXPANDED MULTI-MODEL ANALYSIS\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Models: {', '.join(models)}\n")
        f.write(f"Samples per model: 30 vulnerable code samples\n")
        f.write(f"Total trials: {len(rows)}\n\n")

        for m in models:
            f.write(f"MODEL: {m}\n")
            f.write("-" * 60 + "\n")
            f.write(f"  Clean baseline:        {pct(*stats[m]['clean']):.1f}%\n")
            f.write(f"  Adversarial (overall): {pct(*stats[m]['adv']):.1f}%\n")
            for s in strategies:
                f.write(f"     {s:22s}: {pct(*stats[m]['per_strat'][s]):.1f}%\n")
            f.write("\n")

        f.write("STATISTICAL SIGNIFICANCE\n")
        f.write("-" * 60 + "\n")
        f.write("Question: does model choice significantly affect adversarial\n")
        f.write("detection rate? Chi-square test of independence.\n\n")
        f.write(f"  Chi-square = {chi2:.2f}\n")
        f.write(f"  Degrees of freedom = {dof}\n")
        f.write(f"  p-value approx = {pval:.5f}\n")
        if pval < 0.05:
            f.write("  Result: SIGNIFICANT (p < 0.05). Model choice affects\n")
            f.write("  adversarial robustness beyond chance.\n\n")
        else:
            f.write("  Result: not significant at p < 0.05.\n\n")

        f.write("VULNERABILITY TYPE DIFFICULTY (adversarial, all models)\n")
        f.write("-" * 60 + "\n")
        f.write("Lower detection = harder to catch under adversarial comments.\n\n")
        ranked = sorted(cwe_stats.items(), key=lambda x: x[1][0] / max(x[1][1], 1))
        for cwe, (d, t) in ranked:
            f.write(f"  {cwe:12s}: {pct(d, t):.1f}% detected ({d}/{t})\n")

    # Screen output
    print("=" * 60)
    print("EXPANDED RESULTS")
    print("=" * 60)
    print(f"{'Condition':22s}" + "".join(f"{m[:13]:>15s}" for m in models))
    print(f"{'Clean baseline':22s}" + "".join(f"{pct(*stats[m]['clean']):>14.1f}%" for m in models))
    for s in strategies:
        print(f"{s:22s}" + "".join(f"{pct(*stats[m]['per_strat'][s]):>14.1f}%" for m in models))
    print(f"{'All adversarial':22s}" + "".join(f"{pct(*stats[m]['adv']):>14.1f}%" for m in models))
    print()
    print(f"Chi-square = {chi2:.2f}, dof = {dof}, p approx = {pval:.5f}")
    print("SIGNIFICANT" if pval < 0.05 else "not significant", "at p < 0.05")
    print()
    print("Saved: results/comparison_expanded.csv, results/expanded_report.txt")


if __name__ == "__main__":
    main()
