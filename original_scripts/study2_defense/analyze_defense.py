"""
DEFENSE ANALYSIS: does comment-stripping recover detection?
Computes, per model and overall:
  - clean baseline detection
  - adversarial detection (attack succeeds = low)
  - defended detection (comments stripped)
  - RECOVERY = how much of the lost detection the defense restores
  - statistical test: does the defense significantly improve over adversarial?

Usage: python3 analyze_defense.py
"""
import csv, math
from collections import defaultdict

def load(): 
    with open("results/raw_results_defense.csv") as f:
        return list(csv.DictReader(f))
def tb(s): return str(s).strip().lower() == "true"

def wilson(k, n, z=1.96):
    if n == 0: return (0,0)
    p=k/n; d=1+z*z/n
    c=(p+z*z/(2*n))/d; h=(z*math.sqrt(p*(1-p)/n+z*z/(4*n*n)))/d
    return (max(0,c-h)*100, min(1,c+h)*100)

def mcnemar(pairs):
    # pairs: list of (adv_detected, def_detected) booleans for matched samples
    b = sum(1 for a,d in pairs if (not a) and d)   # attack missed, defense caught
    c = sum(1 for a,d in pairs if a and (not d))   # attack caught, defense missed
    n = b + c
    if n == 0: return 0.0, 1.0, b, c
    chi = (abs(b-c)-1)**2 / n  # continuity-corrected
    p = math.erfc(math.sqrt(chi/2))
    return chi, p, b, c

def main():
    rows = load()
    models = sorted(set(r["model"] for r in rows))
    def pct(d,t): return 100*d/t if t else 0

    clean = [r for r in rows if r["condition"]=="clean"]
    adv   = [r for r in rows if r["condition"]=="adversarial"]
    dfd   = [r for r in rows if r["condition"]=="defended"]

    cd = sum(1 for r in clean if tb(r["detected"]))
    ad = sum(1 for r in adv if tb(r["detected"]))
    dd = sum(1 for r in dfd if tb(r["detected"]))

    print("="*60)
    print("DEFENSE EXPERIMENT RESULTS: COMMENT-STRIPPED ANALYSIS")
    print("="*60)
    print(f"Clean baseline:      {pct(cd,len(clean)):.1f}%  ({cd}/{len(clean)})")
    print(f"Under attack (adv):  {pct(ad,len(adv)):.1f}%  ({ad}/{len(adv)})")
    print(f"With defense:        {pct(dd,len(dfd)):.1f}%  ({dd}/{len(dfd)})")
    lo_d, hi_d = wilson(dd, len(dfd))
    print(f"  Defense 95% CI: [{lo_d:.1f}, {hi_d:.1f}]")

    adv_rate = pct(ad,len(adv)); def_rate = pct(dd,len(dfd)); clean_rate = pct(cd,len(clean))
    lost = clean_rate - adv_rate
    recovered = def_rate - adv_rate
    recovery_pct = (recovered/lost*100) if lost>0 else 0
    print(f"\nDetection lost to attack:     {lost:.1f} points")
    print(f"Detection recovered by defense: {recovered:.1f} points")
    print(f"RECOVERY RATE: {recovery_pct:.1f}% of lost detection restored")

    # McNemar on matched adversarial vs defended (same model+sample+strategy)
    adv_map = {(r["model"],r["sample_id"],r["strategy"]): tb(r["detected"]) for r in adv}
    pairs = []
    for r in dfd:
        key=(r["model"],r["sample_id"],r["strategy"])
        if key in adv_map:
            pairs.append((adv_map[key], tb(r["detected"])))
    chi,p,b,c = mcnemar(pairs)
    print(f"\nMcNemar test (defense vs attack, matched):")
    print(f"  Attack missed but defense caught: {b}")
    print(f"  Attack caught but defense missed: {c}")
    print(f"  chi-square = {chi:.2f}, p = {p:.5f}  {'SIGNIFICANT' if p<0.05 else 'ns'}")

    # per-model
    print(f"\nPER-MODEL:")
    for m in models:
        mc=[r for r in clean if r['model']==m]; ma=[r for r in adv if r['model']==m]; md=[r for r in dfd if r['model']==m]
        cdm=sum(1 for r in mc if tb(r['detected'])); adm=sum(1 for r in ma if tb(r['detected'])); ddm=sum(1 for r in md if tb(r['detected']))
        print(f"  {m}: clean {pct(cdm,len(mc)):.1f}% | attack {pct(adm,len(ma)):.1f}% | defended {pct(ddm,len(md)):.1f}%")

    with open("results/defense_report.txt","w") as f:
        f.write("DEFENSE EXPERIMENT: COMMENT-STRIPPED ANALYSIS\n")
        f.write("="*60+"\n\n")
        f.write(f"Models: {', '.join(models)}\n")
        f.write(f"Clean baseline: {pct(cd,len(clean)):.1f}%\n")
        f.write(f"Under attack: {pct(ad,len(adv)):.1f}%\n")
        f.write(f"With defense: {pct(dd,len(dfd)):.1f}%  95% CI [{lo_d:.1f}, {hi_d:.1f}]\n")
        f.write(f"Recovery rate: {recovery_pct:.1f}% of lost detection restored\n")
        f.write(f"McNemar: chi-square={chi:.2f}, p={p:.5f} (b={b}, c={c})\n\n")
        f.write("PER-MODEL:\n")
        for m in models:
            mc=[r for r in clean if r['model']==m]; ma=[r for r in adv if r['model']==m]; md=[r for r in dfd if r['model']==m]
            cdm=sum(1 for r in mc if tb(r['detected'])); adm=sum(1 for r in ma if tb(r['detected'])); ddm=sum(1 for r in md if tb(r['detected']))
            f.write(f"  {m}: clean {pct(cdm,len(mc)):.1f}% | attack {pct(adm,len(ma)):.1f}% | defended {pct(ddm,len(md)):.1f}%\n")
    print("\nSaved results/defense_report.txt")

if __name__ == "__main__":
    main()
