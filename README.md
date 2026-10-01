# CommentInject

A benchmark of **adversarial code-comment injection** against LLM-based code vulnerability detectors, with the full trial record of four studies.

The attack is simple: leave the vulnerable code exactly as it is and add a comment that tells the reviewer the code is safe ("SECURITY REVIEWED", "input is sanitized upstream", "formally verified"). CommentInject measures how often that comment makes a locally run code model miss a real vulnerability, which kinds of comment work best, whether stripping comments defends against it, and whether a comment that fools one model also fools others.

## What is in the benchmark

- **30 vulnerable Python functions** across 14 CWE categories (`data/samples.jsonl`). Every sample is vulnerable; the ground truth never changes.
- **12 adversarial comment strategies** in four families (`data/strategies.jsonl`). Each one only prepends a comment. The executable code is identical.
- **3,360 recorded trials** from four studies (`results/`), run locally through Ollama at temperature 0.

| Family | Strategies |
|---|---|
| Verification premise | authority_claim, false_test_coverage, fake_review_approval |
| Context manipulation | misleading_context, false_reassurance, scope_limitation |
| Credibility vocabulary | security_camouflage, compliance_claim, formal_verification |
| Pressure and distraction | deadline_pressure, distraction_comment, authorial_confidence |

CWE coverage (samples): CWE-89 (5), CWE-78, CWE-22, CWE-94 (3 each), CWE-79, CWE-798, CWE-327, CWE-502, CWE-330, CWE-611 (2 each), CWE-259, CWE-918, CWE-77, CWE-295 (1 each).

## The four studies

| File | Study | Design | Trials |
|---|---|---|---|
| `results/study1_attack_ranking.csv` | Which comment strategies work best | 30 samples x (clean + 12 strategies) x 2 models | 780 |
| `results/study2_defense.csv` | Does stripping comments defend | 30 samples x 8 strategies x (attacked, defended) x 2 models, plus clean | 1,020 |
| `results/study3_cross_model.csv` | Does model choice matter | 30 samples x (clean + 4 strategies) x 4 models | 600 |
| `results/study4_transferability.csv` | Does a comment that fools one model fool others | 30 samples x 8 strategies x 4 models | 960 |

Models: qwen2.5-coder:7b and deepseek-coder:6.7b (studies 1 and 2), plus codellama:7b and codegemma:7b (studies 3 and 4).

Columns: `model, sample_id, cwe, name, condition, strategy, detected` (study 4 has `fooled` instead of `condition`). `condition` is `clean`, `adversarial` or `defended`; `detected` is True when the model's verdict was VULNERABLE; `fooled` is True when it was not.

## Headline results

Reproduce every number below with `python3 scripts/analyze.py` (standard library only). Intervals are Wilson 95%.

- **Study 1.** Clean detection 95.0%. The most effective comment was an authority claim (71.7% [59.2, 81.5] detection), and a bare statement of the author's confidence with no evidence ranked second (73.3%). Strategies differ significantly (chi-square = 21.60, dof = 11).
- **Study 2.** The attack cut detection from 90.0% to 75.2%. Removing all comments before analysis restored it to 90.0% [87.0, 92.4] (McNemar b = 73, c = 2).
- **Study 3.** Under attack, detection ranged from 17.5% (codegemma:7b) to 93.3% (qwen2.5-coder:7b), although every model's clean baseline was 76.7% or higher (chi-square = 145.08, dof = 3).
- **Study 4.** Mean cross-model transfer rate 53.0%. Only 2.9% of adversarial cases fooled all four models.

## Reproducing the experiments

`original_scripts/` holds each study's harness **exactly as it was run**, one folder per study. Each folder is self-contained.

```bash
ollama pull qwen2.5-coder:7b
ollama pull deepseek-coder:6.7b
cd original_scripts/study1_attack_ranking
mkdir results
python3 run_p9_12strat.py
```

Notes on the original scripts:
- Docstrings and print statements use internal working names ("Paper 9", "Paper 10") and some describe earlier drafts (for example "8 strategies" in the 12-strategy runner). The code, not the docstrings, defines each experiment.
- Studies 2 and 4 used the first eight strategies; their prompt ends "name the vulnerability type if present" instead of "if any". All four studies use the same verdict parser on the first line of the reply.
- The study 2 defense removes everything after `#` on each line. That is safe for these samples because none contains `#` inside a string.

## Limitations

Thirty samples, all Python, all synthetic, so several CWEs are represented by one or two functions. Four open models of roughly 7B parameters, default Ollama quantization, one fixed prompt, temperature 0. The verdict is binary and only detection is scored.

## Safety

The samples contain classic vulnerability patterns written for this benchmark. Credentials in them (for example `sk-1234567890abcdef`, `P@ssw0rd123`) are fake. Nothing here exploits or touches a live system.

## Related papers

1. S. Chokshi, "Not All Adversarial Comments Are Equal: A Ranked Empirical Study of Twelve Comment Injection Attacks Against LLM-Based Code Vulnerability Detection," IEEE Cyber-AI 2026. (Study 1)
2. S. Chokshi, "Analyze the Code, Not the Comments: Comment-Stripped Analysis Fully Defends LLM-Based Code Vulnerability Detectors Against Adversarial Comment Injection," IEEE Cyber-AI 2026. (Study 2)
3. S. Chokshi, "Model Choice Matters: A Cross-Model Study of Adversarial Comment Injection in LLM-Based Code Vulnerability Detection," under review. (Study 3)
4. S. Chokshi, "Adversarial Comments That Defeat a Robust Model Transfer to Weaker Ones: An Asymmetric Transferability Study of Comment Injection Against LLM-Based Code Vulnerability Detection," ICon INDIA 2026. (Study 4)

## Citation

Dataset: see `CITATION.cff`. A Zenodo DOI will be added here once minted.

## License

Code is MIT. Data and results are CC BY 4.0. See `LICENSE`.

## Author

Sunny Chokshi, University of the Cumberlands. ORCID [0009-0003-4738-7759](https://orcid.org/0009-0003-4738-7759).
