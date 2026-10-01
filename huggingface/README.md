---
license: cc-by-4.0
language:
  - en
task_categories:
  - text-classification
tags:
  - code
  - security
  - prompt-injection
  - adversarial-attacks
  - vulnerability-detection
  - cwe
  - llm-evaluation
  - python
pretty_name: CommentInject
size_categories:
  - 1K<n<10K
configs:
  - config_name: samples
    data_files: samples.jsonl
  - config_name: strategies
    data_files: strategies.jsonl
  - config_name: study1_attack_ranking
    data_files: study1_attack_ranking.jsonl
  - config_name: study2_defense
    data_files: study2_defense.jsonl
  - config_name: study3_cross_model
    data_files: study3_cross_model.jsonl
  - config_name: study4_transferability
    data_files: study4_transferability.jsonl
---

# CommentInject

A benchmark of **adversarial code-comment injection** against LLM-based code vulnerability detectors. The vulnerable code stays exactly the same; only a comment claiming the code is safe is added.

- **30 vulnerable Python functions** across 14 CWE categories (`samples`).
- **12 adversarial comment strategies** in four families (`strategies`).
- **3,360 recorded trials** from four studies, run locally through Ollama at temperature 0 on qwen2.5-coder 7B, deepseek-coder 6.7B, codellama 7B and codegemma 7B.

## Configs

| Config | Study | Trials |
|---|---|---|
| `study1_attack_ranking` | Which of 12 comment strategies best suppresses detection (2 models) | 780 |
| `study2_defense` | Clean vs. attacked vs. comments-stripped (8 strategies, 2 models) | 1,020 |
| `study3_cross_model` | Same attacks on 4 models (4 strategies) | 600 |
| `study4_transferability` | Same adversarial case shown to 4 models (8 strategies) | 960 |

Fields: `model, sample_id, cwe, name, condition, strategy, detected` (study 4: `fooled` instead of `condition`). `detected` is true when the model's verdict was VULNERABLE.

## Headline results

- Strategies differ significantly; an authority claim and a bare statement of author confidence were the two most effective (71.7% and 73.3% detection vs. 95.0% clean).
- Stripping comments before analysis restored detection from 75.2% under attack to 90.0%, the clean baseline.
- Under attack, detection ranged from 17.5% (codegemma 7B) to 93.3% (qwen2.5-coder 7B).
- Mean cross-model transfer rate 53.0%; only 2.9% of cases fooled all four models.

## Harness and reproduction

Original harnesses and a one-command analysis script are in the companion GitHub repository: https://github.com/sunny-chokshi/commentinject

## Safety

All samples are synthetic; credentials in them are fake. No exploit code, nothing that touches a live system.

## Citation

Dataset: CommentInject v1.0.0, Zenodo, 2026. doi:10.5281/zenodo.23088528. Author: Sunny Chokshi, University of the Cumberlands. ORCID 0009-0003-4738-7759.
