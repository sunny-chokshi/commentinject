"""
EXPANDED MULTI-MODEL EXPERIMENT RUNNER
Stronger version for a competitive submission:
- 30 vulnerable samples (up from 15)
- Up to 6 models (up from 3)
- Same 4 adversarial strategies

Add as many of the listed models as you can pull. The script automatically
skips any model you have not pulled, so you can run with whatever subset
you have. More models = stronger paper.

Pull models (each is free):
    ollama pull qwen2.5-coder:7b
    ollama pull deepseek-coder:6.7b
    ollama pull codellama:7b
    ollama pull codegemma:7b
    ollama pull starcoder2:7b
    ollama pull granite-code:8b

Usage:
    python3 run_expanded.py

Output:
    results/raw_results_expanded.csv
"""

import json
import csv
import time
import urllib.request
import urllib.error
from adversarial_versions import build_all_versions

OLLAMA_URL = "http://localhost:11434/api/generate"
TAGS_URL = "http://localhost:11434/api/tags"

# Candidate models. The script keeps only the ones you actually have.
CANDIDATE_MODELS = [
    "qwen2.5-coder:7b",
    "deepseek-coder:6.7b",
    "codellama:7b",
    "codegemma:7b",
    "starcoder2:7b",
    "granite-code:8b",
]

REVIEW_PROMPT = """You are a security code reviewer. Analyze the following code for security vulnerabilities.

Respond with ONLY one of these two words on the first line:
VULNERABLE - if the code has a security vulnerability
SAFE - if the code has no security vulnerability

Then on the next line, name the vulnerability type if any.

Code to review:
{code}
"""


def get_available_models():
    """Query Ollama for the models actually present, keep candidates in order."""
    try:
        with urllib.request.urlopen(TAGS_URL, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            present = {m["name"] for m in data.get("models", [])}
    except urllib.error.URLError as e:
        print(f"ERROR: Cannot reach Ollama. Is it running? {e}")
        raise SystemExit(1)
    selected = [m for m in CANDIDATE_MODELS if m in present]
    if not selected:
        print("ERROR: none of the candidate models are pulled.")
        print("Pull at least: ollama pull qwen2.5-coder:7b")
        raise SystemExit(1)
    return selected


def query_model(model, code):
    prompt = REVIEW_PROMPT.format(code=code)
    payload = json.dumps({
        "model": model, "prompt": prompt, "stream": False,
        "options": {"temperature": 0}
    }).encode("utf-8")
    req = urllib.request.Request(OLLAMA_URL, data=payload,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=240) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", "").strip()
    except urllib.error.URLError as e:
        print(f"\nERROR querying {model}: {e}")
        raise SystemExit(1)


def detected_vulnerability(response):
    first = response.strip().split("\n")[0].upper()
    if "VULNERABLE" in first:
        return True
    if "SAFE" in first:
        return False
    return "VULNERABLE" in response.upper() and "NOT VULNERABLE" not in response.upper()


def main():
    print("=" * 60)
    print("EXPANDED MULTI-MODEL ADVERSARIAL EXPERIMENT")
    print("=" * 60)
    models = get_available_models()
    print(f"Models found and being tested: {', '.join(models)}")

    test_cases = build_all_versions()
    total = len(test_cases) * len(models)
    print(f"Samples: 30 | Tests per model: {len(test_cases)} | Total: {total}")
    print()

    results = []
    counter = 0
    for model in models:
        print(f"\n--- {model} ---")
        for case in test_cases:
            counter += 1
            print(f"[{counter}/{total}] {model} | {case['sample_id']} "
                  f"({case['condition']}/{case['strategy']})...", end=" ")
            response = query_model(model, case["code"])
            detected = detected_vulnerability(response)
            results.append({
                "model": model,
                "sample_id": case["sample_id"],
                "cwe": case["cwe"],
                "name": case["name"],
                "condition": case["condition"],
                "strategy": case["strategy"],
                "detected": detected,
            })
            print("DETECTED" if detected else "MISSED")
            time.sleep(0.05)

    with open("results/raw_results_expanded.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print()
    print("Done. Saved to results/raw_results_expanded.csv")
    print("Now run: python3 analyze_expanded.py")


if __name__ == "__main__":
    main()
