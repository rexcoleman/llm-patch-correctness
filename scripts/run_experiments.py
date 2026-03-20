#!/usr/bin/env python3
"""FP-20: LLM-Generated Patch Correctness — Experiment Runner.

Tests whether LLM-generated security patches fix vulnerabilities and/or introduce new ones.

Usage:
    python -u scripts/run_experiments.py --experiments E0
    python -u scripts/run_experiments.py --experiments E0,E1,E2,E3,E4
"""
import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.patch_generator import generate_patch
from src.static_analyzer import check_regression
from src.cve_dataset import get_snippets, get_cwe_categories

OUTPUT_DIR = Path("outputs/experiments")
SEEDS = [42, 123, 456, 789, 1024]


def save_results(name, data):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_file = OUTPUT_DIR / f"{name}_results.json"
    with open(out_file, "w") as f:
        json.dump({"experiment": name, "date": datetime.now().isoformat(),
                    "results": data}, f, indent=2, default=str)
    print(f"  Saved: {out_file}")


def run_e0():
    """E0: Sanity — LLM generates syntactically valid patches."""
    print(f"\n{'='*60}\nE0: Sanity Validation\n{'='*60}")
    import anthropic
    client = anthropic.Anthropic()

    snippets = get_snippets()[:3]  # Test on 3 snippets
    results = []
    for s in snippets:
        patch = generate_patch(client, s["vulnerable_code"], s["cwe_id"], s["cwe_name"])
        has_code = len(patch["patched_code"]) > 10
        results.append({"id": s["id"], "has_code": has_code,
                        "code_length": len(patch["patched_code"])})
        print(f"  {s['id']}: {'PASS' if has_code else 'FAIL'} "
              f"(patch length: {len(patch['patched_code'])} chars)")

    overall = all(r["has_code"] for r in results)
    print(f"  E0 OVERALL: {'PASS' if overall else 'FAIL'}")
    return {"results": results, "overall_pass": overall}


def run_e1_e2(seeds):
    """E1+E2: Fix rate and regression rate across all snippets."""
    print(f"\n{'='*60}\nE1/E2: Fix Rate and Regression Rate\n{'='*60}")
    import anthropic
    client = anthropic.Anthropic()

    snippets = get_snippets()
    all_results = []

    for seed_idx, seed in enumerate(seeds):
        seed_results = []
        for s in snippets:
            patch = generate_patch(client, s["vulnerable_code"],
                                   s["cwe_id"], s["cwe_name"],
                                   prompt_level="guided", seed=seed)
            check = check_regression(s["vulnerable_code"], patch["patched_code"],
                                     s["cwe_id"])
            result = {
                "id": s["id"],
                "cwe_id": s["cwe_id"],
                "seed": seed,
                "target_fixed": check["target_fixed"],
                "regression_count": check["regression_count"],
                "has_regression": check["regression_count"] > 0,
            }
            seed_results.append(result)

        fix_rate = np.mean([r["target_fixed"] for r in seed_results])
        reg_rate = np.mean([r["has_regression"] for r in seed_results])
        print(f"  seed={seed}: fix_rate={fix_rate:.2%}, regression_rate={reg_rate:.2%} "
              f"(n={len(seed_results)})")
        all_results.extend(seed_results)

    # Aggregate
    overall_fix = np.mean([r["target_fixed"] for r in all_results])
    overall_reg = np.mean([r["has_regression"] for r in all_results])
    print(f"\n  OVERALL: fix_rate={overall_fix:.2%}, regression_rate={overall_reg:.2%} "
          f"(n={len(all_results)})")

    e1_result = {
        "fix_rate_mean": float(overall_fix),
        "fix_rate_per_seed": {str(s): float(np.mean([r["target_fixed"] for r in all_results if r["seed"]==s]))
                              for s in seeds},
        "n": len(all_results),
    }
    e2_result = {
        "regression_rate_mean": float(overall_reg),
        "regression_rate_per_seed": {str(s): float(np.mean([r["has_regression"] for r in all_results if r["seed"]==s]))
                                     for s in seeds},
        "n": len(all_results),
        "details": all_results,
    }

    save_results("e1", e1_result)
    save_results("e2", e2_result)
    return e1_result, e2_result


def run_e3(seeds):
    """E3: CWE category analysis — which types have highest regression?"""
    print(f"\n{'='*60}\nE3: CWE Category Analysis\n{'='*60}")
    import anthropic
    client = anthropic.Anthropic()

    categories = get_cwe_categories()
    results = {}

    for cwe_id in categories:
        snippets = get_snippets(cwe_filter=cwe_id)
        cwe_results = []

        for seed in seeds:
            for s in snippets:
                patch = generate_patch(client, s["vulnerable_code"],
                                       s["cwe_id"], s["cwe_name"], seed=seed)
                check = check_regression(s["vulnerable_code"],
                                         patch["patched_code"], s["cwe_id"])
                cwe_results.append({
                    "id": s["id"], "seed": seed,
                    "target_fixed": check["target_fixed"],
                    "has_regression": check["regression_count"] > 0,
                })

        fix_rate = np.mean([r["target_fixed"] for r in cwe_results])
        reg_rate = np.mean([r["has_regression"] for r in cwe_results])
        results[cwe_id] = {
            "fix_rate": float(fix_rate),
            "regression_rate": float(reg_rate),
            "n": len(cwe_results),
        }
        print(f"  {cwe_id}: fix={fix_rate:.2%}, regression={reg_rate:.2%} (n={len(cwe_results)})")

    save_results("e3", results)
    return results


def run_e4(seeds):
    """E4: Prompt detail ablation."""
    print(f"\n{'='*60}\nE4: Prompt Detail Ablation\n{'='*60}")
    import anthropic
    client = anthropic.Anthropic()

    snippets = get_snippets()[:20]  # Subset for ablation
    results = {}

    for level in ["minimal", "cwe_desc", "guided"]:
        level_results = []
        for seed in seeds:
            for s in snippets:
                patch = generate_patch(client, s["vulnerable_code"],
                                       s["cwe_id"], s["cwe_name"],
                                       prompt_level=level, seed=seed)
                check = check_regression(s["vulnerable_code"],
                                         patch["patched_code"], s["cwe_id"])
                level_results.append({
                    "target_fixed": check["target_fixed"],
                    "has_regression": check["regression_count"] > 0,
                })

        fix_rate = np.mean([r["target_fixed"] for r in level_results])
        reg_rate = np.mean([r["has_regression"] for r in level_results])
        results[level] = {
            "fix_rate": float(fix_rate),
            "regression_rate": float(reg_rate),
            "n": len(level_results),
        }
        print(f"  {level}: fix={fix_rate:.2%}, regression={reg_rate:.2%}")

    save_results("e4", results)
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--experiments", default="E0")
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    requested = [e.strip() for e in args.experiments.split(",")]
    all_results = {}

    for exp_id in requested:
        if exp_id == "E0":
            result = run_e0()
            all_results["E0"] = result
            save_results("e0", result)
            if not result.get("overall_pass", False):
                print("\n*** E0 FAILED — stopping. ***")
                break
        elif exp_id in ("E1", "E2"):
            if "E1" not in all_results:
                e1, e2 = run_e1_e2(SEEDS)
                all_results["E1"] = e1
                all_results["E2"] = e2
        elif exp_id == "E3":
            all_results["E3"] = run_e3(SEEDS)
        elif exp_id == "E4":
            all_results["E4"] = run_e4(SEEDS)

    summary_file = OUTPUT_DIR / "all_experiments_summary.json"
    with open(summary_file, "w") as f:
        json.dump({"date": datetime.now().isoformat(),
                    "seeds": SEEDS, "results": all_results}, f, indent=2, default=str)
    print(f"\nSaved: {summary_file}")


if __name__ == "__main__":
    main()
