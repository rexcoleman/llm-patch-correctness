#!/usr/bin/env python3
"""Generate FP-20 report figures."""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

INPUT_DIR = Path("outputs/experiments")
OUT_DIRS = [Path("blog/images"), Path("outputs/figures")]

def ensure_dirs():
    for d in OUT_DIRS:
        d.mkdir(parents=True, exist_ok=True)

def save(fig, name):
    for d in OUT_DIRS:
        fig.savefig(d / f"{name}.png", dpi=150, bbox_inches="tight")
    print(f"  Saved: {name}.png")

def fig_e3():
    with open(INPUT_DIR / "e3_results.json") as f:
        data = json.load(f)["results"]
    cwes = sorted(data.keys())
    labels = {"CWE-120": "Buffer\nOverflow", "CWE-22": "Path\nTraversal",
              "CWE-327": "Weak\nCrypto", "CWE-79": "XSS", "CWE-89": "SQL\nInjection"}
    x = np.arange(len(cwes))
    fix_rates = [data[c]["fix_rate"]*100 for c in cwes]
    reg_rates = [data[c]["regression_rate"]*100 for c in cwes]
    fig, ax = plt.subplots(figsize=(10, 6))
    w = 0.35
    ax.bar(x - w/2, fix_rates, w, label="Fix Rate", color="#16a34a", alpha=0.8)
    ax.bar(x + w/2, reg_rates, w, label="Regression Rate", color="#dc2626", alpha=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels([labels.get(c, c) for c in cwes])
    ax.set_ylabel("Rate (%)")
    ax.set_title("LLM Patch Safety by CWE Category\n(Claude Haiku, 50 snippets x 5 seeds)")
    ax.set_ylim(0, 115)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    save(fig, "e3_cwe_analysis")
    plt.close()

def fig_e1():
    with open(INPUT_DIR / "e1_results.json") as f:
        e1 = json.load(f)["results"]
    with open(INPUT_DIR / "e2_results.json") as f:
        e2 = json.load(f)["results"]
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.bar(["Fix Rate", "Regression Rate"],
           [e1["fix_rate_mean"]*100, e2["regression_rate_mean"]*100],
           color=["#16a34a", "#dc2626"], alpha=0.8)
    ax.set_ylabel("Rate (%)")
    ax.set_title("Overall LLM Patch Correctness\n(50 snippets x 5 CWEs x 5 seeds)")
    ax.set_ylim(0, 100)
    ax.grid(axis="y", alpha=0.3)
    save(fig, "e1_overall_rates")
    plt.close()

def main():
    ensure_dirs()
    print("Generating FP-20 figures...")
    fig_e3()
    fig_e1()
    print("Done.")

if __name__ == "__main__":
    main()
