# FP-20: LLM-Generated Patch Correctness

LLM-generated security patches have a 42% fix rate and 10% regression rate. SQL injection patches are net-negative: 0% fix, 50% regression. Cryptography patches hit 100% fix with 0% regression. Which CWE you're patching determines whether AI help is safe.

**Blog post:** [Your AI Makes SQL Injection Worse](https://rexcoleman.dev/posts/llm-patch-correctness/)

## Key Results

| CWE Category | Fix Rate | Regression Rate | Net Effect |
|-------------|----------|-----------------|------------|
| CWE-89 (SQL Injection) | 0% | 50% | Net negative |
| CWE-79 (XSS) | 40% | 10% | Marginal positive |
| CWE-327 (Crypto) | 100% | 0% | Strong positive |
| CWE-22 (Path Traversal) | 30% | 0% | Positive |
| CWE-78 (OS Command) | 40% | 0% | Positive |
| **Aggregate** | **42%** | **10%** | **Mixed** |

## Quick Start

```bash
pip install -r requirements.txt
bash reproduce.sh
```

5 experiments (E0-E4). Claude 3 Haiku. 5 seeds. Static analysis validation. Built with [govML](https://rexcoleman.dev/posts/govml-methodology/) governance.
