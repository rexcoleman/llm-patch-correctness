# I tested LLM-generated security patches across 5 CWE categories — SQL injection patches have a 0% fix rate and 50% regression rate

I had Claude Haiku generate patches for 50 vulnerable code snippets across 5 CWE categories and measured both fix rate and regression rate with static analysis. The headline: SQL injection patches are net-negative. The model fixes 0% of SQLi vulnerabilities and introduces NEW injection vectors in 50% of attempts. Meanwhile, cryptography patches are perfect — 100% fix rate, 0% regression.

The overall numbers are 42% fix rate and 10% regression rate, both below my pre-registered predictions. But the aggregate is misleading. The CWE category is the dominant predictor, not randomness — results are perfectly deterministic across all 5 seeds at temperature=0. The 100 percentage point range across categories (0% to 100% fix, 0% to 50% regression) is the actionable finding.

The pattern is clear when you look at what the model actually does:

- **Crypto fixes work (100% fix, 0% regression)** — md5 to sha256 is a direct token replacement, context-independent
- **XSS and buffer overflow are mixed (50% fix, 0% regression)** — worth reviewing but not trusting blindly
- **Path traversal is ineffective (10% fix)** — the model doesn't understand directory traversal context
- **SQL injection is dangerous (0% fix, 50% regression)** — the model rewrites string formatting but introduces new concatenation patterns that are equally vulnerable
- **The general rule: if the fix is a token-level pattern swap, AI works. If it requires understanding data flow, AI fails.**

The distinction is pattern replacement vs context-dependent reasoning. LLMs excel at the former (swap md5 for sha256) and fail at the latter (implement parameterized queries correctly in context). The model understands the CONCEPT of parameterized queries but can't implement them without introducing new injection vectors.

Methodology: 50 vulnerable Python snippets (10 per CWE), Claude 3 Haiku at temperature=0, regex-based static analysis for fix and regression detection. 5 seeds, pre-registered hypotheses. ~$2 API cost.

Repo: [github.com/rexcoleman/llm-patch-correctness](https://github.com/rexcoleman/llm-patch-correctness)

Code is open source with reproduce.sh. Happy to answer questions — especially from teams using Copilot or Claude for security patching.
