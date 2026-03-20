# Experimental Design Review — FP-20: LLM-Generated Patch Correctness

> **Gate:** 0 (must pass before Phase 1 compute)
> **Date:** 2026-03-20
> **Target venue:** USENIX Security 2026 [HYPOTHESIZED]
> **lock_commit: `eb454e0`
> **Profile:** contract-track
> **Budget:** ~$3-5 Claude API (Haiku)

---

## Novelty Claim

> First empirical measurement of regression rate when LLMs generate security patches, showing what fraction introduce new vulnerabilities detectable by static analysis.

---

## Comparison Baselines

| # | Method | Citation | How We Compare | Why This Baseline |
|---|--------|----------|---------------|-------------------|
| 1 | No-patch baseline | Control | Vulnerability count in original code | Lower bound — any patch must not increase vuln count |
| 2 | Template-based fix | Rule-based | CWE-specific fix templates (e.g., parameterized queries for SQLi) | Shows whether LLM adds value beyond known patterns |
| 3 | Human patches (NVD reference) | NVD database | Compare regression rates: LLM vs human patches | Gold standard for patch quality |

---

## Pre-Registered Reviewer Kill Shots

| # | Criticism | Planned Mitigation |
|---|----------|-------------------|
| 1 | "Static analysis has high false positive rates" | Report both raw and verified findings. Use semgrep with high-confidence rules only. Manual verification on 10% sample. |
| 2 | "Synthetic code snippets don't represent real codebases" | Use CWE top 25 patterns from real CVE reports. Snippets are minimal reproducible examples, not toy code. Limitation acknowledged. |
| 3 | "Prompt engineering determines results, not model capability" | Ablation E4 tests 3 prompt detail levels. Report all prompts for reproducibility. |

---

## Ablation Plan

| Component | Hypothesis When Changed | Expected Effect | Priority |
|-----------|------------------------|-----------------|----------|
| Prompt detail (minimal / CWE description / CWE + fix guidance) | More guidance = fewer regressions | Regression rate decreases with prompt detail | HIGH |
| CWE category (injection, logic, memory, crypto) | Regression rate varies by CWE type | Injection fixes have lowest regression (well-known patterns) | HIGH |
| Model (Haiku only in this study) | N/A — single model | N/A | DEFERRED |

---

## Ground Truth Audit

| Source | Type | Count | Known Lag | Positive Rate | Limitations |
|--------|------|-------|-----------|---------------|-------------|
| CWE Top 25 vulnerable code patterns | Constructed from real CVE reports | 50 code snippets | N/A | 100% vulnerable (by construction) | Synthetic, not full codebase context |
| Semgrep high-confidence rules | Static analysis | Per-snippet | Real-time | Varies by rule | False positives possible |
| Manual verification | Expert review | 10% sample | N/A | Ground truth | Subjective, small sample |

### Alternative Sources Considered

| Source | Included? | Rationale |
|--------|-----------|-----------|
| Real CVE patches from GitHub | NO | Extraction complexity, licensing issues. Future work. |
| CodeQL | NO | Requires build context. Semgrep is lighter weight for snippet analysis. |

---

## Statistical Plan

| Parameter | Value | Justification |
|-----------|-------|---------------|
| Seeds | 5 (42, 123, 456, 789, 1024) | govML standard (temperature sampling) |
| Code snippets | 50 (10 per CWE category × 5 categories) | Covers top CWE types |
| Primary metrics | Fix rate (target vuln resolved), Regression rate (new vulns introduced) | Both matter: a patch that fixes one vuln but adds another is net zero |
| Significance test | McNemar's test (paired: same snippet, LLM vs template fix) | Paired design |
| Multiple comparisons | Holm-Bonferroni for 5 CWE categories | Controls family-wise error rate |
| Effect size | Regression rate ≥15% | Practitioner-meaningful — 1 in 7 patches introduces a new vuln |

---

## Related Work

| # | Paper | Year | Relevance |
|---|-------|------|-----------|
| 1 | Pearce et al. — "Examining Zero-Shot Vulnerability Repair with LLMs" | 2023 | LLM patch generation study. We extend with regression analysis. |
| 2 | He & Vechev — "Large Language Models for Code: Security Hardening and Adversarial Testing" | 2023 | LLM security code generation. We focus on patch regression specifically. |
| 3 | Jesse et al. — "LLM-Assisted Code Cleaning and Vulnerability Remediation" | 2023 | Closest to our work. We add static analysis regression measurement. |
| 4 | Chen et al. — "Evaluating Large Language Models Trained on Code" | 2021 | Codex evaluation methodology. We adapt for security-specific metrics. |
| 5 | Fang et al. — "LLM Agents Can Autonomously Exploit Vulnerabilities" | 2024 | LLM offensive capability. We test the defensive side (patching). |

---

## Threats to Validity

| Threat | Type | Mitigation |
|--------|------|-----------|
| Synthetic code snippets may not represent real codebase complexity | External validity | Snippets are minimal reproducible examples from real CVE patterns. Acknowledged in Limitations. Real-codebase testing is future work. |
| Static analysis false positives inflate regression rate | Construct validity | Use semgrep high-confidence rules only. Manual verification on 10% sample. Report verified and unverified rates separately. |
| Prompt engineering confound — results depend on prompt, not model | Construct validity | Ablation E4 tests 3 prompt levels. Report all prompts. |
| CWE sampling bias — top 25 may not represent full vulnerability landscape | External validity | Top 25 covers ~75% of real-world vulns by frequency. Acknowledged limitation. |
| LLM may have seen specific CVE fixes in training data | Internal validity | Use recently published CVEs where possible. The measurement is still valid: we're testing what practitioners would actually get from the tool. |

---

## Depth Escalation (R34)

### Depth Commitment
ONE primary finding: LLM patch safety is entirely CWE-dependent — 100% fix rate for crypto, 50% regression for SQL injection.

### Mechanism Analysis Plan
| Finding | Proposed Mechanism | Experiment |
|---------|-------------------|-----------|
| Crypto fixes work (100%) | Pattern replacement: md5→sha256 is context-independent | E3 CWE analysis |
| SQL fixes regress (50%) | Context-dependent reasoning failure: model rewrites SQL but introduces new concatenation | E3 CWE analysis |

### Adaptive Adversary Plan
| Robustness Claim | Weak Test | Adaptive Test |
|-----------------|-----------|---------------|
| LLM patches fix vulnerabilities | Standard CWE snippets | Adversarial snippets with misleading comments that encourage wrong fix patterns |
| Regression detection catches issues | Standard static analysis patterns | Obfuscated vulnerability patterns that evade regex detection |

Note: Adaptive adversary testing is acknowledged as future work. Current study establishes baseline fix/regression rates on standard snippets.

### Published Baseline Reproduction
Compare against Pearce et al. (2023) fix rates where possible.

### Parameter Sensitivity Plan
| Parameter | Range | Expected Effect |
|-----------|-------|-----------------|
| Prompt detail level | minimal/CWE/guided | More guidance = lower regression (E4) |
| CWE category | 5 categories | Fix rate varies by CWE (E3) |

### Defense Harm Test
N/A — measuring patch quality, not deploying a defense.

### Formal Contribution Statement
We contribute CWE-stratified patch regression rates showing AI patching is safe for crypto but dangerous for SQL injection.

---

## Audience Alignment

- **Audience:** Security practitioners using AI coding assistants (Copilot, Claude) + AI builders evaluating code generation safety
- **Portfolio position:** "Security FROM AI" — LLM output as potential attack surface. Complements FP-18 (watermark detection). First code-generation project.
- **Distribution plan:** Blog on rexcoleman.dev → LinkedIn → Reddit r/netsec + r/programming → DEF CON AI Village. "X% of AI patches introduce new vulns" is a shareable headline.

---

## Experiment Matrix

| ID | Question | IV | Levels | DV | Seeds |
|----|----------|-----|--------|-----|-------|
| E0 | Sanity: LLM generates syntactically valid patches | N/A | 3 known CWEs | Valid patch output | 1 |
| E1 | Fix rate: does the patch resolve the target vulnerability? | CWE category | 5 categories | Fix rate (%) | 5 |
| E2 | Regression rate: does the patch introduce new vulnerabilities? | CWE category | 5 categories | Regression rate (%) | 5 |
| E3 | CWE category analysis: which types have highest regression? | CWE category | injection, XSS, memory, logic, crypto | Regression rate per category | 5 |
| E4 | Prompt detail ablation: does guidance reduce regression? | Prompt level | minimal, CWE desc, CWE+fix guidance | Regression rate | 5 |
