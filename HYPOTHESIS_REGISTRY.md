# HYPOTHESIS REGISTRY — FP-20 LLM-Generated Patch Correctness

> **Project:** FP-20
> **Created:** 2026-03-20
> **Status:** PENDING (0/4 resolved)
> **Lock commit:** TBD
> **Lock date:** 2026-03-20

---

## H-1: LLM patches fix the target vulnerability ≥70% of the time

| Field | Value |
|-------|-------|
| **Statement** | Claude Haiku generates patches that resolve the target vulnerability in ≥70% of test cases, verified by static analysis. |
| **Prediction** | fix_rate ≥ 0.70 |
| **Falsification** | If fix_rate < 0.70, LLM patches are unreliable for security remediation. |
| **Status** | PENDING |
| **Linked Experiment** | E1 |

---

## H-2: ≥15% of LLM patches introduce new vulnerabilities

| Field | Value |
|-------|-------|
| **Statement** | At least 15% of LLM-generated patches introduce new security issues detectable by static analysis (regression). |
| **Prediction** | regression_rate ≥ 0.15 |
| **Falsification** | If regression_rate < 0.15, LLM patches are safer than expected. |
| **Status** | PENDING |
| **Linked Experiment** | E2 |

---

## H-3: Regression rate varies by CWE category

| Field | Value |
|-------|-------|
| **Statement** | Regression rate is highest for memory safety CWEs and lowest for injection CWEs, because injection fixes follow well-known patterns. |
| **Prediction** | regression_rate(memory) > regression_rate(injection) by ≥15pp |
| **Falsification** | If regression rates are uniform across CWE categories, the LLM does not differentiate by vulnerability type. |
| **Status** | PENDING |
| **Linked Experiment** | E3 |

---

## H-4: More detailed prompts reduce regression rate

| Field | Value |
|-------|-------|
| **Statement** | Providing CWE description + fix guidance in the prompt reduces regression rate by ≥10pp compared to minimal prompts. |
| **Prediction** | regression_rate(guided) < regression_rate(minimal) by ≥10pp |
| **Falsification** | If prompt detail doesn't affect regression rate, the LLM already knows how to fix these. |
| **Status** | PENDING |
| **Linked Experiment** | E4 |

---

## Summary

| ID | Statement (short) | Prediction | Status |
|----|-------------------|-----------|--------|
| H-1 | LLM fixes target vuln ≥70% | fix_rate ≥ 0.70 | NOT SUPPORTED (42%) |
| H-2 | ≥15% introduce new vulns | regression_rate ≥ 0.15 | NOT SUPPORTED (10%, but 50% CWE-89) |
| H-3 | Regression varies by CWE | memory > injection | PENDING |
| H-4 | Detailed prompts reduce regression | ≥10pp improvement | PENDING |
