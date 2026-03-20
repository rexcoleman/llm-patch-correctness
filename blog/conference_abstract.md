# Conference Abstract — LLM Patch Correctness

**Title:** LLM-Generated Security Patches Introduce New Vulnerabilities: A CWE-Stratified Regression Analysis

**Target venue:** USENIX Security 2026 [HYPOTHESIZED]
**Authors:** Rex Coleman, Singularity Cybersecurity LLC

## Abstract (250 words)

We measure the regression rate of LLM-generated security patches — how often AI fixes introduce new vulnerabilities — using static analysis across 50 code snippets spanning 5 CWE categories. Claude Haiku achieves 42% fix rate overall with 10% regression, but these aggregates obscure dramatic CWE-dependent variation: cryptographic weakness patches (CWE-327) have 100% fix rate and 0% regression, while SQL injection patches (CWE-89) have 0% fix rate and 50% regression — the model makes SQL injection worse.

The key finding: LLM patch safety is entirely CWE-dependent. Pattern-replacement fixes (md5→sha256) are reliable. Context-dependent fixes (parameterized queries, path validation) fail because the model cannot reason about data flow through the code.

**Keywords:** LLM security, code generation, vulnerability patching, regression testing, CWE analysis

## Author Bio

**Rex Coleman** is the founder of Singularity Cybersecurity LLC, focused on AI security research spanning security OF AI systems and security FROM AI. Previously at FireEye/Mandiant. MS Computer Science, Georgia Tech (ML). Securing AI from the architecture up.
