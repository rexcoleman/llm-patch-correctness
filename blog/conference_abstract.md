# Conference Abstract — LLM Patch Correctness

**Title:** LLM-Generated Security Patches Introduce New Vulnerabilities: A CWE-Stratified Regression Analysis

**Target venue:** USENIX Security 2026 [HYPOTHESIZED]
**Authors:** Rex Coleman, Singularity Cybersecurity LLC

## Abstract (250 words)

Organizations are adopting LLM-generated code fixes for security vulnerabilities, but no empirical data exists on regression rates — how often the AI fix introduces a new vulnerability. Deploying an AI patch that makes SQL injection worse is not a theoretical risk; we measured it.

We evaluate Claude Haiku across 50 code snippets spanning 5 CWE categories using static analysis. Overall: 42% fix rate, 10% regression. But aggregates obscure dramatic CWE-dependent variation: cryptographic weakness patches (CWE-327) achieve 100% fix rate and 0% regression, while SQL injection patches (CWE-89) achieve 0% fix rate and 50% regression. The key finding: LLM patch safety is entirely CWE-dependent. Pattern-replacement fixes (md5 to sha256) are reliable; context-dependent fixes (parameterized queries, path validation) fail because the model cannot reason about data flow.

Attendees will leave with a CWE-stratified safety map showing which vulnerability categories are safe for AI patching and which require human review, directly applicable to any team integrating LLM code generation into their remediation workflow.

**Keywords:** LLM security, code generation, vulnerability patching, regression testing, CWE analysis

## Author Bio

**Rex Coleman** is the founder of Singularity Cybersecurity LLC, focused on AI security research spanning security OF AI systems and security FROM AI. Previously at FireEye/Mandiant. MS Computer Science, Georgia Tech (ML). Securing AI from the architecture up.
