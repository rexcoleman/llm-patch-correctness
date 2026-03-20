# For: OpenClaw Discord

if your OpenClaw agent generates code patches — especially through coding skills — be careful with SQL injection fixes. they make things worse. tested Claude Haiku generating security patches across 5 CWE categories.

```
CWE category          fix rate   regression
CWE-327 (weak crypto)   100%       0%    ← safe to automate
CWE-120 (buffer overflow) 50%      0%
CWE-79  (XSS)            50%       0%
CWE-22  (path traversal)  10%      0%
CWE-89  (SQL injection)    0%     50%    ← makes it worse
```

the pattern: if the fix is a token-level swap (md5 → sha256), the LLM nails it. if it requires understanding data flow (parameterized queries for SQL injection), it fails and introduces NEW injection vectors. 50% regression means half the time your agent's "fix" creates a vulnerability that wasn't there before.

for OpenClaw agents with coding skills: you probably want tool policies that gate which CWE categories your agent is allowed to auto-patch. crypto fixes? let it rip. SQL injection? require human review.

results are deterministic at temp=0. variance is 100% between CWE categories, 0% between random seeds. so this isn't a sampling issue — the model fundamentally can't implement parameterized queries correctly in context even though it can describe them perfectly.

if you have a skill that runs agent-generated patches against a codebase, consider a CWE-aware policy in your config: auto-apply for token-swap fixes, block or flag for data-flow fixes.

anyone running auto-patching skills in OpenClaw? what's your review gate look like?
