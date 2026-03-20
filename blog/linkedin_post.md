# LinkedIn Post — LLM Patch Correctness

I tested Claude Haiku generating security patches for 50 vulnerable code snippets across 5 CWE types.

Overall: 42% fix rate, 10% regression rate.

But the averages hide the real story:

CWE-327 (weak crypto): 100% fix, 0% regression — AI perfectly replaces md5 with sha256.
CWE-89 (SQL injection): 0% fix, 50% REGRESSION — AI makes SQL injection WORSE.

The pattern: if the fix is a token-level swap, AI works. If it requires understanding data flow, AI fails.

Practical takeaway for security teams using AI coding assistants:
- Trust AI for crypto upgrades
- Review AI patches for XSS and buffer overflow (50% fix rate)
- Never trust AI for SQL injection or path traversal patches

Which vulnerability types are you comfortable letting AI patch? Which aren't you?

#AISecurity #CodeGeneration #VulnerabilityManagement #LLMSecurity #SQLInjection

---

> First comment: "Full CWE-stratified analysis: [blog URL]"
