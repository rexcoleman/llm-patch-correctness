"""LLM patch generator — asks Claude Haiku to fix vulnerable code snippets."""
import anthropic


def generate_patch(client, vulnerable_code, cwe_id, cwe_name, prompt_level="guided", seed=42):
    """Generate a security patch using Claude Haiku.

    Args:
        client: Anthropic client
        vulnerable_code: str, the vulnerable code snippet
        cwe_id: str, e.g. "CWE-89"
        cwe_name: str, e.g. "SQL Injection"
        prompt_level: 'minimal', 'cwe_desc', or 'guided'
        seed: unused (temperature=0 for determinism)

    Returns: dict with 'patched_code', 'explanation'
    """
    if prompt_level == "minimal":
        prompt = f"Fix the security vulnerability in this code. Return only the fixed code.\n\n```\n{vulnerable_code}\n```"
    elif prompt_level == "cwe_desc":
        prompt = f"This code has a {cwe_name} ({cwe_id}) vulnerability. Fix it. Return only the fixed code.\n\n```\n{vulnerable_code}\n```"
    else:  # guided
        prompt = f"""This code has a {cwe_name} ({cwe_id}) vulnerability.

Fix the vulnerability by applying the standard remediation for {cwe_id}:
- For SQL Injection: use parameterized queries
- For XSS: sanitize/encode output
- For Buffer Overflow: add bounds checking
- For Path Traversal: validate/canonicalize paths
- For Insecure Crypto: use modern algorithms (AES-256, SHA-256+)

Return ONLY the fixed code, no explanation.

Vulnerable code:
```
{vulnerable_code}
```"""

    resp = client.messages.create(
        model="claude-3-haiku-20240307",
        max_tokens=1000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}],
    )

    text = resp.content[0].text
    # Extract code from response (may be in code block)
    if "```" in text:
        parts = text.split("```")
        if len(parts) >= 3:
            code = parts[1]
            # Strip language identifier
            if code.startswith(("python", "java", "c", "php", "js")):
                code = code.split("\n", 1)[1] if "\n" in code else code
            return {"patched_code": code.strip(), "raw_response": text}
    return {"patched_code": text.strip(), "raw_response": text}
