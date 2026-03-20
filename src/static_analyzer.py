"""Simple static analysis for detecting common vulnerability patterns.

Uses regex-based pattern matching as a lightweight alternative to semgrep/bandit.
Detects: SQL injection, XSS, buffer overflow patterns, path traversal, weak crypto.
"""
import re


VULN_PATTERNS = {
    "CWE-89": {  # SQL Injection
        "name": "SQL Injection",
        "patterns": [
            r'execute\s*\(\s*["\'].*%s',  # String formatting in SQL
            r'execute\s*\(\s*f["\']',  # f-string in SQL
            r'execute\s*\(\s*["\'].*\+',  # String concatenation in SQL
            r'cursor\.execute\s*\(\s*["\'].*\{',  # Format string in SQL
            r'query\s*=\s*["\'].*%',  # SQL with % formatting
        ],
        "safe_patterns": [
            r'execute\s*\(.*,\s*[\(\[]',  # Parameterized query
            r'execute\s*\(.*%s.*,\s*\(',  # Parameterized with tuple
        ]
    },
    "CWE-79": {  # XSS
        "name": "Cross-Site Scripting",
        "patterns": [
            r'innerHTML\s*=',  # Direct innerHTML assignment
            r'document\.write\s*\(',  # document.write
            r'\.html\s*\(\s*[^)]*\+',  # jQuery .html() with concatenation
            r'render_template_string\s*\(',  # Flask template injection
        ],
        "safe_patterns": [
            r'escape\s*\(', r'sanitize\s*\(', r'encode\s*\(',
            r'textContent\s*=',  # Safe text assignment
        ]
    },
    "CWE-120": {  # Buffer Overflow
        "name": "Buffer Overflow",
        "patterns": [
            r'strcpy\s*\(', r'strcat\s*\(', r'gets\s*\(',
            r'sprintf\s*\(',
        ],
        "safe_patterns": [
            r'strncpy\s*\(', r'strncat\s*\(', r'snprintf\s*\(',
            r'fgets\s*\(',
        ]
    },
    "CWE-22": {  # Path Traversal
        "name": "Path Traversal",
        "patterns": [
            r'open\s*\(\s*[^)]*\+',  # open() with concatenation
            r'os\.path\.join\s*\(\s*[^)]*request',  # join with user input
        ],
        "safe_patterns": [
            r'os\.path\.abspath', r'os\.path\.realpath',
            r'pathlib.*resolve',
        ]
    },
    "CWE-327": {  # Weak Crypto
        "name": "Insecure Cryptography",
        "patterns": [
            r'MD5\s*\(', r'SHA1\s*\(', r'DES\s*\.',
            r'hashlib\.md5', r'hashlib\.sha1',
            r'AES\.new\s*\([^)]*MODE_ECB',
        ],
        "safe_patterns": [
            r'SHA256\s*\(', r'SHA512\s*\(', r'AES\.new\s*\([^)]*MODE_GCM',
            r'hashlib\.sha256', r'bcrypt',
        ]
    }
}


def analyze_code(code, target_cwe=None):
    """Analyze code for vulnerability patterns.

    Returns:
        dict with 'vulnerabilities' (list of found issues),
        'safe_patterns' (list of safe patterns found),
        'vuln_count', 'safe_count'
    """
    vulns = []
    safe = []

    cwes_to_check = [target_cwe] if target_cwe else VULN_PATTERNS.keys()

    for cwe_id in cwes_to_check:
        if cwe_id not in VULN_PATTERNS:
            continue
        info = VULN_PATTERNS[cwe_id]

        for pattern in info["patterns"]:
            matches = re.findall(pattern, code, re.IGNORECASE)
            for match in matches:
                vulns.append({
                    "cwe_id": cwe_id,
                    "cwe_name": info["name"],
                    "pattern": pattern,
                    "match": match if isinstance(match, str) else str(match),
                })

        for pattern in info.get("safe_patterns", []):
            if re.search(pattern, code, re.IGNORECASE):
                safe.append({
                    "cwe_id": cwe_id,
                    "pattern": pattern,
                })

    return {
        "vulnerabilities": vulns,
        "safe_patterns": safe,
        "vuln_count": len(vulns),
        "safe_count": len(safe),
    }


def check_regression(original_code, patched_code, target_cwe):
    """Check if a patch introduces NEW vulnerabilities.

    Returns:
        dict with 'target_fixed' (bool), 'regressions' (list), 'regression_count'
    """
    # Check all CWEs, not just the target
    original_vulns = analyze_code(original_code)
    patched_vulns = analyze_code(patched_code)

    # Target fixed?
    original_target = analyze_code(original_code, target_cwe)
    patched_target = analyze_code(patched_code, target_cwe)
    target_fixed = patched_target["vuln_count"] < original_target["vuln_count"]

    # New vulnerabilities?
    original_cwe_set = {(v["cwe_id"], v["pattern"]) for v in original_vulns["vulnerabilities"]}
    patched_cwe_set = {(v["cwe_id"], v["pattern"]) for v in patched_vulns["vulnerabilities"]}
    new_vulns = patched_cwe_set - original_cwe_set

    regressions = [{"cwe_id": cwe, "pattern": pat} for cwe, pat in new_vulns]

    return {
        "target_fixed": target_fixed,
        "regressions": regressions,
        "regression_count": len(regressions),
        "original_vuln_count": original_vulns["vuln_count"],
        "patched_vuln_count": patched_vulns["vuln_count"],
    }
