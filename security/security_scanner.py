import re


def scan_code(code):
    findings = []

    patterns = {
        "API Key": r"(api[_-]?key|apikey)\s*[:=]\s*['\"][^'\"]+['\"]",
        "Password": r"(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]+['\"]",
        "Secret": r"(secret|secret[_-]?key)\s*[:=]\s*['\"][^'\"]+['\"]",
        "Token": r"(token|access[_-]?token)\s*[:=]\s*['\"][^'\"]+['\"]",
    }

    for name, pattern in patterns.items():
        if re.search(pattern, code, re.IGNORECASE):
            findings.append({
                "type": name,
                "severity": "high",
                "message": f"Possible hardcoded {name.lower()} detected"
            })

    return findings