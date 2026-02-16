# taxonomy.py

TAXONOMY = {

    "Injection": {
        "cwe": ["CWE-89", "CWE-90", "CWE-943"],
        "description": "Injection vulnerabilities caused by improper input handling.",
        "mitigation": [
            "Use parameterized queries",
            "Apply prepared statements",
            "Use ORM frameworks"
        ]
    },

    "Sensitive Data Exposure": {
        "cwe": ["CWE-598"],
        "description": "Exposure of sensitive information through insecure channels.",
        "mitigation": [
            "Use POST instead of GET",
            "Encrypt transport with TLS",
            "Avoid URL parameters for credentials"
        ]
    },

    "Authentication Abuse": {
        "cwe": ["CWE-307", "CWE-770", "CWE-400"],
        "description": "Weaknesses enabling brute-force and denial-of-service attacks.",
        "mitigation": [
            "Implement rate limiting",
            "Use CAPTCHA",
            "Apply account lockout policies"
        ]
    }
}
