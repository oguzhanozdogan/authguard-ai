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

   "Data Protection Failures": {
    "cwe": ["CWE-598", "CWE-311", "CWE-312", "CWE-319"],
    "description": "Weaknesses that expose sensitive information due to improper encryption, cleartext storage, insecure transmission, or unsafe use of URL parameters.",
    "mitigation": [
        "Encrypt sensitive data in transit using TLS",
        "Encrypt sensitive data at rest using strong cryptographic algorithms",
        "Avoid including sensitive data in URLs",
        "Implement proper key management"
        ]
    },
"Session Management Weaknesses": {
    "cwe": ["CWE-384", "CWE-614", "CWE-352"],
    "description": "Weaknesses in session handling and state management that may allow session hijacking, fixation, or unauthorized request execution.",
    "mitigation": [
        "Regenerate session IDs after authentication",
        "Set Secure, HttpOnly, and SameSite cookie attributes",
        "Implement anti-CSRF tokens",
        "Enforce HTTPS across the application"
    ]
},

   "Authentication and Resource Abuse": {
    "cwe": ["CWE-307", "CWE-770", "CWE-400"],
    "description": "Weaknesses that allow attackers to abuse authentication mechanisms or exhaust system resources through brute-force or denial-of-service techniques.",
    "mitigation": [
        "Implement rate limiting",
        "Use CAPTCHA where appropriate",
        "Apply account lockout policies",
        "Enforce resource usage quotas"
    ]
},

   "Logging and Monitoring Weaknesses": {
    "cwe": ["CWE-117"],
    "description": "Improper neutralization of user-controlled input in logs, allowing attackers to inject or manipulate log entries and undermine audit integrity.",
    "mitigation": [
        "Sanitize control characters before logging",
        "Use structured logging formats",
        "Implement parameterized logging",
        "Restrict logged data length and format"
    ]
}
}
