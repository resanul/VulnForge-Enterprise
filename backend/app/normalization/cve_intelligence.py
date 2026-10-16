from typing import Dict, Any, Optional
from backend.app.normalization.schema import SeverityLevel

# Curated high-fidelity CVE intelligence feed for common network services, web servers, and operating systems
KNOWN_CVE_DATABASE: Dict[str, Dict[str, Any]] = {
    "CVE-2021-44228": {
        "title": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "severity": SeverityLevel.CRITICAL,
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-502",
        "description": "Apache Log4j2 versions 2.0-beta9 through 2.14.1 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        "remediation": "Upgrade Apache Log4j to version 2.17.1 or higher. Set log4j2.formatMsgNoLookups=true as temporary mitigation."
    },
    "CVE-2014-0160": {
        "title": "OpenSSL TLS Heartbeat Information Disclosure (Heartbleed)",
        "severity": SeverityLevel.HIGH,
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-125",
        "description": "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, allowing remote attackers to obtain sensitive information from memory.",
        "remediation": "Upgrade OpenSSL to version 1.0.1g or newer. Revoke and re-issue all SSL/TLS private keys and certificates."
    },
    "CVE-2017-0144": {
        "title": "Microsoft Windows SMBv1 Remote Code Execution (EternalBlue)",
        "severity": SeverityLevel.CRITICAL,
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-119",
        "description": "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via crafted packets (EternalBlue).",
        "remediation": "Apply Microsoft Security Update MS17-010. Disable SMBv1 across all systems."
    },
    "CVE-2023-44487": {
        "title": "HTTP/2 Rapid Reset Denial of Service",
        "severity": SeverityLevel.HIGH,
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "cwe": "CWE-400",
        "description": "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams rapidly.",
        "remediation": "Apply vendor patches for HTTP/2 servers (nginx, Apache, Envoy) or limit concurrent streams per connection."
    },
    "CVE-2021-34527": {
        "title": "Microsoft Windows Print Spooler Remote Code Execution (PrintNightmare)",
        "severity": SeverityLevel.CRITICAL,
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-269",
        "description": "Windows Print Spooler service improperly performs privileged file operations, allowing remote authenticated attackers to execute arbitrary code.",
        "remediation": "Apply Microsoft security update KB5004945 or disable the Print Spooler service on domain controllers."
    },
    "CVE-2024-3094": {
        "title": "XZ Utils Backdoor In liblzma",
        "severity": SeverityLevel.CRITICAL,
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-506",
        "description": "Malicious code was discovered in the upstream tarballs of xz utils version 5.6.0 and 5.6.1 that intercepts OpenSSH authentication.",
        "remediation": "Downgrade xz-utils to version 5.4.x or upgrade to clean vendor releases immediately."
    }
}

def enrich_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    return KNOWN_CVE_DATABASE.get(cve_id.upper())

def score_to_severity(score: float) -> SeverityLevel:
    if score >= 9.0:
        return SeverityLevel.CRITICAL
    elif score >= 7.0:
        return SeverityLevel.HIGH
    elif score >= 4.0:
        return SeverityLevel.MEDIUM
    elif score > 0.0:
        return SeverityLevel.LOW
    return SeverityLevel.INFO
