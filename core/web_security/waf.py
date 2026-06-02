"""
AVOS AI - Web Application Firewall + Phishing URL Filter
SQLi/XSS pattern matching + Google Safe Browsing integration
"""

import logging
import re
import requests
from typing import Optional, Tuple

logger = logging.getLogger('AVOS.WAF')

# SQLi patterns
SQLI_PATTERNS = [
    r"(\bSELECT\b.+\bFROM\b)",
    r"(\bUNION\b.+\bSELECT\b)",
    r"(\bINSERT\b.+\bINTO\b)",
    r"(\bDROP\b.+\bTABLE\b)",
    r"(\bDELETE\b.+\bFROM\b)",
    r"(--\s*$)",
    r"(;\s*(SELECT|DROP|INSERT|UPDATE|DELETE))",
    r"(\bOR\b\s+['\"0-9].+=.+['\"0-9])",
    r"(\bAND\b\s+1\s*=\s*1)",
    r"(WAITFOR\s+DELAY)",
    r"(SLEEP\s*\(\s*\d+\s*\))",
    r"(xp_cmdshell)",
]

# XSS patterns
XSS_PATTERNS = [
    r"<script[\s>]",
    r"javascript\s*:",
    r"on\w+\s*=",          # onerror=, onclick=, etc.
    r"<iframe[\s>]",
    r"<object[\s>]",
    r"<embed[\s>]",
    r"document\.cookie",
    r"document\.write",
    r"eval\s*\(",
    r"atob\s*\(",
    r"String\.fromCharCode",
]

# Known phishing domains blocklist (offline base)
PHISHING_BLOCKLIST = {
    'phishing-test.com', 'malware.testing.google.test',
    'paypal-security-alert.com', 'apple-id-verify.net',
    'microsoft-support-urgent.com', 'amazon-order-update.ru',
}


class WAFEngine:
    """Web Application Firewall for SQLi/XSS detection and phishing URL filtering."""

    def __init__(self, safe_browsing_api_key: Optional[str] = None):
        self.api_key = safe_browsing_api_key
        self._sqli_re = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in SQLI_PATTERNS]
        self._xss_re  = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in XSS_PATTERNS]
        self._blocklist = set(PHISHING_BLOCKLIST)
        logger.info("WAF Engine initialized.")

    def inspect_payload(self, payload: str) -> Tuple[bool, str, str]:
        """
        Inspect HTTP payload for SQLi / XSS.
        Returns: (is_threat, threat_type, matched_pattern)
        """
        # SQLi check
        for pattern in self._sqli_re:
            m = pattern.search(payload)
            if m:
                logger.warning(f"SQLi detected: {m.group()[:80]}")
                return True, 'sqli', m.group()[:80]

        # XSS check
        for pattern in self._xss_re:
            m = pattern.search(payload)
            if m:
                logger.warning(f"XSS detected: {m.group()[:80]}")
                return True, 'xss', m.group()[:80]

        return False, '', ''

    def is_phishing_url(self, url: str) -> Tuple[bool, str]:
        """
        Check URL against local blocklist + Google Safe Browsing API.
        Returns: (is_phishing, reason)
        """
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().lstrip('www.')
        except Exception:
            domain = url.lower()

        # Local blocklist
        if domain in self._blocklist:
            return True, f"Domain {domain} is in local phishing blocklist"

        # Heuristic checks
        suspicious_keywords = ['paypa1', 'apple-id', 'secure-login', 'verify-account',
                                'account-suspended', 'unusual-activity', 'confirm-payment']
        for kw in suspicious_keywords:
            if kw in url.lower():
                return True, f"Phishing keyword detected in URL: {kw}"

        # Google Safe Browsing API (if key available)
        if self.api_key:
            result = self._check_safe_browsing(url)
            if result:
                return True, f"Google Safe Browsing: {result}"

        return False, ''

    def _check_safe_browsing(self, url: str) -> Optional[str]:
        """Query Google Safe Browsing API."""
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        payload = {
            "client": {"clientId": "avos_ai", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["WINDOWS"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        try:
            response = requests.post(api_url, json=payload, timeout=3)
            data = response.json()
            if data.get('matches'):
                return data['matches'][0].get('threatType', 'PHISHING')
        except Exception:
            pass
        return None

    def add_to_blocklist(self, domain: str):
        self._blocklist.add(domain.lower())
        logger.info(f"Added to phishing blocklist: {domain}")

    def remove_from_blocklist(self, domain: str):
        self._blocklist.discard(domain.lower())
