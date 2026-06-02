"""
AVOS AI - Dark Web Monitor
HIBP breach alert integration + email monitoring
"""

import asyncio
import hashlib
import logging
import time
from typing import List

import requests

logger = logging.getLogger('AVOS.DarkWeb')

HIBP_API = "https://haveibeenpwned.com/api/v3"
POLL_INTERVAL_H = 24  # Check every 24 hours


class DarkWebMonitor:
    """
    Monitors for credential breaches using the HaveIBeenPwned (HIBP) API.
    Stores results locally. No dark-web crawling — safe and legal.
    """

    def __init__(self, db_manager=None):
        self._db = db_manager
        self._monitored_emails: List[str] = []
        self._api_key: str = ""  # HIBP requires API key for /breachedaccount endpoint
        self._running = False

    def add_email(self, email: str):
        if email not in self._monitored_emails:
            self._monitored_emails.append(email)
            logger.info(f"Dark Web Monitor: watching {email}")

    def set_api_key(self, key: str):
        self._api_key = key

    async def start_monitor(self):
        self._running = True
        logger.info("Dark Web Monitor started.")
        while self._running:
            try:
                await asyncio.to_thread(self._check_all_emails)
            except Exception as e:
                logger.error(f"Dark web monitor error: {e}")
            await asyncio.sleep(POLL_INTERVAL_H * 3600)

    def _check_all_emails(self):
        for email in self._monitored_emails:
            breaches = self._check_hibp(email)
            for breach in breaches:
                logger.warning(f"Breach found for {email}: {breach.get('Name')}")
                if self._db:
                    self._db.upsert_breach_alert(
                        email=email,
                        source=breach.get('Name', 'Unknown'),
                        date=breach.get('BreachDate', ''),
                        data_types=', '.join(breach.get('DataClasses', []))
                    )

    def _check_hibp(self, email: str) -> list:
        """Query HIBP API for breaches. Requires API key."""
        if not self._api_key:
            # Use the free password check (k-anonymity) as demo
            return self._check_password_pwned_demo()

        try:
            headers = {
                'hibp-api-key': self._api_key,
                'User-Agent': 'AVOS-AI-Monitor'
            }
            url = f"{HIBP_API}/breachedaccount/{email}?truncateResponse=false"
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return []  # No breaches
            else:
                logger.warning(f"HIBP API status {response.status_code} for {email}")
                return []
        except Exception as e:
            logger.error(f"HIBP API error: {e}")
            return []

    def _check_password_pwned_demo(self) -> list:
        """Demonstrate k-anonymity password check (no email, just SHA1 prefix lookup)."""
        return []  # Placeholder for demo

    def check_password_pwned(self, password: str) -> int:
        """
        Check if a password has been seen in breaches (k-anonymity model).
        Returns count of times seen (0 = not found).
        """
        try:
            sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1[:5]
            suffix = sha1[5:]

            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=5
            )
            if response.status_code == 200:
                for line in response.text.splitlines():
                    h, count = line.split(':')
                    if h == suffix:
                        return int(count)
            return 0
        except Exception:
            return -1  # Error

    def get_alerts(self) -> list:
        if self._db:
            return self._db.get_breach_alerts()
        return []
