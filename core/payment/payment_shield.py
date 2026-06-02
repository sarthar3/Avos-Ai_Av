"""
AVOS AI - Payment Security Shield
Provides real-time clipboard protection, DNS poisoning checks, Card tokenization,
and secure sandbox browser isolation for banking transactions.
"""

import asyncio
import logging
import os
import re
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from cryptography.fernet import Fernet

logger = logging.getLogger('AVOS.PaymentShield')

# Financial patterns to monitor
CARD_PATTERN = re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b')
CVV_PATTERN = re.compile(r'\b\d{3,4}\b')
UPI_PATTERN = re.compile(r'\b[\w\.\-]+@[a-zA-Z]{2,}\b')

MONITORED_DOMAINS = [
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "paytm.com", "phonepe.com", "paypal.com", "razorpay.com"
]

class PaymentShield:
    """Tier 5 (Elite) Payment Protection Engine."""

    def __init__(self, db_manager=None, event_bus=None):
        self.db = db_manager
        self.event_bus = event_bus
        self.running = False
        
        # Tokenizer key - load from vault or generate new one
        self.key = self._load_or_generate_key()
        self.cipher = Fernet(self.key)
        
        # Clipboard state
        self._last_clipboard = ""
        self._clipboard_wiped_at = 0.0

    def _load_or_generate_key(self) -> bytes:
        """Load encryption key from vault or generate and store a new one."""
        if self.db:
            try:
                # Try to load existing key from vault
                key_data = self.db.get_vault_key('payment_tokenizer_key')
                if key_data:
                    logger.info("Loaded existing payment tokenizer key from vault.")
                    return key_data.encode() if isinstance(key_data, str) else key_data
            except Exception as e:
                logger.warning(f"Could not load key from vault: {e}")
        
        # Generate new key and store it
        new_key = Fernet.generate_key()
        if self.db:
            try:
                self.db.store_vault_key('payment_tokenizer_key', new_key.decode())
                logger.info("Generated and stored new payment tokenizer key in vault.")
            except Exception as e:
                logger.error(f"Could not store key in vault: {e}")
        else:
            logger.warning("No database manager - key will not persist across restarts!")
        
        return new_key

    async def start_monitor(self, event_bus=None):
        """Starts background tasks for clipboard and DNS monitoring."""
        if event_bus:
            self.event_bus = event_bus
            
        self.running = True
        logger.info("Payment Security Shield background monitors started.")
        
        # Run monitors concurrently
        await asyncio.gather(
            self._clipboard_monitor_loop(),
            self._dns_monitor_loop(),
            return_exceptions=True
        )

    async def stop(self):
        self.running = False
        logger.info("Payment Security Shield stopped.")

    # ─── Clipboard Guard ──────────────────────────────────────────────────────
    async def _clipboard_monitor_loop(self):
        """Monitor system clipboard for sensitive credit card or UPI details."""
        while self.running:
            try:
                text = self._read_clipboard()
                if text and text != self._last_clipboard:
                    self._last_clipboard = text
                    await self._inspect_clipboard_text(text)
            except Exception as e:
                logger.debug(f"Clipboard read error: {e}")
            await asyncio.sleep(3.0)  # Optimized: reduced polling frequency for better performance

    def _read_clipboard(self) -> str:
        """Reads unicode text from Windows clipboard safely."""
        try:
            import win32clipboard
            win32clipboard.OpenClipboard()
            try:
                if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                    return win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
            finally:
                win32clipboard.CloseClipboard()
        except ImportError:
            pass  # Fallback for non-windows / missing pywin32
        except Exception:
            pass
        return ""

    def wipe_clipboard(self):
        """Wipes the system clipboard instantly."""
        try:
            import win32clipboard
            win32clipboard.OpenClipboard()
            try:
                win32clipboard.EmptyClipboard()
            finally:
                win32clipboard.CloseClipboard()
            self._last_clipboard = ""
            logger.info("Clipboard securely wiped.")
        except Exception as e:
            logger.error(f"Failed to wipe clipboard: {e}")

    async def _inspect_clipboard_text(self, text: str):
        """Inspect copied text and alert if card or UPI data is found."""
        card_match = CARD_PATTERN.search(text)
        upi_match = UPI_PATTERN.search(text)
        
        if card_match or upi_match:
            threat_type = "card_leak" if card_match else "upi_leak"
            leaked_val = card_match.group(0) if card_match else upi_match.group(0)
            masked = leaked_val[:4] + "*" * (len(leaked_val) - 6) + leaked_val[-2:] if len(leaked_val) > 6 else "***"
            
            explanation = (
                f"Sensitive financial data ({'Credit Card' if card_match else 'UPI ID'}) "
                f"was copied to the clipboard: {masked}. This exposes you to clipboard-sniffing spyware."
            )
            
            logger.warning(f"Payment Shield Alert: {explanation}")
            
            # Wipe clipboard automatically for safety
            self.wipe_clipboard()
            
            if self.event_bus:
                await self.event_bus.put({
                    'event_type': 'payment_threat',
                    'pid': None,
                    'details': {
                        'type': threat_type,
                        'masked': masked,
                        'explanation': explanation
                    }
                })

    # ─── DNS Spoofing Protection ──────────────────────────────────────────────
    async def _dns_monitor_loop(self):
        """Verify banking domain DNS health periodically."""
        while self.running:
            for domain in MONITORED_DOMAINS:
                if not self.running:
                    break
                await self.verify_domain_dns(domain)
                await asyncio.sleep(15)  # Throttle lookup intervals
            await asyncio.sleep(60)

    async def verify_domain_dns(self, domain: str) -> bool:
        """Compares local DNS resolution against secure Cloudflare DNS over HTTPS."""
        try:
            # 1. Local Lookup
            local_ip = await asyncio.to_thread(self._get_local_ip, domain)
            if not local_ip:
                return True # Domain currently offline/unreachable locally, skip
                
            # 2. Secure Public Lookup via DNS-over-HTTPS (DoH)
            secure_ip = await asyncio.to_thread(self._get_secure_ip, domain)
            
            if secure_ip and local_ip != secure_ip:
                explanation = (
                    f"DNS spoofing/poisoning detected for bank: {domain}! "
                    f"Local IP resolved to {local_ip}, but secure Cloudflare DNS resolved to {secure_ip}."
                )
                logger.error(f"DNS HIJACK ALERT: {explanation}")
                
                if self.event_bus:
                    await self.event_bus.put({
                        'event_type': 'payment_threat',
                        'pid': None,
                        'details': {
                            'type': 'dns_poisoning',
                            'domain': domain,
                            'local_ip': local_ip,
                            'secure_ip': secure_ip,
                            'explanation': explanation
                        }
                    })
                return False
        except Exception as e:
            logger.debug(f"DNS verify error for {domain}: {e}")
        return True

    def _get_local_ip(self, domain: str) -> Optional[str]:
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    def _get_secure_ip(self, domain: str) -> Optional[str]:
        """Fetch true IP using standard Google DNS HTTP API."""
        try:
            import requests
            url = f"https://dns.google/resolve?name={domain}&type=A"
            res = requests.get(url, timeout=3.0)
            if res.status_code == 200:
                data = res.json()
                if "Answer" in data:
                    for ans in data["Answer"]:
                        if ans.get("type") == 1: # A record
                            return ans.get("data")
        except Exception:
            pass
        return None

    # ─── Card Tokenization Engine ─────────────────────────────────────────────
    def tokenize(self, card_number: str, expiry: str, cvv: str) -> str:
        """Securely encrypts card details, returning a safe high-entropy token."""
        raw_payload = f"{card_number}|{expiry}|{cvv}".encode('utf-8')
        encrypted = self.cipher.encrypt(raw_payload)
        return encrypted.decode('utf-8')

    def detokenize(self, token: str) -> Tuple[str, str, str]:
        """Decrypts a token back into raw card details."""
        try:
            decrypted = self.cipher.decrypt(token.encode('utf-8'))
            parts = decrypted.decode('utf-8').split('|')
            if len(parts) == 3:
                return parts[0], parts[1], parts[2]
        except Exception:
            pass
        return "", "", ""

    # ─── Isolated Browser Launcher ─────────────────────────────────────────────
    def launch_secure_browser(self, target_url: str = "https://www.paypal.com") -> bool:
        """Launches an isolated browser instance with extensions and caching disabled."""
        browsers = [
            (r"C:\Program Files\Google\Chrome\Application\chrome.exe", ["--incognito", "--disable-extensions"]),
            (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", ["--inprivate", "--disable-extensions"]),
            (r"C:\Program Files\Mozilla Firefox\firefox.exe", ["-private-window"]),
        ]
        
        # Check standard installation locations
        for exe_path, flags in browsers:
            if os.path.exists(exe_path):
                # Create a temporary empty user profile directory
                temp_profile = Path(tempfile.gettempdir()) / f"avos_secure_profile_{int(time.time())}"
                temp_profile.mkdir(parents=True, exist_ok=True)
                
                cmd = [exe_path] + flags
                if "chrome" in exe_path.lower() or "msedge" in exe_path.lower():
                    cmd.append(f"--user-data-dir={temp_profile}")
                cmd.append(target_url)
                
                try:
                    subprocess.Popen(cmd)
                    logger.info(f"Launched secure browser using: {exe_path}")
                    return True
                except Exception as e:
                    logger.error(f"Failed to spawn secure browser process: {e}")
                    
        # Fallback to default system browser in private mode if possible
        try:
            import webbrowser
            webbrowser.open(target_url)
            logger.warning("No secure isolated browser executable found. Fell back to default browser.")
            return True
        except Exception:
            return False
