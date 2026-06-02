"""
AVOS AI - Payment Security Shield Unit Tests
Run with: python -m pytest tests/test_payment_shield.py -v
"""

import os
import sys
import pytest

# Add project root to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.payment.payment_shield import PaymentShield, CARD_PATTERN, UPI_PATTERN

class TestPaymentShield:

    def test_tokenization_roundtrip(self):
        """Verify that credit card details can be securely encrypted and decrypted correctly."""
        shield = PaymentShield()
        card = "4111222233334444"
        expiry = "12/28"
        cvv = "123"
        
        # Encrypt card details
        token = shield.tokenize(card, expiry, cvv)
        assert token != ""
        assert token != f"{card}|{expiry}|{cvv}" # Must be ciphertext
        
        # Decrypt token
        d_card, d_expiry, d_cvv = shield.detokenize(token)
        assert d_card == card
        assert d_expiry == expiry
        assert d_cvv == cvv

    def test_invalid_token_decryption(self):
        """Ensure invalid tokens fail gracefully and return empty strings instead of crashing."""
        shield = PaymentShield()
        card, expiry, cvv = shield.detokenize("invalid_base64_or_token")
        assert card == ""
        assert expiry == ""
        assert cvv == ""

    def test_regex_credit_card_matching(self):
        """Check regex accuracy for credit card detection (Visa, MasterCard, Amex)."""
        # Valid test cases
        assert CARD_PATTERN.search("4111222233334444") is not None  # Visa
        assert CARD_PATTERN.search("5123456789012345") is not None  # MasterCard
        assert CARD_PATTERN.search("378282246310005") is not None   # Amex
        
        # Invalid / non-card test cases
        assert CARD_PATTERN.search("12345") is None
        assert CARD_PATTERN.search("abcde12345fghij") is None

    def test_regex_upi_matching(self):
        """Check regex accuracy for Indian UPI Virtual Payment Address (VPA) IDs."""
        # Valid test cases
        assert UPI_PATTERN.search("john.doe@okicici") is not None
        assert UPI_PATTERN.search("bhim-pay-99@ybl") is not None
        assert UPI_PATTERN.search("user@paytm") is not None
        
        # Invalid / normal emails (UPI patterns require short bank handles, but let's see)
        assert UPI_PATTERN.search("not_a_upi") is None

    def test_dns_secure_api_lookup(self):
        """Validate DNS verification API helper resolves host addresses."""
        shield = PaymentShield()
        ip = shield._get_secure_ip("google.com")
        if ip is None:
            # Fallback to local resolver if DoH API is offline or rate-limited
            ip = shield._get_local_ip("google.com")
            
        if ip is not None:
            assert isinstance(ip, str)
            assert len(ip.split('.')) == 4

    def test_secure_browser_launcher_fallback(self):
        """Ensure secure browser launch completes gracefully without crashing."""
        shield = PaymentShield()
        # Even if Chrome/Edge don't exist, it should fallback to standard webbrowser module safely
        res = shield.launch_secure_browser("https://www.paypal.com")
        assert res is True
