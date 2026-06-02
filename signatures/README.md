# AVOS Signature Database

This directory contains malware signature definitions for fast hash-based and pattern-based detection.

## Signature Types

### 1. Hash Signatures (SHA256/MD5)
Stored in SQLite database (`logs/avos.db`) for fast lookup:
- Known malware file hashes
- Updated from threat intelligence feeds
- ~1 million signatures loaded

### 2. YARA Rules
Pattern-based detection rules in `rules.yar`:
```yara
rule Ransomware_Generic {
    meta:
        description = "Generic ransomware indicators"
        severity = "CRITICAL"
    strings:
        $s1 = "encrypted" nocase
        $s2 = "bitcoin" nocase
        $s3 = ".locked" nocase
    condition:
        2 of them
}
```

## File Structure

```
signatures/
├── rules.yar           # Main YARA ruleset
├── custom_rules.yar    # User-defined rules
└── README.md          # This file
```

## Adding Custom Signatures

### Hash Signature
```bash
python -m core.db.db_manager --add-signature \
    --sha256 <hash> \
    --name "Trojan.CustomMalware" \
    --severity CRITICAL
```

### YARA Rule
Edit `custom_rules.yar`:
```yara
rule MyCustomRule {
    meta:
        author = "Security Team"
        date = "2026-06-02"
    strings:
        $pattern = { 4D 5A 90 00 }
    condition:
        $pattern at 0
}
```

## Signature Updates

Automatic updates via Intelligence Updater:
- Checks every 6 hours
- Downloads from threat feeds (VirusTotal, MISP, etc.)
- Validates signatures before loading
- Rollback on errors

Manual update:
```bash
python -m core.ai.update_engine --update-signatures
```

## Performance

- **Hash lookup**: O(1), < 1ms
- **YARA scan**: ~5ms per file (depends on ruleset size)
- **Memory usage**: ~100MB for full signature database

## Sources

Signatures aggregated from:
- VirusTotal
- Malware Bazaar
- MISP Threat Sharing
- Custom threat intelligence
- Community submissions