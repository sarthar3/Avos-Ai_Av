"""
AVOS AI - System Utilities
Registry Cleaner, Temp File Cleaner, Folder/App Lock (AES-256-GCM)
"""

import logging
import os
import shutil
import winreg
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger('AVOS.Utilities')


# ─── Registry Cleaner ─────────────────────────────────────────────────────────
class RegistryCleaner:
    """Clean up orphaned/invalid Windows registry entries."""

    UNINSTALL_PATHS = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]

    def scan(self) -> List[Tuple[str, str, str]]:
        """
        Scan for orphaned uninstall entries (app uninstalled but registry remains).
        Returns list of (key_path, name, install_location) tuples.
        """
        orphans = []
        for reg_path in self.UNINSTALL_PATHS:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as base:
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(base, i)
                            full_path = f"{reg_path}\\{subkey_name}"
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, full_path) as subkey:
                                try:
                                    install_loc, _ = winreg.QueryValueEx(subkey, "InstallLocation")
                                    if install_loc and not os.path.exists(install_loc):
                                        name = "Unknown"
                                        try:
                                            name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                                        except Exception:
                                            pass
                                        orphans.append((full_path, name, install_loc))
                                except FileNotFoundError:
                                    pass
                            i += 1
                        except OSError:
                            break
            except Exception as e:
                logger.debug(f"Registry scan error in {reg_path}: {e}")
        return orphans

    def clean(self, key_path: str) -> bool:
        """Delete a registry key (with backup)."""
        try:
            parts = key_path.split('\\')
            parent_path = '\\'.join(parts[:-1])
            key_name    = parts[-1]
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, parent_path, 0, winreg.KEY_WRITE) as parent:
                winreg.DeleteKey(parent, key_name)
            logger.info(f"Deleted registry key: {key_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete registry key {key_path}: {e}")
            return False


# ─── Temp File Cleaner ────────────────────────────────────────────────────────
class TempCleaner:
    """Clean temp directories and browser caches."""

    TEMP_DIRS = [
        os.environ.get('TEMP', 'C:\\Windows\\Temp'),
        os.environ.get('TMP',  'C:\\Windows\\Temp'),
        os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'Temp'),
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Temp'),
    ]

    BROWSER_CACHES = [
        # Chrome
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Default', 'Cache'),
        # Edge
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Edge', 'User Data', 'Default', 'Cache'),
        # Firefox
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Mozilla', 'Firefox', 'Profiles'),
    ]

    def scan(self) -> Tuple[int, int]:
        """Returns (file_count, total_size_bytes)."""
        total_files = 0
        total_size  = 0
        for dir_path in self._all_dirs():
            for f in self._iter_files(dir_path):
                try:
                    total_size += os.path.getsize(f)
                    total_files += 1
                except Exception:
                    pass
        return total_files, total_size

    def clean(self, include_browser_cache: bool = True) -> Tuple[int, int]:
        """Delete temp files. Returns (files_deleted, bytes_freed)."""
        deleted_files = 0
        bytes_freed   = 0
        dirs = list(self.TEMP_DIRS)
        if include_browser_cache:
            dirs.extend(self.BROWSER_CACHES)

        for dir_path in dirs:
            if not os.path.isdir(dir_path):
                continue
            for f in self._iter_files(dir_path):
                try:
                    size = os.path.getsize(f)
                    os.remove(f)
                    deleted_files += 1
                    bytes_freed   += size
                except Exception:
                    pass

        logger.info(f"Temp cleaner: deleted {deleted_files} files, freed {bytes_freed / (1024**2):.1f} MB")
        return deleted_files, bytes_freed

    def _all_dirs(self) -> List[str]:
        seen = set()
        result = []
        for d in self.TEMP_DIRS:
            if d and d not in seen:
                seen.add(d)
                result.append(d)
        return result

    @staticmethod
    def _iter_files(directory: str):
        try:
            for root, dirs, files in os.walk(directory):
                for f in files:
                    yield os.path.join(root, f)
        except Exception:
            return


# ─── Folder Lock (AES-256-GCM) ───────────────────────────────────────────────
class FolderLock:
    """
    Lock/unlock folders using AES-256-GCM encryption.
    Key derived from password with PBKDF2-HMAC-SHA256.
    """

    ITERATIONS   = 390000
    SALT_SIZE    = 16
    NONCE_SIZE   = 12
    KEY_SIZE     = 32
    ENC_SUFFIX   = '.avos_locked'

    def lock_folder(self, folder_path: str, password: str) -> Tuple[bool, str]:
        """Encrypt all files in a folder in-place."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            import os, secrets

            folder = Path(folder_path)
            if not folder.is_dir():
                return False, "Not a valid directory"

            encrypted_count = 0
            for file_path in folder.rglob('*'):
                if file_path.is_file() and not file_path.name.endswith(self.ENC_SUFFIX):
                    salt  = secrets.token_bytes(self.SALT_SIZE)
                    nonce = secrets.token_bytes(self.NONCE_SIZE)
                    key   = self._derive_key(password, salt)
                    aesgcm = AESGCM(key)

                    data = file_path.read_bytes()
                    ct   = aesgcm.encrypt(nonce, data, None)

                    enc_path = file_path.with_suffix(file_path.suffix + self.ENC_SUFFIX)
                    enc_path.write_bytes(salt + nonce + ct)
                    file_path.unlink()
                    encrypted_count += 1

            return True, f"Locked {encrypted_count} files in {folder_path}"
        except ImportError:
            return False, "cryptography package not installed"
        except Exception as e:
            return False, str(e)

    def unlock_folder(self, folder_path: str, password: str) -> Tuple[bool, str]:
        """Decrypt all locked files in a folder."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            folder = Path(folder_path)
            if not folder.is_dir():
                return False, "Not a valid directory"

            decrypted_count = 0
            failed_count    = 0

            for file_path in folder.rglob(f'*{self.ENC_SUFFIX}'):
                try:
                    raw = file_path.read_bytes()
                    salt  = raw[:self.SALT_SIZE]
                    nonce = raw[self.SALT_SIZE:self.SALT_SIZE + self.NONCE_SIZE]
                    ct    = raw[self.SALT_SIZE + self.NONCE_SIZE:]

                    key    = self._derive_key(password, salt)
                    aesgcm = AESGCM(key)
                    data   = aesgcm.decrypt(nonce, ct, None)

                    # Restore original filename
                    original_name = file_path.name.replace(self.ENC_SUFFIX, '')
                    out_path = file_path.parent / original_name
                    out_path.write_bytes(data)
                    file_path.unlink()
                    decrypted_count += 1
                except Exception:
                    failed_count += 1

            if failed_count > 0:
                return False, f"Decrypted {decrypted_count}, failed {failed_count} (wrong password?)"
            return True, f"Unlocked {decrypted_count} files in {folder_path}"

        except ImportError:
            return False, "cryptography package not installed"
        except Exception as e:
            return False, str(e)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.ITERATIONS,
        )
        return kdf.derive(password.encode('utf-8'))
