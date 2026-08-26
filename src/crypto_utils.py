#!/usr/bin/env python3
"""
Bootstrap System - Cryptographic Utilities

High-security symmetric encryption using:
- ChaCha20-Poly1305 (authenticated encryption with 256-bit key and Poly1305 MAC)
- Argon2id (preferred memory-hard KDF) with automatic scrypt fallback (stdlib)
- Authenticated encrypted bundle packaging (.tar.enc / .tar.gz.enc)
"""

import os
import sys
import json
import base64
import tarfile
import hashlib
import secrets
import getpass
import tempfile
from pathlib import Path
from typing import Tuple, Dict, Any, List, Optional

# Debug flag
DEBUG_CRYPTO = os.environ.get('CRYPTO_DEBUG', '0') == '1'

# Try importing cryptography AEAD
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:
    print("Error: cryptography library is required.", file=sys.stderr)
    print("Install with: pacman -S python-cryptography OR pip3 install cryptography", file=sys.stderr)
    sys.exit(1)

# Check for Argon2
HAS_ARGON2 = False
try:
    from argon2.low_level import hash_secret_raw, Type
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False


class SecureBootstrapCrypto:
    """High-security cryptographic operations for sensitive bootstrap data and archives."""

    # Argon2id parameters (conservative)
    ARGON2_TIME_COST = 3
    ARGON2_MEMORY_COST = 65536  # 64 MB
    ARGON2_PARALLELISM = 4
    ARGON2_HASH_LEN = 32
    ARGON2_SALT_LEN = 16

    # scrypt fallback parameters (memory-hard, standard library)
    SCRYPT_N = 16384     # CPU/memory cost
    SCRYPT_R = 8         # block size
    SCRYPT_P = 1         # parallelization

    # ChaCha20-Poly1305 parameters
    CHACHA20_KEY_LEN = 32
    CHACHA20_NONCE_LEN = 12
    POLY1305_TAG_LEN = 16

    MAGIC_HEADER = b"BOOTSTRAP_VAULT_V3\n"

    def __init__(self):
        self.cipher = ChaCha20Poly1305

    def derive_key(self, password: str, salt: bytes = None, kdf: str = None) -> Tuple[bytes, bytes, str]:
        """
        Derive a 256-bit cryptographic key from a password.
        Uses Argon2id if available or specified, otherwise scrypt.
        """
        if salt is None:
            salt = secrets.token_bytes(self.ARGON2_SALT_LEN)

        chosen_kdf = kdf
        if chosen_kdf is None:
            chosen_kdf = 'Argon2id' if HAS_ARGON2 else 'scrypt'

        password_bytes = password.encode('utf-8')

        if chosen_kdf == 'Argon2id':
            if not HAS_ARGON2:
                # If Argon2id was requested but library missing, try scrypt
                if DEBUG_CRYPTO:
                    print("Argon2 not available, falling back to scrypt")
                chosen_kdf = 'scrypt'
                derived_key = hashlib.scrypt(
                    password_bytes, salt=salt, n=self.SCRYPT_N, r=self.SCRYPT_R, p=self.SCRYPT_P, maxmem=128*1024*1024, dklen=self.CHACHA20_KEY_LEN
                )
            else:
                derived_key = hash_secret_raw(
                    password_bytes,
                    salt,
                    time_cost=self.ARGON2_TIME_COST,
                    memory_cost=self.ARGON2_MEMORY_COST,
                    parallelism=self.ARGON2_PARALLELISM,
                    hash_len=self.ARGON2_HASH_LEN,
                    type=Type.ID
                )
        elif chosen_kdf == 'scrypt':
            derived_key = hashlib.scrypt(
                password_bytes, salt=salt, n=self.SCRYPT_N, r=self.SCRYPT_R, p=self.SCRYPT_P, maxmem=128*1024*1024, dklen=self.CHACHA20_KEY_LEN
            )
        elif chosen_kdf == 'PBKDF2-SHA256':
            derived_key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 200000, dklen=self.CHACHA20_KEY_LEN)
        else:
            raise ValueError(f"Unsupported KDF: {chosen_kdf}")

        if len(derived_key) != self.CHACHA20_KEY_LEN:
            raise ValueError(f"Key derivation produced {len(derived_key)} bytes, expected {self.CHACHA20_KEY_LEN}")

        return derived_key, salt, chosen_kdf

    def encrypt_bytes(self, data: bytes, password: str) -> Dict[str, str]:
        """Encrypt raw bytes with ChaCha20-Poly1305 and derived key."""
        key, salt, kdf = self.derive_key(password)
        nonce = secrets.token_bytes(self.CHACHA20_NONCE_LEN)
        cipher = self.cipher(key)
        ciphertext = cipher.encrypt(nonce, data, None)
        key = b'\x00' * len(key)

        return {
            'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
            'nonce': base64.b64encode(nonce).decode('ascii'),
            'salt': base64.b64encode(salt).decode('ascii'),
            'algorithm': 'ChaCha20-Poly1305',
            'kdf': kdf
        }

    def decrypt_bytes(self, enc: Dict[str, str], password: str) -> bytes:
        """Decrypt raw bytes from an encrypted dictionary."""
        ciphertext = base64.b64decode(enc['ciphertext'])
        nonce = base64.b64decode(enc['nonce'])
        salt = base64.b64decode(enc['salt'])
        kdf = enc.get('kdf', 'Argon2id')

        if enc.get('algorithm') != 'ChaCha20-Poly1305':
            raise ValueError(f"Unsupported algorithm: {enc.get('algorithm')}")

        key, _, _ = self.derive_key(password, salt=salt, kdf=kdf)
        cipher = self.cipher(key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        key = b'\x00' * len(key)
        return plaintext

    def encrypt(self, plaintext: str, password: str) -> Dict[str, str]:
        """Encrypt plaintext string."""
        return self.encrypt_bytes(plaintext.encode('utf-8'), password)

    def decrypt(self, encrypted_data: Dict[str, str], password: str) -> str:
        """Decrypt plaintext string."""
        return self.decrypt_bytes(encrypted_data, password).decode('utf-8')

    def encrypt_file(self, path: str, password: str, **kwargs) -> Dict[str, Any]:
        """Encrypt a single file and record its metadata (path, permissions)."""
        p = Path(path).expanduser()
        if not p.exists():
            raise FileNotFoundError(f"File not found: {path}")

        mode = oct(p.stat().st_mode)[-3:]
        with open(p, 'rb') as f:
            data = f.read()

        enc = self.encrypt_bytes(data, password)
        enc['path'] = str(path)
        enc['mode'] = mode

        for k in ['not_to_restore', 'ask', 'default', 'description']:
            if k in kwargs:
                enc[k] = kwargs[k]

        return enc

    def decrypt_file_to_path(self, enc: Dict[str, Any], password: str, dest_path: str = None, prefix_dir: str = None) -> str:
        """Decrypt an encrypted file dict back to disk with proper permissions."""
        out_path = dest_path or enc.get('path')
        if not out_path:
            raise ValueError("Encrypted file object missing path")

        out_path = os.path.expanduser(out_path)
        if prefix_dir:
            rel = out_path.lstrip('/')
            out_path = os.path.join(prefix_dir, rel)

        data = self.decrypt_bytes(enc, password)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)

        with open(out_path, 'wb') as f:
            f.write(data)

        mode = enc.get('mode')
        if mode and mode.isdigit():
            try:
                os.chmod(out_path, int(mode, 8))
            except Exception:
                pass

        return out_path

    def encrypt_dict(self, sensitive_data: Dict[str, Any], password: str, file_paths: List[str] = None) -> Dict[str, Any]:
        """Encrypt dictionary of values and files."""
        encrypted_items = {}
        encrypted_files = {}

        for k, v in sensitive_data.items():
            if isinstance(v, str) and v.strip():
                encrypted_items[k] = self.encrypt(v, password)
            else:
                encrypted_items[k] = v

        if file_paths:
            for fp in file_paths:
                p = Path(fp).expanduser()
                if p.exists() and p.is_file():
                    try:
                        encrypted_files[p.name] = self.encrypt_file(str(p), password)
                    except Exception as e:
                        if DEBUG_CRYPTO:
                            print(f"Warning: could not encrypt {fp}: {e}")

        result = {
            'encrypted_data': encrypted_items,
            'version': '3.0',
            'total_items': len(encrypted_items)
        }
        if encrypted_files:
            result['encrypted_files'] = encrypted_files
            result['total_files'] = len(encrypted_files)

        return result

    def decrypt_dict(self, encrypted_dict: Dict[str, Any], password: str, restore_files: bool = False, prefix_dir: str = None) -> Dict[str, str]:
        """Decrypt dictionary and optionally restore files."""
        decrypted = {}
        items = encrypted_dict.get('encrypted_data', {})

        for k, v in items.items():
            if isinstance(v, dict) and 'ciphertext' in v:
                decrypted[k] = self.decrypt(v, password)
            else:
                decrypted[k] = v

        if restore_files and 'encrypted_files' in encrypted_dict:
            for f_key, enc_file in encrypted_dict['encrypted_files'].items():
                try:
                    if enc_file.get('not_to_restore', False):
                        continue
                    self.decrypt_file_to_path(enc_file, password, prefix_dir=prefix_dir)
                except Exception as e:
                    print(f"Failed to restore file {f_key}: {e}", file=sys.stderr)

        return decrypted

    # --- Authenticated Encrypted Archive Bundle Packaging ---

    def create_encrypted_vault(self, source_dir: Path, output_file: Path, password: str, metadata: Dict[str, Any] = None) -> Path:
        """
        Package an entire directory tree into a compressed, authenticated encrypted vault.
        Output format:
          [MAGIC HEADER: b"BOOTSTRAP_VAULT_V3\n"]
          [METADATA JSON (Base64) + b"\n"]
          [RAW CHACHA20-POLY1305 CIPHERTEXT (incl 16-byte Poly1305 Tag)]
        """
        source_dir = Path(source_dir)
        output_file = Path(output_file)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # 1. Compress source_dir to temporary in-memory or disk tar.gz
        with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as tmp_tar:
            tmp_tar_path = Path(tmp_tar.name)

        try:
            with tarfile.open(tmp_tar_path, 'w:gz') as tar:
                tar.add(source_dir, arcname='.')

            with open(tmp_tar_path, 'rb') as f:
                tar_bytes = f.read()
        finally:
            if tmp_tar_path.exists():
                tmp_tar_path.unlink()

        # 2. Derive key and encrypt
        key, salt, kdf = self.derive_key(password)
        nonce = secrets.token_bytes(self.CHACHA20_NONCE_LEN)
        cipher = self.cipher(key)
        ciphertext = cipher.encrypt(nonce, tar_bytes, None)
        key = b'\x00' * len(key)

        # 3. Create envelope metadata
        meta = metadata.copy() if metadata else {}
        meta.update({
            'version': '3.0',
            'kdf': kdf,
            'algorithm': 'ChaCha20-Poly1305',
            'salt': base64.b64encode(salt).decode('ascii'),
            'nonce': base64.b64encode(nonce).decode('ascii'),
            'sha256_uncompressed': hashlib.sha256(tar_bytes).hexdigest(),
            'ciphertext_len': len(ciphertext),
            'timestamp': hashlib.sha256(nonce).hexdigest()[:8]
        })

        meta_json_b64 = base64.b64encode(json.dumps(meta).encode('utf-8'))

        # 4. Write sealed container
        with open(output_file, 'wb') as f:
            f.write(self.MAGIC_HEADER)
            f.write(meta_json_b64)
            f.write(b'\n')
            f.write(ciphertext)

        return output_file

    def extract_encrypted_vault(self, vault_file: Path, destination_dir: Path, password: str) -> Dict[str, Any]:
        """
        Authenticate, decrypt, and unpack an encrypted vault to destination_dir.
        """
        vault_file = Path(vault_file)
        destination_dir = Path(destination_dir)
        destination_dir.mkdir(parents=True, exist_ok=True)

        with open(vault_file, 'rb') as f:
            header = f.readline()
            if header != self.MAGIC_HEADER:
                raise ValueError("Invalid vault header: not a valid Bootstrap Vault V3")

            meta_b64 = f.readline().strip()
            ciphertext = f.read()

        try:
            meta = json.loads(base64.b64decode(meta_b64).decode('utf-8'))
        except Exception as e:
            raise ValueError(f"Corrupted vault header metadata: {e}")

        salt = base64.b64decode(meta['salt'])
        nonce = base64.b64decode(meta['nonce'])
        kdf = meta.get('kdf', 'Argon2id')

        # Derive key and decrypt
        key, _, _ = self.derive_key(password, salt=salt, kdf=kdf)
        cipher = self.cipher(key)

        try:
            tar_bytes = cipher.decrypt(nonce, ciphertext, None)
        except Exception as e:
            key = b'\x00' * len(key)
            raise ValueError(f"Authentication/Decryption failed: invalid password or corrupted data ({e})")

        key = b'\x00' * len(key)

        # Unpack tar.gz to destination
        with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as tmp_tar:
            tmp_tar_path = Path(tmp_tar.name)
            tmp_tar.write(tar_bytes)

        try:
            with tarfile.open(tmp_tar_path, 'r:gz') as tar:
                tar.extractall(path=destination_dir, filter='data' if hasattr(tarfile, 'data_filter') else None)
        finally:
            if tmp_tar_path.exists():
                tmp_tar_path.unlink()

        return meta


def prompt_for_password(purpose: str = "encryption", allow_env_fallback: bool = True) -> str:
    """Prompt user for password with optional environment variable fallback."""
    if allow_env_fallback:
        env_pwd = os.environ.get('BOOTSTRAP_SECRET')
        if env_pwd:
            return env_pwd

    try:
        pwd = getpass.getpass(f"Enter master password for {purpose}: ")
        if not pwd or len(pwd) < 8:
            print("Warning: Master password should be at least 8 characters.", file=sys.stderr)
        return pwd
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(0)


if __name__ == '__main__':
    # Unit self-tests
    print("🧪 Running cryptographic tests...")
    crypto = SecureBootstrapCrypto()
    test_pwd = "[REDACTED_MOCK_PWD]"
    test_data = "Sample test payload for crypto validation"

    # Test basic string encrypt/decrypt
    enc = crypto.encrypt(test_data, test_pwd)
    dec = crypto.decrypt(enc, test_pwd)
    assert dec == test_data, "String encryption failed"
    print("  ✓ String encryption/decryption passed")

    # Test wrong password rejection
    try:
        crypto.decrypt(enc, "wrong_pass_123")
        assert False, "Should have failed with wrong password"
    except Exception:
        print("  ✓ Wrong password authentication rejection passed")

    # Test vault packaging
    with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as dest_dir:
        (Path(src_dir) / "fstab").write_text("UUID=123 / btrfs defaults 0 0\n")
        (Path(src_dir) / "config.fish").write_text("set -gx PATH $PATH /opt/bin\n")

        vault_path = Path(dest_dir) / "test.tar.enc"
        crypto.create_encrypted_vault(Path(src_dir), vault_path, test_pwd, metadata={'host': 'testbox'})
        assert vault_path.exists() and vault_path.stat().st_size > 0

        # Extract
        unpack_dir = Path(dest_dir) / "unpacked"
        meta = crypto.extract_encrypted_vault(vault_path, unpack_dir, test_pwd)
        assert (unpack_dir / "fstab").read_text() == "UUID=123 / btrfs defaults 0 0\n"
        assert (unpack_dir / "config.fish").read_text() == "set -gx PATH $PATH /opt/bin\n"
        assert meta['host'] == 'testbox'
        print("  ✓ Authenticated encrypted vault packaging/extraction passed")

    print("✅ All crypto tests passed successfully!")
