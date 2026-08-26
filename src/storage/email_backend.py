#!/usr/bin/env python3
"""
Email (SMTP) Backup Storage Backend

Sends encrypted configuration archive directly to user's email address as a secure attachment.
"""

import os
import smtplib
import hashlib
import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, List, Any

try:
    from .base_backend import BaseStorageBackend
except ImportError:
    from base_backend import BaseStorageBackend


class EmailStorageBackend(BaseStorageBackend):
    """Sends encrypted backup vault as an email attachment via SMTP."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.smtp_host = config.get('smtp_host', 'smtp.gmail.com')
        self.smtp_port = config.get('smtp_port', 587)
        self.use_tls = config.get('use_tls', True)
        self.use_ssl = config.get('use_ssl', False)
        self.username = config.get('smtp_username', '')
        self.password = config.get('smtp_password', '')
        self.recipient = config.get('recipient_email', self.username)
        self.sender = config.get('sender_email', self.username)

    def upload(self, local_file_path: Path, remote_filename: str = None) -> Dict[str, Any]:
        local_file = Path(local_file_path)
        if not local_file.exists():
            return {'success': False, 'error': f"File not found: {local_file}"}

        file_size_mb = local_file.stat().st_size / (1024 * 1024)
        if file_size_mb > 24.0:
            return {
                'success': False,
                'error': f"Archive size ({file_size_mb:.2f} MB) exceeds maximum standard email limit (24 MB)."
            }

        with open(local_file, 'rb') as f:
            file_bytes = f.read()

        file_sha256 = hashlib.sha256(file_bytes).hexdigest()
        now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        msg = EmailMessage()
        target_name = remote_filename or local_file.name
        msg['Subject'] = f"[Bootstrap Backup] System Vault - {now_str}"
        msg['From'] = self.sender
        msg['To'] = self.recipient

        body = f"""Encrypted System Configuration Vault Backup

Timestamp: {now_str}
Archive Name: {target_name}
File Size: {file_size_mb:.2f} MB ({len(file_bytes):,} bytes)
SHA256 (Ciphertext): {file_sha256}
Encryption: ChaCha20-Poly1305 + Argon2id AEAD

To restore this backup on a fresh system:
1. Download the attached '{target_name}' file
2. Run: python3 src/restore.py --backup-file {target_name}
3. Enter your master password when prompted.

Note: This archive is fully encrypted. Storage is considered untrusted.
"""
        msg.set_content(body)
        msg.add_attachment(
            file_bytes,
            maintype='application',
            subtype='octet-stream',
            filename=target_name
        )

        try:
            if self.use_ssl or self.smtp_port == 465:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=30)
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30)
                if self.use_tls:
                    server.starttls()

            if self.username and self.password:
                server.login(self.username, self.password)

            server.send_message(msg)
            server.quit()

            return {
                'success': True,
                'location': f"email://{self.recipient}",
                'size_bytes': len(file_bytes)
            }
        except Exception as e:
            return {'success': False, 'error': f"SMTP Email error: {e}"}

    def list_backups(self) -> List[Dict[str, Any]]:
        # Email backend is write-only / archive storage
        return []
