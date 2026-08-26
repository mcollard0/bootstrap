#!/usr/bin/env python3
"""
Email (SMTP) Backup Storage Backend

Sends encrypted configuration archive directly to user's email address as a secure attachment.
Supports automatic multi-part chunking/splitting if the vault exceeds standard email size limits.
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
    """Sends encrypted backup vault as an email attachment via SMTP, with automatic splitting."""

    # 20 MB max attachment size per message to stay well within provider limits (Gmail/Outlook 25MB)
    MAX_ATTACHMENT_BYTES = 20 * 1024 * 1024

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

    def _send_single_message(self, subject: str, body: str, attachment_bytes: bytes, attachment_name: str) -> None:
        """Connect to SMTP and dispatch a single message."""
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = self.sender
        msg['To'] = self.recipient
        msg.set_content(body)
        msg.add_attachment(
            attachment_bytes,
            maintype='application',
            subtype='octet-stream',
            filename=attachment_name
        )

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

    def upload(self, local_file_path: Path, remote_filename: str = None) -> Dict[str, Any]:
        local_file = Path(local_file_path)
        if not local_file.exists():
            return {'success': False, 'error': f"File not found: {local_file}"}

        if not self.recipient or not self.smtp_host:
            return {'success': False, 'error': "Missing SMTP host or recipient email address."}

        target_name = remote_filename or local_file.name
        file_bytes = local_file.read_bytes()
        file_size = len(file_bytes)
        file_sha256 = hashlib.sha256(file_bytes).hexdigest()
        now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Check if splitting is necessary
        if file_size <= self.MAX_ATTACHMENT_BYTES:
            # Single email
            subject = f"[Bootstrap Backup] System Vault - {target_name}"
            body = f"""Encrypted System Configuration Vault Backup

Timestamp: {now_str}
Vault File: {target_name}
Size: {file_size / (1024*1024):.2f} MB ({file_size:,} bytes)
SHA-256: {file_sha256}
Encryption: ChaCha20-Poly1305 + Argon2id / zstd

To restore this backup on a fresh system:
1. Download the attached '{target_name}' file
2. Run: python3 src/restore.py --vault {target_name}
3. Enter your master password when prompted.

Note: All contents are encrypted. Storage is considered untrusted.
"""
            try:
                self._send_single_message(subject, body, file_bytes, target_name)
                return {
                    'success': True,
                    'location': f"email://{self.recipient} (1 message)",
                    'size_bytes': file_size
                }
            except Exception as e:
                return {'success': False, 'error': f"SMTP error: {e}"}

        else:
            # Multi-part splitting
            chunks = []
            chunk_size = self.MAX_ATTACHMENT_BYTES
            for i in range(0, file_size, chunk_size):
                chunks.append(file_bytes[i:i + chunk_size])

            total_parts = len(chunks)
            print(f"      ℹ️  Vault size ({file_size / (1024*1024):.2f} MB) exceeds 20MB. Splitting into {total_parts} parts...")

            sent_count = 0
            for idx, chunk in enumerate(chunks, 1):
                part_name = f"{target_name}.part{idx:02d}"
                subject = f"[Bootstrap Backup Part {idx}/{total_parts}] System Vault - {target_name}"
                body = f"""Encrypted System Configuration Vault Backup (Part {idx} of {total_parts})

Timestamp: {now_str}
Original File: {target_name}
Part File: {part_name}
Part Size: {len(chunk) / (1024*1024):.2f} MB
Full Vault Size: {file_size / (1024*1024):.2f} MB
Full Vault SHA-256: {file_sha256}

REASSEMBLY INSTRUCTIONS:
1. Download all {total_parts} parts into the same folder
2. In terminal, run:
   cat {target_name}.part* > {target_name}
3. Verify with:
   sha256sum {target_name}   # Must match: {file_sha256}
4. Restore with:
   python3 src/restore.py --vault {target_name}
"""
                try:
                    self._send_single_message(subject, body, chunk, part_name)
                    sent_count += 1
                except Exception as e:
                    return {'success': False, 'error': f"Failed sending part {idx}/{total_parts}: {e}"}

            return {
                'success': True,
                'location': f"email://{self.recipient} ({sent_count} split messages)",
                'size_bytes': file_size
            }

    def list_backups(self) -> List[Dict[str, Any]]:
        return []
