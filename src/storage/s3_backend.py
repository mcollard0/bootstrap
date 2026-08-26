#!/usr/bin/env python3
"""
AWS S3 & S3-Compatible Storage Backend

Supports:
- AWS S3
- Cloudflare R2
- Wasabi
- Backblaze B2
- MinIO / Custom S3 endpoints
Uses boto3 if available, or lightweight native SigV4 HTTP client.
"""

import os
import hmac
import hashlib
import datetime
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Any

try:
    from .base_backend import BaseStorageBackend
except ImportError:
    from base_backend import BaseStorageBackend


class S3StorageBackend(BaseStorageBackend):
    """Stores encrypted backup archives in an S3 or S3-compatible bucket."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.bucket = config.get('bucket_name', '')
        self.access_key = config.get('access_key_id', '')
        self.secret_key = config.get('secret_access_key', '')
        self.region = config.get('region_name', 'us-east-1')
        self.endpoint_url = config.get('endpoint_url')  # For R2, Wasabi, MinIO
        self.prefix = config.get('prefix', 'bootstrap-backups/').strip('/')
        if self.prefix:
            self.prefix += '/'

    def upload(self, local_file_path: Path, remote_filename: str = None) -> Dict[str, Any]:
        local_file = Path(local_file_path)
        if not local_file.exists():
            return {'success': False, 'error': f"File not found: {local_file}"}

        target_name = remote_filename or local_file.name
        s3_key = f"{self.prefix}{target_name}"

        # Try using boto3 first if installed
        try:
            import boto3
            from botocore.config import Config
            s3_client = boto3.client(
                's3',
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region,
                endpoint_url=self.endpoint_url,
                config=Config(signature_version='s3v4')
            )
            s3_client.upload_file(str(local_file), self.bucket, s3_key)
            self.cleanup_old_backups()
            return {
                'success': True,
                'location': f"s3://{self.bucket}/{s3_key}",
                'size_bytes': local_file.stat().st_size
            }
        except ImportError:
            # Native SigV4 fallback
            return self._upload_native_sigv4(local_file, s3_key)
        except Exception as e:
            return {'success': False, 'error': f"S3 upload error: {e}"}

    def _upload_native_sigv4(self, local_file: Path, s3_key: str) -> Dict[str, Any]:
        """Direct REST upload with AWS Signature Version 4 without boto3."""
        if not self.access_key or not self.secret_key or not self.bucket:
            return {'success': False, 'error': "Missing S3 credentials or bucket name"}

        with open(local_file, 'rb') as f:
            payload_data = f.read()

        payload_hash = hashlib.sha256(payload_data).hexdigest()
        now = datetime.datetime.now(datetime.timezone.utc)
        amz_date = now.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = now.strftime('%Y%m%d')

        if self.endpoint_url:
            host = self.endpoint_url.replace('https://', '').replace('http://', '').strip('/')
            url = f"{self.endpoint_url.rstrip('/')}/{self.bucket}/{s3_key}"
        else:
            host = f"{self.bucket}.s3.{self.region}.amazonaws.com"
            url = f"https://{host}/{s3_key}"

        canonical_uri = f"/{s3_key}" if not self.endpoint_url else f"/{self.bucket}/{s3_key}"
        canonical_querystring = ""
        canonical_headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
        signed_headers = "host;x-amz-content-sha256;x-amz-date"
        canonical_request = f"PUT\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = f"{date_stamp}/{self.region}/s3/aws4_request"
        string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

        def sign(key, msg):
            return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

        k_date = sign(('AWS4' + self.secret_key).encode('utf-8'), date_stamp)
        k_region = sign(k_date, self.region)
        k_service = sign(k_region, 's3')
        k_signing = sign(k_service, 'aws4_request')
        signature = hmac.new(k_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

        authorization_header = f"{algorithm} Credential={self.access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

        req = urllib.request.Request(url, data=payload_data, method='PUT')
        req.add_header('Host', host)
        req.add_header('x-amz-date', amz_date)
        req.add_header('x-amz-content-sha256', payload_hash)
        req.add_header('Authorization', authorization_header)
        req.add_header('Content-Length', str(len(payload_data)))

        try:
            with urllib.request.urlopen(req) as resp:
                if resp.status in (200, 201, 204):
                    return {
                        'success': True,
                        'location': f"s3://{self.bucket}/{s3_key}",
                        'size_bytes': len(payload_data)
                    }
                return {'success': False, 'error': f"HTTP {resp.status}"}
        except urllib.error.HTTPError as e:
            return {'success': False, 'error': f"HTTP Error {e.code}: {e.read().decode('utf-8', errors='ignore')}"}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def list_backups(self) -> List[Dict[str, Any]]:
        # If boto3 available
        try:
            import boto3
            from botocore.config import Config
            s3_client = boto3.client(
                's3',
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region,
                endpoint_url=self.endpoint_url,
                config=Config(signature_version='s3v4')
            )
            res = s3_client.list_objects_v2(Bucket=self.bucket, Prefix=self.prefix)
            backups = []
            for item in res.get('Contents', []):
                backups.append({
                    'name': item['Key'].replace(self.prefix, ''),
                    'key': item['Key'],
                    'size': item['Size'],
                    'mtime': item['LastModified'].timestamp()
                })
            backups.sort(key=lambda x: x['mtime'], reverse=True)
            return backups
        except Exception:
            return []

    def cleanup_old_backups(self) -> int:
        try:
            import boto3
            from botocore.config import Config
            backups = self.list_backups()
            if len(backups) <= self.retention_count:
                return 0

            to_remove = backups[self.retention_count:]
            s3_client = boto3.client(
                's3',
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region,
                endpoint_url=self.endpoint_url,
                config=Config(signature_version='s3v4')
            )
            delete_keys = [{'Key': item['key']} for item in to_remove]
            s3_client.delete_objects(Bucket=self.bucket, Delete={'Objects': delete_keys})
            return len(delete_keys)
        except Exception:
            return 0
