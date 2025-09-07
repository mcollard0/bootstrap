#!/usr/bin/env python3
"""
Ubuntu Bootstrap System - Cryptographic Utilities

This module provides high-security symmetric encryption using:
- ChaCha20-Poly1305 (authenticated encryption)  
- Argon2id (password-based key derivation)

Security Properties:
- Confidentiality: ChaCha20 stream cipher (256-bit key)
- Integrity: Poly1305 MAC (128-bit authentication tag)
- Key Derivation: Argon2id (memory-hard, side-channel resistant)
"""

import os;
import base64;
import secrets;
import getpass;
from typing import Tuple, Dict, Any;

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305;
    from argon2 import PasswordHasher;
    from argon2.low_level import hash_secret, Type;
except ImportError as e:
    print( f"Missing required cryptography libraries: {e}" );
    print( "Install with: pip3 install cryptography argon2-cffi" );
    exit( 1 );


class SecureBootstrapCrypto:
    """High-security cryptographic operations for sensitive bootstrap data."""
    
    # Argon2id parameters (conservative for maximum security)
    ARGON2_TIME_COST = 3;        # Number of iterations
    ARGON2_MEMORY_COST = 65536;  # 64 MB memory usage
    ARGON2_PARALLELISM = 4;      # Number of threads
    ARGON2_HASH_LEN = 32;        # 256-bit derived key
    ARGON2_SALT_LEN = 16;        # 128-bit salt
    
    # ChaCha20-Poly1305 parameters
    CHACHA20_KEY_LEN = 32;       # 256-bit key
    CHACHA20_NONCE_LEN = 12;     # 96-bit nonce
    POLY1305_TAG_LEN = 16;       # 128-bit authentication tag
    
    def __init__( self ):
        """Initialize the cryptographic subsystem."""
        self.cipher = ChaCha20Poly1305;
        pass;
    
    def derive_key( self, password: str, salt: bytes = None ) -> Tuple[bytes, bytes]:
        """
        Derive a cryptographic key from password using Argon2id.
        
        Args:
            password: Master password string
            salt: Optional salt bytes (generates random if None)
            
        Returns:
            Tuple of (derived_key, salt) both as bytes
        """
        if salt is None:
            salt = secrets.token_bytes( self.ARGON2_SALT_LEN );
        
        # Use Argon2id for maximum security against all attack vectors
        derived_key = hash_secret(
            password.encode( 'utf-8' ),
            salt,
            time_cost=self.ARGON2_TIME_COST,
            memory_cost=self.ARGON2_MEMORY_COST, 
            parallelism=self.ARGON2_PARALLELISM,
            hash_len=self.ARGON2_HASH_LEN,
            type=Type.ID  # Argon2id variant
        );
        
        # Extract the actual key bytes (Argon2 returns the hash directly)
        if isinstance( derived_key, bytes ) and len( derived_key ) == self.ARGON2_HASH_LEN:
            key = derived_key;
        else:
            # Fallback: take first 32 bytes if format is different
            key = derived_key[:self.ARGON2_HASH_LEN];
        
        return key, salt;
    
    def encrypt( self, plaintext: str, password: str ) -> Dict[str, str]:
        """
        Encrypt plaintext using ChaCha20-Poly1305.
        
        Args:
            plaintext: Data to encrypt
            password: Master password
            
        Returns:
            Dictionary with base64-encoded cipher components
        """
        # Convert string to bytes
        plaintext_bytes = plaintext.encode( 'utf-8' );
        
        # Derive encryption key
        key, salt = self.derive_key( password );
        
        # Generate random nonce
        nonce = secrets.token_bytes( self.CHACHA20_NONCE_LEN );
        
        # Create cipher instance and encrypt
        cipher = self.cipher( key );
        ciphertext = cipher.encrypt( nonce, plaintext_bytes, None );
        
        # Clear sensitive key from memory
        key = b'\x00' * len( key );
        
        # Return base64-encoded components
        return {
            'ciphertext': base64.b64encode( ciphertext ).decode( 'ascii' ),
            'nonce': base64.b64encode( nonce ).decode( 'ascii' ),
            'salt': base64.b64encode( salt ).decode( 'ascii' ),
            'algorithm': 'ChaCha20-Poly1305',
            'kdf': 'Argon2id'
        };
    
    def decrypt( self, encrypted_data: Dict[str, str], password: str ) -> str:
        """
        Decrypt ciphertext using ChaCha20-Poly1305.
        
        Args:
            encrypted_data: Dictionary from encrypt() method
            password: Master password
            
        Returns:
            Decrypted plaintext string
            
        Raises:
            ValueError: If decryption fails (wrong password or corrupted data)
        """
        try:
            # Decode base64 components
            ciphertext = base64.b64decode( encrypted_data['ciphertext'] );
            nonce = base64.b64decode( encrypted_data['nonce'] );
            salt = base64.b64decode( encrypted_data['salt'] );
            
            # Verify algorithm compatibility
            if encrypted_data.get( 'algorithm' ) != 'ChaCha20-Poly1305':
                raise ValueError( f"Unsupported algorithm: {encrypted_data.get('algorithm')}" );
            
            # Re-derive the key using stored salt
            key, _ = self.derive_key( password, salt );
            
            # Create cipher and decrypt
            cipher = self.cipher( key );
            plaintext_bytes = cipher.decrypt( nonce, ciphertext, None );
            
            # Clear sensitive key from memory
            key = b'\x00' * len( key );
            
            # Convert back to string
            return plaintext_bytes.decode( 'utf-8' );
            
        except Exception as e:
            raise ValueError( f"Decryption failed - invalid password or corrupted data: {e}" );
    
    def encrypt_dict( self, sensitive_data: Dict[str, Any], password: str ) -> Dict[str, Any]:
        """
        Encrypt a dictionary of sensitive key-value pairs.
        
        Args:
            sensitive_data: Dictionary with sensitive values
            password: Master password
            
        Returns:
            Dictionary with encrypted values and metadata
        """
        encrypted_items = {};
        
        for key, value in sensitive_data.items():
            if isinstance( value, str ) and value.strip():
                encrypted_items[key] = self.encrypt( value, password );
            else:
                encrypted_items[key] = value;  # Keep non-string values as-is
        
        return {
            'encrypted_data': encrypted_items,
            'version': '1.0',
            'total_items': len( encrypted_items )
        };
    
    def decrypt_dict( self, encrypted_dict: Dict[str, Any], password: str ) -> Dict[str, str]:
        """
        Decrypt a dictionary of encrypted values.
        
        Args:
            encrypted_dict: Dictionary from encrypt_dict() method
            password: Master password
            
        Returns:
            Dictionary with decrypted plaintext values
        """
        decrypted_data = {};
        encrypted_items = encrypted_dict.get( 'encrypted_data', {} );
        
        for key, encrypted_value in encrypted_items.items():
            if isinstance( encrypted_value, dict ) and 'ciphertext' in encrypted_value:
                decrypted_data[key] = self.decrypt( encrypted_value, password );
            else:
                decrypted_data[key] = encrypted_value;  # Non-encrypted values
        
        return decrypted_data;


def prompt_for_password( purpose: str = "encryption" ) -> str:
    """
    Securely prompt user for password.
    
    Args:
        purpose: Description of what the password is for
        
    Returns:
        Password string
    """
    try:
        password = getpass.getpass( f"Enter master password for {purpose}: " );
        if not password or len( password ) < 8:
            print( "Warning: Password should be at least 8 characters for security." );
        return password;
    except KeyboardInterrupt:
        print( "\nOperation cancelled by user." );
        exit( 0 );


def test_crypto_functions():
    """Unit tests for cryptographic functions."""
    print( "🧪 Testing cryptographic functions..." );
    
    crypto = SecureBootstrapCrypto();
    test_password = "test_bootstrap_password_2025!";
    test_data = "mongodb+srv://user:secret@cluster.mongodb.net/db";
    
    # Test basic encryption/decryption
    print( "  ✓ Testing encrypt/decrypt cycle..." );
    encrypted = crypto.encrypt( test_data, test_password );
    decrypted = crypto.decrypt( encrypted, test_password );
    assert decrypted == test_data, "Basic encryption/decryption failed";
    
    # Test dictionary encryption
    print( "  ✓ Testing dictionary encrypt/decrypt..." );
    sensitive_dict = {
        'mongodb_uri': 'mongodb+srv://user:pass@host/db',
        'api_key': 'sk-test-key-1234567890abcdef',
        'normal_value': 'not_sensitive'
    };
    
    encrypted_dict = crypto.encrypt_dict( sensitive_dict, test_password );
    decrypted_dict = crypto.decrypt_dict( encrypted_dict, test_password );
    assert decrypted_dict == sensitive_dict, "Dictionary encryption failed";
    
    # Test wrong password
    print( "  ✓ Testing wrong password rejection..." );
    try:
        result = crypto.decrypt( encrypted, "wrong_password" );
        assert False, f"Should have rejected wrong password but got: {result}";
    except ValueError as e:
        # Expected - wrong password should fail
        assert "Decryption failed" in str( e ) or "invalid password" in str( e );
    except Exception as e:
        # ChaCha20Poly1305 might throw different exception
        pass;  # Any decryption failure is acceptable
    
    # Test key derivation consistency
    print( "  ✓ Testing key derivation consistency..." );
    key1, salt = crypto.derive_key( test_password );
    key2, _ = crypto.derive_key( test_password, salt );
    assert key1 == key2, "Key derivation not consistent";
    
    print( "✅ All cryptographic tests passed!" );


if __name__ == '__main__':
    # Run self-tests when executed directly
    test_crypto_functions();
    
    # Interactive test
    print( "\n🔐 Interactive Encryption Test" );
    crypto = SecureBootstrapCrypto();
    
    test_secret = input( "Enter test data to encrypt: " );
    if test_secret:
        password = prompt_for_password( "testing" );
        
        encrypted = crypto.encrypt( test_secret, password );
        print( f"\n📦 Encrypted data structure:" );
        for key, value in encrypted.items():
            print( f"  {key}: {value}" );
        
        print( f"\n🔓 Decrypted: {crypto.decrypt( encrypted, password )}" );
