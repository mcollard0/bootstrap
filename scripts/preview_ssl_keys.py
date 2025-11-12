#!/usr/bin/env python3
"""
Dry-run preview: Show what SSL keys would be added to encrypted secrets.
Does not modify any files.
"""

import json
import sys
import os
import subprocess

def main():
    print( "🔍 SSL Key Addition Preview (Dry Run)" );
    print( "=" * 50 );
    print();
    
    # Check current encrypted_secrets.json
    script_dir = os.path.dirname( os.path.abspath( __file__ ) );
    project_root = os.path.dirname( script_dir );
    secrets_file = os.path.join( project_root, 'data', 'encrypted_secrets.json' );
    
    try:
        with open( secrets_file, 'r' ) as f:
            current_secrets = json.load( f );
    except Exception as e:
        print( f"❌ Error reading {secrets_file}: {e}" );
        return 1;
    
    print( f"📊 Current state:" );
    print( f"   Version: {current_secrets.get('version')}" );
    print( f"   Encrypted data items: {current_secrets.get('total_items')}" );
    print( f"   Encrypted files: {current_secrets.get('total_files')}" );
    print();
    
    if 'encrypted_files' in current_secrets:
        print( f"📁 Currently encrypted files:" );
        for file_key in current_secrets['encrypted_files'].keys():
            file_data = current_secrets['encrypted_files'][file_key];
            print( f"   • {file_key} → {file_data.get('path', 'unknown')}" );
    print();
    
    # Scan for SSL keys
    ssl_private_dir = '/etc/ssl/private';
    print( f"🔍 Scanning {ssl_private_dir}..." );
    
    if not os.path.exists( ssl_private_dir ):
        print( f"   ⚠️  Directory not found: {ssl_private_dir}" );
        return 1;
    
    try:
        result = subprocess.run(
            ['sudo', 'ls', '-la', ssl_private_dir],
            capture_output=True, text=True
        );
        
        if result.returncode != 0:
            print( f"   ❌ Cannot access {ssl_private_dir} (requires sudo)" );
            return 1;
        
        print();
        print( "📂 Files in /etc/ssl/private/:" );
        print( result.stdout );
        
        # Parse key files
        key_files = [];
        for line in result.stdout.strip().split( '\n' ):
            parts = line.split();
            if len( parts ) >= 9 and parts[-1].endswith( '.key' ):
                filename = parts[-1];
                permissions = parts[0];
                size = parts[4];
                key_files.append( (filename, permissions, size) );
        
        if not key_files:
            print( "   ℹ️  No .key files found" );
            return 0;
        
        print();
        print( "🔐 SSL keys that would be added:" );
        print();
        
        new_files = [];
        skipped_files = [];
        existing_files = [];
        
        for filename, permissions, size in key_files:
            key_path = f"/etc/ssl/private/{filename}";
            
            # Check if already encrypted
            already_exists = False;
            if 'encrypted_files' in current_secrets:
                for existing_key, existing_data in current_secrets['encrypted_files'].items():
                    if existing_data.get( 'path' ) == key_path:
                        already_exists = True;
                        existing_files.append( (filename, key_path) );
                        break;
            
            # Skip snakeoil keys
            if 'snakeoil' in filename:
                skipped_files.append( (filename, key_path, 'default system key') );
                continue;
            
            if not already_exists:
                new_files.append( (filename, key_path, permissions, size) );
        
        if new_files:
            print( "✨ NEW files to be encrypted:" );
            for filename, path, perms, size in new_files:
                print( f"   ✓ {filename}" );
                print( f"     Path: {path}" );
                print( f"     Permissions: {perms}" );
                print( f"     Size: {size} bytes" );
                print( f"     Flags: ask=True, default=yes" );
                print();
        else:
            print( "   ℹ️  No new files to add" );
        
        if existing_files:
            print( "♻️  ALREADY encrypted (would be updated):" );
            for filename, path in existing_files:
                print( f"   • {filename} → {path}" );
            print();
        
        if skipped_files:
            print( "⏭️  SKIPPED files:" );
            for filename, path, reason in skipped_files:
                print( f"   • {filename} ({reason})" );
            print();
        
        # Summary
        print( "=" * 50 );
        print( "📈 Summary:" );
        print( f"   New files to add: {len(new_files)}" );
        print( f"   Existing files: {len(existing_files)}" );
        print( f"   Skipped files: {len(skipped_files)}" );
        print( f"   Total after operation: {current_secrets.get('total_files', 0) + len(new_files)}" );
        print();
        
        if new_files:
            print( "💡 To add these files, run:" );
            print( "   python3 scripts/add_secret.py --add-ssl-keys" );
        
    except Exception as e:
        print( f"❌ Error scanning SSL keys: {e}" );
        import traceback;
        traceback.print_exc();
        return 1;
    
    return 0;

if __name__ == '__main__':
    sys.exit( main() );
