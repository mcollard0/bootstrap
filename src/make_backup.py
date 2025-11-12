#!/usr/bin/env python3
"""
Ubuntu Bootstrap System - Backup Management

This module manages automated backups of code files with rotation policies.
Follows user preferences for backup naming and retention limits.
"""

import os;
import shutil;
import datetime;
from pathlib import Path;
from typing import List, Dict, Tuple;


class BootstrapBackupManager:
    """Manages backup creation and rotation for bootstrap project files."""
    
    def __init__( self, project_root: str = None ):
        """
        Initialize backup manager.
        
        Args:
            project_root: Root directory of bootstrap project
        """
        if project_root is None:
            current_dir = Path( __file__ ).parent;
            self.project_root = current_dir.parent;
        else:
            self.project_root = Path( project_root );
        
        self.backup_dir = self.project_root / 'backup';
        self.backup_dir.mkdir( exist_ok=True );
        
        # Backup limits per user rules
        self.max_backups_small = 50;  # Files under 150KB
        self.max_backups_large = 25;  # Files 150KB and above
        self.size_threshold = 150 * 1024;  # 150KB in bytes
        
        print( f"💾 Backup Manager initialized" );
        print( f"   Project root: {self.project_root}" );
        print( f"   Backup directory: {self.backup_dir}" );
    
    def get_file_size( self, file_path: Path ) -> int:
        """Get file size in bytes."""
        try:
            return file_path.stat().st_size;
        except FileNotFoundError:
            return 0;
    
    def generate_backup_filename( self, original_file: Path ) -> str:
        """
        Generate backup filename with ISO-8601 date format.
        Format: {name}.{iso-8601-date}.{ext}
        
        Args:
            original_file: Path to original file
            
        Returns:
            Backup filename string
        """
        timestamp = datetime.datetime.now().strftime( '%Y%m%d' );
        
        # Split filename into parts
        name_parts = original_file.name.split( '.' );
        
        if len( name_parts ) == 1:
            # No extension
            backup_name = f"{name_parts[0]}.{timestamp}";
        else:
            # Has extension
            name = '.'.join( name_parts[:-1] );
            extension = name_parts[-1];
            backup_name = f"{name}.{timestamp}.{extension}";
        
        return backup_name;
    
    def get_existing_backups( self, original_file: Path ) -> List[Tuple[Path, datetime.datetime]]:
        """
        Get list of existing backups for a file, sorted by date (oldest first).
        
        Args:
            original_file: Path to original file
            
        Returns:
            List of tuples (backup_path, creation_date)
        """
        base_name = original_file.stem;
        extension = original_file.suffix;
        
        backups = [];
        
        # Pattern: {name}.{YYYYMMDD}.{ext} or {name}.{YYYYMMDD} (no ext)
        for backup_file in self.backup_dir.glob( f"{base_name}.*" ):
            name_parts = backup_file.name.split( '.' );
            
            if len( name_parts ) >= 2:
                # Try to parse date part
                date_part = None;
                
                if extension:
                    # File has extension: name.YYYYMMDD.ext
                    if len( name_parts ) >= 3 and name_parts[-1] == extension[1:]:
                        date_part = name_parts[-2];
                else:
                    # No extension: name.YYYYMMDD
                    if len( name_parts ) == 2:
                        date_part = name_parts[-1];
                
                if date_part and len( date_part ) == 8 and date_part.isdigit():
                    try:
                        backup_date = datetime.datetime.strptime( date_part, '%Y%m%d' );
                        backups.append( (backup_file, backup_date) );
                    except ValueError:
                        continue;
        
        # Sort by date (oldest first)
        backups.sort( key=lambda x: x[1] );
        return backups;
    
    def cleanup_old_backups( self, original_file: Path ) -> int:
        """
        Remove excess backups based on file size and retention limits.
        
        Args:
            original_file: Path to original file
            
        Returns:
            Number of backups removed
        """
        file_size = self.get_file_size( original_file );
        max_backups = self.max_backups_small if file_size < self.size_threshold else self.max_backups_large;
        
        existing_backups = self.get_existing_backups( original_file );
        
        if len( existing_backups ) <= max_backups:
            return 0;
        
        # Remove oldest backups (LRU deletion)
        backups_to_remove = existing_backups[:len( existing_backups ) - max_backups];
        removed_count = 0;
        
        for backup_path, backup_date in backups_to_remove:
            try:
                backup_path.unlink();
                removed_count += 1;
                print( f"    🗑️  Removed old backup: {backup_path.name}" );
            except Exception as e:
                print( f"    ⚠️  Failed to remove {backup_path.name}: {e}" );
        
        return removed_count;
    
    def create_backup( self, file_path: Path ) -> bool:
        """
        Create backup of a single file.
        
        Args:
            file_path: Path to file to backup
            
        Returns:
            True if backup was created successfully
        """
        if not file_path.exists():
            print( f"    ⚠️  File not found: {file_path}" );
            return False;
        
        backup_name = self.generate_backup_filename( file_path );
        backup_path = self.backup_dir / backup_name;
        
        # Check if backup already exists (same date)
        if backup_path.exists():
            print( f"    ℹ️  Backup already exists: {backup_name}" );
            return True;
        
        try:
            # Copy file to backup directory
            shutil.copy2( file_path, backup_path );
            
            # Cleanup old backups
            removed_count = self.cleanup_old_backups( file_path );
            
            file_size = self.get_file_size( file_path );
            size_mb = file_size / (1024 * 1024);
            
            print( f"    ✅ Created backup: {backup_name} ({size_mb:.1f}MB)" );
            if removed_count > 0:
                print( f"    🧹 Cleaned up {removed_count} old backups" );
            
            return True;
            
        except Exception as e:
            print( f"    ❌ Failed to create backup: {e}" );
            return False;
    
    def backup_project_files( self ) -> Dict[str, bool]:
        """
        Create backups of all important project files.
        
        Returns:
            Dictionary mapping file paths to backup success status
        """
        print( "💾 Creating backups of project files..." );
        
        # Define important files to backup
        important_files = [
            # Core Python source files
            self.project_root / 'src' / 'crypto_utils.py',
            self.project_root / 'src' / 'bootstrap_scanner.py', 
            self.project_root / 'src' / 'generate_bootstrap.py',
            self.project_root / 'src' / 'make_backup.py',
            
            # Critical scripts
            self.project_root / 'scripts' / 'bootstrap.sh',
            self.project_root / 'scripts' / 'add_secret.py',
            self.project_root / 'scripts' / 'decrypt_secrets.py',
            self.project_root / 'scripts' / 'git_auto_push.sh',
            self.project_root / 'scripts' / 'setup_cron.sh',
            self.project_root / 'scripts' / 'preview_ssl_keys.py',
            self.project_root / 'scripts' / 'serve_bootstrap.py',
            self.project_root / 'scripts' / 'configure_display_server.sh',
            self.project_root / 'scripts' / 'configure_keyboard_shortcuts.sh',
            self.project_root / 'scripts' / 'warp_reinstall.sh',
            self.project_root / 'scripts' / 'install_0xproto_font.sh',
            
            # Data files (critical!)
            self.project_root / 'data' / 'inventory.json',
            self.project_root / 'data' / 'encrypted_secrets.json',
            self.project_root / 'data' / 'encrypted_secrets.example.json',
            
            # Documentation
            self.project_root / 'docs' / 'architecture.md',
            self.project_root / 'docs' / 'CONTRIBUTING.md',
            self.project_root / 'docs' / 'TESTING.md',
            self.project_root / 'docs' / 'SSL_KEY_BACKUP.md',
            
            # Root documentation
            self.project_root / 'README.md',
            self.project_root / 'DISASTER_RECOVERY.md',
            self.project_root / 'EMERGENCY_CARD.md',
            self.project_root / 'SECRETS_SETUP.md',
            self.project_root / 'VM_TESTING_INSTRUCTIONS.md',
            self.project_root / 'VERIFICATION_SUMMARY.md',
        ];
        
        results = {};
        successful_backups = 0;
        total_files = 0;
        
        for file_path in important_files:
            if file_path.exists():
                total_files += 1;
                print( f"  📄 Backing up: {file_path.name}" );
                success = self.create_backup( file_path );
                results[str( file_path )] = success;
                if success:
                    successful_backups += 1;
        
        print( f"\\n📊 Backup Summary:" );
        print( f"   Files processed: {total_files}" );
        print( f"   Successful backups: {successful_backups}" );
        print( f"   Failed backups: {total_files - successful_backups}" );
        
        return results;
    
    def get_backup_stats( self ) -> Dict[str, int]:
        """Get statistics about backup directory."""
        if not self.backup_dir.exists():
            return {'total_files': 0, 'total_size': 0};
        
        total_files = 0;
        total_size = 0;
        
        for backup_file in self.backup_dir.iterdir():
            if backup_file.is_file():
                total_files += 1;
                total_size += backup_file.stat().st_size;
        
        return {
            'total_files': total_files,
            'total_size': total_size,
            'total_size_mb': total_size / (1024 * 1024)
        };


def main():
    """Main backup execution."""
    print( "🚀 Ubuntu Bootstrap Backup Manager" );
    print( "==================================\\n" );
    
    backup_manager = BootstrapBackupManager();
    
    # Create backups
    results = backup_manager.backup_project_files();
    
    # Show statistics
    stats = backup_manager.get_backup_stats();
    print( f"\\n📈 Backup Directory Statistics:" );
    print( f"   Total backup files: {stats['total_files']}" );
    print( f"   Total size: {stats['total_size_mb']:.1f} MB" );
    
    print( f"\\n💡 Next steps:" );
    print( f"   • Backups are stored in: {backup_manager.backup_dir}" );
    print( f"   • Run this before major changes or git pushes" );
    print( f"   • Backup retention: {backup_manager.max_backups_small} files <150KB, {backup_manager.max_backups_large} files ≥150KB" );


if __name__ == '__main__':
    main();
