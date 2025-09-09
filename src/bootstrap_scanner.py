#!/usr/bin/env python3
"""
Ubuntu Bootstrap System - System Scanner

This module scans the current Ubuntu system to create a comprehensive inventory
of installed packages, configurations, and sensitive data. The inventory is 
saved as JSON and can be used to reproduce the system configuration.
"""

import os;
import json;
import re;
import subprocess;
import socket;
import datetime;
import shutil;
from pathlib import Path;
from typing import Dict, List, Any, Optional, Tuple;

try:
    from .crypto_utils import SecureBootstrapCrypto, prompt_for_password;
except ImportError:
    from crypto_utils import SecureBootstrapCrypto, prompt_for_password;


class UbuntuSystemScanner:
    """Comprehensive system scanner for Ubuntu bootstrap inventory."""
    
    # Regex patterns for detecting sensitive data
    SENSITIVE_PATTERNS = [
        (r'(mongodb(\+srv)?://[^@\s]+:[^@\s]+@[^\s]+)', 'MongoDB URI'),
        (r'(sk-[A-Za-z0-9\-_]{20,})', 'API Key (sk- format)'),
        (r'(xai-[A-Za-z0-9\-_]{20,})', 'XAI API Key'),
        (r'([A-Za-z0-9\-_]{40,})', 'Generic Long Token'),
        (r'(AKIA[0-9A-Z]{16})', 'AWS Access Key'),
        (r'([A-Za-z0-9+/]{40})', 'Base64-like Secret'),
        (r'(gmail.*password.*=\s*["\']?([^"\'\s]+))', 'Gmail Password'),
        (r'(api.*key.*=\s*["\']?([^"\'\s]+))', 'API Key Assignment')
    ];
    
    def __init__( self, base_dir: str = None ):
        """
        Initialize the system scanner.
        
        Args:
            base_dir: Base directory for bootstrap project (auto-detect if None)
        """
        if base_dir is None:
            # Auto-detect project directory
            current_dir = Path( __file__ ).parent;
            self.base_dir = current_dir.parent;
        else:
            self.base_dir = Path( base_dir );
        
        self.data_dir = self.base_dir / 'data';
        self.data_dir.mkdir( exist_ok=True );
        
        self.crypto = SecureBootstrapCrypto();
        self.sensitive_data = {};
        
        print( f"📊 Ubuntu System Scanner initialized" );
        print( f"   Base directory: {self.base_dir}" );
    
    def get_system_info( self ) -> Dict[str, str]:
        """Get basic system information."""
        info = {};
        
        try:
            # OS version
            with open( '/etc/lsb-release' ) as f:
                for line in f:
                    if line.startswith( 'DISTRIB_RELEASE=' ):
                        info['ubuntu_version'] = line.split( '=' )[1].strip();
                    elif line.startswith( 'DISTRIB_CODENAME=' ):
                        info['codename'] = line.split( '=' )[1].strip();
        except:
            info['ubuntu_version'] = 'unknown';
        
        info['hostname'] = socket.gethostname();
        info['timestamp'] = datetime.datetime.now().isoformat();
        
        return info;
    
    def scan_apt_packages( self ) -> List[Dict[str, str]]:
        """Scan APT packages and their versions."""
        print( "  🔍 Scanning APT packages..." );
        packages = [];
        
        try:
            result = subprocess.run( 
                ['dpkg', '--get-selections'], 
                capture_output=True, text=True, check=True 
            );
            
            for line in result.stdout.strip().split( '\n' ):
                if '\t' in line:
                    name, status = line.split( '\t', 1 );
                    if status.strip() == 'install':
                        # Get version info
                        try:
                            version_result = subprocess.run(
                                ['dpkg-query', '-W', '--showformat=${Version}', name],
                                capture_output=True, text=True
                            );
                            version = version_result.stdout.strip() if version_result.returncode == 0 else 'unknown';
                        except:
                            version = 'unknown';
                        
                        packages.append({
                            'name': name,
                            'version': version,
                            'status': 'installed'
                        });
        except subprocess.CalledProcessError:
            print( "    ⚠️  Failed to scan APT packages" );
        
        print( f"    ✅ Found {len(packages)} APT packages" );
        return packages;
    
    def scan_snap_packages( self ) -> List[Dict[str, str]]:
        """Scan Snap packages and their versions."""
        print( "  🔍 Scanning Snap packages..." );
        packages = [];
        
        try:
            result = subprocess.run( 
                ['snap', 'list'], 
                capture_output=True, text=True, check=True 
            );
            
            lines = result.stdout.strip().split( '\n' )[1:];  # Skip header
            for line in lines:
                parts = line.split();
                if len( parts ) >= 3:
                    packages.append({
                        'name': parts[0],
                        'version': parts[1],
                        'channel': parts[2] if len( parts ) > 2 else 'unknown'
                    });
        except subprocess.CalledProcessError:
            print( "    ⚠️  Snap not available or no packages installed" );
        
        print( f"    ✅ Found {len(packages)} Snap packages" );
        return packages;
    
    def scan_flatpak_packages( self ) -> List[Dict[str, str]]:
        """Scan Flatpak packages and their versions."""
        print( "  🔍 Scanning Flatpak packages..." );
        packages = [];
        
        try:
            result = subprocess.run( 
                ['flatpak', 'list', '--app'], 
                capture_output=True, text=True, check=True 
            );
            
            for line in result.stdout.strip().split( '\n' ):
                if line.strip():
                    parts = line.split( '\t' );
                    if len( parts ) >= 2:
                        packages.append({
                            'name': parts[0],
                            'version': parts[1] if len( parts ) > 1 else 'unknown',
                            'runtime': parts[2] if len( parts ) > 2 else 'unknown'
                        });
        except (subprocess.CalledProcessError, FileNotFoundError):
            print( "    ⚠️  Flatpak not available or no packages installed" );
        
        print( f"    ✅ Found {len(packages)} Flatpak packages" );
        return packages;
    
    def scan_python_packages( self ) -> List[Dict[str, str]]:
        """Scan Python packages using pip3."""
        print( "  🔍 Scanning Python packages..." );
        packages = [];
        
        try:
            result = subprocess.run( 
                ['pip3', 'list', '--format=json'], 
                capture_output=True, text=True, check=True 
            );
            
            pip_data = json.loads( result.stdout );
            for pkg in pip_data:
                packages.append({
                    'name': pkg['name'],
                    'version': pkg['version']
                });
        except ( subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError ):
            print( "    ⚠️  Failed to scan Python packages" );
        
        print( f"    ✅ Found {len(packages)} Python packages" );
        return packages;
    
    def scan_custom_services( self ) -> List[Dict[str, Any]]:
        """Scan for custom services and installations like gridshift."""
        print( "  🔍 Scanning custom services..." );
        services = [];
        
        # Check for gridshift installation
        gridshift_paths = [
            '/media/michael/FASTESTARCHIVE/Archive/Programming/Python/gridshift',
            os.path.expanduser( '~/gridshift' ),
            '/opt/gridshift',
            '/usr/local/gridshift'
        ];
        
        for path in gridshift_paths:
            if os.path.exists( path ) and os.path.isdir( path ):
                # Check if it's a git repository
                git_dir = os.path.join( path, '.git' );
                if os.path.exists( git_dir ):
                    try:
                        # Get git remote info
                        result = subprocess.run(
                            ['git', '-C', path, 'remote', '-v'],
                            capture_output=True, text=True, check=True
                        );
                        remote_info = result.stdout.strip();
                        
                        # Check if requirements.txt exists
                        requirements_file = os.path.join( path, 'requirements.txt' );
                        has_requirements = os.path.exists( requirements_file );
                        
                        # Check if venv exists
                        venv_path = os.path.join( path, 'venv' );
                        has_venv = os.path.exists( venv_path );
                        
                        # Check if it's currently running
                        is_running = False;
                        try:
                            ps_result = subprocess.run(
                                ['ps', 'aux'],
                                capture_output=True, text=True, check=True
                            );
                            is_running = 'gridshift' in ps_result.stdout.lower();
                        except:
                            pass;
                        
                        services.append({
                            'name': 'gridshift',
                            'type': 'custom_service',
                            'path': path,
                            'git_remote': remote_info,
                            'has_requirements': has_requirements,
                            'has_venv': has_venv,
                            'is_running': is_running,
                            'installation_method': 'git_clone_venv'
                        });
                        
                        break;  # Found one, don't check other paths
                    except subprocess.CalledProcessError:
                        # Not a git repository or other error
                        continue;
        
        print( f"    ✅ Found {len(services)} custom services" );
        return services;
    
    def scan_bashrc_customizations( self ) -> Tuple[List[str], Dict[str, Any]]:
        """
        Scan .bashrc for custom additions, separating sensitive data.
        
        Returns:
            Tuple of (safe_lines, sensitive_data_dict)
        """
        print( "  🔍 Scanning .bashrc customizations..." );
        safe_lines = [];
        sensitive_items = {};
        
        bashrc_path = Path.home() / '.bashrc';
        
        if not bashrc_path.exists():
            print( "    ⚠️  .bashrc not found" );
            return [], {};
        
        try:
            with open( bashrc_path, 'r' ) as f:
                content = f.read();
            
            # Skip default Ubuntu .bashrc content (before first custom addition)
            lines = content.split( '\n' );
            custom_start = -1;
            
            # Look for typical end of default content
            for i, line in enumerate( lines ):
                if 'export mongodb_uri=' in line or 'export gmail_sender_email=' in line:
                    custom_start = i;
                    break;
            
            if custom_start >= 0:
                custom_lines = lines[custom_start:];
                
                for line_num, line in enumerate( custom_lines, custom_start ):
                    line = line.strip();
                    if not line or line.startswith( '#' ):
                        continue;
                    
                    # Check for sensitive patterns
                    is_sensitive = False;
                    for pattern, description in self.SENSITIVE_PATTERNS:
                        if re.search( pattern, line, re.IGNORECASE ):
                            # Extract variable name and value
                            if '=' in line and line.startswith( 'export ' ):
                                var_name = line.replace( 'export ', '' ).split( '=' )[0];
                                var_value = '='.join( line.split( '=' )[1:] ).strip( '"' );
                                
                                sensitive_items[var_name] = {
                                    'value': var_value,
                                    'line_number': line_num,
                                    'description': description
                                };
                                is_sensitive = True;
                                break;
                    
                    if not is_sensitive:
                        safe_lines.append( line );
        
        except Exception as e:
            print( f"    ⚠️  Error reading .bashrc: {e}" );
        
        print( f"    ✅ Found {len(safe_lines)} safe lines, {len(sensitive_items)} sensitive items" );
        return safe_lines, sensitive_items;
    
    def scan_sysctl_settings( self ) -> Dict[str, str]:
        """Scan custom sysctl settings."""
        print( "  🔍 Scanning sysctl settings..." );
        custom_settings = {};
        
        try:
            # Get all current settings
            result = subprocess.run( 
                ['sysctl', '-a'], 
                capture_output=True, text=True 
            );
            
            current_settings = {};
            for line in result.stdout.split( '\n' ):
                if '=' in line:
                    key, value = line.split( '=', 1 );
                    current_settings[key.strip()] = value.strip();
            
            # Compare against default system files to find customizations
            default_files = [
                '/usr/lib/sysctl.d/*.conf',
                '/etc/sysctl.conf',
                '/etc/sysctl.d/*.conf'
            ];
            
            # For now, just capture a subset of commonly customized settings
            interesting_keys = [
                'vm.swappiness', 'fs.inotify.max_user_watches', 
                'net.core.somaxconn', 'kernel.shmmax'
            ];
            
            for key in interesting_keys:
                if key in current_settings:
                    custom_settings[key] = current_settings[key];
            
        except subprocess.CalledProcessError:
            print( "    ⚠️  Failed to scan sysctl settings" );
        
        print( f"    ✅ Found {len(custom_settings)} sysctl customizations" );
        return custom_settings;
    
    def scan_ssh_keys( self ) -> List[Dict[str, str]]:
        """Scan SSH keys and configuration."""
        print( "  🔍 Scanning SSH keys..." );
        ssh_items = [];
        
        ssh_dir = Path.home() / '.ssh';
        if not ssh_dir.exists():
            print( "    ⚠️  .ssh directory not found" );
            return [];
        
        # Common SSH key files
        key_files = ['id_rsa', 'id_rsa.pub', 'id_ed25519', 'id_ed25519.pub', 'config'];
        
        for key_file in key_files:
            key_path = ssh_dir / key_file;
            if key_path.exists():
                try:
                    if key_file.endswith( '.pub' ) or key_file == 'config':
                        # Public keys and config are safe to read
                        content = key_path.read_text().strip();
                        ssh_items.append({
                            'path': f'~/.ssh/{key_file}',
                            'content': content,
                            'permissions': oct( key_path.stat().st_mode )[-3:]
                        });
                    else:
                        # Private keys - just note their existence
                        ssh_items.append({
                            'path': f'~/.ssh/{key_file}',
                            'content': '[PRIVATE_KEY_EXISTS]',
                            'permissions': oct( key_path.stat().st_mode )[-3:]
                        });
                except Exception as e:
                    print( f"    ⚠️  Error reading {key_file}: {e}" );
        
        print( f"    ✅ Found {len(ssh_items)} SSH items" );
        return ssh_items;
    
    def scan_cron_jobs( self ) -> List[str]:
        """Scan user crontab entries."""
        print( "  🔍 Scanning cron jobs..." );
        cron_jobs = [];
        
        try:
            result = subprocess.run( 
                ['crontab', '-l'], 
                capture_output=True, text=True 
            );
            
            if result.returncode == 0:
                for line in result.stdout.strip().split( '\n' ):
                    line = line.strip();
                    if line and not line.startswith( '#' ):
                        cron_jobs.append( line );
        except subprocess.CalledProcessError:
            print( "    ⚠️  No crontab found or access denied" );
        
        print( f"    ✅ Found {len(cron_jobs)} cron jobs" );
        return cron_jobs;
    
    def create_inventory( self, encrypt_sensitive: bool = True ) -> Dict[str, Any]:
        """Create complete system inventory."""
        print( "🔍 Creating comprehensive system inventory..." );
        
        system_info = self.get_system_info();
        
        # Scan all system components
        apt_packages = self.scan_apt_packages();
        snap_packages = self.scan_snap_packages();
        flatpak_packages = self.scan_flatpak_packages();
        python_packages = self.scan_python_packages();
        custom_services = self.scan_custom_services();
        
        bashrc_safe, bashrc_sensitive = self.scan_bashrc_customizations();
        sysctl_settings = self.scan_sysctl_settings();
        ssh_keys = self.scan_ssh_keys();
        cron_jobs = self.scan_cron_jobs();
        
        # Handle sensitive data encryption
        encrypted_refs = [];
        if encrypt_sensitive and bashrc_sensitive:
            print( "  🔐 Encrypting sensitive data..." );
            password = prompt_for_password( "system inventory encryption" );
            
            sensitive_values = { k: v['value'] for k, v in bashrc_sensitive.items() };
            self.sensitive_data = self.crypto.encrypt_dict( sensitive_values, password );
            encrypted_refs = list( bashrc_sensitive.keys() );
        
        # Build complete inventory
        inventory = {
            'version': '1.0',
            'system_info': system_info,
            'packages': {
                'apt': apt_packages,
                'snap': snap_packages,
                'flatpak': flatpak_packages,
                'python': python_packages
            },
            'custom_services': custom_services,
            'system_config': {
                'sysctl': sysctl_settings,
                'bashrc_additions': bashrc_safe,
                'cron_jobs': cron_jobs
            },
            'files': {
                'ssh_keys': ssh_keys
            },
            'encrypted_refs': encrypted_refs
        };
        
        print( "✅ System inventory created successfully!" );
        return inventory;
    
    def save_inventory( self, inventory: Dict[str, Any], filename: str = 'inventory.json' ) -> str:
        """Save inventory to JSON file."""
        inventory_path = self.data_dir / filename;
        
        with open( inventory_path, 'w' ) as f:
            json.dump( inventory, f, indent=2, ensure_ascii=False );
        
        # Save encrypted sensitive data separately
        if self.sensitive_data:
            sensitive_path = self.data_dir / 'encrypted_secrets.json';
            with open( sensitive_path, 'w' ) as f:
                json.dump( self.sensitive_data, f, indent=2 );
        
        print( f"💾 Inventory saved to: {inventory_path}" );
        if self.sensitive_data:
            print( f"🔐 Encrypted data saved to: {sensitive_path}" );
        
        return str( inventory_path );


def main():
    """Main scanner execution."""
    print( "🚀 Ubuntu Bootstrap System Scanner" );
    print( "=====================================\n" );
    
    scanner = UbuntuSystemScanner();
    
    # Create inventory
    inventory = scanner.create_inventory( encrypt_sensitive=True );
    
    # Save to file
    inventory_path = scanner.save_inventory( inventory );
    
    print( f"\n📊 Inventory Summary:" );
    print( f"   APT packages: {len(inventory['packages']['apt'])}" );
    print( f"   Snap packages: {len(inventory['packages']['snap'])}" );
    print( f"   Python packages: {len(inventory['packages']['python'])}" );
    print( f"   Custom services: {len(inventory['custom_services'])}" );
    print( f"   SSH keys: {len(inventory['files']['ssh_keys'])}" );
    print( f"   Cron jobs: {len(inventory['system_config']['cron_jobs'])}" );
    print( f"   Encrypted secrets: {len(inventory['encrypted_refs'])}" );
    
    print( f"\n💡 Next steps:" );
    print( f"   1. Run: python3 src/generate_bootstrap.py" );
    print( f"   2. Review generated scripts/bootstrap.sh" );
    print( f"   3. Test on a clean Ubuntu system" );


if __name__ == '__main__':
    main();
