# Dry Run Mode - Quick Reference Guide

## Overview
Dry run mode allows you to extract system settings and generate bootstrap scripts **without modifying your main bootstrap project directory**. This is ideal for testing, previewing, or setting up a new computer.

## Basic Usage

### Extract Settings (Dry Run)
```bash
# Use default /tmp/bootstrap directory
python3 src/bootstrap_scanner.py --dry-run

# Use custom directory
python3 src/bootstrap_scanner.py --dry-run --output-dir /home/user/my-bootstrap
```

### Generate Bootstrap Script (Dry Run)
```bash
# Read from default /tmp/bootstrap directory
python3 src/generate_bootstrap.py --dry-run

# Read from custom directory
python3 src/generate_bootstrap.py --input-dir /home/user/my-bootstrap
```

## Command-Line Options

### bootstrap_scanner.py
| Option | Description |
|--------|-------------|
| `--dry-run` | Enable dry run mode (outputs to /tmp/bootstrap by default) |
| `--output-dir <path>` | Custom output directory (requires --dry-run) |
| `--no-encrypt` | Skip encryption of sensitive data (for testing) |

### generate_bootstrap.py
| Option | Description |
|--------|-------------|
| `--dry-run` | Enable dry run mode (reads from /tmp/bootstrap) |
| `--input-dir <path>` | Custom input directory to read inventory from |
| `--output-dir <path>` | Custom output directory for generated script |

## Use Cases

### 1. Preview Before Committing
Extract settings to see what would be captured without affecting your repo:
```bash
python3 src/bootstrap_scanner.py --dry-run
ls -la /tmp/bootstrap/data/
cat /tmp/bootstrap/data/inventory.json
```

### 2. New Computer Setup
On a new computer, extract settings to test before making it permanent:
```bash
# Extract to temporary location
python3 src/bootstrap_scanner.py --dry-run

# Review the output
cat /tmp/bootstrap/data/inventory.json

# If satisfied, run without --dry-run to save to project
python3 src/bootstrap_scanner.py
```

### 3. Share Configuration with Team
Extract settings to a shared directory:
```bash
# Extract to shared location
python3 src/bootstrap_scanner.py --dry-run --output-dir /shared/team-bootstrap

# Teammate can generate script from it
python3 src/generate_bootstrap.py --input-dir /shared/team-bootstrap
```

### 4. Testing Changes
Test configuration changes without modifying production bootstrap:
```bash
# Modify scanner settings, then dry run
python3 src/bootstrap_scanner.py --dry-run --output-dir /tmp/test-run

# Generate and review script
python3 src/generate_bootstrap.py --input-dir /tmp/test-run
less /tmp/test-run/scripts/bootstrap.sh
```

## Directory Structure

When running in dry run mode, the following structure is created:

```
/tmp/bootstrap/               # Default dry run directory
├── data/                     # System inventory and encrypted data
│   ├── inventory.json        # Complete system state
│   └── encrypted_secrets.json # Encrypted sensitive values
├── scripts/                  # Generated bootstrap scripts
│   └── bootstrap.sh          # Main restoration script
└── backup/                   # (created but not used in dry run)
```

## Workflow Examples

### Complete Dry Run Workflow
```bash
# Step 1: Extract settings
python3 src/bootstrap_scanner.py --dry-run
# Output: /tmp/bootstrap/data/inventory.json

# Step 2: Generate script
python3 src/generate_bootstrap.py --dry-run
# Output: /tmp/bootstrap/scripts/bootstrap.sh

# Step 3: Review
less /tmp/bootstrap/scripts/bootstrap.sh

# Step 4: Test on another machine (copy files over)
scp -r /tmp/bootstrap user@newmachine:/tmp/
ssh user@newmachine "sudo /tmp/bootstrap/scripts/bootstrap.sh"
```

### Custom Directory Workflow
```bash
# Extract to custom location
python3 src/bootstrap_scanner.py --dry-run --output-dir ~/Documents/bootstrap-backup

# Generate script from custom location
python3 src/generate_bootstrap.py --input-dir ~/Documents/bootstrap-backup

# Archive for safekeeping
tar czf bootstrap-$(date +%Y%m%d).tar.gz ~/Documents/bootstrap-backup
```

## Important Notes

1. **Default Location**: `/tmp/bootstrap` is cleared on reboot - copy elsewhere if you need persistence
2. **Encryption**: Dry run mode still encrypts sensitive data by default (use `--no-encrypt` to skip)
3. **No Git Operations**: Dry run mode never commits or pushes to git
4. **Independent**: Dry run output is completely separate from your main project
5. **Testing Safe**: You can safely delete `/tmp/bootstrap` without affecting your project

## Troubleshooting

### "Directory not found" errors
Make sure to run scanner before generator:
```bash
python3 src/bootstrap_scanner.py --dry-run
python3 src/generate_bootstrap.py --dry-run  # Now this will work
```

### Custom directory not working
Ensure the directory exists or let the scanner create it:
```bash
# This will create the directory:
python3 src/bootstrap_scanner.py --dry-run --output-dir /path/to/new/dir
```

### Want to see unencrypted output (testing only)
```bash
python3 src/bootstrap_scanner.py --dry-run --no-encrypt
# Warning: Sensitive data will be in plaintext!
```

## Security Considerations

- Even in dry run mode, sensitive data is encrypted by default
- The `/tmp` directory may be accessible to other users - use custom directories for sensitive systems
- Dry run mode does not bypass password prompts for encryption
- Generated scripts in dry run mode are functionally identical to normal mode

---

**Quick Command Reference:**
```bash
# Basic dry run
python3 src/bootstrap_scanner.py --dry-run
python3 src/generate_bootstrap.py --dry-run

# Custom location
python3 src/bootstrap_scanner.py --dry-run --output-dir <path>
python3 src/generate_bootstrap.py --input-dir <path>

# Help
python3 src/bootstrap_scanner.py --help
python3 src/generate_bootstrap.py --help
```
