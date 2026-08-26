#!/bin/bash
#
# Bootstrap System - Master Backup & Multi-Destination Sync
#
# 1. Scans system inventory (Arch/Ubuntu, Fish/Bash, mounts, keys, packages)
# 2. Generates updated restoration script (scripts/bootstrap.sh)
# 3. Packages all configs & keys into an authenticated encrypted vault (.tar.enc)
# 4. Dispatches encrypted vault to all configured storage destinations:
#    - Local project backup (./backup)
#    - Local FAST_ARCHIVE mount (/run/media/michael/FAST_ARCHIVE/SystemBackups)
#    - AWS S3 / Wasabi / Cloudflare R2
#    - Google Drive / OneDrive
#    - Email (SMTP encrypted attachment)
# 5. Pushes git commits to remote repository
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

main() {
    log_info "🚀 Starting Master Bootstrap Backup & Vault Dispatch"
    log_info "====================================================="
    cd "$PROJECT_ROOT"

    # 1. Run Universal Scanner & Vault Packaging
    log_info "🔍 Scanning system and creating encrypted vault..."
    python3 "$PROJECT_ROOT/src/bootstrap_scanner.py" "$@"

    # 2. Generate updated bootstrap restoration script
    log_info "🔧 Generating latest bootstrap restoration script..."
    python3 "$PROJECT_ROOT/src/generate_bootstrap.py"

    # 3. Perform Git commit & push if git is configured
    if [[ -d "$PROJECT_ROOT/.git" ]]; then
        log_info "📝 Checking git status and syncing repository..."
        "$PROJECT_ROOT/scripts/git_auto_push.sh" || log_warning "Git push skipped or failed."
    fi

    log_success "🎉 Master backup workflow completed successfully!"
}

main "$@"
