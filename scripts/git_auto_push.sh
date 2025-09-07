#!/bin/bash
#
# Ubuntu Bootstrap - Automated Git Operations
#
# This script handles automated git operations for the bootstrap project,
# including backup creation, commits, and pushes to remote repository.
#

set -euo pipefail;

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)";
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")";
readonly BACKUP_SCRIPT="$PROJECT_ROOT/src/make_backup.py";

# Colors for output
readonly RED='\033[0;31m';
readonly GREEN='\033[0;32m';
readonly YELLOW='\033[1;33m';
readonly BLUE='\033[0;34m';
readonly NC='\033[0m';

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; };
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; };
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; };
log_error() { echo -e "${RED}[ERROR]${NC} $1"; };

main() {
    log_info "🚀 Starting automated Git operations";
    echo;
    
    cd "$PROJECT_ROOT";
    
    # Check if we're in a git repository
    if [[ ! -d ".git" ]]; then
        log_error "Not in a git repository";
        exit 1;
    fi;
    
    # Create backups before git operations
    log_info "📦 Creating backups before git operations...";
    if command -v python3 >/dev/null 2>&1 && [[ -f "$BACKUP_SCRIPT" ]]; then
        python3 "$BACKUP_SCRIPT";
    else
        log_warning "Backup script not found or Python not available";
    fi;
    
    echo;
    
    # Check for changes
    if git diff --quiet && git diff --cached --quiet; then
        log_info "No changes to commit";
        return 0;
    fi;
    
    # Add all changes (except ignored files)
    log_info "📝 Adding changes to git...";
    git add .;
    
    # Create commit message with timestamp
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S');
    local commit_message="Automated update - $timestamp

- Updated system inventory and bootstrap scripts
- Encrypted sensitive data maintained
- Backups created before commit";
    
    # Commit changes
    log_info "💾 Committing changes...";
    git commit -m "$commit_message";
    
    # Check if remote exists
    if git remote get-url origin >/dev/null 2>&1; then
        log_info "📤 Pushing to remote repository...";
        
        # Push using SSH (per user preference)
        if git push origin HEAD; then
            log_success "Successfully pushed to remote repository";
        else
            log_error "Failed to push to remote repository";
            return 1;
        fi;
    else
        log_warning "No remote repository configured";
        log_info "To add remote: git remote add origin git@github.com:USERNAME/bootstrap.git";
    fi;
    
    log_success "Git operations completed successfully";
    
    return 0;
};

# Execute main function
main "$@";
