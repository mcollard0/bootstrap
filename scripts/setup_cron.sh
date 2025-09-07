#!/bin/bash
#
# Ubuntu Bootstrap - Cron Job Setup
#
# This script sets up automated weekly inventory refresh and git operations.
# Runs every Monday at 3 AM to update system inventory and push changes.
#

set -euo pipefail;

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)";
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")";

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

setup_cron_job() {
    log_info "⏰ Setting up weekly cron job for automated inventory updates";
    
    # Define the cron job command
    local cron_command="0 3 * * 1 cd $PROJECT_ROOT && /usr/bin/python3 src/bootstrap_scanner.py >/dev/null 2>&1 && /usr/bin/python3 src/generate_bootstrap.py >/dev/null 2>&1 && ./scripts/git_auto_push.sh >/dev/null 2>&1";
    
    # Check if cron job already exists
    if crontab -l 2>/dev/null | grep -q "bootstrap_scanner.py"; then
        log_info "Cron job already exists";
        
        # Show existing cron job
        echo;
        log_info "Current bootstrap-related cron jobs:";
        crontab -l 2>/dev/null | grep "bootstrap" || log_info "No bootstrap jobs found";
        echo;
        
        read -p "Replace existing cron job? (y/N): " -n 1 -r;
        echo;
        
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Keeping existing cron job";
            return 0;
        fi;
        
        # Remove existing bootstrap cron jobs
        log_info "Removing existing bootstrap cron jobs...";
        crontab -l 2>/dev/null | grep -v "bootstrap" | crontab -;
    fi;
    
    # Add new cron job
    log_info "Adding new weekly cron job...";
    
    # Create temporary cron file with existing jobs + new job
    local temp_cron=$(mktemp);
    
    # Get existing crontab (if any)
    crontab -l 2>/dev/null > "$temp_cron" || true;
    
    # Add comment and new job
    echo "" >> "$temp_cron";
    echo "# Ubuntu Bootstrap - Weekly inventory update and sync" >> "$temp_cron";
    echo "# Runs every Monday at 3:00 AM" >> "$temp_cron";
    echo "$cron_command" >> "$temp_cron";
    
    # Install new crontab
    crontab "$temp_cron";
    rm "$temp_cron";
    
    log_success "Cron job installed successfully";
    
    # Show confirmation
    echo;
    log_info "📋 Current crontab:";
    crontab -l;
    
    echo;
    log_info "📅 Schedule: Every Monday at 3:00 AM";
    log_info "🔄 Actions: Scan system → Generate bootstrap → Create backups → Git push";
    
    return 0;
};

remove_cron_job() {
    log_info "🗑️  Removing bootstrap cron jobs...";
    
    if crontab -l 2>/dev/null | grep -q "bootstrap"; then
        crontab -l 2>/dev/null | grep -v "bootstrap" | crontab -;
        log_success "Bootstrap cron jobs removed";
    else
        log_info "No bootstrap cron jobs found";
    fi;
    
    return 0;
};

show_cron_status() {
    log_info "📊 Bootstrap Cron Job Status";
    echo;
    
    if crontab -l 2>/dev/null | grep -q "bootstrap"; then
        log_success "Bootstrap cron job is installed";
        echo;
        log_info "Current bootstrap cron jobs:";
        crontab -l 2>/dev/null | grep "bootstrap";
        echo;
        
        # Calculate next run time
        log_info "⏰ Next run: Next Monday at 3:00 AM";
    else
        log_warning "No bootstrap cron jobs found";
        echo;
        log_info "Run: ./scripts/setup_cron.sh install";
    fi;
    
    return 0;
};

show_help() {
    echo "Ubuntu Bootstrap - Cron Job Setup";
    echo;
    echo "Usage: $0 [command]";
    echo;
    echo "Commands:";
    echo "  install    Install weekly cron job (default)";
    echo "  remove     Remove bootstrap cron jobs";
    echo "  status     Show current cron job status";
    echo "  help       Show this help message";
    echo;
    echo "The cron job runs every Monday at 3:00 AM and performs:";
    echo "  1. System inventory scan (bootstrap_scanner.py)";
    echo "  2. Bootstrap script generation (generate_bootstrap.py)";
    echo "  3. Backup creation and git operations (git_auto_push.sh)";
};

main() {
    local command="${1:-install}";
    
    case "$command" in
        "install")
            setup_cron_job;
            ;;
        "remove")
            remove_cron_job;
            ;;
        "status")
            show_cron_status;
            ;;
        "help"|"-h"|"--help")
            show_help;
            ;;
        *)
            log_error "Unknown command: $command";
            echo;
            show_help;
            exit 1;
            ;;
    esac;
    
    return 0;
};

# Execute main function
main "$@";
