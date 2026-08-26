#!/bin/bash
#
# Bootstrap System - Systemd Timer & Service Setup
#
# Configures a systemd user service and timer for automated, periodic
# system inventory scanning, encrypted vault packaging, and multi-destination dispatch.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RUN_BACKUP_SCRIPT="$PROJECT_ROOT/scripts/run_backup.sh"

USER_SYSTEMD_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
SERVICE_NAME="bootstrap-backup.service"
TIMER_NAME="bootstrap-backup.timer"
SERVICE_FILE="$USER_SYSTEMD_DIR/$SERVICE_NAME"
TIMER_FILE="$USER_SYSTEMD_DIR/$TIMER_NAME"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

show_status() {
    echo -e "\n${BOLD}${BLUE}======================================================${NC}"
    echo -e "${BOLD}⏱️  Bootstrap Systemd Timer & Service Status${NC}"
    echo -e "${BOLD}${BLUE}======================================================${NC}"

    if systemctl --user is-enabled "$TIMER_NAME" >/dev/null 2>&1; then
        echo -e "Timer Status:   ${GREEN}Enabled & Active${NC}"
    else
        echo -e "Timer Status:   ${YELLOW}Inactive / Not Installed${NC}"
    fi

    echo -e "\n${CYAN}Timer Details:${NC}"
    systemctl --user list-timers "$TIMER_NAME" --all 2>/dev/null || true

    echo -e "\n${CYAN}Service Unit File:${NC} $SERVICE_FILE"
    echo -e "${CYAN}Timer Unit File:${NC}   $TIMER_FILE"

    if [[ -f "$SERVICE_FILE" ]]; then
        echo -e "\n${CYAN}Permissions:${NC}"
        ls -la "$SERVICE_FILE" "$TIMER_FILE" 2>/dev/null || true
    fi
    echo
}

uninstall_timer() {
    log_info "Disabling and removing bootstrap systemd timer..."
    systemctl --user stop "$TIMER_NAME" 2>/dev/null || true
    systemctl --user disable "$TIMER_NAME" 2>/dev/null || true

    if [[ -f "$TIMER_FILE" ]]; then
        rm -f "$TIMER_FILE"
        log_success "Removed $TIMER_FILE"
    fi

    if [[ -f "$SERVICE_FILE" ]]; then
        rm -f "$SERVICE_FILE"
        log_success "Removed $SERVICE_FILE"
    fi

    systemctl --user daemon-reload
    log_success "Systemd daemon reloaded. Uninstallation complete."
}

prompt_secret() {
    local secret=""
    local secret_confirm=""

    while true; do
        read -s -p "Enter master SECRET for backup vault encryption: " secret
        echo
        if [[ -z "$secret" ]]; then
            log_error "SECRET cannot be empty. Please enter a valid password."
            continue
        fi

        if [[ ${#secret} -lt 8 ]]; then
            log_warning "Master secret is less than 8 characters."
        fi

        read -s -p "Confirm master SECRET: " secret_confirm
        echo
        if [[ "$secret" != "$secret_confirm" ]]; then
            log_error "Secrets did not match. Please try again."
            continue
        fi

        break
    done

    echo "$secret"
}

main() {
    local custom_secret=""
    local schedule_calendar="Mon *-*-* 03:00:00" # Default: Every Monday at 3:00 AM
    local schedule_desc="Weekly on Monday at 3:00 AM"

    # Argument handling
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --status|-s)
                show_status
                exit 0
                ;;
            --uninstall|-u)
                uninstall_timer
                exit 0
                ;;
            --secret|--password|-p)
                custom_secret="$2"
                shift 2
                ;;
            --daily)
                schedule_calendar="*-*-* 03:00:00"
                schedule_desc="Daily at 3:00 AM"
                shift
                ;;
            --weekly)
                schedule_calendar="Mon *-*-* 03:00:00"
                schedule_desc="Weekly on Monday at 3:00 AM"
                shift
                ;;
            --schedule)
                schedule_calendar="$2"
                schedule_desc="Custom: $2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo
                echo "Options:"
                echo "  --secret, --password <PWD>  Pass SECRET non-interactively"
                echo "  --daily                     Schedule daily at 3:00 AM"
                echo "  --weekly                    Schedule weekly on Monday at 3:00 AM (default)"
                echo "  --schedule '<EXPR>'         Custom systemd OnCalendar expression"
                echo "  --status, -s                Show timer and service status"
                echo "  --uninstall, -u             Disable and remove timer and service"
                echo "  --help, -h                  Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    echo -e "\n${BOLD}${BLUE}======================================================${NC}"
    echo -e "${BOLD}⚙️  Automated Bootstrap Backup - Systemd Setup${NC}"
    echo -e "${BOLD}${BLUE}======================================================${NC}"
    log_info "Target Project Root: $PROJECT_ROOT"
    log_info "Master Script:       $RUN_BACKUP_SCRIPT"

    if [[ ! -x "$RUN_BACKUP_SCRIPT" ]]; then
        chmod +x "$RUN_BACKUP_SCRIPT"
    fi

    # Check if timer is already installed
    if [[ -f "$TIMER_FILE" || -f "$SERVICE_FILE" ]]; then
        log_warning "An existing bootstrap systemd timer or service was detected."
        read -p "Do you want to reconfigure and replace it? [Y/n]: " -r reply
        if [[ "$reply" =~ ^[Nn]$ ]]; then
            log_info "Setup cancelled. Existing units left intact."
            exit 0
        fi
    fi

    # Prompt for SECRET if not provided
    local secret="$custom_secret"
    if [[ -z "$secret" ]]; then
        secret=$(prompt_secret)
    fi

    # Select schedule if interactive and not specified via flags
    if [[ -z "${1:-}" && -t 0 && "$schedule_desc" == "Weekly on Monday at 3:00 AM" ]]; then
        echo -e "\nSelect backup schedule:"
        echo "  1) Weekly on Monday at 3:00 AM [Default]"
        echo "  2) Daily at 3:00 AM"
        echo "  3) Custom interval"
        read -p "Enter choice [1-3, default: 1]: " -r sched_choice
        case "$sched_choice" in
            2)
                schedule_calendar="*-*-* 03:00:00"
                schedule_desc="Daily at 3:00 AM"
                ;;
            3)
                read -p "Enter systemd OnCalendar expression (e.g. daily, weekly, '*-*-* 04:00:00'): " -r custom_cal
                if [[ -n "$custom_cal" ]]; then
                    schedule_calendar="$custom_cal"
                    schedule_desc="Custom: $custom_cal"
                fi
                ;;
            *)
                schedule_calendar="Mon *-*-* 03:00:00"
                schedule_desc="Weekly on Monday at 3:00 AM"
                ;;
        esac
    fi

    log_info "Selected schedule: $schedule_desc ($schedule_calendar)"

    # Ensure systemd user directory exists
    mkdir -p "$USER_SYSTEMD_DIR"

    # Escape quotes and backslashes for systemd ExecStart
    # In systemd ExecStart, arguments containing spaces or special chars are wrapped in double quotes
    local escaped_secret="${secret//\\/\\\\}"
    escaped_secret="${escaped_secret//\"/\\\"}"
    escaped_secret="${escaped_secret//\$/\$\$}"

    # 1. Write the user service file
    log_info "Writing systemd service unit: $SERVICE_FILE..."
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Automated Bootstrap System Inventory Backup & Encrypted Vault Dispatch
Documentation=file://$PROJECT_ROOT/README.md
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$PROJECT_ROOT
ExecStart=/bin/bash $RUN_BACKUP_SCRIPT --password "$escaped_secret"
StandardOutput=journal
StandardError=journal
ProtectSystem=full
ProtectHome=read-only
ReadOnlyPaths=/
ReadWritePaths=$PROJECT_ROOT /run/media /tmp
PrivateTmp=true

[Install]
WantedBy=default.target
EOF

    # Restrict permissions to 0600 so only the user can read the SECRET
    chmod 0600 "$SERVICE_FILE"
    log_success "Service unit created with secure 0600 permissions."

    # 2. Write the user timer file
    log_info "Writing systemd timer unit: $TIMER_FILE..."
    cat > "$TIMER_FILE" <<EOF
[Unit]
Description=Automated Bootstrap Backup Timer ($schedule_desc)
Requires=$SERVICE_NAME

[Timer]
OnCalendar=$schedule_calendar
Persistent=true
RandomizedDelaySec=15m

[Install]
WantedBy=timers.target
EOF

    chmod 0644 "$TIMER_FILE"
    log_success "Timer unit created."

    # 3. Reload systemd daemon and enable timer
    log_info "Reloading systemd user daemon..."
    systemctl --user daemon-reload

    log_info "Enabling and starting $TIMER_NAME..."
    systemctl --user enable --now "$TIMER_NAME"

    # 4. Check linger status
    local user_name="${USER:-$(whoami)}"
    if command -v loginctl >/dev/null 2>&1; then
        local linger_status
        linger_status=$(loginctl show-user "$user_name" 2>/dev/null | grep -i "Linger=" | cut -d'=' -f2 || echo "no")
        if [[ "$linger_status" != "yes" ]]; then
            echo
            log_warning "User lingering is currently disabled for '$user_name'."
            log_info "Without lingering, user timers only run while you are logged in (GUI or SSH)."
            read -p "Enable lingering so backups run even when logged out? (Requires sudo) [Y/n]: " -r linger_reply
            if [[ ! "$linger_reply" =~ ^[Nn]$ ]]; then
                if sudo -n loginctl enable-linger "$user_name" 2>/dev/null || sudo loginctl enable-linger "$user_name"; then
                    log_success "Enabled lingering for user '$user_name'."
                else
                    log_warning "Could not automatically enable lingering. You can run manually: sudo loginctl enable-linger $user_name"
                fi
            fi
        fi
    fi

    # 5. Display status
    echo
    log_success "🎉 Bootstrap automated backup timer successfully configured!"
    show_status

    echo -e "${BOLD}Useful Commands:${NC}"
    echo "  • View timer:         systemctl --user list-timers $TIMER_NAME"
    echo "  • Trigger manual run: systemctl --user start $SERVICE_NAME"
    echo "  • View run logs:      journalctl --user -u $SERVICE_NAME -n 50 --no-pager"
    echo "  • Check status:       $0 --status"
    echo "  • Uninstall:          $0 --uninstall"
    echo
}

main "$@"
