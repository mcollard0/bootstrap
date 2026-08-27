#!/bin/bash
#
# Arch Linux / CachyOS Bootstrap Restoration Script
# Generated: 2026-08-27T11:04:19.382337
# Source System: CachyOS
#

set -euo pipefail

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

check_sudo() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be executed with root/sudo privileges."
        log_info "Usage: sudo $0"
        exit 1
    fi
}

main() {
    log_info "🚀 Starting Arch / CachyOS Bootstrap Restoration"
    log_info "==============================================="
    check_sudo

    readonly TARGET_USER="${SUDO_USER:-$USER}"
    readonly USER_HOME="/home/$TARGET_USER"

    log_info "Target User: $TARGET_USER"
    log_info "User Home:   $USER_HOME"
    echo

    # 1. Update package databases and install base development tools
    log_info "📦 Synchronizing pacman mirrors and installing base-devel..."
    pacman -Sy --needed --noconfirm base-devel git curl wget

    # 2. Recreate mount points for external archive drives
    log_info "💾 Ensuring archive drive mount directories exist..."
    mkdir -p '/run/media/michael/LARGE_ARCHIVE'
    mkdir -p '/run/media/michael/FAST_ARCHIVE'
    mkdir -p '/run/media/michael/SHARD_9'
    mkdir -p '/run/media/michael/SLOW_ARCHIVE'
    mkdir -p '/run/media/michael/SHARD_3'
    mkdir -p '/run/media/michael/SHARD_4'

    log_success "Archive mount points verified."

    # 3. Check/Install AUR Helper (paru or yay)
    log_info "🔧 Verifying AUR helper..."
    local aur_helper=""
    if sudo -u "$TARGET_USER" command -v paru >/dev/null 2>&1; then
        aur_helper="paru"
    elif sudo -u "$TARGET_USER" command -v yay >/dev/null 2>&1; then
        aur_helper="yay"
    else
        log_info "Installing paru from AUR..."
        local tmp_paru=$(mktemp -d)
        chown "$TARGET_USER:$TARGET_USER" "$tmp_paru"
        sudo -u "$TARGET_USER" git clone https://aur.archlinux.org/paru-bin.git "$tmp_paru/paru-bin"
        (cd "$tmp_paru/paru-bin" && sudo -u "$TARGET_USER" makepkg -si --noconfirm)
        rm -rf "$tmp_paru"
        aur_helper="paru"
    fi
    log_success "AUR helper available: $aur_helper"

    # 4. Check & Install Native Pacman Packages
    local native_packages=(7zip accountsservice alacritty alsa-firmware alsa-plugins alsa-utils amd-ucode anki ark awesome-terminal-fonts base-devel bash-completion bind bluedevil bluez bluez-hid2hci bluez-libs bluez-utils boost bpftune-git breeze-gtk btop btrfs-assistant btrfs-progs cachyos-emerald-kde-theme-git cachyos-fish-config cachyos-grub-theme cachyos-hello cachyos-hooks cachyos-iridescent-kde cachyos-kde-settings cachyos-kernel-manager cachyos-keyring cachyos-micro-settings cachyos-mirrorlist cachyos-nord-kde-theme-git cachyos-packageinstaller cachyos-plymouth-bootanimation cachyos-rate-mirrors cachyos-settings cachyos-themes-sddm cachyos-v3-mirrorlist cachyos-v4-mirrorlist cachyos-wallpapers cachyos-zsh-config cantarell-fonts char-white chntpw chwd cmake cockpit cockpit-machines code copyq cpu-x cpupower cryptsetup cuda cups cups-filters cups-pdf dcmtk device-mapper dhclient diffutils discord dkms dmidecode dmraid dnsmasq docker docker-buildx docker-compose dolphin dosfstools dotnet-sdk duf dust e2fsprogs efibootmgr efitools egl-wayland ethtool ex-vi-compat exfatprogs f2fs-tools fastfetch ffmpegthumbnailer ffmpegthumbs filelight firefox foomatic-db foomatic-db-engine foomatic-db-gutenprint-ppds foomatic-db-nonfree foomatic-db-nonfree-ppds foomatic-db-ppds fortune-mod freetds fsarchiver fwupd gdb gemini-cli ghostscript gimp git git-filter-repo github-cli glances gopls gperf grub grub-btrfs-support grub-hook gsfonts gst-libav gst-plugin-pipewire gst-plugin-va gst-plugins-bad gst-plugins-ugly gutenprint gwenview haruna haveged hdparm hwdetect hwinfo hypnotix ifuse inetutils inotify-tools iptables iwd jellyfin-ffmpeg jellyfin-server jellyfin-web jfsutils kamoso kate kcalc kde-gtk-config kdeconnect kdegraphics-thumbnailers kdeplasma-addons kdialog kinfocenter kio-admin kio-gdrive konsole krdc krfb kscreen kwallet-pam kwalletmanager kwave less lib32-nvidia-utils lib32-opencl-nvidia lib32-vulkan-icd-loader lib32-vulkan-radeon libdvdcss libgsf libguestfs libopenraw libplasma libreoffice-fresh libva-nvidia-driver libwebsockets libwnck3 linux-cachyos linux-cachyos-headers linux-cachyos-lts linux-cachyos-lts-headers linux-cachyos-lts-nvidia-open linux-cachyos-nvidia-open logrotate lsb-release lsof lsscsi lvm2 man-db man-pages mariadb-libs mdadm meld mesa-utils micro mingw-w64-gcc miniupnpc mkinitcpio mkvtoolnix-cli modemmanager mtools nano nano-syntax-highlighting net-tools netctl networkmanager networkmanager-openvpn nfs-utils nginx nilfs-utils ninja nlohmann-json noto-color-emoji-fontconfig noto-fonts noto-fonts-cjk noto-fonts-emoji npm nss-mdns ntp nvidia-container-toolkit nvidia-prime nvidia-settings nvidia-utils nvtop obs-studio obsidian obsidian-icon-theme octopi ollama ollama-cuda opencl-nvidia openssh os-prober pacman-contrib partitionmanager paru pavucontrol perl phonon-qt6-vlc php-fpm picard pipewire-alsa pipewire-pulse pkgfile plasma-browser-integration plasma-desktop plasma-firewall plasma-integration plasma-nm plasma-pa plasma-systemmonitor plasma-thunderbolt plasma-workspace plocate plymouth plymouth-kcm poppler-glib postgresql-libs power-profiles-daemon powerdevil print-manager pv pyright python python-debugpy python-defusedxml python-packaging python-pillow python-pydicom python311 qemu-full qt6-wayland rebuild-detector reflector ripgrep rsync rtkit s-nail scrcpy sddm sddm-kcm sg3_utils sharutils smartmontools snapper snapshot sof-firmware spectacle sshfs sshpass sudo sysfsutils sysstat system-config-printer tailscale texinfo thefuck tmux tree-sitter-cli ttf-bitstream-vera ttf-dejavu ttf-liberation ttf-meslo-nerd ttf-opensans ufw unixodbc unrar unzip upower usb_modeswitch usbmuxd usbutils uv vim virt-manager virt-viewer vlc-plugins-all vulkan-headers vulkan-icd-loader vulkan-radeon warp-terminal warp-terminal-preview wget which wireless-regdb wireplumber wireshark-qt wl-clipboard wlr-randr wmctrl wpa_supplicant wtype xclip xdg-desktop-portal xdg-desktop-portal-kde xdg-user-dirs xdotool xf86-input-libinput xf86-video-amdgpu xfsprogs xl2tpd xorg-server xorg-xdpyinfo xorg-xinit xorg-xinput xorg-xkill xorg-xrandr xsel xsettingsd yay-bin ydotool zip zoxide)
    if [[ ${#native_packages[@]} -gt 0 ]]; then
        log_info "Checking which native packages are missing via pacman -T..."
        local missing_native=($(pacman -T "${native_packages[@]}" 2>/dev/null || true))
        if [[ ${#missing_native[@]} -eq 0 ]]; then
            log_success "All ${#native_packages[@]} native packages are already installed - skipping."
        else
            log_info "Installing ${#missing_native[@]} missing native packages (out of ${#native_packages[@]})..."
            for ((i=0; i<${#missing_native[@]}; i+=50)); do
                local batch=("${missing_native[@]:i:50}")
                pacman -S --needed --noconfirm "${batch[@]}" || log_warning "Some packages in batch failed to install."
            done
            log_success "Native packages installation step completed."
        fi
    fi

    # 5. Check & Install AUR Packages
    local aur_packages=(alizams-git antigravity-cli antigravity-ide beekeeper-studio-bin bridge-utils electron37 extundelete fladder-bin google-chrome-beta icaclient kdecodexbar mgrep moonfin-bin obs-pipewire-audio-capture ombi-bin openwebstart-bin oracle-instantclient-basic plex-media-server policycoreutils py-spy python-genanki-git python313 slack-desktop-wayland splix streamcontroller-git stremio virtio-win webkit2gtk zoom)
    if [[ ${#aur_packages[@]} -gt 0 ]]; then
        log_info "Checking which AUR packages are missing via pacman -T..."
        local missing_aur=($(pacman -T "${aur_packages[@]}" 2>/dev/null || true))
        if [[ ${#missing_aur[@]} -eq 0 ]]; then
            log_success "All ${#aur_packages[@]} AUR packages are already installed - skipping."
        else
            log_info "Installing ${#missing_aur[@]} missing AUR packages via $aur_helper (out of ${#aur_packages[@]})..."
            sudo -u "$TARGET_USER" "$aur_helper" -S --needed --noconfirm "${missing_aur[@]}" || log_warning "Some AUR packages failed to install."
            log_success "AUR packages installation step completed."
        fi
    fi

    # 6. Set user default shell to fish if installed
    if command -v fish >/dev/null 2>&1; then
        log_info "🐚 Setting default shell to Fish..."
        chsh -s "$(which fish)" "$TARGET_USER" || true
        log_success "Default shell set to Fish for $TARGET_USER."
    fi

    # 7. Enable system services
    log_info "⚙️  Enabling essential system services..."
    systemctl enable --now NetworkManager 2>/dev/null || true
    systemctl enable --now fstrim.timer 2>/dev/null || true

    log_success "🎉 System bootstrap restoration complete!"
    log_info "To restore encrypted dotfiles, SSH keys, and fstab directly from a vault, run:"
    log_info "   python3 src/restore.py"
}

main "$@"
