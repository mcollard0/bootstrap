#!/usr/bin/env python3
"""
Universal Linux Bootstrap - Install & Disaster Recovery Media Creator

Provisions a dual-volume bootable USB drive:
  Volume 1: Bootable Linux OS Installer (CachyOS, Arch, Ubuntu, Debian, Fedora, etc.)
            Dynamically discovers and fetches the latest upstream release online.
  Volume 2: Standalone Disaster Recovery Engine (Volume: BOOTSTRAP)
            Pre-loaded with offline repo, decryptor, and latest encrypted backup vault.

Usage:
  sudo ./create_install_media.sh [options]
  sudo python3 scripts/create_install_media.py [options]

Options:
  --dev /dev/sdX     Target USB block device (e.g. /dev/sdb)
  --iso /path/to.iso Path to local ISO file
  --distro <1-8>     Preset distribution number
  --confirm, -y      Bypass interactive 'YES' confirmation prompt
  --dry-run          Simulate drive detection & online queries without writing
  --force-download   Force re-download even if ISO is cached
  --help, -h         Show this help message
"""

import os
import sys
import re
import json
import time
import shutil
import argparse
import subprocess
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

# ANSI Colors
BOLD = "\033[1m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
CYAN = "\033[0;36m"
RED = "\033[0;31m"
NC = "\033[0m"

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_CACHE_DIR = Path("/run/media/michael/FAST_ARCHIVE/VM/IMAGES")
LOCAL_CACHE_DIR = REPO_ROOT / "data" / "iso_cache"
BACKUP_ARCHIVE_DIR = Path("/run/media/michael/FAST_ARCHIVE/SystemBackups")

HTTP_HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; UniversalLinuxBootstrap)"}


def log_info(msg: str):
    print(f"  {BLUE}ℹ️  [INFO]{NC} {msg}")


def log_success(msg: str):
    print(f"  {GREEN}✅ [SUCCESS]{NC} {msg}")


def log_warn(msg: str):
    print(f"  {YELLOW}⚠️  [WARN]{NC} {msg}")


def log_error(msg: str):
    print(f"  {RED}❌ [ERROR]{NC} {msg}", file=sys.stderr)


def print_banner():
    print(f"{BOLD}{CYAN}======================================================================{NC}")
    print(f"{BOLD}{CYAN}  🛠️  Universal Linux Bootstrap - Install & Recovery Media Creator   {NC}")
    print(f"{BOLD}{CYAN}======================================================================{NC}")
    print("  Provisions a dual-volume bootable USB drive:")
    print(f"    • {BOLD}Volume 1 (Installer){NC}: UEFI bootable Linux OS installer (dynamic online check)")
    print(f"    • {BOLD}Volume 2 (BOOTSTRAP){NC}: Automated disaster recovery engine & vaults")
    print(f"{BOLD}{CYAN}======================================================================{NC}\n")


# ------------------------------------------------------------------------------
# 1. Dynamic Upstream ISO Resolvers (No hardcoded versions or dead links)
# ------------------------------------------------------------------------------

class IsoResolver:
    """Queries official upstream APIs, RSS feeds, and mirror indices for latest releases."""

    @staticmethod
    def resolve_cachyos() -> Tuple[str, str, str]:
        """Queries CachyOS SourceForge RSS feed for latest desktop ISO and maps to high-speed CDN."""
        rss_url = "https://sourceforge.net/projects/cachyos-arch/rss?path=/"
        req = urllib.request.Request(rss_url, headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=12) as resp:
            tree = ET.fromstring(resp.read())

        candidates = []
        for item in tree.findall(".//item"):
            title = item.findtext("title", "")
            m = re.search(r"/desktop/(\d+)/(cachyos-desktop-linux-\d+\.iso)$", title)
            if m:
                version, filename = m.group(1), m.group(2)
                cdn_url = f"https://cdn77.cachyos.org/ISO/desktop/{version}/{filename}"
                candidates.append((version, filename, cdn_url))

        if not candidates:
            # Fallback if RSS schema changed
            return ("latest", "cachyos-desktop-linux-latest.iso", "https://iso.cachyos.org/desktop/cachyos-desktop-linux-latest.iso")

        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0]

    @staticmethod
    def resolve_arch() -> Tuple[str, str, str]:
        """Queries official Arch Linux release engineering JSON API."""
        api_url = "https://archlinux.org/releng/releases/json/"
        req = urllib.request.Request(api_url, headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        rel = data["releases"][0]
        version = rel["version"]
        filename = rel["torrent"]["file_name"]
        download_url = f"https://geo.mirror.pkgbuild.com/iso/{version}/{filename}"
        return (version, filename, download_url)

    @staticmethod
    def resolve_ubuntu_desktop() -> Tuple[str, str, str]:
        """Queries official Ubuntu releases directory for latest 24.04 LTS point release."""
        index_url = "https://releases.ubuntu.com/24.04/"
        req = urllib.request.Request(index_url, headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=12) as resp:
            html = resp.read().decode("utf-8")

        matches = re.findall(r"href=\"(ubuntu-24\.04(?:\.\d+)?-desktop-amd64\.iso)\"", html)
        if matches:
            filename = sorted(matches, reverse=True)[0]
            ver_m = re.search(r"ubuntu-(24\.04(?:\.\d+)?)-", filename)
            ver = ver_m.group(1) if ver_m else "24.04"
            return (ver, filename, f"https://releases.ubuntu.com/24.04/{filename}")

        return ("24.04", "ubuntu-24.04-desktop-amd64.iso", "https://releases.ubuntu.com/24.04/ubuntu-24.04-desktop-amd64.iso")

    @staticmethod
    def resolve_ubuntu_server() -> Tuple[str, str, str]:
        """Queries official Ubuntu releases directory for latest 24.04 server release."""
        index_url = "https://releases.ubuntu.com/24.04/"
        req = urllib.request.Request(index_url, headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=12) as resp:
            html = resp.read().decode("utf-8")

        matches = re.findall(r"href=\"(ubuntu-24\.04(?:\.\d+)?-live-server-amd64\.iso)\"", html)
        if matches:
            filename = sorted(matches, reverse=True)[0]
            ver_m = re.search(r"ubuntu-(24\.04(?:\.\d+)?)-", filename)
            ver = ver_m.group(1) if ver_m else "24.04"
            return (ver, filename, f"https://releases.ubuntu.com/24.04/{filename}")

        return ("24.04", "ubuntu-24.04-live-server-amd64.iso", "https://releases.ubuntu.com/24.04/ubuntu-24.04-live-server-amd64.iso")

    @staticmethod
    def resolve_debian() -> Tuple[str, str, str]:
        """Queries official Debian current release index."""
        index_url = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/"
        req = urllib.request.Request(index_url, headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=12) as resp:
            html = resp.read().decode("utf-8")

        matches = re.findall(r"href=\"(debian-([0-9\.]+)-amd64-netinst\.iso)\"", html)
        if matches:
            filename, version = matches[0]
            return (version, filename, f"{index_url}{filename}")

        return ("stable", "debian-netinst.iso", "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-netinst.iso")

    @staticmethod
    def resolve_fedora() -> Tuple[str, str, str]:
        """Queries Fedora Workstation download gateway for latest stable Live release."""
        download_page = "https://fedoraproject.org/workstation/download/"
        req = urllib.request.Request(download_page, headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=12) as resp:
            html = resp.read().decode("utf-8")

        matches = re.findall(
            r"(https://download\.fedoraproject\.org/pub/fedora/linux/releases/\d+/Workstation/x86_64/iso/Fedora-Workstation-[^\"]+\.iso)",
            html
        )
        if matches:
            dl_url = matches[0]
            filename = dl_url.split("/")[-1]
            ver_m = re.search(r"releases/(\d+)/", dl_url)
            ver = ver_m.group(1) if ver_m else "latest"
            return (ver, filename, dl_url)

        return ("latest", "Fedora-Workstation-Live-x86_64.iso", "https://download.fedoraproject.org/pub/fedora/linux/releases/41/Workstation/x86_64/iso/Fedora-Workstation-Live-x86_64-41-1.4.iso")


# ------------------------------------------------------------------------------
# 2. Download and Cache Management
# ------------------------------------------------------------------------------

def download_with_progress(url: str, dest_path: Path):
    """Downloads a remote file with resume support and console progress reporting."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = dest_path.with_suffix(".part")

    existing_bytes = temp_path.stat().st_size if temp_path.exists() else 0
    headers = dict(HTTP_HEADERS)
    if existing_bytes > 0:
        headers["Range"] = f"bytes={existing_bytes}-"
        log_info(f"Resuming download from byte {existing_bytes}...")

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            total_size = resp.headers.get("Content-Length")
            if total_size:
                total_bytes = int(total_size) + existing_bytes
            else:
                total_bytes = None

            mode = "ab" if existing_bytes > 0 else "wb"
            downloaded = existing_bytes
            start_time = time.time()
            last_print = 0

            with open(temp_path, mode) as f:
                while True:
                    chunk = resp.read(1024 * 512)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)

                    now = time.time()
                    if now - last_print > 0.4:
                        last_print = now
                        elapsed = now - start_time
                        speed = (downloaded - existing_bytes) / max(elapsed, 0.001) / 1048576
                        if total_bytes:
                            pct = (downloaded / total_bytes) * 100
                            mb_cur = downloaded / 1048576
                            mb_tot = total_bytes / 1048576
                            sys.stdout.write(f"\r  📥 Downloading: {pct:5.1f}% [{mb_cur:6.1f} / {mb_tot:6.1f} MB] ({speed:5.1f} MB/s) ")
                        else:
                            mb_cur = downloaded / 1048576
                            sys.stdout.write(f"\r  📥 Downloading: {mb_cur:6.1f} MB ({speed:5.1f} MB/s) ")
                        sys.stdout.flush()

            sys.stdout.write("\n")
            sys.stdout.flush()

        temp_path.rename(dest_path)
        log_success(f"Downloaded: {dest_path.name} ({dest_path.stat().st_size / 1073741824:.2f} GB)")
    except Exception as e:
        # Fall back to curl if urllib encounters complex redirects or proxy setups
        if shutil.which("curl"):
            log_warn(f"Python download interrupted ({e}). Falling back to curl...")
            cmd = ["curl", "-C", "-", "-L", "--progress-bar", "-o", str(dest_path), url]
            subprocess.run(cmd, check=True)
            log_success(f"Downloaded via curl: {dest_path.name}")
        else:
            raise


def acquire_distro_iso(distro_id: int, force_download: bool = False) -> Tuple[str, Path]:
    """Dynamically resolves, checks local cache, and obtains the latest ISO."""
    resolvers = {
        1: ("CachyOS Desktop Linux", IsoResolver.resolve_cachyos),
        2: ("Arch Linux", IsoResolver.resolve_arch),
        3: ("Ubuntu Desktop 24.04 LTS", IsoResolver.resolve_ubuntu_desktop),
        4: ("Ubuntu Server 24.04 LTS", IsoResolver.resolve_ubuntu_server),
        5: ("Debian (Netinst)", IsoResolver.resolve_debian),
        6: ("Fedora Workstation", IsoResolver.resolve_fedora),
    }

    distro_name, resolver_func = resolvers[distro_id]
    print(f"\n{BOLD}🔍 Checking online upstream for latest {distro_name} release...{NC}")

    try:
        version, filename, download_url = resolver_func()
        log_success(f"Latest upstream release: {BOLD}{version}{NC} ({filename})")
    except Exception as e:
        log_warn(f"Online check failed ({e}). Checking local cache for existing images...")
        version, filename, download_url = ("cached", f"{distro_name.lower().split()[0]}.iso", "")

    # Check cache locations: primary VM/IMAGES, secondary repo cache
    cached_candidates = []
    for c_dir in [DEFAULT_CACHE_DIR, LOCAL_CACHE_DIR]:
        if c_dir.exists():
            exact = c_dir / filename
            if exact.exists() and exact.stat().st_size > 500 * 1024 * 1024:
                cached_candidates.append(exact)

            # Look for prefix matches (e.g. older versions)
            distro_prefix = filename.split("-")[0].lower()
            for f in c_dir.glob(f"*{distro_prefix}*.iso"):
                if f.is_file() and f.stat().st_size > 500 * 1024 * 1024:
                    if f not in cached_candidates:
                        cached_candidates.append(f)

    # If exact cached image exists and not force-downloading
    if cached_candidates and not force_download:
        exact_match = [f for f in cached_candidates if f.name == filename]
        if exact_match:
            chosen = exact_match[0]
            sz_gb = chosen.stat().st_size / (1024 ** 3)
            log_success(f"Using up-to-date cached image: {chosen} ({sz_gb:.2f} GB)")
            return (distro_name, chosen)

        # Older version found in cache
        first = cached_candidates[0]
        log_warn(f"Found existing cached ISO: {first.name}")
        if not download_url:
            return (distro_name, first)
        print(f"  A newer release is available online: {BOLD}{filename}{NC}")
        resp = input("  Download the latest release? [Y/n]: ").strip().lower()
        if resp in ["n", "no"]:
            return (distro_name, first)

    # Need to download
    if not download_url:
        raise RuntimeError(f"No download URL could be determined for {distro_name}")

    target_dir = DEFAULT_CACHE_DIR if DEFAULT_CACHE_DIR.exists() else LOCAL_CACHE_DIR
    target_path = target_dir / filename

    print(f"\n  {YELLOW}📥 Downloading latest {distro_name} ISO...{NC}")
    print(f"     Source:      {download_url}")
    print(f"     Destination: {target_path}\n")

    download_with_progress(download_url, target_path)
    return (distro_name, target_path)


# ------------------------------------------------------------------------------
# 3. System Drive Protection & USB Device Discovery
# ------------------------------------------------------------------------------

def is_disk_protected(dev_path: str) -> bool:
    """Strictly protects internal system disks, NVMe, and partitions holding system mounts."""
    dev_str = str(dev_path)

    # Always strictly protect NVMe drives and primary SATA disk sda
    if re.search(r"^/dev/(nvme|sda)", dev_str):
        return True

    # Check critical system mount points
    critical_mounts = ["/", "/boot", "/boot/efi", "/home",
                       "/run/media/michael/FAST_ARCHIVE",
                       "/run/media/michael/SLOW_ARCHIVE",
                       "/run/media/michael/LARGE_ARCHIVE"]
    for mnt in critical_mounts:
        try:
            res = subprocess.run(["findmnt", "-n", "-o", "SOURCE", mnt], capture_output=True, text=True)
            mnt_src = res.stdout.strip()
            if mnt_src:
                res_pk = subprocess.run(["lsblk", "-n", "-o", "PKNAME", mnt_src], capture_output=True, text=True)
                parent = res_pk.stdout.strip()
                if dev_str == mnt_src or (parent and dev_str == f"/dev/{parent}"):
                    return True
        except Exception:
            pass

    return False


def detect_usb_drives(preselected: Optional[str] = None) -> str:
    """Scans system block devices for eligible USB removable disks."""
    if preselected:
        if not os.path.exists(preselected):
            log_error(f"Specified target device '{preselected}' does not exist.")
            sys.exit(1)
        if is_disk_protected(preselected):
            log_error(f"Target device '{preselected}' is a PROTECTED system disk! Aborting.")
            sys.exit(1)
        return preselected

    print(f"\n{BOLD}Scanning for connected USB removable storage devices...{NC}")
    res = subprocess.run(["lsblk", "-d", "-p", "-n", "-l", "-o", "NAME,TRAN,SIZE,MODEL,RM,HOTPLUG"],
                         capture_output=True, text=True)

    candidates = []
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, tran, sz = parts[0], parts[1], parts[2]
        rm = parts[-2] if len(parts) >= 5 else "0"
        hotplug = parts[-1] if len(parts) >= 5 else "0"
        model = " ".join(parts[3:-2]) if len(parts) >= 6 else "USB Drive"

        if tran == "usb" or rm == "1" or hotplug == "1":
            if not is_disk_protected(dev):
                candidates.append((dev, sz, model, tran))

    if not candidates:
        log_warn("No eligible USB storage drives detected.")
        input("  Please insert your USB flash drive and press [Enter] to re-scan... ")
        return detect_usb_drives()

    print(f"{BOLD}{GREEN}Found {len(candidates)} candidate drive(s):{NC}")
    for idx, (dev, sz, model, tran) in enumerate(candidates, start=1):
        print(f"  {CYAN}[{idx}]{NC} {dev} ({sz}) - {model} [Bus: {tran}]")

    if len(candidates) == 1:
        chosen = candidates[0][0]
        print(f"\n  Auto-selected only available USB drive: {BOLD}{chosen}{NC}")
        return chosen

    while True:
        sel = input(f"Select target USB drive [1-{len(candidates)}]: ").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(candidates):
            return candidates[int(sel) - 1][0]
        print("Invalid selection.")


# ------------------------------------------------------------------------------
# 4. Flashing & Preserving Multi-Volume Layout
# ------------------------------------------------------------------------------

def flash_and_partition(iso_path: Path, target_dev: str):
    """Flashes the ISO and creates a dedicated, visible BOOTSTRAP partition."""
    # Step 1: Unmount existing partitions on target
    log_info(f"Step 1: Unmounting all active partitions on {target_dev}...")
    lsblk_parts = subprocess.run(["lsblk", "-n", "-r", "-o", "PATH", target_dev],
                                 capture_output=True, text=True).stdout.splitlines()
    for p in lsblk_parts:
        if p and p != target_dev:
            subprocess.run(["umount", p], capture_output=True)

    # Step 2: Flash ISO with dd
    log_info(f"Step 2: Flashing ISO to {target_dev} (this may take 1-3 minutes)...")
    subprocess.run(["dd", f"if={iso_path}", f"of={target_dev}", "bs=4M", "status=progress", "conv=fsync"], check=True)
    subprocess.run(["sync"], check=True)

    log_info("Step 3: Probing partition table boundaries...")
    subprocess.run(["udevadm", "settle"], capture_output=True)
    subprocess.run(["partprobe", target_dev], capture_output=True)
    time.sleep(2)

    iso_bytes = iso_path.stat().st_size
    iso_mb = (iso_bytes // (1024 * 1024)) + 16

    # Determine partition table type (GPT or DOS/MBR)
    p_info = subprocess.run(["parted", "-m", target_dev, "print"], capture_output=True, text=True).stdout
    is_gpt = ":gpt:" in p_info

    log_info(f"ISO spans ~{iso_mb} MiB. Configuring partition layout...")

    if is_gpt:
        subprocess.run(["sgdisk", "-e", target_dev], capture_output=True)
        subprocess.run(["partprobe", target_dev], capture_output=True)
        time.sleep(1)
        subprocess.run(["parted", "-s", target_dev, "mkpart", "BOOTSTRAP", "ext4", f"{iso_mb}MiB", "100%"], check=True)
    else:
        # MBR: preserve slot 1 as the ISO installer partition (type 07) and create slot 3 as BOOTSTRAP
        total_sectors = int(Path(f"/sys/class/block/{Path(target_dev).name}/size").read_text().strip())
        start_sector = (iso_mb * 1024 * 1024) // 512
        part_size_sectors = total_sectors - start_sector

        sf_dump = subprocess.run(["sfdisk", "-d", target_dev], capture_output=True, text=True).stdout

        def get_field(part_num: int, field: str, default: str) -> str:
            for line in sf_dump.splitlines():
                if re.search(rf"{target_dev}(p)?{part_num}\b", line):
                    m = re.search(rf"{field}=[ ]*([0-9]+)", line)
                    if m:
                        return m.group(1)
            return default

        p1_start = get_field(1, "start", "64")
        p1_size = get_field(1, "size", "")
        p2_start = get_field(2, "start", "")
        p2_size = get_field(2, "size", "")

        part_prefix = f"{target_dev}p" if target_dev[-1].isdigit() else target_dev

        if p1_size and p2_size:
            sfdisk_script = f"""unit: sectors
{part_prefix}1 : start={p1_start}, size={p1_size}, type=07, bootable
{part_prefix}2 : start={p2_start}, size={p2_size}, type=ef
{part_prefix}3 : start={start_sector}, size={part_size_sectors}, type=83
"""
            subprocess.run(["sfdisk", "--force", target_dev], input=sfdisk_script, text=True,
                           capture_output=True, check=True)
        else:
            subprocess.run(["parted", "-s", target_dev, "mkpart", "primary", "ext4", f"{iso_mb}MiB", "100%"], check=True)

    subprocess.run(["udevadm", "settle"], capture_output=True)
    subprocess.run(["partprobe", target_dev], capture_output=True)
    time.sleep(2)

    # Locate the large BOOTSTRAP data partition
    bootstrap_part = None
    iso_sectors = iso_bytes // 512

    ls_parts = subprocess.run(["lsblk", "-n", "-r", "-o", "PATH,TYPE", target_dev],
                              capture_output=True, text=True).stdout.splitlines()
    for line in ls_parts:
        parts = line.split()
        if len(parts) == 2 and parts[1] == "part":
            p_path = parts[0]
            p_name = Path(p_path).name
            sys_start = Path(f"/sys/class/block/{p_name}/start")
            sys_size = Path(f"/sys/class/block/{p_name}/size")
            if sys_start.exists() and sys_size.exists():
                start = int(sys_start.read_text().strip())
                size_bytes = int(sys_size.read_text().strip()) * 512
                if start >= iso_sectors and size_bytes >= 500 * 1024 * 1024:
                    bootstrap_part = p_path
                    break

    if not bootstrap_part:
        # Fallback to partition with size > 1GB
        for line in ls_parts:
            parts = line.split()
            if len(parts) == 2 and parts[1] == "part":
                p_path = parts[0]
                p_sz = subprocess.run(["lsblk", "-b", "-n", "-d", "-o", "SIZE", p_path],
                                      capture_output=True, text=True).stdout.strip()
                if p_sz.isdigit() and int(p_sz) >= 1024 ** 3:
                    bootstrap_part = p_path
                    break

    if not bootstrap_part:
        raise RuntimeError(f"Could not locate created data partition on {target_dev}")

    log_info(f"Step 4: Formatting {bootstrap_part} as ext4 with label 'BOOTSTRAP'...")
    subprocess.run(["mkfs.ext4", "-F", "-L", "BOOTSTRAP", bootstrap_part], check=True)
    log_success(f"Created partition {bootstrap_part} (LABEL=BOOTSTRAP)")

    return bootstrap_part


# ------------------------------------------------------------------------------
# 5. Populate Recovery Engine & Vaults
# ------------------------------------------------------------------------------

def stage_recovery_payload(bootstrap_part: str, distro_name: str):
    """Mounts the BOOTSTRAP partition and copies all disaster recovery assets."""
    with tempfile.TemporaryDirectory(prefix="usb_bootstrap_") as mnt_dir:
        log_info(f"Step 5: Mounting {bootstrap_part} to {mnt_dir}...")
        subprocess.run(["mount", bootstrap_part, mnt_dir], check=True)
        time.sleep(1)

        try:
            log_info("Step 6: Copying disaster recovery engine and configuration templates...")
            for sub in ["src", "scripts", "config", "data", "docs", "backups"]:
                os.makedirs(os.path.join(mnt_dir, sub), exist_ok=True)

            # Copy core scripts
            for script in ["emergency_restore.sh", "restore.sh"]:
                src_script = REPO_ROOT / script
                if src_script.exists():
                    shutil.copy2(src_script, os.path.join(mnt_dir, script))
                    os.chmod(os.path.join(mnt_dir, script), 0o755)

            # Copy python engine and configs
            subprocess.run([
                "rsync", "-a", "--exclude=__pycache__",
                str(REPO_ROOT / "src") + "/", os.path.join(mnt_dir, "src") + "/"
            ], check=True)

            subprocess.run([
                "rsync", "-a",
                "--exclude=*.iso", "--exclude=*.qcow2", "--exclude=*.img", "--exclude=venv",
                str(REPO_ROOT / "scripts") + "/", os.path.join(mnt_dir, "scripts") + "/"
            ], check=True)

            for item in ["config", "docs"]:
                src_item = REPO_ROOT / item
                if src_item.exists():
                    subprocess.run(["rsync", "-a", str(src_item) + "/", os.path.join(mnt_dir, item) + "/"], check=True)

            for doc in ["README.md", "DISASTER_RECOVERY.md"]:
                doc_path = REPO_ROOT / doc
                if doc_path.exists():
                    shutil.copy2(doc_path, os.path.join(mnt_dir, doc))

            # Locate latest encrypted vault
            log_info("Step 7: Checking for latest encrypted backup vault...")
            latest_vault = None
            for s_dir in [BACKUP_ARCHIVE_DIR, REPO_ROOT / "backup", REPO_ROOT / "data"]:
                if s_dir.exists():
                    candidates = list(s_dir.glob("bootstrap_vault_*.tar.enc")) + list(s_dir.glob("bootstrap_vault_*.tar.zst.enc"))
                    if candidates:
                        candidates.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                        latest_vault = candidates[0]
                        break

            if latest_vault:
                log_info(f"Staging latest encrypted backup vault: {latest_vault.name}")
                shutil.copy2(latest_vault, os.path.join(mnt_dir, "backups", latest_vault.name))
                shutil.copy2(latest_vault, os.path.join(mnt_dir, "backups", "bootstrap_vault_latest.tar.enc"))
                log_success(f"Vault copied to {bootstrap_part}:/backups/{latest_vault.name}")
            else:
                log_warn("No local encrypted backup vault found. Recovery will fall back to cloud/local search.")

            # Create run_restore.sh launcher
            launcher = f"""#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
echo -e "\\033[1;36m======================================================================\\033[0m"
echo -e "\\033[1;36m  🚀 Universal Linux Bootstrap - One-Click Disaster Recovery Launcher \\033[0m"
echo -e "\\033[1;36m======================================================================\\033[0m\\n"

if [ "$EUID" -ne 0 ]; then
    echo "Elevating privileges to root..."
    exec sudo "$DIR/emergency_restore.sh" "$@"
else
    exec "$DIR/emergency_restore.sh" "$@"
fi
"""
            launcher_path = os.path.join(mnt_dir, "run_restore.sh")
            Path(launcher_path).write_text(launcher)
            os.chmod(launcher_path, 0o755)

            # Create README_RECOVERY.txt
            readme_text = f"""======================================================================
UNIVERSAL LINUX BOOTSTRAP - DISASTER RECOVERY DRIVE
======================================================================

This USB drive contains:
  1. Bootable Linux OS Installer ({distro_name})
  2. Standalone Disaster Recovery Engine (Volume: BOOTSTRAP)

----------------------------------------------------------------------
HOW TO RESTORE YOUR SYSTEM:
----------------------------------------------------------------------

[Scenario 1: Fresh Installation on Internal Drive (Recommended)]
  1. Boot this USB drive and install Linux onto your internal SSD/NVMe.
  2. Reboot into your newly installed Linux desktop/server.
  3. Keep this USB drive plugged in.
  4. Open a terminal and run:
       sudo /run/media/$USER/BOOTSTRAP/emergency_restore.sh
       (or cd /run/media/$USER/BOOTSTRAP && sudo ./run_restore.sh)
  5. Enter your vault decryption password when prompted.
  6. The engine will restore your storage mounts (/etc/fstab), Fish/Bash
     dotfiles, SSH/GPG keys, typography (0xProto), and native packages!

[Scenario 2: Standalone Rescue from Live ISO Environment]
  1. Boot this USB into the Live desktop environment.
  2. Open a terminal.
  3. Mount your internal Linux root partition to /mnt:
       sudo mount /dev/nvme0n1p2 /mnt
  4. Mount the BOOTSTRAP partition:
       sudo mkdir -p /mnt/usb
       sudo mount {bootstrap_part} /mnt/usb
  5. Run emergency_restore.sh to restore system state.

======================================================================
"""
            Path(os.path.join(mnt_dir, "README_RECOVERY.txt")).write_text(readme_text)
            subprocess.run(["sync"], check=True)
        finally:
            log_info(f"Unmounting {mnt_dir}...")
            subprocess.run(["sync"], check=True)
            subprocess.run(["umount", mnt_dir], check=False)


def run_pre_provisioning_backup(skip_backup: bool = False):
    """
    Scans the system, generates a fresh encrypted vault, updates restoration scripts,
    and commits/pushes the encrypted vault to git before provisioning media.
    """
    if skip_backup:
        log_info("Skipping pre-provisioning backup scan (--skip-backup requested).")
        return

    print(f"\n{BOLD}🔄 Step 0: Pre-provisioning System Scan, Vault Packaging & Git Sync...{NC}")

    # Determine vault.env location (check SUDO_USER if running as root)
    vault_env_paths = [
        Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "bootstrap" / "vault.env",
    ]
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        vault_env_paths.append(Path(f"/home/{sudo_user}/.config/bootstrap/vault.env"))

    env = os.environ.copy()
    if "BOOTSTRAP_PASSWORD" not in env:
        for v_path in vault_env_paths:
            if v_path.exists():
                log_info(f"Sourcing vault credentials from {v_path}")
                try:
                    for line in v_path.read_text().splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            env[k.strip()] = v.strip().strip("'\"")
                    break
                except Exception as e:
                    log_warn(f"Could not read {v_path}: {e}")

    backup_script = REPO_ROOT / "scripts" / "run_backup.sh"
    if backup_script.exists():
        if sudo_user:
            cmd = ["sudo", "-u", sudo_user, "bash", str(backup_script)]
        else:
            cmd = ["bash", str(backup_script)]

        try:
            res = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, check=False)
            if res.returncode == 0:
                log_success("Pre-provisioning system backup & git sync completed successfully!")
            else:
                log_warn(f"Backup script exited with code {res.returncode}. Continuing with media creation...")
        except Exception as e:
            log_warn(f"Pre-provisioning backup encountered an issue: {e}. Continuing with existing vaults...")
    else:
        log_warn("scripts/run_backup.sh not found. Skipping backup step.")


# ------------------------------------------------------------------------------
# 6. CLI Entrypoint
# ------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Universal Linux Bootstrap - Install & Recovery Media Creator")
    parser.add_argument("--dev", help="Target USB block device (e.g. /dev/sdb)")
    parser.add_argument("--iso", help="Path to local ISO file (skips online query)")
    parser.add_argument("--distro", type=int, choices=range(1, 9), help="Preset distribution number (1-8)")
    parser.add_argument("--confirm", "--yes", "-y", action="store_true", help="Bypass interactive 'YES' confirmation prompt")
    parser.add_argument("--dry-run", action="store_true", help="Simulate drive detection & online queries without writing")
    parser.add_argument("--force-download", action="store_true", help="Force re-download even if ISO is cached")
    parser.add_argument("--skip-backup", action="store_true", help="Skip pre-provisioning system inventory scan & git sync")
    args, unknown = parser.parse_known_args()

    # Handle loose 'confirm' passed as a positional argument
    if "confirm" in unknown or "yes" in unknown:
        args.confirm = True

    print_banner()

    if not args.dry_run and os.geteuid() != 0:
        log_error("This script requires root privileges to partition and format block devices.")
        print(f"   Please run with sudo:\n      {BOLD}sudo python3 {SCRIPT_PATH} {' '.join(sys.argv[1:])}{NC}\n")
        sys.exit(1)

    # Check required system utilities
    for util in ["dd", "sfdisk", "parted", "mkfs.ext4", "rsync", "lsblk"]:
        if not shutil.which(util):
            log_error(f"Missing required utility: {util}")
            sys.exit(1)

    # Distro Selection
    distro_choice = args.distro
    if not distro_choice and not args.iso:
        print(f"{BOLD}Select Linux Installation Media:{NC}")
        print(f"  {CYAN}[1]{NC} CachyOS Desktop Linux (Arch-based, Performance Kernel, KDE)")
        print(f"  {CYAN}[2]{NC} Arch Linux (Official Latest Release)")
        print(f"  {CYAN}[3]{NC} Ubuntu Desktop 24.04 LTS (Noble Numbat)")
        print(f"  {CYAN}[4]{NC} Ubuntu Server 24.04 LTS")
        print(f"  {CYAN}[5]{NC} Debian Stable (Netinst)")
        print(f"  {CYAN}[6]{NC} Fedora Workstation")
        print(f"  {CYAN}[7]{NC} Omarchy (Arch-based)")
        print(f"  {CYAN}[8]{NC} Custom / Local ISO file")
        sel = input("Enter choice [1-8] (default: 1): ").strip()
        distro_choice = int(sel) if sel.isdigit() and 1 <= int(sel) <= 8 else 1

    # Resolve ISO
    if args.iso:
        iso_path = Path(args.iso)
        if not iso_path.exists():
            log_error(f"Specified ISO file does not exist: {iso_path}")
            sys.exit(1)
        distro_name = f"Custom ({iso_path.name})"
    elif distro_choice == 7:
        # Omarchy
        omarchy_cache = DEFAULT_CACHE_DIR / "omarchy-4.0.1.iso"
        if omarchy_cache.exists():
            distro_name, iso_path = "Omarchy 4.0.1", omarchy_cache
        else:
            log_error("Omarchy ISO not found in cache.")
            sys.exit(1)
    elif distro_choice == 8:
        # Custom local ISO
        print(f"\n{BOLD}Cached ISOs in {DEFAULT_CACHE_DIR}:{NC}")
        cached_isos = list(DEFAULT_CACHE_DIR.glob("*.iso")) if DEFAULT_CACHE_DIR.exists() else []
        for i, f in enumerate(cached_isos, start=1):
            print(f"  [{i}] {f.name} ({f.stat().st_size / 1073741824:.2f} GB)")
        custom_input = input("Select cached ISO number or enter custom path: ").strip()
        if custom_input.isdigit() and 1 <= int(custom_input) <= len(cached_isos):
            iso_path = cached_isos[int(custom_input) - 1]
        else:
            iso_path = Path(custom_input)
        if not iso_path.exists():
            log_error(f"File not found: {iso_path}")
            sys.exit(1)
        distro_name = f"Custom ({iso_path.name})"
    else:
        distro_name, iso_path = acquire_distro_iso(distro_choice, force_download=args.force_download)

    # Detect Target USB Drive
    target_dev = detect_usb_drives(preselected=args.dev)

    # Verify drive capacity
    iso_size = iso_path.stat().st_size
    dev_size = int(subprocess.run(["lsblk", "-b", "-n", "-d", "-o", "SIZE", target_dev],
                                  capture_output=True, text=True).stdout.strip() or 0)
    min_required = iso_size + (1500 * 1024 * 1024)

    log_info(f"Target drive capacity: {dev_size / 1073741824:.1f} GB (ISO size: {iso_size / 1073741824:.1f} GB)")
    if dev_size < min_required:
        log_error(f"Target drive {target_dev} is too small ({dev_size / 1073741824:.1f} GB). Minimum required: {min_required / 1073741824:.1f} GB")
        sys.exit(1)

    # Confirmation
    if args.dry_run:
        print(f"\n{BOLD}{YELLOW}[DRY-RUN MODE]{NC} Skipping destructive write.")
        log_success("Dry-run check completed successfully!")
        print(f"   Distro:        {distro_name}")
        print(f"   ISO:           {iso_path}")
        print(f"   Target Device: {target_dev}")
        sys.exit(0)

    if not args.confirm:
        print(f"\n{BOLD}{RED}╔══════════════════════════════════════════════════════════════════════╗{NC}")
        print(f"{BOLD}{RED}║                        ⚠️  DESTRUCTIVE ACTION ⚠️                      ║{NC}")
        print(f"{BOLD}{RED}╠══════════════════════════════════════════════════════════════════════╣{NC}")
        print(f"{BOLD}  Target Device:{NC}  {RED}{BOLD}{target_dev}{NC}")
        print(f"{BOLD}  OS Installer:{NC}   {distro_name} ({iso_path.name})")
        print(f"{BOLD}  All existing data on {target_dev} will be PERMANENTLY ERASED.{NC}")
        print(f"{BOLD}{RED}╚══════════════════════════════════════════════════════════════════════╝{NC}\n")

        conf = input("Type 'YES' (all caps) to proceed with writing: ").strip()
        if conf != "YES":
            print("Operation cancelled by user.")
            sys.exit(0)
    else:
        print(f"\n{BOLD}{YELLOW}⚡ Bypass confirmation active (--confirm/confirm passed). Proceeding with target {target_dev}...{NC}\n")

    # Step 0: Pre-provisioning fresh system scan, vault packaging, and git sync
    run_pre_provisioning_backup(skip_backup=args.skip_backup)

    # Flash and partition
    bootstrap_part = flash_and_partition(iso_path, target_dev)

    # Stage payload
    stage_recovery_payload(bootstrap_part, distro_name)

    print(f"\n{BOLD}{GREEN}======================================================================{NC}")
    print(f"{BOLD}{GREEN}  🎉 USB Installation & Recovery Media Created Successfully!         {NC}")
    print(f"{BOLD}{GREEN}======================================================================{NC}")
    print(f"  Target Drive:      {BOLD}{target_dev}{NC}")
    print(f"  OS Installer:      {BOLD}{distro_name}{NC}")
    print(f"  Recovery Volume:   {BOLD}{bootstrap_part} (LABEL=BOOTSTRAP){NC}")
    print(f"\n  {BOLD}Restoration Instructions:{NC}")
    print(f"    1. Boot PC from USB to install Linux ({distro_name})")
    print("    2. Boot into newly installed system and keep USB inserted")
    print(f"    3. Run: {CYAN}sudo /run/media/$USER/BOOTSTRAP/emergency_restore.sh{NC}")
    print(f"{BOLD}{GREEN}======================================================================{NC}\n")


if __name__ == "__main__":
    main()
