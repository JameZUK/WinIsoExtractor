#!/usr/bin/env python3
"""
Windows ISO Extractor for Qiling Framework / PeMCP

Extracts Windows system files (DLLs, registry hives, etc.) from a Windows ISO
image and organizes them into the rootfs directory structure expected by the
Qiling binary emulation framework.  Designed for use with PeMCP
(https://github.com/JameZUK/PeMCP) to enable Windows PE emulation.

Usage:
    python extract_iso.py <path_to_iso> [--output <output_dir>] [--index <wim_index>]
"""

import argparse
import logging
import os
import shutil
import subprocess
import sys
import tempfile

try:
    import pycdlib
except ImportError:
    print("Error: pycdlib is required. Install it with: pip install pycdlib")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Files required by Qiling for each architecture
# ---------------------------------------------------------------------------

# 32-bit DLLs (placed in x86_windows/Windows/System32/)
# Sourced from SysWOW64 on 64-bit ISOs, System32 on 32-bit ISOs.
DLLS_X86 = [
    "advapi32.dll",
    "bcrypt.dll",
    "cabinet.dll",
    "cfgmgr32.dll",
    "ci.dll",
    "clbcatq.dll",
    "combase.dll",
    "comctl32.dll",
    "comdlg32.dll",
    "crypt32.dll",
    "cryptbase.dll",
    "dnsapi.dll",
    "gdi32.dll",
    "gdi32full.dll",
    "hal.dll",
    "imm32.dll",
    "iphlpapi.dll",
    "kdcom.dll",
    "kernel32.dll",
    "KernelBase.dll",
    "mpr.dll",
    "mscoree.dll",
    "msvcp_win.dll",
    "msvcp60.dll",
    "msvcr120_clr0400.dll",
    "msvcr110.dll",
    "msvcrt.dll",
    "mswsock.dll",
    "netapi32.dll",
    "nsi.dll",
    "ntdll.dll",
    "ole32.dll",
    "oleaut32.dll",
    "psapi.dll",
    "rpcrt4.dll",
    "sechost.dll",
    "setupapi.dll",
    "shell32.dll",
    "shlwapi.dll",
    "sspicli.dll",
    "ucrtbase.dll",
    "urlmon.dll",
    "user32.dll",
    "userenv.dll",
    "uxtheme.dll",
    "vcruntime140.dll",
    "version.dll",
    "win32u.dll",
    "winhttp.dll",
    "wininet.dll",
    "winmm.dll",
    "wintrust.dll",
    "ws2_32.dll",
    "wsock32.dll",
    # API Set / Downlevel DLLs (extras are auto-collected by copy_dlls)
    "api-ms-win-core-fibers-l1-1-1.dll",
    "api-ms-win-core-localization-l1-2-1.dll",
    "api-ms-win-core-synch-l1-2-0.dll",
    "api-ms-win-core-sysinfo-l1-2-1.dll",
    "api-ms-win-crt-heap-l1-1-0.dll",
    "api-ms-win-crt-locale-l1-1-0.dll",
    "api-ms-win-crt-math-l1-1-0.dll",
    "api-ms-win-crt-runtime-l1-1-0.dll",
    "api-ms-win-crt-stdio-l1-1-0.dll",
]

# 64-bit DLLs (placed in x8664_windows/Windows/System32/)
DLLS_X64 = [
    "advapi32.dll",
    "bcrypt.dll",
    "cabinet.dll",
    "cfgmgr32.dll",
    "ci.dll",
    "clbcatq.dll",
    "combase.dll",
    "comctl32.dll",
    "comdlg32.dll",
    "crypt32.dll",
    "cryptbase.dll",
    "dnsapi.dll",
    "gdi32.dll",
    "gdi32full.dll",
    "hal.dll",
    "imm32.dll",
    "iphlpapi.dll",
    "kdcom.dll",
    "kernel32.dll",
    "KernelBase.dll",
    "mpr.dll",
    "mscoree.dll",
    "msvcp_win.dll",
    "msvcp60.dll",
    "msvcr120_clr0400.dll",
    "msvcr110.dll",
    "msvcrt.dll",
    "mswsock.dll",
    "netapi32.dll",
    "nsi.dll",
    "ntdll.dll",
    "ntoskrnl.exe",
    "ole32.dll",
    "oleaut32.dll",
    "psapi.dll",
    "rpcrt4.dll",
    "sechost.dll",
    "setupapi.dll",
    "shell32.dll",
    "shlwapi.dll",
    "sspicli.dll",
    "ucrtbase.dll",
    "urlmon.dll",
    "user32.dll",
    "userenv.dll",
    "uxtheme.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "version.dll",
    "win32u.dll",
    "winhttp.dll",
    "wininet.dll",
    "winmm.dll",
    "wintrust.dll",
    "ws2_32.dll",
    "wsock32.dll",
    # API Set / Downlevel DLLs (extras are auto-collected by copy_dlls)
    "api-ms-win-core-fibers-l1-1-1.dll",
    "api-ms-win-core-localization-l1-2-1.dll",
    "api-ms-win-core-synch-l1-2-0.dll",
    "api-ms-win-core-sysinfo-l1-2-1.dll",
    "api-ms-win-crt-heap-l1-1-0.dll",
    "api-ms-win-crt-locale-l1-1-0.dll",
    "api-ms-win-crt-math-l1-1-0.dll",
    "api-ms-win-crt-runtime-l1-1-0.dll",
    "api-ms-win-crt-stdio-l1-1-0.dll",
]

# Registry hives needed by Qiling (source path relative to Windows root)
REGISTRY_HIVES = {
    "Windows/System32/config/SYSTEM": "SYSTEM",
    "Windows/System32/config/SOFTWARE": "SOFTWARE",
    "Windows/System32/config/SECURITY": "SECURITY",
    "Windows/System32/config/SAM": "SAM",
    "Windows/System32/config/DEFAULT": "DEFAULT",
}

NTUSER_SOURCE = "Users/Default/NTUSER.DAT"
NTUSER_DEST = "NTUSER.DAT"


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def check_wimlib():
    """Verify that wimlib-imagex is available on the system."""
    if shutil.which("wimlib-imagex") is None:
        log.error(
            "wimlib-imagex not found. Install it with:\n"
            "  Debian/Ubuntu: apt-get install wimtools\n"
            "  Fedora:        dnf install wimlib-utils\n"
            "  macOS (brew):  brew install wimlib\n"
            "  Or use the provided Dockerfile."
        )
        sys.exit(1)


def find_case_insensitive(base_dir, rel_path):
    """Walk *base_dir* resolving *rel_path* component-by-component in a
    case-insensitive manner.  Returns the real path on disk or ``None``."""
    parts = rel_path.replace("\\", "/").strip("/").split("/")
    current = base_dir
    for part in parts:
        part_lower = part.lower()
        found = False
        try:
            entries = os.listdir(current)
        except OSError:
            return None
        for entry in entries:
            if entry.lower() == part_lower:
                current = os.path.join(current, entry)
                found = True
                break
        if not found:
            return None
    return current


# ---------------------------------------------------------------------------
# ISO extraction
# ---------------------------------------------------------------------------


def _strip_iso_version(name):
    """Remove the ISO 9660 / Joliet version suffix (e.g. ';1') from a filename."""
    idx = name.rfind(";")
    if idx != -1:
        return name[:idx]
    return name


def extract_wim_from_iso(iso_path, dest_dir):
    """Open *iso_path* with pycdlib and extract the install.wim (or
    install.esd) to *dest_dir*.  Returns the path to the extracted file."""

    iso = pycdlib.PyCdlib()
    iso.open(iso_path)

    try:
        # Prefer UDF, then Joliet, then plain ISO9660 for long file names.
        if iso.has_udf():
            facade = iso.list_children(udf_path="/sources")
            source_prefix = "/sources/"
            use = "udf"
        elif iso.has_joliet():
            facade = iso.list_children(joliet_path="/sources")
            source_prefix = "/sources/"
            use = "joliet"
        else:
            facade = iso.list_children(iso_path="/SOURCES")
            source_prefix = "/SOURCES/"
            use = "iso"

        wim_name = None
        for child in facade:
            if use == "udf":
                name = child.file_identifier().decode("utf-8", errors="replace")
            elif use == "joliet":
                raw = child.file_identifier().decode("utf-16-be", errors="replace")
                name = _strip_iso_version(raw).rstrip("\x00")
            else:
                raw = child.file_identifier().decode("ascii", errors="replace")
                name = _strip_iso_version(raw)

            name_lower = name.lower()
            if name_lower in ("install.wim", "install.esd"):
                wim_name = name
                break

        if wim_name is None:
            log.error(
                "Could not find install.wim or install.esd inside the ISO. "
                "Is this a valid Windows installation ISO?"
            )
            sys.exit(1)

        dest_path = os.path.join(dest_dir, wim_name)
        log.info("Extracting %s from ISO (this may take a while) ...", wim_name)

        if use == "udf":
            iso.udf_get_file_from_iso(dest_path, udf_path=source_prefix + wim_name)
        elif use == "joliet":
            iso.get_file_from_iso(dest_path, joliet_path=source_prefix + wim_name)
        else:
            # ISO 9660 paths need the version suffix for pycdlib lookups
            iso_name = wim_name.upper()
            if ";" not in iso_name:
                iso_name += ";1"
            iso.get_file_from_iso(dest_path, iso_path=source_prefix + iso_name)
    finally:
        iso.close()

    log.info("Extracted %s (%d MB)", wim_name, os.path.getsize(dest_path) // (1024 * 1024))
    return dest_path


# ---------------------------------------------------------------------------
# WIM handling
# ---------------------------------------------------------------------------


def list_wim_images(wim_path):
    """Return a list of (index, name, description) tuples for the images
    inside the WIM file."""
    result = subprocess.run(
        ["wimlib-imagex", "info", wim_path],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log.error("wimlib-imagex info failed:\n%s", result.stderr)
        sys.exit(1)

    images = []
    current_index = None
    current_name = ""
    current_desc = ""

    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Index:"):
            if current_index is not None:
                images.append((current_index, current_name, current_desc))
            current_index = int(line.split(":", 1)[1].strip())
            current_name = ""
            current_desc = ""
        elif line.startswith("Name:"):
            current_name = line.split(":", 1)[1].strip()
        elif line.startswith("Description:"):
            current_desc = line.split(":", 1)[1].strip()

    if current_index is not None:
        images.append((current_index, current_name, current_desc))

    return images


def extract_wim_image(wim_path, index, dest_dir):
    """Extract a single image from the WIM file to *dest_dir*."""
    log.info(
        "Extracting WIM image index %d to %s (this may take several minutes) ...",
        index,
        dest_dir,
    )
    # Stream stderr so the user can see wimlib's progress output
    proc = subprocess.Popen(
        ["wimlib-imagex", "apply", wim_path, str(index), dest_dir],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _, stderr = proc.communicate()
    if proc.returncode != 0:
        log.error("wimlib-imagex apply failed:\n%s", stderr.decode(errors="replace"))
        sys.exit(1)
    log.info("WIM image extracted successfully.")


# ---------------------------------------------------------------------------
# Detect architecture from the extracted Windows image
# ---------------------------------------------------------------------------


def detect_architecture(wim_root):
    """Heuristic: if 64-bit ntdll.dll exists, it's x64.  Checks for the
    presence of SysWOW64 as another indicator."""
    syswow64 = find_case_insensitive(wim_root, "Windows/SysWOW64")
    if syswow64 and os.path.isdir(syswow64):
        return "x64"

    # Check the PE header of ntdll.dll
    ntdll = find_case_insensitive(wim_root, "Windows/System32/ntdll.dll")
    if ntdll and os.path.isfile(ntdll):
        try:
            with open(ntdll, "rb") as f:
                # Read DOS header to find PE offset
                f.seek(0x3C)
                buf = f.read(4)
                if len(buf) < 4:
                    log.debug("ntdll.dll too small to read PE offset")
                else:
                    pe_offset = int.from_bytes(buf, "little")
                    f.seek(pe_offset + 4)  # skip PE signature
                    buf = f.read(2)
                    if len(buf) < 2:
                        log.debug("ntdll.dll truncated at COFF machine field")
                    else:
                        machine = int.from_bytes(buf, "little")
                        if machine == 0x8664:
                            return "x64"
                        elif machine == 0x014C:
                            return "x86"
        except OSError:
            pass

    return "x64"  # default assumption


# ---------------------------------------------------------------------------
# Build the Qiling rootfs
# ---------------------------------------------------------------------------


def copy_file_ci(wim_root, rel_src, dest_path):
    """Copy a file from the extracted WIM using case-insensitive lookup.
    Returns True on success."""
    src = find_case_insensitive(wim_root, rel_src)
    if src and os.path.isfile(src):
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        shutil.copy2(src, dest_path)
        return True
    return False


def copy_dlls(wim_root, src_dir_rel, dll_list, dest_sys32, *, all_dlls=False,
              dry_run=False):
    """Copy the required DLLs.  When *all_dlls* is True, copy every DLL and
    EXE from the source directory for maximum emulation compatibility.
    Otherwise copy only the known-required list plus any api-ms-win-* stubs.
    When *dry_run* is True, count files without copying."""
    if not dry_run:
        os.makedirs(dest_sys32, exist_ok=True)

    copied = 0
    missing = []
    src_dir = find_case_insensitive(wim_root, src_dir_rel)
    if src_dir is None or not os.path.isdir(src_dir):
        log.warning("Source directory %s not found in WIM image.", src_dir_rel)
        return 0, dll_list

    # Build a case-insensitive map of files in the source directory
    available = {}
    try:
        for entry in os.listdir(src_dir):
            available[entry.lower()] = entry
    except OSError:
        pass

    if all_dlls:
        # Copy every DLL, EXE, and related PE file from the directory
        dll_count = 0
        exe_count = 0
        for name_lower, real_name in available.items():
            if name_lower.endswith((".dll", ".drv", ".ocx", ".cpl")):
                src = os.path.join(src_dir, real_name)
                if os.path.isfile(src):
                    if not dry_run:
                        shutil.copy2(src, os.path.join(dest_sys32, real_name))
                    dll_count += 1
            elif name_lower.endswith(".exe"):
                src = os.path.join(src_dir, real_name)
                if os.path.isfile(src):
                    if not dry_run:
                        shutil.copy2(src, os.path.join(dest_sys32, real_name))
                    exe_count += 1
        copied = dll_count + exe_count
        log.info("    --all-dlls: %d DLLs + %d EXEs%s",
                 dll_count, exe_count, " (dry run)" if dry_run else " copied")
        return copied, []

    for dll in dll_list:
        real_name = available.get(dll.lower())
        if real_name:
            src = os.path.join(src_dir, real_name)
            if not dry_run:
                dst = os.path.join(dest_sys32, dll)
                shutil.copy2(src, dst)
            copied += 1
        else:
            missing.append(dll)

    # Additionally copy any api-ms-win-* DLLs not in the explicit list
    already = {d.lower() for d in dll_list}
    for name_lower, real_name in available.items():
        if name_lower.startswith("api-ms-win-") and name_lower.endswith(".dll"):
            if name_lower not in already:
                if not dry_run:
                    dst = os.path.join(dest_sys32, real_name)
                    if not os.path.exists(dst):
                        shutil.copy2(os.path.join(src_dir, real_name), dst)
                copied += 1

    return copied, missing


def copy_drivers(wim_root, src_dir_rel, dest_drivers, *, dry_run=False):
    """Copy common driver files (.sys) needed for kernel-mode emulation."""
    if not dry_run:
        os.makedirs(dest_drivers, exist_ok=True)
    src_dir = find_case_insensitive(wim_root, src_dir_rel)
    if src_dir is None or not os.path.isdir(src_dir):
        return 0
    copied = 0
    try:
        for entry in os.listdir(src_dir):
            if entry.lower().endswith(".sys"):
                if not dry_run:
                    shutil.copy2(os.path.join(src_dir, entry), os.path.join(dest_drivers, entry))
                copied += 1
    except OSError:
        pass
    return copied


def copy_registry_hives(wim_root, dest_registry, *, dry_run=False):
    """Copy registry hive files into the Qiling registry directory."""
    if not dry_run:
        os.makedirs(dest_registry, exist_ok=True)
    copied = 0

    for src_rel, dest_name in REGISTRY_HIVES.items():
        src = find_case_insensitive(wim_root, src_rel)
        if src and os.path.isfile(src):
            if not dry_run:
                copy_file_ci(wim_root, src_rel, os.path.join(dest_registry, dest_name))
            log.info("  Registry hive: %s -> %s", src_rel, dest_name)
            copied += 1
        else:
            log.warning("  Registry hive NOT found: %s", src_rel)

    # NTUSER.DAT
    ntuser_src = find_case_insensitive(wim_root, NTUSER_SOURCE)
    if ntuser_src and os.path.isfile(ntuser_src):
        if not dry_run:
            copy_file_ci(wim_root, NTUSER_SOURCE, os.path.join(dest_registry, NTUSER_DEST))
        log.info("  Registry hive: %s -> %s", NTUSER_SOURCE, NTUSER_DEST)
        copied += 1
    else:
        log.warning("  NTUSER.DAT not found at %s", NTUSER_SOURCE)

    return copied


def build_rootfs(wim_root, output_dir, arch, *, all_dlls=False,
                 no_registry=False, dry_run=False):
    """Construct the Qiling rootfs directory tree from an extracted Windows
    image at *wim_root*.

    When *all_dlls* is True every DLL/EXE in System32 / SysWOW64 is copied
    for maximum emulation coverage.  When *no_registry* is True, registry
    hives are skipped (PeMCP auto-generates its own stubs).  When *dry_run*
    is True, report what would be extracted without writing anything.
    """
    verb = "found" if dry_run else "copied"

    if arch == "x64":
        rootfs_x64 = os.path.join(output_dir, "x8664_windows")
        rootfs_x86 = os.path.join(output_dir, "x86_windows")

        # --- x86_64 rootfs ---
        log.info("Building x8664_windows rootfs ...")
        sys32_x64 = os.path.join(rootfs_x64, "Windows", "System32")
        drivers_x64 = os.path.join(sys32_x64, "drivers")
        reg_x64 = os.path.join(rootfs_x64, "Windows", "registry")
        if not dry_run:
            os.makedirs(os.path.join(rootfs_x64, "Windows", "Temp"), exist_ok=True)
            os.makedirs(os.path.join(rootfs_x64, "bin"), exist_ok=True)

        copied, missing = copy_dlls(
            wim_root, "Windows/System32", DLLS_X64, sys32_x64,
            all_dlls=all_dlls, dry_run=dry_run,
        )
        log.info("  64-bit DLLs %s: %d, missing: %d", verb, copied, len(missing))
        if missing:
            log.warning("  Missing 64-bit DLLs: %s", ", ".join(missing))

        drv = copy_drivers(wim_root, "Windows/System32/drivers", drivers_x64,
                           dry_run=dry_run)
        log.info("  64-bit drivers %s: %d", verb, drv)

        if not no_registry:
            log.info("  Copying registry hives for x8664 ...")
            copy_registry_hives(wim_root, reg_x64, dry_run=dry_run)

        # --- x86 rootfs (from SysWOW64) ---
        log.info("Building x86_windows rootfs (from SysWOW64) ...")
        sys32_x86 = os.path.join(rootfs_x86, "Windows", "System32")
        drivers_x86 = os.path.join(sys32_x86, "drivers")
        reg_x86 = os.path.join(rootfs_x86, "Windows", "registry")
        if not dry_run:
            os.makedirs(os.path.join(rootfs_x86, "Windows", "Temp"), exist_ok=True)
            os.makedirs(os.path.join(rootfs_x86, "bin"), exist_ok=True)

        copied, missing = copy_dlls(
            wim_root, "Windows/SysWOW64", DLLS_X86, sys32_x86,
            all_dlls=all_dlls, dry_run=dry_run,
        )
        log.info("  32-bit DLLs %s: %d, missing: %d", verb, copied, len(missing))
        if missing:
            log.warning("  Missing 32-bit DLLs: %s", ", ".join(missing))

        drv = copy_drivers(wim_root, "Windows/SysWOW64/drivers", drivers_x86,
                           dry_run=dry_run)
        if drv == 0:
            drv = copy_drivers(wim_root, "Windows/System32/drivers", drivers_x86,
                               dry_run=dry_run)
        log.info("  32-bit drivers %s: %d", verb, drv)

        if not no_registry:
            log.info("  Copying registry hives for x86 ...")
            copy_registry_hives(wim_root, reg_x86, dry_run=dry_run)

    else:
        # 32-bit only ISO
        rootfs_x86 = os.path.join(output_dir, "x86_windows")

        log.info("Building x86_windows rootfs ...")
        sys32 = os.path.join(rootfs_x86, "Windows", "System32")
        drivers = os.path.join(sys32, "drivers")
        reg = os.path.join(rootfs_x86, "Windows", "registry")
        if not dry_run:
            os.makedirs(os.path.join(rootfs_x86, "Windows", "Temp"), exist_ok=True)
            os.makedirs(os.path.join(rootfs_x86, "bin"), exist_ok=True)

        copied, missing = copy_dlls(
            wim_root, "Windows/System32", DLLS_X86, sys32,
            all_dlls=all_dlls, dry_run=dry_run,
        )
        log.info("  32-bit DLLs %s: %d, missing: %d", verb, copied, len(missing))
        if missing:
            log.warning("  Missing 32-bit DLLs: %s", ", ".join(missing))

        drv = copy_drivers(wim_root, "Windows/System32/drivers", drivers,
                           dry_run=dry_run)
        log.info("  32-bit drivers %s: %d", verb, drv)

        if not no_registry:
            log.info("  Copying registry hives ...")
            copy_registry_hives(wim_root, reg, dry_run=dry_run)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Extract Windows system files from an ISO for the Qiling framework rootfs.\n"
            "Designed for use with PeMCP (https://github.com/JameZUK/PeMCP)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s Win10.iso\n"
            "  %(prog)s Win10.iso --output ./qiling-rootfs --index 1\n"
            "  %(prog)s Win10.iso --all-dlls\n"
            "  %(prog)s Win10.iso --list\n"
        ),
    )
    parser.add_argument("iso", help="Path to the Windows ISO file")
    parser.add_argument(
        "-o",
        "--output",
        default="qiling-rootfs",
        help="Output directory for the Qiling rootfs (default: ./qiling-rootfs)",
    )
    parser.add_argument(
        "-i",
        "--index",
        type=int,
        default=None,
        help="WIM image index to extract (default: auto-select or prompt)",
    )
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        dest="list_images",
        help="List available images in the ISO and exit",
    )
    parser.add_argument(
        "--all-dlls",
        action="store_true",
        help="Copy ALL DLLs/EXEs from System32 (not just the known-required set). "
        "Uses more disk space but gives maximum emulation compatibility.",
    )
    parser.add_argument(
        "--no-registry",
        action="store_true",
        help="Skip extracting registry hives. PeMCP auto-generates its own "
        "registry stubs, so this is safe when using PeMCP.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Extract the WIM and report what would be copied, without "
        "writing anything to the output directory.",
    )
    parser.add_argument(
        "--keep-wim",
        action="store_true",
        help="Keep the intermediate extracted WIM file (not deleted after use)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not os.path.isfile(args.iso):
        log.error("ISO file not found: %s", args.iso)
        sys.exit(1)

    check_wimlib()

    # --- Step 1: Extract install.wim / install.esd from the ISO -----------
    tmpdir = tempfile.mkdtemp(prefix="winiso_")
    try:
        wim_path = extract_wim_from_iso(args.iso, tmpdir)

        # --- Step 2: List / select the WIM image index --------------------
        images = list_wim_images(wim_path)
        if not images:
            log.error("No images found in the WIM file.")
            sys.exit(1)

        if args.list_images:
            print("\nAvailable images in the WIM:\n")
            for idx, name, desc in images:
                print(f"  Index {idx}: {name}")
                if desc:
                    print(f"            {desc}")
            sys.exit(0)

        if args.index is not None:
            index = args.index
            valid_indices = [i for i, _, _ in images]
            if index not in valid_indices:
                log.error(
                    "Invalid index %d. Available indices: %s",
                    index,
                    ", ".join(str(i) for i in valid_indices),
                )
                sys.exit(1)
        elif len(images) == 1:
            index = images[0][0]
            log.info("Single image found: %s (index %d)", images[0][1], index)
        else:
            print("\nMultiple Windows editions found in the ISO:\n")
            for idx, name, desc in images:
                print(f"  [{idx}] {name}")
                if desc:
                    print(f"      {desc}")
            print()
            try:
                choice = input("Select an image index [1]: ").strip()
                index = int(choice) if choice else 1
            except (ValueError, EOFError):
                index = 1
            valid_indices = [i for i, _, _ in images]
            if index not in valid_indices:
                log.error("Invalid selection. Exiting.")
                sys.exit(1)

        # --- Step 3: Extract the WIM image --------------------------------
        wim_extract_dir = os.path.join(tmpdir, "wimroot")
        os.makedirs(wim_extract_dir, exist_ok=True)
        extract_wim_image(wim_path, index, wim_extract_dir)

        if not args.keep_wim:
            os.remove(wim_path)
            log.debug("Removed intermediate WIM file.")

        # --- Step 4: Detect architecture and build rootfs -----------------
        arch = detect_architecture(wim_extract_dir)
        log.info("Detected architecture: %s", arch)

        output_dir = os.path.abspath(args.output)
        if not args.dry_run:
            os.makedirs(output_dir, exist_ok=True)

        build_rootfs(
            wim_extract_dir,
            output_dir,
            arch,
            all_dlls=args.all_dlls,
            no_registry=args.no_registry,
            dry_run=args.dry_run,
        )

        log.info("=" * 60)
        if args.dry_run:
            log.info("DRY RUN complete -- no files were written")
            log.info("Output would be: %s", output_dir)
        else:
            log.info("Qiling rootfs created at: %s", output_dir)
        if args.all_dlls:
            log.info("Mode: ALL DLLs copied for maximum compatibility")
        log.info("=" * 60)

        # Print summary of what was created
        if not args.dry_run:
            for dirpath, dirnames, filenames in os.walk(output_dir):
                depth = dirpath.replace(output_dir, "").count(os.sep)
                if depth <= 3:
                    indent = "  " * depth
                    rel = os.path.relpath(dirpath, output_dir)
                    file_count = len(filenames)
                    if file_count > 0:
                        log.info("%s%s/ (%d files)", indent, rel, file_count)

    finally:
        # Clean up temp directory
        if os.path.exists(tmpdir):
            shutil.rmtree(tmpdir, ignore_errors=True)
            log.debug("Cleaned up temporary directory: %s", tmpdir)


if __name__ == "__main__":
    main()
