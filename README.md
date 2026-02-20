# Windows ISO Extractor for Qiling / PeMCP

Extract Windows system files (DLLs, registry hives, drivers) from a Windows
ISO image and organize them into the `qiling-rootfs` directory structure
required by the [Qiling](https://github.com/qilingframework/qiling) binary
emulation framework.

Designed for use with [PeMCP](https://github.com/JameZUK/PeMCP) to enable
Windows PE binary emulation and analysis.

## What it does

1. Reads the Windows ISO using `pycdlib`
2. Extracts `install.wim` (or `install.esd`) from the `sources/` directory
3. Uses `wimlib-imagex` to unpack the chosen Windows edition
4. Copies DLLs, drivers, and optionally registry hives into a Qiling-compatible rootfs

For a 64-bit ISO, both `x8664_windows` and `x86_windows` rootfs directories
are created (32-bit DLLs are sourced from `SysWOW64`).

## Using with PeMCP

PeMCP expects the rootfs at `./qiling-rootfs/` (or the path set via
`PEMCP_ROOTFS`). This tool outputs to that location by default.

### Quick setup (Docker)

```bash
# 1. Build the extractor image
docker build -t win-iso-extractor .

# 2. Create the output directory and extract DLLs
mkdir -p qiling-rootfs
docker run --rm \
  -v /path/to/Win10.iso:/data/input.iso:ro \
  -v $(pwd)/qiling-rootfs:/data/rootfs \
  win-iso-extractor /data/input.iso --output /data/rootfs --index 1

# 3. Run PeMCP with the populated rootfs
cd /path/to/PeMCP
PEMCP_ROOTFS=/path/to/qiling-rootfs ./run.sh --mcp
```

Or use `--all-dlls` for maximum compatibility (copies every DLL from
System32, uses more disk space but avoids missing-DLL errors during
emulation):

```bash
mkdir -p qiling-rootfs
docker run --rm \
  -v /path/to/Win10.iso:/data/input.iso:ro \
  -v $(pwd)/qiling-rootfs:/data/rootfs \
  win-iso-extractor /data/input.iso --output /data/rootfs --index 1 --all-dlls
```

### PeMCP docker-compose integration

Point `PEMCP_ROOTFS` at the extracted rootfs in your `.env` or environment:

```bash
export PEMCP_ROOTFS=/path/to/qiling-rootfs
docker compose up
```

PeMCP's `run.sh` and `docker-compose.yml` both mount this directory to
`/app/qiling-rootfs` inside the container automatically.

### Registry hives

PeMCP auto-generates minimal registry hive stubs, so you can safely skip
registry extraction with `--no-registry`. However, if you want real registry
data (richer emulation), omit that flag and the genuine hives from the ISO
will be used instead.

## Quick start with Docker

Build the image once:

```bash
docker build -t win-iso-extractor .
```

List the Windows editions available in an ISO:

```bash
docker run --rm \
  -v /path/to/Win10.iso:/data/input.iso \
  win-iso-extractor /data/input.iso --list
```

Extract to a local `qiling-rootfs/` directory (create it first — the
container runtime requires the bind-mount target to exist on the host):

```bash
mkdir -p qiling-rootfs
docker run --rm \
  -v /path/to/Win10.iso:/data/input.iso:ro \
  -v $(pwd)/qiling-rootfs:/data/rootfs \
  win-iso-extractor /data/input.iso --output /data/rootfs --index 1
```

> **Podman / SELinux users:** If you get `PermissionError` when writing to
> the output directory, add `:Z` to the output volume mount:
> `-v $(pwd)/qiling-rootfs:/data/rootfs:Z`

## Running natively

### Prerequisites

- Python 3.9+
- `wimlib-imagex` (part of wimtools)

Install system dependencies:

```bash
# Debian / Ubuntu
sudo apt-get install wimtools

# Fedora
sudo dnf install wimlib-utils

# macOS (Homebrew)
brew install wimlib
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

### Usage

```
python extract_iso.py <path_to_iso> [options]

positional arguments:
  iso                   Path to the Windows ISO file

options:
  -o, --output DIR      Output directory (default: ./qiling-rootfs)
  -i, --index N         WIM image index to extract
  -l, --list            List available images in the ISO and exit
  --all-dlls            Copy ALL DLLs/EXEs from System32 (maximum compatibility)
  --no-registry         Skip registry hive extraction (PeMCP generates its own)
  --dry-run             Report what would be extracted without writing anything
  --keep-wim            Keep the intermediate WIM file after extraction
  -v, --verbose         Enable debug logging
```

### Examples

```bash
# List editions in the ISO
python extract_iso.py Win10.iso --list

# Extract with interactive edition selection
python extract_iso.py Win10.iso

# Extract a specific edition to a custom directory
python extract_iso.py Win10.iso --output ./my_rootfs --index 1

# Maximum compatibility: all DLLs, skip registry (PeMCP generates stubs)
python extract_iso.py Win10.iso --all-dlls --no-registry

# Preview what would be extracted without copying anything
python extract_iso.py Win10.iso --dry-run --index 1
```

## Output structure

```
qiling-rootfs/
├── x8664_windows/
│   ├── bin/
│   └── Windows/
│       ├── System32/
│       │   ├── drivers/
│       │   ├── ntdll.dll
│       │   ├── kernel32.dll
│       │   └── ...
│       ├── Temp/
│       └── registry/
│           ├── SYSTEM
│           ├── SOFTWARE
│           ├── SAM
│           ├── SECURITY
│           ├── DEFAULT
│           └── NTUSER.DAT
└── x86_windows/
    ├── bin/
    └── Windows/
        ├── System32/
        │   ├── drivers/
        │   ├── ntdll.dll
        │   ├── kernel32.dll
        │   └── ...
        ├── Temp/
        └── registry/
            ├── SYSTEM
            ├── SOFTWARE
            ├── SAM
            ├── SECURITY
            ├── DEFAULT
            └── NTUSER.DAT
```

## Using with Qiling directly

If you're using Qiling without PeMCP:

```python
from qiling import Qiling

ql = Qiling(
    argv=[r"qiling-rootfs/x8664_windows/bin/your_target.exe"],
    rootfs="qiling-rootfs/x8664_windows",
)
ql.run()
```

Copy the binary you want to emulate into the `bin/` directory within the
appropriate rootfs. Any additional DLLs your target needs should be placed in
`Windows/System32/`.

## License

MIT
