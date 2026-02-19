# Windows ISO Extractor for Qiling Framework

Extract Windows system files (DLLs, registry hives, drivers) from a Windows
ISO image and organize them into the `rootfs` directory structure required by
the [Qiling](https://github.com/qilingframework/qiling) binary emulation
framework.

## What it does

1. Reads the Windows ISO using `pycdlib`
2. Extracts `install.wim` (or `install.esd`) from the `sources/` directory
3. Uses `wimlib-imagex` to unpack the chosen Windows edition
4. Copies the required DLLs, registry hives, and drivers into a Qiling-compatible rootfs layout

For a 64-bit ISO, both `x8664_windows` and `x86_windows` rootfs directories
are created (32-bit DLLs are sourced from `SysWOW64`).

## Quick start with Docker (recommended)

Build the image once:

```bash
docker build -t win-iso-extractor .
```

List the Windows editions available in an ISO:

```bash
docker run --rm -v /path/to/Win10.iso:/data/input.iso win-iso-extractor /data/input.iso --list
```

Extract to a local `rootfs/` directory:

```bash
docker run --rm \
  -v /path/to/Win10.iso:/data/input.iso:ro \
  -v $(pwd)/rootfs:/data/rootfs \
  win-iso-extractor /data/input.iso --output /data/rootfs --index 1
```

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
  -o, --output DIR      Output directory (default: ./rootfs)
  -i, --index N         WIM image index to extract
  -l, --list            List available images in the ISO and exit
  --keep-wim            Keep the intermediate WIM file after extraction
  -v, --verbose         Enable debug logging
```

### Examples

```bash
# List editions in the ISO
python extract_iso.py Win10.iso --list

# Extract with interactive edition selection
python extract_iso.py Win10.iso

# Extract a specific edition (index 1) to a custom directory
python extract_iso.py Win10.iso --output ./my_rootfs --index 1
```

## Output structure

```
rootfs/
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

## Using with Qiling

Once extracted, point Qiling at the rootfs:

```python
from qiling import Qiling

ql = Qiling(
    argv=[r"rootfs/x8664_windows/bin/your_target.exe"],
    rootfs="rootfs/x8664_windows",
)
ql.run()
```

Copy the binary you want to emulate into the `bin/` directory within the
appropriate rootfs. Any additional DLLs your target needs should be placed in
`Windows/System32/`.

## License

MIT
