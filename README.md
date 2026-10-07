# pe2bin

[![All rights reserved](https://img.shields.io/badge/license-all%20rights%20reserved-red.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![Stdlib only](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](requirements.txt)

**Convert a Windows PE (`.exe` / `.dll`) into a raw flat binary blob.**

Pick the layout your consumer expects — a memory image for a manual-map / payload
loader, a verbatim file copy, or headers-stripped section bytes with an offset map.

- **Python ≥ 3.8, standard library only** — no third-party packages to install
- **Offline by design** — no network, no subprocess, never executes the input,
  no persistence, no auto-execution; writes only to the `--output` path you name
- **Overwrite-gated** — refuses to clobber an existing file without `--force`
- **Hardened parser** — bounds-checked reads, hostile-header guards,
  `SizeOfImage` repair, truncated-section clamping, 2 GiB allocation cap
- **Honest report** — SHA-256 of input and output, plus every anomaly the binary
  shows (overlaps, packed-style headers, dropped overlay) as warnings

## Modes

| Mode | Layout | Use when |
|---|---|---|
| `image` **(default)** | headers at offset 0, each section at its `VirtualAddress`, zero-filled to `SizeOfImage` | your loader copies the blob into a `SizeOfImage` allocation, applies relocations + imports, then jumps to the entry point |
| `file` | verbatim input bytes (`PointerToRawData` layout, overlay/Authenticode intact) | your loader parses the PE itself and maps sections from the file headers |
| `sections` | headers stripped, section raw data concatenated in `VirtualAddress` order | you want pure payload bytes — the JSON report gives you every section's `output_offset` |

```
image mode output                    file mode output      sections mode output
┌─────────────────────┐              ┌──────────────────┐   ┌──────────────────┐
│ PE headers (0x0000) │              │ identical bytes  │   │ .text            │
├─────────────────────┤              │ of the input     │   │ .rdata           │
│ .text  @ VA         │              │ file,            │   │ .data            │
├─────────────────────┤              │ including        │   │ ...concatenated  │
│ .rdata @ VA         │              │ overlay          │   │ in VA order      │
├─────────────────────┤              └──────────────────┘   │ (no headers)     │
│ .data  @ VA         │                                      └──────────────────┘
│ … zero-pad …         │
└─────────────────────┘
total = SizeOfImage
```

## Quick start

```bash
# 1. Default: raw PE image for a payload loader
python pe2bin.py {{TARGET_EXE}} -o {{OUTPUT_BIN}}

# 2. Verbatim bytes, overwrite an existing output
python pe2bin.py {{TARGET_DLL}} -o out\{{TARGET_DLL}}.bin --mode file --force

# 3. Headers-stripped section dump + machine-readable report
python pe2bin.py {{TARGET_EXE}} -o {{OUTPUT_BIN}} --mode sections --json > report.json
```

No installation step — run `pe2bin.py` directly from the repo.

## CLI

```
pe2bin INPUT -o OUTPUT [--mode image|file|sections] [--force] [--json] [--quiet]
```

| Flag | Description |
|---|---|
| `INPUT` | path to the input `.exe` / `.dll` (positional) |
| `-o, --output` | **required** — path of the `.bin` to write (parent dirs are created) |
| `-m, --mode` | `image` (default) · `file` · `sections` — aliases: `raw`/`memory`, `verbatim`/`copy`, `noheaders` |
| `-f, --force` | overwrite the output if it exists |
| `--json` | full report as JSON on stdout; errors as JSON on stderr |
| `-q, --quiet` | suppress the human-readable summary |
| `--version` | print version |

**Exit codes:** `0` success · `1` internal · `2` format/validation · `3` I/O · `4` path conflict.

## Report (what your loader needs)

```bash
python pe2bin.py target.dll -o target.bin --json
```

```jsonc
{
  "status": "OK",
  "mode": "image",
  "input":  { "path": "...", "size": 204800, "sha256": "..." },
  "output": { "path": "...", "size": 208896, "sha256": "..." },
  "pe": {
    "arch": "x64", "bits": 64, "is_dll": true,
    "image_base": 140737488355328,      // "*_hex" fields also provided
    "entry_rva": 40960,
    "size_of_image_effective": 208896,  // validated value the blob actually uses
    "has_relocs": true,                 // relocate if you map at a different base
    "is_managed_dotnet": false,         // .NET -> needs a CLR host, not raw exec
    "has_authenticode_signature": false,
    "sections": [
      { "name": ".text", "virtual_address": 4096, "raw_size": 90112,
        "output_offset": 4096, "flags": "R-X code" }
    ]
  },
  "entry_output_offset": 40960,         // where to jump/call inside YOUR blob
  "warnings": []
}
```

Consuming the `image` blob: allocate `size_of_image_effective` → copy the blob in →
apply relocations if `has_relocs` and the base differs → resolve imports →
call `DllMain` (DLL) or jump to `entry_output_offset` (EXE).

## Notes & limitations

- The input is **never executed**; it is read as bytes only.
- `image` / `sections` modes drop overlay data and the Authenticode table —
  they are file-layout artifacts. Use `file` mode for byte-exact copies.
- Relocations and imports are **not** applied — that is your loader's job;
  the report tells you what it needs.
- Encrypted/packed sections are dumped as-is: `pe2bin` does not unpack.
- Hostile or malformed inputs fail closed with a structured error instead of
  producing a corrupt blob.

Errors are structured everywhere:

```json
{
  "status": "ERROR",
  "code": "E_NO_PE",
  "message": "Missing PE signature at offset 0x... .",
  "suggestion": "Input is not a PE executable (maybe ELF/Mach-O?)."
}
```

Full reference — every error code, all JSON fields, loader-integration details:
[`usage.md`](usage.md).

## Project layout

```
pe2bin.py          # the tool (single file, stdlib only)
usage.md           # full reference: modes, CLI, error contract, report fields
config.meta        # machine-readable manifest (dependencies, OS, risk flags)
requirements.txt   # dependency declaration (stdlib only)
LICENSE            # © 2026 WDRXN — all rights reserved
```

## Copyright

© 2026 WDRXN. **All rights reserved.**

No license is granted. This software may not be used, copied, modified,
distributed, or incorporated into other work — in whole or in part — without
explicit written permission from the author. See [`LICENSE`](LICENSE).
