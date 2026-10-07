# pe2bin — PE (.exe/.dll) → raw flat binary

[![All rights reserved](https://img.shields.io/badge/license-all%20rights%20reserved-red.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Stdlib only](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](requirements.txt)

`pe2bin` takes a Windows PE file and writes a raw `.bin` blob to a path you
specify. Pure Python 3, standard library only, no dependencies.

> **Note:** per your AGENTS.md rule, the tool is *built but not executed* here.
> Run it yourself when you're ready.

---

## 1. Quick start

```bash
# default: memory-image layout (what a payload loader wants)
python pe2bin.py target.exe -o target.bin

# overwrite an existing output
python pe2bin.py target.dll -o out\target.bin --mode image --force

# machine-readable report on stdout
python pe2bin.py target.exe -o target.bin --json > report.json
```

Requires **Python 3.8+** on Windows / Linux / macOS. The *input* can be any
PE (x86/x64/ARM/ARM64, EXE or DLL); the *host* OS does not matter.

---

## 2. Output modes — pick the one your loader expects

### `image` (default) — raw PE image, memory layout

```
offset 0x0000  ┌─────────────────────────┐
                │ PE headers (SizeOfHeaders)  │
offset 0x1000  ├─────────────────────────┤
                │ .text   @ VirtualAddress    │
                │ .rdata  @ VirtualAddress    │
                │ .data   @ VirtualAddress    │
                │ ...  zero-padded to SizeOfImage
                └─────────────────────────┘
                total size = SizeOfImage
```

Headers stay at offset 0, every section is placed at its `VirtualAddress`,
gaps are zero-filled, total length = `SizeOfImage`. This is exactly how the
module looks once mapped in memory.

**Loader consumption:** the blob is position-independent (sections use RVAs):

1. Allocate `SizeOfImage` RWX (or per-section protections after copying).
2. Copy the blob in.
3. Apply base relocations if `ImageBase != actual base`
   (report tells you `has_relocs`).
4. Resolve imports.
5. (DLL) call `DllMain`; (EXE) jump to `entry_output_offset` from the report.

### `file` — verbatim bytes

Identical bytes to the input file (headers + `PointerToRawData` layout +
overlay/Authenticode intact). Choose this when your loader parses the PE
itself and maps sections using `PointerToRawData`.

### `sections` — headers stripped

Section raw data only, concatenated in `VirtualAddress` order. The JSON
report gives you `output_offset` for every section, so your loader/loader
stub knows where each one landed. Header-only RVAs (entry in headers) are
reported as `null`.

---

## 3. CLI reference

| Flag | Description |
|---|---|
| `input` | path to the input `.exe` / `.dll` (positional) |
| `-o, --output` | **required** — path of the `.bin` to write |
| `-m, --mode` | `image` (default) \| `file` \| `sections` |
| | aliases: `raw`, `memory` → image; `verbatim`, `copy` → file; `noheaders` → sections |
| `-f, --force` | overwrite the output if it exists (default: refuse) |
| `--json` | full report as JSON on stdout; errors as JSON on stderr |
| `-q, --quiet` | suppress the human summary |
| `--version` | print version |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | unexpected internal error (traceback on stderr) |
| 2 | format/validation error (`E_NO_MZ`, `E_NO_PE`, `E_BAD_MAGIC`, …) |
| 3 | I/O error (missing input, unreadable/unwritable path) |
| 4 | path conflict (output exists without `--force`, input == output) |

### Error contract (with `--json`)

```json
{
  "status": "ERROR",
  "code": "E_NO_PE",
  "message": "Missing PE signature at offset 0x... .",
  "suggestion": "Input is not a PE executable (maybe ELF/Mach-O?)."
}
```

Error codes: `E_TOO_SMALL`, `E_NO_MZ`, `E_BAD_LFANEW`, `E_NO_PE`,
`E_NO_SECTIONS`, `E_BAD_SECTIONS`, `E_BAD_OPT_HDR`, `E_BAD_MAGIC`,
`E_ROM_IMAGE`, `E_TRUNCATED`, `E_IMAGE_TOO_LARGE`, `E_NO_RAW_DATA`,
`E_BAD_MODE`, `E_NO_INPUT`, `E_EMPTY`, `E_IO`, `E_OUTPUT_EXISTS`,
`E_SAME_PATH`, `E_INTERNAL`.

---

## 4. JSON report fields (loader-relevant)

```jsonc
{
  "status": "OK",
  "mode": "image",
  "input":  { "path": "...", "size": 123456, "sha256": "..." },
  "output": { "path": "...", "size": 126976, "sha256": "...", "mode": "image" },
  "pe": {
    "arch": "x64", "bits": 64, "is_dll": true,
    "image_base": 74448885760,        // decimal; also "*_hex" fields
    "entry_rva": 40960,
    "size_of_image_effective": 126976, // validated/repaired value the blob uses
    "size_of_headers": 1024,
    "has_relocs": true,               // loader must relocate if base differs
    "is_managed_dotnet": false,       // .NET -> needs CLR host, not raw exec
    "has_authenticode_signature": false, // kept in 'file', dropped otherwise
    "subsystem": "Windows_CUI",
    "sections": [
      { "name": ".text", "virtual_address": 4096, "virtual_size": 90112,
        "raw_size": 90112, "raw_offset": 1024,
        "output_offset": 4096,        // offset inside YOUR blob
        "flags": "R-X code" }
    ]
  },
  "entry_output_offset": 40960,       // where to jump/call in the blob
  "warnings": ["..."]
}
```

**Warnings** cover real-world junk: repaired `SizeOfImage`, truncated section
raw data, `PointerToRawData = 0`, overlapping sections, dropped overlay, bogus
`SizeOfHeaders`. Read them — hostile/packed binaries trigger several by design.

---

## 5. Notes & limitations

- The tool **never executes** the input, never touches the network, never
  writes anywhere except the `--output` path (atomic: temp file + rename).
  Missing parent directories in the output path are created automatically;
  existing outputs are refused unless `--force` is given.
- `image`/`sections` modes drop overlay data and the Authenticode table
  (they are file-layout artifacts). Use `file` mode if you need them byte-exact.
- Relocations and imports are **not** applied — that is your loader's job.
  The report tells you what it needs (`has_relocs`, `image_base`, dirs).
- Encrypted/packed sections are dumped as-is: `pe2bin` does not unpack.
- The output blob carries no checksum validation; compare the report's
  `sha256` values if you need integrity verification downstream.

---

## Copyright

© 2026 WDRXN. **All rights reserved.**

No license is granted. This software may not be used, copied, modified,
distributed, or incorporated into other work — in whole or in part — without
explicit written permission from the author. See [`LICENSE`](LICENSE).
