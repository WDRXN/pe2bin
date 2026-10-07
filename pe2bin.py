#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pe2bin - convert a PE executable (.exe) / library (.dll) into a raw flat binary.

Copyright (c) 2026 WDRXN. All rights reserved. See LICENSE.
No license is granted - no use, copying, modification, distribution, or
incorporation into other work without explicit written permission from the
author.

[Xyberix] Tool Development Framework - Build only. Requires Manual Execution.
[Xyberix] Disk write: writes ONLY to the user-specified --output path.
          No network access, no process spawn, no registry, no persistence,
          no injection, no self-replication. The tool never runs the input file.

Modes:
  image    (default) PE headers at offset 0, each section placed at its
           VirtualAddress, zero-padded to SizeOfImage. The classic "raw PE
           image" a manual-map / payload loader consumes.
  file     Verbatim byte copy of the input (PointerToRawData layout intact).
  sections Headers stripped; section raw data concatenated in VirtualAddress
           order; per-section output offsets reported.

Usage:
  python pe2bin.py input.exe -o output.bin
  python pe2bin.py input.dll -o output.bin --mode image --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import tempfile
import traceback

TOOL_NAME = "pe2bin"
TOOL_VERSION = "1.0.0"

# --------------------------------------------------------------------------
# PE constants
# --------------------------------------------------------------------------

IMAGE_DOS_MAGIC = b"MZ"
IMAGE_NT_SIGNATURE = b"PE\x00\x00"

OPT_MAGIC_PE32 = 0x10B
OPT_MAGIC_PE32_PLUS = 0x20B
OPT_MAGIC_ROM = 0x107

MACHINE_NAMES = {
    0x014C: "x86 (i386)",
    0x0166: "MIPS R4000",
    0x01A2: "SH3",
    0x01C0: "ARM",
    0x01C4: "ARM Thumb-2",
    0x0200: "IA-64",
    0x8664: "x64 (AMD64)",
    0xAA64: "ARM64",
    0x5032: "RISCV32",
    0x5064: "RISCV64",
    0x5128: "RISCV128",
}

SUBSYSTEM_NAMES = {
    0: "Unknown",
    1: "Native",
    2: "Windows_GUI",
    3: "Windows_CUI",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    9: "Windows_CE_GUI",
    10: "EFI_Application",
    11: "EFI_Boot_Service_Driver",
    12: "EFI_Runtime_Driver",
    13: "EFI_ROM",
    14: "XBOX",
    16: "Windows_Boot_Application",
}

IMAGE_FILE_DLL = 0x2000
IMAGE_FILE_RELOCS_STRIPPED = 0x0001

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# Data directory indices we care about
DD_IMPORT = 1
DD_BASERELOC = 5
DD_SECURITY = 4        # Authenticode (file offset, not RVA)
DD_COM_DESCRIPTOR = 14  # .NET

MAX_REASONABLE_IMAGE = 0x80000000  # 2 GiB hard cap for image/sections modes


# --------------------------------------------------------------------------
# Structured error contract (AGENTS.md "TECH_UNFEASIBLE" style)
# --------------------------------------------------------------------------

class ToolError(Exception):
    """Fatal, structured error. Always rendered as a documented payload."""

    def __init__(self, code: str, message: str, suggestion: str = "",
                 status: int = 2):
        super().__init__(message)
        self.code = code
        self.message = message
        self.suggestion = suggestion
        self.status = status  # process exit status

    def to_json(self) -> str:
        return json.dumps({
            "status": "ERROR",
            "code": self.code,
            "message": self.message,
            "suggestion": self.suggestion,
        }, indent=2)


# --------------------------------------------------------------------------
# Tiny bounds-checked readers
# --------------------------------------------------------------------------

def _u16(data: bytes, off: int) -> int:
    if off + 2 > len(data):
        raise ToolError("E_TRUNCATED", f"Read u16 at 0x{off:X} past end of file.",
                        "Input file is truncated or corrupt.")
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    if off + 4 > len(data):
        raise ToolError("E_TRUNCATED", f"Read u32 at 0x{off:X} past end of file.",
                        "Input file is truncated or corrupt.")
    return struct.unpack_from("<I", data, off)[0]


def _u64(data: bytes, off: int) -> int:
    if off + 8 > len(data):
        raise ToolError("E_TRUNCATED", f"Read u64 at 0x{off:X} past end of file.",
                        "Input file is truncated or corrupt.")
    return struct.unpack_from("<Q", data, off)[0]


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return ((value + alignment - 1) // alignment) * alignment


# --------------------------------------------------------------------------
# PE model
# --------------------------------------------------------------------------

class Section:
    __slots__ = ("name", "virtual_size", "virtual_address", "raw_size",
                 "raw_offset", "characteristics", "output_offset")

    def __init__(self, name, virtual_size, virtual_address, raw_size,
                 raw_offset, characteristics):
        self.name = name
        self.virtual_size = virtual_size
        self.virtual_address = virtual_address
        self.raw_size = raw_size
        self.raw_offset = raw_offset
        self.characteristics = characteristics
        self.output_offset = None  # filled in per mode

    @property
    def flags(self) -> str:
        c = self.characteristics
        perms = ("R" if c & IMAGE_SCN_MEM_READ else "-")
        perms += ("W" if c & IMAGE_SCN_MEM_WRITE else "-")
        perms += ("X" if c & IMAGE_SCN_MEM_EXECUTE else "-")
        kind = "code" if c & IMAGE_SCN_CNT_CODE else (
            "data" if c & IMAGE_SCN_CNT_INITIALIZED_DATA else (
                "bss" if c & IMAGE_SCN_CNT_UNINITIALIZED_DATA else "none"))
        return f"{perms} {kind}"

    @property
    def mapped_end(self) -> int:
        return self.virtual_address + max(self.virtual_size, self.raw_size)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "virtual_address": self.virtual_address,
            "virtual_address_hex": f"0x{self.virtual_address:08X}",
            "virtual_size": self.virtual_size,
            "raw_size": self.raw_size,
            "raw_offset": self.raw_offset,
            "output_offset": self.output_offset,
            "characteristics": f"0x{self.characteristics:08X}",
            "flags": self.flags,
        }


class PEInfo:
    def __init__(self):
        self.machine = 0
        self.machine_name = "unknown"
        self.arch = "unknown"
        self.number_of_sections = 0
        self.file_characteristics = 0
        self.is_dll = False
        self.is_relocs_stripped = False
        self.pe32_plus = False
        self.opt_magic = 0
        self.entry_rva = 0
        self.image_base = 0
        self.section_alignment = 0
        self.file_alignment = 0
        self.size_of_image = 0        # as declared
        self.effective_size_of_image = 0  # validated / repaired
        self.size_of_headers = 0
        self.subsystem = 0
        self.dll_characteristics = 0
        self.checksum = 0
        self.sections: list = []
        self.has_relocs = False
        self.is_managed = False       # .NET
        self.has_authenticode = False
        self.overlay_offset = 0
        self.warnings: list = []

    def to_dict(self) -> dict:
        return {
            "machine": f"0x{self.machine:04X}",
            "arch": self.arch,
            "machine_name": self.machine_name,
            "bits": 64 if self.pe32_plus else 32,
            "is_dll": self.is_dll,
            "is_managed_dotnet": self.is_managed,
            "has_relocs": self.has_relocs,
            "relocs_stripped": self.is_relocs_stripped,
            "has_authenticode_signature": self.has_authenticode,
            "entry_rva": self.entry_rva,
            "entry_rva_hex": f"0x{self.entry_rva:08X}",
            "image_base": self.image_base,
            "image_base_hex": f"0x{self.image_base:X}",
            "section_alignment": self.section_alignment,
            "file_alignment": self.file_alignment,
            "size_of_image_declared": self.size_of_image,
            "size_of_image_effective": self.effective_size_of_image,
            "size_of_headers": self.size_of_headers,
            "subsystem": SUBSYSTEM_NAMES.get(self.subsystem, str(self.subsystem)),
            "dll_characteristics": f"0x{self.dll_characteristics:04X}",
            "checksum": f"0x{self.checksum:08X}",
            "file_characteristics": f"0x{self.file_characteristics:04X}",
            "overlay_offset": self.overlay_offset,
            "section_count": len(self.sections),
            "sections": [s.to_dict() for s in self.sections],
        }


def parse_pe(data: bytes) -> PEInfo:
    """Parse and validate a PE image. Raises ToolError on anything malformed."""
    if len(data) < 0x40:
        raise ToolError("E_TOO_SMALL",
                        f"File is {len(data)} bytes; a PE needs at least 64.",
                        "Provide a valid .exe or .dll input.")

    if data[0:2] != IMAGE_DOS_MAGIC:
        raise ToolError("E_NO_MZ",
                        "Missing MZ signature at offset 0x00.",
                        "Input is not a DOS/PE executable (check the file).")

    e_lfanew = _u32(data, 0x3C)
    if e_lfanew < 0x40 or e_lfanew + 24 > len(data):
        raise ToolError("E_BAD_LFANEW",
                        f"e_lfanew points at 0x{e_lfanew:X}, outside the file.",
                        "File is corrupt or not a PE.")

    if data[e_lfanew:e_lfanew + 4] != IMAGE_NT_SIGNATURE:
        raise ToolError("E_NO_PE",
                        f"Missing PE signature at offset 0x{e_lfanew:X}.",
                        "Input is not a PE executable (maybe ELF/Mach-O?).")

    coff = e_lfanew + 4
    pe = PEInfo()
    pe.machine = _u16(data, coff + 0)
    pe.number_of_sections = _u16(data, coff + 2)
    size_of_optional = _u16(data, coff + 16)
    pe.file_characteristics = _u16(data, coff + 18)

    pe.machine_name = MACHINE_NAMES.get(pe.machine, f"unknown (0x{pe.machine:04X})")
    pe.arch = {0x014C: "x86", 0x8664: "x64", 0x01C4: "arm", 0x01C0: "arm",
               0xAA64: "arm64"}.get(pe.machine, pe.machine_name)
    pe.is_dll = bool(pe.file_characteristics & IMAGE_FILE_DLL)
    pe.is_relocs_stripped = bool(pe.file_characteristics & IMAGE_FILE_RELOCS_STRIPPED)

    if pe.number_of_sections == 0:
        raise ToolError("E_NO_SECTIONS", "PE declares zero sections.",
                        "File is malformed; nothing to convert.")
    if pe.number_of_sections > 512:
        raise ToolError("E_BAD_SECTIONS",
                        f"Implausible section count: {pe.number_of_sections}.",
                        "File is malformed or adversarially crafted.")

    opt = coff + 20
    # >= 72 so that CheckSum/Subsystem/DllCharacteristics all lie inside the
    # optional header (real PEs declare 224 / 240 bytes).
    if size_of_optional < 72 or opt + size_of_optional > len(data):
        raise ToolError("E_BAD_OPT_HDR",
                        f"Optional header size {size_of_optional} is invalid.",
                        "File is malformed or truncated.")

    pe.opt_magic = _u16(data, opt + 0)
    if pe.opt_magic == OPT_MAGIC_ROM:
        raise ToolError("E_ROM_IMAGE", "ROM image (PE32 ROM) is not supported.",
                        "Convert a normal executable instead.")
    if pe.opt_magic not in (OPT_MAGIC_PE32, OPT_MAGIC_PE32_PLUS):
        raise ToolError("E_BAD_MAGIC",
                        f"Unknown optional header magic 0x{pe.opt_magic:X}.",
                        "Expected PE32 (0x10B) or PE32+ (0x20B).")
    pe.pe32_plus = pe.opt_magic == OPT_MAGIC_PE32_PLUS

    expected_opt = 240 if pe.pe32_plus else 224
    if size_of_optional < expected_opt:
        pe.warnings.append(
            f"Optional header is {size_of_optional} bytes (expected {expected_opt}); "
            "reading only the core fields that are present.")

    pe.entry_rva = _u32(data, opt + 16)
    pe.image_base = _u64(data, opt + 24) if pe.pe32_plus else _u32(data, opt + 28)
    pe.section_alignment = _u32(data, opt + 32)
    pe.file_alignment = _u32(data, opt + 36)
    pe.size_of_image = _u32(data, opt + 56)
    pe.size_of_headers = _u32(data, opt + 60)
    pe.checksum = _u32(data, opt + 64)
    pe.subsystem = _u16(data, opt + 68)
    pe.dll_characteristics = _u16(data, opt + 70)

    # Data directories (bounded by what the header actually declares)
    dd_base = opt + (112 if pe.pe32_plus else 96)
    num_dd_off = opt + (108 if pe.pe32_plus else 92)
    num_dd = _u32(data, num_dd_off) if num_dd_off + 4 <= opt + size_of_optional else 0

    def dd(index: int):
        if index >= num_dd:
            return (0, 0)
        off = dd_base + index * 8
        if off + 8 > opt + size_of_optional:
            return (0, 0)
        return (_u32(data, off), _u32(data, off + 4))

    reloc_rva, reloc_size = dd(DD_BASERELOC)
    com_rva, _ = dd(DD_COM_DESCRIPTOR)
    _, auth_size = dd(DD_SECURITY)
    _, import_size = dd(DD_IMPORT)

    pe.has_relocs = (not pe.is_relocs_stripped) and reloc_rva != 0 and reloc_size != 0
    pe.is_managed = com_rva != 0
    pe.has_authenticode = auth_size != 0
    if import_size == 0 and not pe.is_managed:
        pe.warnings.append("No import directory found (possibly packed/reflective).")

    # ---- Section table ----------------------------------------------------
    sect_off = opt + size_of_optional
    table_end = sect_off + pe.number_of_sections * 40
    if table_end > len(data):
        raise ToolError("E_TRUNCATED",
                        f"Section table (0x{sect_off:X}-0x{table_end:X}) "
                        "extends past end of file.",
                        "File is truncated.")

    for i in range(pe.number_of_sections):
        off = sect_off + i * 40
        raw_name = data[off:off + 8]
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        sec = Section(
            name=name or f"sec{i}",
            virtual_size=_u32(data, off + 8),
            virtual_address=_u32(data, off + 12),
            raw_size=_u32(data, off + 16),
            raw_offset=_u32(data, off + 20),
            characteristics=_u32(data, off + 36),
        )
        # Truncated raw data: clamp later, but warn now.
        if sec.raw_size > 0 and sec.raw_offset > 0 and \
                sec.raw_offset + sec.raw_size > len(data):
            pe.warnings.append(
                f"Section '{sec.name}' raw data (0x{sec.raw_offset:X}+"
                f"0x{sec.raw_size:X}) exceeds file size; output will be clamped.")
        if sec.raw_size > 0 and sec.raw_offset == 0:
            pe.warnings.append(
                f"Section '{sec.name}' declares raw size but PointerToRawData=0; "
                "treated as zero-filled.")
        pe.sections.append(sec)

    # Section overlap sanity (warnings only - hostile binaries do this on purpose)
    ordered = sorted(pe.sections, key=lambda s: s.virtual_address)
    for a, b in zip(ordered, ordered[1:]):
        if a.mapped_end > b.virtual_address and a.raw_size > 0:
            pe.warnings.append(
                f"Section '{a.name}' (ends 0x{a.mapped_end:X}) overlaps "
                f"section '{b.name}' at VA 0x{b.virtual_address:X}.")

    # ---- Validate / repair SizeOfImage ------------------------------------
    sa = pe.section_alignment
    if sa == 0 or sa > 0x10000000:
        pe.warnings.append(f"Bogus SectionAlignment 0x{sa:X}; assuming 0x1000.")
        sa = 0x1000
    if sa & (sa - 1):
        pe.warnings.append(f"SectionAlignment 0x{sa:X} is not a power of two; "
                           "alignment output may differ from the loader's view.")

    hdr_len = pe.size_of_headers
    if not (0 < hdr_len <= len(data)):
        raw_ptrs = [s.raw_offset for s in pe.sections if s.raw_offset > 0]
        hdr_len = min(raw_ptrs) if raw_ptrs else min(0x200, len(data))
        pe.warnings.append(
            f"Bogus SizeOfHeaders 0x{pe.size_of_headers:X}; using 0x{hdr_len:X}.")

    needed = hdr_len
    for sec in pe.sections:
        if sec.virtual_address == 0 and sec.raw_size == 0 and sec.virtual_size == 0:
            continue
        needed = max(needed, sec.mapped_end)
    needed = _align_up(needed, sa)

    declared = pe.size_of_image
    if declared < needed:
        pe.warnings.append(
            f"SizeOfImage 0x{declared:X} is smaller than the mapped sections "
            f"(0x{needed:X}); repaired to 0x{needed:X}.")
        declared = needed
    if declared > MAX_REASONABLE_IMAGE:
        raise ToolError(
            "E_IMAGE_TOO_LARGE",
            f"Resulting image would be {declared} bytes "
            f"(> {MAX_REASONABLE_IMAGE} bytes).",
            "Hostile or corrupt SizeOfImage; refusing to allocate.",
            status=2)

    pe.effective_size_of_image = declared
    pe.size_of_headers = hdr_len

    # Overlay (data past the last section's raw end) - dropped in image/sections
    last_raw_end = 0
    for sec in pe.sections:
        if sec.raw_size > 0 and sec.raw_offset > 0:
            last_raw_end = max(last_raw_end, sec.raw_offset + sec.raw_size)
    pe.overlay_offset = last_raw_end
    if last_raw_end < len(data) and not (pe.has_authenticode and
                                         auth_size == len(data) - last_raw_end):
        if len(data) - last_raw_end > 0:
            pe.warnings.append(
                f"{len(data) - last_raw_end} bytes of overlay/cert data follow the "
                "image; kept in 'file' mode, dropped in 'image'/'sections' mode.")

    return pe


# --------------------------------------------------------------------------
# Conversion modes
# --------------------------------------------------------------------------

def build_image(data: bytes, pe: PEInfo) -> bytes:
    """Flat memory image: headers at 0, sections at their VirtualAddress."""
    size = pe.effective_size_of_image
    try:
        out = bytearray(size)
    except MemoryError:
        raise ToolError(
            "E_IMAGE_TOO_LARGE",
            f"Could not allocate a {size} byte image buffer.",
            "SizeOfImage is implausibly large for this machine.",
            status=2)

    # [Xyberix] — Memory-image builder: pure byte shuffling, no execution.
    hdr_len = min(pe.size_of_headers, len(data))
    min_va = min((s.virtual_address for s in pe.sections
                  if s.virtual_address > 0), default=hdr_len)
    if hdr_len > min_va:
        pe.warnings.append(
            f"SizeOfHeaders (0x{hdr_len:X}) reaches into the first section "
            f"(0x{min_va:X}); header copy clamped.")
        hdr_len = min_va
    out[0:hdr_len] = data[0:hdr_len]

    for sec in pe.sections:
        sec.output_offset = sec.virtual_address
        if sec.raw_size <= 0 or sec.raw_offset <= 0:
            continue
        if sec.virtual_address >= size:
            pe.warnings.append(
                f"Section '{sec.name}' VA 0x{sec.virtual_address:X} lies outside "
                f"the image (0x{size:X}); dropped.")
            sec.output_offset = None
            continue
        avail = min(sec.raw_size, len(data) - sec.raw_offset)
        if avail <= 0:
            continue
        copy_len = min(avail, size - sec.virtual_address)
        dst = sec.virtual_address
        out[dst:dst + copy_len] = data[sec.raw_offset:sec.raw_offset + copy_len]
        # remainder stays zero-filled (covers .bss and VirtualSize padding)

    return bytes(out)


def build_sections(data: bytes, pe: PEInfo) -> bytes:
    """Headers stripped; section raw data concatenated in VA order."""
    # [Xyberix] — Flat-section builder: pure byte shuffling, no execution.
    chunks = []
    offset = 0
    for sec in sorted(pe.sections, key=lambda s: s.virtual_address):
        if sec.raw_size > 0 and sec.raw_offset > 0:
            avail = min(sec.raw_size, len(data) - sec.raw_offset)
            if avail > 0:
                sec.output_offset = offset
                chunks.append(data[sec.raw_offset:sec.raw_offset + avail])
                offset += avail
                continue
        sec.output_offset = None
    if not chunks:
        raise ToolError("E_NO_RAW_DATA",
                        "No section contains raw data to emit.",
                        "Input may be a header-only or corrupt file.")
    return b"".join(chunks)


def build_file(data: bytes, pe: PEInfo) -> bytes:
    """Verbatim byte copy - PointerToRawData layout preserved."""
    for sec in pe.sections:
        sec.output_offset = sec.raw_offset if sec.raw_size > 0 else None
    return data


def resolve_entry_offset(mode: str, entry_rva: int, pe: PEInfo):
    """Map the entry RVA to an offset inside the produced blob (or None)."""
    if entry_rva == 0:
        return None
    if mode == "file":
        if entry_rva < pe.size_of_headers:
            return entry_rva
        for sec in pe.sections:
            if sec.raw_size > 0 and sec.virtual_address <= entry_rva < \
                    sec.virtual_address + sec.raw_size:
                return sec.raw_offset + (entry_rva - sec.virtual_address)
        return None
    if mode == "image":
        return entry_rva if entry_rva < pe.effective_size_of_image else None
    # sections mode
    for sec in pe.sections:
        span = max(sec.virtual_size, sec.raw_size)
        if sec.output_offset is not None and span > 0 and \
                sec.virtual_address <= entry_rva < sec.virtual_address + span:
            return sec.output_offset + (entry_rva - sec.virtual_address)
    return None


BUILDERS = {
    "image": build_image,
    "file": build_file,
    "sections": build_sections,
}
MODE_ALIASES = {
    "image": "image", "img": "image", "memory": "image", "raw": "image",
    "file": "file", "verbatim": "file", "copy": "file",
    "sections": "sections", "noheaders": "sections", "sec": "sections",
}


# --------------------------------------------------------------------------
# Output (the only disk write in this tool)
# --------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# [Xyberix] — Disk write: output ONLY goes to the caller-specified path.
def atomic_write(path: str, payload: bytes, force: bool) -> None:
    path = os.path.abspath(path)
    parent = os.path.dirname(path)
    try:
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        if os.path.exists(path) and not force:
            raise ToolError(
                "E_OUTPUT_EXISTS",
                f"Output already exists: {path}",
                "Re-run with --force to overwrite, or pick another path.",
                status=4)
        fd, tmp = tempfile.mkstemp(prefix=".pe2bin.", suffix=".tmp", dir=parent or ".")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except ToolError:
        raise
    except OSError as exc:
        raise ToolError("E_IO", f"Cannot write output: {exc}",
                        "Check path permissions and free space.", status=3)


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def print_human_report(report: dict, quiet: bool) -> None:
    if quiet:
        return
    pe = report["pe"]
    src, dst = report["input"], report["output"]
    print(f"{TOOL_NAME} v{TOOL_VERSION} - status: OK")
    print(f"  input   : {src['path']}  ({src['size']} bytes, sha256 {src['sha256'][:16]}...)")
    print(f"  output  : {dst['path']}  ({dst['size']} bytes, mode={dst['mode']})")
    print(f"  format  : {'PE32+' if pe['bits'] == 64 else 'PE32'} "
          f"{pe['arch']}  {'DLL' if pe['is_dll'] else 'EXE'}  "
          f"{'(.NET)' if pe['is_managed_dotnet'] else ''}")
    print(f"  base    : 0x{pe['image_base']:X}  entry RVA 0x{pe['entry_rva']:08X}"
          f"  ->  blob offset "
          f"{'0x%08X' % report['entry_output_offset'] if report['entry_output_offset'] is not None else 'n/a'}")
    print(f"  image   : SizeOfImage 0x{pe['size_of_image_effective']:X}  "
          f"SectionAlignment 0x{pe['section_alignment']:X}")
    print(f"  sections: {pe['section_count']}")
    print(f"    {'name':<9} {'VA':>10} {'vsize':>10} {'raw':>10} {'out@':>10}  perms")
    for s in pe["sections"]:
        out_at = f"0x{s['output_offset']:X}" if s["output_offset"] is not None else "-"
        print(f"    {s['name'][:9]:<9} 0x{s['virtual_address']:08X} "
              f"{s['virtual_size']:>10} {s['raw_size']:>10} {out_at:>10}  {s['flags']}")
    if report["warnings"]:
        print(f"  warnings ({len(report['warnings'])}):")
        for w in report["warnings"]:
            print(f"    ! {w}")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Convert a PE (.exe/.dll) into a raw flat binary blob.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "modes:\n"
            "  image     headers at 0, sections at VirtualAddress, padded to\n"
            "            SizeOfImage - the raw PE image a manual-map/payload\n"
            "            loader consumes (default).\n"
            "  file      verbatim byte copy (PointerToRawData layout intact).\n"
            "  sections  headers stripped, sections concatenated by VA, per-section\n"
            "            offsets emitted in the JSON report.\n"
            "\nexamples:\n"
            "  python pe2bin.py target.exe -o target.bin\n"
            "  python pe2bin.py target.dll -o out\\target.bin --mode image --force\n"
            "  python pe2bin.py target.exe -o target.bin --json > report.json\n"
            "  python pe2bin.py target.exe -o target.bin --mode sections --json\n"
        ))
    p.add_argument("input", help="path to the input .exe / .dll")
    p.add_argument("-o", "--output", required=True, help="path of the raw .bin to write")
    p.add_argument("-m", "--mode", default="image",
                   help="image | file | sections (aliases: raw/memory, verbatim, "
                        "noheaders). default: image")
    p.add_argument("-f", "--force", action="store_true",
                   help="overwrite the output path if it exists")
    p.add_argument("--json", action="store_true",
                   help="emit the full report as JSON on stdout "
                        "(errors are JSON too, on stderr)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress the human-readable summary")
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    return p


def run(args) -> dict:
    mode = MODE_ALIASES.get(args.mode.lower())
    if mode is None:
        raise ToolError("E_BAD_MODE",
                        f"Unknown mode '{args.mode}'.",
                        "Use one of: image, file, sections.")

    in_path = os.path.abspath(args.input)
    out_path = os.path.abspath(args.output)
    if in_path == out_path:
        raise ToolError("E_SAME_PATH",
                        "Input and output paths are identical.",
                        "Choose a different --output path.", status=4)
    if not os.path.isfile(in_path):
        raise ToolError("E_NO_INPUT", f"Input file not found: {in_path}",
                        "Check the path.", status=3)

    try:
        with open(in_path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise ToolError("E_IO", f"Cannot read input: {exc}",
                        "Check permissions.", status=3)

    if len(data) == 0:
        raise ToolError("E_EMPTY", "Input file is empty.", "Provide a real PE file.")

    pe = parse_pe(data)
    blob = BUILDERS[mode](data, pe)
    entry_offset = resolve_entry_offset(mode, pe.entry_rva, pe)

    atomic_write(out_path, blob, args.force)

    report = {
        "status": "OK",
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "mode": mode,
        "input": {
            "path": in_path,
            "size": len(data),
            "sha256": sha256_bytes(data),
        },
        "output": {
            "path": out_path,
            "size": len(blob),
            "sha256": sha256_bytes(blob),
            "mode": mode,
        },
        "pe": pe.to_dict(),
        "entry_output_offset": entry_offset,
        "entry_output_offset_hex": (
            f"0x{entry_offset:08X}" if entry_offset is not None else None),
        "warnings": pe.warnings,
    }
    return report


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        report = run(args)
    except ToolError as exc:
        if args.json:
            print(exc.to_json(), file=sys.stderr)
        else:
            print(f"{TOOL_NAME}: error [{exc.code}] {exc.message}", file=sys.stderr)
            if exc.suggestion:
                print(f"  suggestion: {exc.suggestion}", file=sys.stderr)
        return exc.status
    except Exception as exc:  # unexpected - still structured
        err = ToolError("E_INTERNAL", f"{type(exc).__name__}: {exc}",
                        "Unexpected failure; rerun with a valid PE input.")
        if args.json:
            print(err.to_json(), file=sys.stderr)
        else:
            print(f"{TOOL_NAME}: internal error: {err.message}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_human_report(report, args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
